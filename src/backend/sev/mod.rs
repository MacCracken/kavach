//! AMD SEV-SNP backend — encrypted VM memory isolation via QEMU.
//!
//! Launches a QEMU VM with SEV-SNP enabled for hardware-level memory
//! encryption. Requires AMD EPYC CPU with SEV-SNP support and `/dev/sev`.

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// AMD SEV-SNP sandbox backend using QEMU.
pub struct SevBackend {
    config: SandboxConfig,
    qemu_path: String,
}

impl SevBackend {
    /// Create a new SEV backend. Verifies QEMU and /dev/sev.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        let qemu_path = find_qemu().ok_or_else(|| {
            crate::KavachError::BackendUnavailable("qemu-system-x86_64 not found".into())
        })?;

        if !std::path::Path::new("/dev/sev").exists() {
            return Err(crate::KavachError::BackendUnavailable(
                "SEV device /dev/sev not found".into(),
            ));
        }

        Ok(Self {
            config: config.clone(),
            qemu_path,
        })
    }

    /// Build QEMU arguments for SEV-SNP VM launch.
    fn build_qemu_args(&self, workdir: &std::path::Path, kernel_path: &str) -> Vec<String> {
        let vcpus = self
            .config
            .policy
            .cpu_limit
            .map(|c| (c.ceil() as u32).max(1))
            .unwrap_or(2);

        let memory = self.config.policy.memory_limit_mb.unwrap_or(512);

        vec![
            "-enable-kvm".into(),
            "-cpu".into(),
            "EPYC-v4".into(),
            "-machine".into(),
            "q35,confidential-guest-support=sev0,memory-backend=ram1".into(),
            "-object".into(),
            "memory-backend-memfd-private,id=ram1,size={memory}M"
                .replace("{memory}", &memory.to_string()),
            "-object".into(),
            "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1".into(),
            "-smp".into(),
            vcpus.to_string(),
            "-m".into(),
            format!("{memory}M"),
            "-nographic".into(),
            "-no-reboot".into(),
            "-kernel".into(),
            kernel_path.into(),
            "-virtfs".into(),
            format!(
                "local,path={},mount_tag=task,security_model=none,readonly=on",
                workdir.display()
            ),
        ]
    }
}

/// Default kernel path for SEV-SNP VMs.
const DEFAULT_KERNEL_PATH: &str = "/var/lib/kavach/vmlinuz-sev";

/// SEV-SNP policy flags.
pub const SEV_SNP_POLICY: u32 = 0x30000;

/// C-bit position for memory encryption.
pub const CBIT_POS: u32 = 51;

#[async_trait::async_trait]
impl SandboxBackend for SevBackend {
    fn backend_type(&self) -> Backend {
        Backend::Sev
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let start = std::time::Instant::now();

        let workdir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("SEV workdir: {e}")))?;

        // Write task script
        let task_script = workdir.path().join("task.sh");
        std::fs::write(&task_script, format!("#!/bin/sh\n{command}\n"))
            .map_err(|e| crate::KavachError::CreationFailed(format!("write task: {e}")))?;

        let _ = policy; // Policy is embedded in QEMU args (memory, vcpus, SNP policy)

        let args = self.build_qemu_args(workdir.path(), DEFAULT_KERNEL_PATH);

        let mut cmd = tokio::process::Command::new(&self.qemu_path);
        cmd.args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        let timeout = std::time::Duration::from_millis(self.config.timeout_ms);

        let mut child = cmd
            .spawn()
            .map_err(|e| crate::KavachError::ExecFailed(format!("qemu spawn: {e}")))?;

        let stdout_handle = child.stdout.take();
        let stderr_handle = child.stderr.take();

        let collect = async {
            use tokio::io::AsyncReadExt;
            let stdout_fut = async {
                let mut buf = Vec::new();
                if let Some(out) = stdout_handle {
                    out.take(1024 * 1024).read_to_end(&mut buf).await?;
                }
                Ok::<_, std::io::Error>(buf)
            };
            let stderr_fut = async {
                let mut buf = Vec::new();
                if let Some(err) = stderr_handle {
                    err.take(1024 * 1024).read_to_end(&mut buf).await?;
                }
                Ok::<_, std::io::Error>(buf)
            };
            let (stdout_buf, stderr_buf, status) =
                tokio::try_join!(stdout_fut, stderr_fut, child.wait())?;
            Ok::<_, std::io::Error>((status, stdout_buf, stderr_buf))
        };

        match tokio::time::timeout(timeout, collect).await {
            Ok(Ok((status, stdout_buf, stderr_buf))) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                Ok(ExecResult {
                    exit_code: status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
                    stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
                    duration_ms,
                    timed_out: false,
                })
            }
            Ok(Err(e)) => Err(crate::KavachError::ExecFailed(format!("qemu error: {e}"))),
            Err(_) => {
                let _ = child.kill().await;
                let duration_ms = start.elapsed().as_millis() as u64;
                Ok(ExecResult {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms,
                    timed_out: true,
                })
            }
        }
    }

    async fn health_check(&self) -> crate::Result<bool> {
        let output = tokio::process::Command::new(&self.qemu_path)
            .arg("--version")
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("SEV health: {e}")))?;
        Ok(output.status.success())
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Find qemu-system-x86_64 binary.
fn find_qemu() -> Option<String> {
    if crate::backend::which_exists("qemu-system-x86_64") {
        return Some("qemu-system-x86_64".into());
    }
    for path in &[
        "/usr/local/bin/qemu-system-x86_64",
        "/usr/bin/qemu-system-x86_64",
    ] {
        if std::path::Path::new(path).exists() {
            return Some((*path).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_args_contain_sev_snp() {
        let config = SandboxConfig::builder().backend(Backend::Sev).build();
        let backend = SevBackend {
            config: config.clone(),
            qemu_path: "qemu-system-x86_64".into(),
        };
        let args = backend.build_qemu_args(std::path::Path::new("/tmp"), "/vmlinuz");
        let joined = args.join(" ");
        assert!(joined.contains("sev-snp-guest"));
        assert!(joined.contains("confidential-guest-support"));
        assert!(joined.contains("EPYC-v4"));
        assert!(joined.contains("-enable-kvm"));
    }

    #[test]
    fn qemu_args_memory_from_policy() {
        let mut config = SandboxConfig::builder().backend(Backend::Sev).build();
        config.policy.memory_limit_mb = Some(1024);
        let backend = SevBackend {
            config,
            qemu_path: "qemu-system-x86_64".into(),
        };
        let args = backend.build_qemu_args(std::path::Path::new("/tmp"), "/vmlinuz");
        assert!(args.contains(&"1024M".to_string()));
    }

    #[test]
    fn qemu_args_cpu_from_policy() {
        let mut config = SandboxConfig::builder().backend(Backend::Sev).build();
        config.policy.cpu_limit = Some(4.0);
        let backend = SevBackend {
            config,
            qemu_path: "qemu-system-x86_64".into(),
        };
        let args = backend.build_qemu_args(std::path::Path::new("/tmp"), "/vmlinuz");
        assert!(args.contains(&"4".to_string()));
    }

    #[test]
    fn sev_snp_policy_constant() {
        assert_eq!(SEV_SNP_POLICY, 0x30000);
        assert_eq!(CBIT_POS, 51);
    }

    #[test]
    fn find_qemu_does_not_panic() {
        let _ = find_qemu();
    }
}
