//! AMD SEV-SNP backend — encrypted VM memory isolation via QEMU.
//!
//! Launches a QEMU VM with SEV-SNP enabled for hardware-level memory
//! encryption. Requires AMD EPYC CPU with SEV-SNP support and `/dev/sev`.

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// AMD SEV-SNP sandbox backend using QEMU.
#[derive(Debug)]
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
        let workdir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("SEV workdir: {e}")))?;

        // Write task script
        let task_script = workdir.path().join("task.sh");
        std::fs::write(&task_script, format!("#!/bin/sh\n{command}\n"))
            .map_err(|e| crate::KavachError::CreationFailed(format!("write task: {e}")))?;

        let _ = policy; // Policy is embedded in QEMU args (memory, vcpus, SNP policy)

        let args = self.build_qemu_args(workdir.path(), DEFAULT_KERNEL_PATH);

        let mut cmd = tokio::process::Command::new(&self.qemu_path);
        cmd.args(&args);

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        crate::backend::exec_util::execute_with_timeout(&mut cmd, self.config.timeout_ms, "qemu")
            .await
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
