//! Firecracker backend — lightweight microVM isolation.
//!
//! Spawns a Firecracker microVM with a JSON config file, executes commands
//! inside the VM via a task script on a secondary drive, and captures output.

pub mod config;

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

use config::FirecrackerConfig;

/// Firecracker microVM sandbox backend.
pub struct FirecrackerBackend {
    sandbox_config: SandboxConfig,
    fc_config: FirecrackerConfig,
}

impl FirecrackerBackend {
    /// Create a new Firecracker backend. Verifies firecracker binary is available.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        if !Backend::Firecracker.is_available() {
            return Err(crate::KavachError::BackendUnavailable(
                "firecracker not found in PATH".into(),
            ));
        }
        let fc_config = FirecrackerConfig::from_sandbox_config(config);
        Ok(Self {
            sandbox_config: config.clone(),
            fc_config,
        })
    }

    /// Detect if the jailer binary is available for hardened execution.
    fn jailer_available() -> bool {
        crate::backend::which_exists("jailer")
    }

    /// Build firecracker command args.
    fn build_args(config_path: &std::path::Path) -> Vec<String> {
        vec![
            "--no-api".into(),
            "--config-file".into(),
            config_path.to_string_lossy().into_owned(),
            "--log-path".into(),
            "/dev/null".into(),
            "--level".into(),
            "Warning".into(),
        ]
    }

    /// Build jailer-wrapped command args.
    fn build_jailer_args(
        vm_id: &str,
        fc_path: &str,
        config_path: &std::path::Path,
        workdir: &std::path::Path,
    ) -> Vec<String> {
        let uid = uid_gid().0;
        let gid = uid_gid().1;

        let mut args = vec![
            "--id".into(),
            vm_id.into(),
            "--exec-file".into(),
            fc_path.into(),
            "--uid".into(),
            uid.to_string(),
            "--gid".into(),
            gid.to_string(),
            "--chroot-base-dir".into(),
            workdir.to_string_lossy().into_owned(),
        ];

        // Detect cgroup version
        if crate::backend::capabilities::cgroup_is_v2() {
            args.extend(["--cgroup-version".into(), "2".into()]);
        }

        // Separator for firecracker args
        args.push("--".into());
        args.extend(Self::build_args(config_path));

        args
    }
}

#[async_trait::async_trait]
impl SandboxBackend for FirecrackerBackend {
    fn backend_type(&self) -> Backend {
        Backend::Firecracker
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let start = std::time::Instant::now();
        let vm_id = format!("kavach-fc-{}", uuid::Uuid::new_v4().as_simple());

        // Create temp working directory
        let workdir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("FC workdir: {e}")))?;

        // Write task script to workdir
        let task_script = workdir.path().join("task.sh");
        std::fs::write(&task_script, format!("#!/bin/sh\n{command}\n"))
            .map_err(|e| crate::KavachError::CreationFailed(format!("write task script: {e}")))?;

        // Write VM config
        let config_path = self.fc_config.write_config(workdir.path())?;

        let _ = policy; // Policy is embedded in the FC config (memory, vcpu)

        // Determine execution mode: jailer (hardened) or direct
        let (program, args) = if Self::jailer_available() {
            let fc_path = find_binary("firecracker").unwrap_or("firecracker".into());
            (
                "jailer".to_string(),
                Self::build_jailer_args(&vm_id, &fc_path, &config_path, workdir.path()),
            )
        } else {
            ("firecracker".to_string(), Self::build_args(&config_path))
        };

        let mut cmd = tokio::process::Command::new(&program);
        cmd.args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Set environment from config
        for (k, v) in &self.sandbox_config.env {
            cmd.env(k, v);
        }

        let timeout = std::time::Duration::from_millis(self.sandbox_config.timeout_ms);

        let mut child = cmd
            .spawn()
            .map_err(|e| crate::KavachError::ExecFailed(format!("{program} spawn failed: {e}")))?;

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
            Ok(Err(e)) => Err(crate::KavachError::ExecFailed(format!(
                "firecracker error: {e}"
            ))),
            Err(_) => {
                // Timeout — kill the VM
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
        let output = tokio::process::Command::new("firecracker")
            .arg("--version")
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("FC health: {e}")))?;
        Ok(output.status.success())
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Get current UID and GID.
fn uid_gid() -> (u32, u32) {
    // Read from /proc/self/status to avoid libc dependency
    #[cfg(target_os = "linux")]
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let mut uid = 0u32;
        let mut gid = 0u32;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Uid:")
                && let Some(first) = val.split_whitespace().next()
            {
                uid = first.parse().unwrap_or(0);
            }
            if let Some(val) = line.strip_prefix("Gid:")
                && let Some(first) = val.split_whitespace().next()
            {
                gid = first.parse().unwrap_or(0);
            }
        }
        return (uid, gid);
    }
    (1000, 1000)
}

/// Find a binary's full path.
fn find_binary(name: &str) -> Option<String> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let full = std::path::Path::new(dir).join(name);
            if full.exists() {
                return Some(full.to_string_lossy().into_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_basic() {
        let args = FirecrackerBackend::build_args(std::path::Path::new("/tmp/fc.json"));
        assert!(args.contains(&"--no-api".to_string()));
        assert!(args.contains(&"--config-file".to_string()));
        assert!(args.contains(&"/tmp/fc.json".to_string()));
    }

    #[test]
    fn find_binary_exists() {
        // echo should exist on any system
        assert!(find_binary("echo").is_some() || find_binary("sh").is_some());
    }

    #[test]
    fn find_binary_not_found() {
        assert!(find_binary("nonexistent_binary_xyz_123").is_none());
    }
}
