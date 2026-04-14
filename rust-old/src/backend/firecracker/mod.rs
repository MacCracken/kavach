//! Firecracker backend — lightweight microVM isolation.
//!
//! Spawns a Firecracker microVM with a JSON config file, executes commands
//! inside the VM via a task script on a secondary drive, and captures output.

pub mod config;
pub mod network;
pub mod snapshot;
pub mod vsock;

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

use config::FirecrackerConfig;

/// Firecracker microVM sandbox backend.
#[derive(Debug)]
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
        cmd.args(&args);

        for (k, v) in &self.sandbox_config.env {
            cmd.env(k, v);
        }

        crate::backend::exec_util::execute_with_timeout(
            &mut cmd,
            self.sandbox_config.timeout_ms,
            &program,
        )
        .await
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
