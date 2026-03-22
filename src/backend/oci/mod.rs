//! OCI container backend — runc/crun integration.
//!
//! Detects available OCI runtime (prefers crun over runc) and executes
//! commands in OCI-compliant containers.

use crate::backend::oci_spec;
use crate::backend::oci_spec::oci_runtime::ProcessBuilder;
use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// OCI container-based sandbox backend.
#[derive(Debug)]
pub struct OciBackend {
    config: SandboxConfig,
    runtime: String,
}

impl OciBackend {
    /// Create a new OCI backend. Detects available runtime.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        let runtime = detect_runtime().ok_or_else(|| {
            crate::KavachError::BackendUnavailable("no OCI runtime (runc/crun) found".into())
        })?;
        Ok(Self {
            config: config.clone(),
            runtime,
        })
    }
}

#[async_trait::async_trait]
impl SandboxBackend for OciBackend {
    fn backend_type(&self) -> Backend {
        Backend::Oci
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let container_id = oci_spec::container_id("kavach-oci");

        // Create temp bundle directory
        let bundle_dir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("temp bundle dir: {e}")))?;

        // Create rootfs directory
        let rootfs_dir = bundle_dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs_dir)
            .map_err(|e| crate::KavachError::CreationFailed(format!("rootfs dir: {e}")))?;

        // Generate and write OCI spec
        let mut spec = oci_spec::generate_spec(&self.config)?;

        // Override process args with the actual command
        if let Some(process) = spec.process_mut() {
            let cwd = self
                .config
                .workdir
                .clone()
                .unwrap_or_else(|| "/".to_string());
            *process = ProcessBuilder::default()
                .terminal(false)
                .args(vec!["/bin/sh".into(), "-c".into(), command.into()])
                .cwd(cwd)
                .env(oci_spec::build_env(&self.config))
                .build()
                .map_err(|e| crate::KavachError::ExecFailed(format!("OCI process: {e}")))?;
        }

        oci_spec::write_spec(&spec, bundle_dir.path())?;

        let _ = policy; // Policy is embedded in the OCI spec

        // Run the container
        let mut cmd = tokio::process::Command::new(&self.runtime);
        cmd.args([
            "run",
            "--bundle",
            &bundle_dir.path().to_string_lossy(),
            &container_id,
        ]);

        let result = crate::backend::exec_util::execute_with_timeout(
            &mut cmd,
            self.config.timeout_ms,
            &self.runtime,
        )
        .await;

        // Cleanup container regardless of result
        let _ = tokio::process::Command::new(&self.runtime)
            .args(["delete", "--force", &container_id])
            .output()
            .await;

        result
    }

    async fn health_check(&self) -> crate::Result<bool> {
        let output = tokio::process::Command::new(&self.runtime)
            .arg("--version")
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("{} health: {e}", self.runtime)))?;
        Ok(output.status.success())
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Detect available OCI runtime. Prefers crun (faster) over runc.
fn detect_runtime() -> Option<String> {
    crate::backend::which_first(&["crun", "runc"]).map(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_defaults() {
        let config = SandboxConfig::builder().backend(Backend::Oci).build();
        let env = oci_spec::build_env(&config);
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
        assert!(env.iter().any(|e| e == "TERM=xterm"));
    }

    #[test]
    fn env_custom_vars() {
        let mut config = SandboxConfig::builder().backend(Backend::Oci).build();
        config.env.push(("MY_VAR".into(), "my_value".into()));
        let env = oci_spec::build_env(&config);
        assert!(env.iter().any(|e| e == "MY_VAR=my_value"));
    }

    #[test]
    fn env_preserves_defaults_with_custom() {
        let mut config = SandboxConfig::builder().backend(Backend::Oci).build();
        config.env.push(("X".into(), "1".into()));
        let env = oci_spec::build_env(&config);
        // defaults still present
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
        assert!(env.iter().any(|e| e == "TERM=xterm"));
        // custom also present
        assert!(env.iter().any(|e| e == "X=1"));
    }

    #[test]
    fn network_mode_default_disabled() {
        let config = SandboxConfig::builder()
            .backend(Backend::Oci)
            .network(false)
            .build();
        assert_eq!(oci_spec::network_mode(&config), "none");
    }

    #[test]
    fn network_mode_when_enabled() {
        let mut config = SandboxConfig::builder().backend(Backend::Oci).build();
        config.policy.network.enabled = true;
        assert_eq!(oci_spec::network_mode(&config), "host");
    }

    #[test]
    fn container_id_has_prefix() {
        let id = oci_spec::container_id("kavach-oci");
        assert!(id.starts_with("kavach-oci-"));
    }

    #[test]
    fn container_ids_are_unique() {
        let id1 = oci_spec::container_id("kavach-oci");
        let id2 = oci_spec::container_id("kavach-oci");
        assert_ne!(id1, id2);
    }

    #[test]
    fn detect_runtime_returns_known_or_none() {
        let rt = detect_runtime();
        if let Some(ref name) = rt {
            assert!(name == "crun" || name == "runc");
        }
    }

    #[test]
    fn generate_spec_basic() {
        let config = SandboxConfig::builder().backend(Backend::Oci).build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        assert_eq!(spec.version(), "1.0.2");
    }

    #[test]
    fn generate_spec_strict_has_limits() {
        let config = SandboxConfig::builder()
            .backend(Backend::Oci)
            .policy(SandboxPolicy::strict())
            .build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        let linux = spec.linux().as_ref().unwrap();
        let resources = linux.resources().as_ref().unwrap();
        assert!(resources.memory().is_some());
        assert!(resources.pids().is_some());
    }

    #[test]
    fn write_and_read_spec() {
        let config = SandboxConfig::builder().backend(Backend::Oci).build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        let dir = tempfile::tempdir().unwrap();
        oci_spec::write_spec(&spec, dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["ociVersion"], "1.0.2");
    }

    #[test]
    fn new_fails_without_runtime() {
        if !Backend::Oci.is_available() {
            let config = SandboxConfig::builder().backend(Backend::Oci).build();
            let err = OciBackend::new(&config).unwrap_err();
            assert!(err.to_string().contains("OCI runtime"));
        }
    }
}
