//! gVisor (runsc) backend — user-space kernel isolation.
//!
//! Creates OCI bundles and executes commands via `runsc run`.

use crate::backend::oci_spec;
use crate::backend::oci_spec::oci_runtime::ProcessBuilder;
use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// gVisor-based sandbox backend using runsc.
#[derive(Debug)]
pub struct GVisorBackend {
    config: SandboxConfig,
}

impl GVisorBackend {
    /// Create a new gVisor backend. Verifies runsc is available.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        if !Backend::GVisor.is_available() {
            return Err(crate::KavachError::BackendUnavailable(
                "runsc not found in PATH".into(),
            ));
        }
        Ok(Self {
            config: config.clone(),
        })
    }
}

#[async_trait::async_trait]
impl SandboxBackend for GVisorBackend {
    fn backend_type(&self) -> Backend {
        Backend::GVisor
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let container_id = oci_spec::container_id("kavach-gvisor");

        // Create temp bundle directory
        let bundle_dir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("temp bundle dir: {e}")))?;

        // Create rootfs directory (required by OCI spec)
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

        let _ = policy; // Policy is already embedded in the OCI spec

        // Build runsc command
        let network = oci_spec::network_mode(&self.config);
        let mut cmd = tokio::process::Command::new("runsc");
        cmd.args([
            "--network",
            network,
            "run",
            "--bundle",
            &bundle_dir.path().to_string_lossy(),
            &container_id,
        ]);

        let result = crate::backend::exec_util::execute_with_timeout(
            &mut cmd,
            self.config.timeout_ms,
            "runsc",
        )
        .await;

        // Cleanup container regardless of result
        let _ = tokio::process::Command::new("runsc")
            .args(["delete", "--force", &container_id])
            .output()
            .await;

        result
    }

    async fn health_check(&self) -> crate::Result<bool> {
        let output = tokio::process::Command::new("runsc")
            .arg("--version")
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("runsc health: {e}")))?;
        Ok(output.status.success())
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_includes_defaults() {
        let config = SandboxConfig::builder().backend(Backend::GVisor).build();
        let env = oci_spec::build_env(&config);
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
    }

    #[test]
    fn env_includes_custom() {
        let mut config = SandboxConfig::builder().backend(Backend::GVisor).build();
        config.env.push(("FOO".into(), "bar".into()));
        let env = oci_spec::build_env(&config);
        assert!(env.iter().any(|e| e == "FOO=bar"));
    }

    #[test]
    fn env_includes_term() {
        let config = SandboxConfig::builder().backend(Backend::GVisor).build();
        let env = oci_spec::build_env(&config);
        assert!(env.iter().any(|e| e == "TERM=xterm"));
    }

    #[test]
    fn env_multiple_custom_vars() {
        let mut config = SandboxConfig::builder().backend(Backend::GVisor).build();
        config.env.push(("A".into(), "1".into()));
        config.env.push(("B".into(), "2".into()));
        config.env.push(("C".into(), "3".into()));
        let env = oci_spec::build_env(&config);
        assert!(env.iter().any(|e| e == "A=1"));
        assert!(env.iter().any(|e| e == "B=2"));
        assert!(env.iter().any(|e| e == "C=3"));
    }

    #[test]
    fn network_mode_disabled() {
        let config = SandboxConfig::builder()
            .backend(Backend::GVisor)
            .network(false)
            .build();
        assert_eq!(oci_spec::network_mode(&config), "none");
    }

    #[test]
    fn network_mode_enabled() {
        let mut config = SandboxConfig::builder().backend(Backend::GVisor).build();
        config.policy.network.enabled = true;
        assert_eq!(oci_spec::network_mode(&config), "host");
    }

    #[test]
    fn container_id_unique() {
        let id1 = oci_spec::container_id("kavach-gvisor");
        let id2 = oci_spec::container_id("kavach-gvisor");
        assert_ne!(id1, id2);
        assert!(id1.starts_with("kavach-gvisor-"));
    }

    #[test]
    fn generate_spec_sets_version() {
        let config = SandboxConfig::builder().backend(Backend::GVisor).build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        assert_eq!(spec.version(), "1.0.2");
    }

    #[test]
    fn generate_spec_readonly_rootfs() {
        let config = SandboxConfig::builder()
            .backend(Backend::GVisor)
            .policy(SandboxPolicy::strict())
            .build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        let root = spec.root().as_ref().unwrap();
        assert!(root.readonly().unwrap_or(false));
    }

    #[test]
    fn generate_spec_resource_limits() {
        let config = SandboxConfig::builder()
            .backend(Backend::GVisor)
            .policy(SandboxPolicy::strict())
            .build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        let linux = spec.linux().as_ref().unwrap();
        let resources = linux.resources().as_ref().unwrap();
        assert!(resources.memory().is_some());
        assert!(resources.pids().is_some());
    }

    #[test]
    fn generate_spec_no_limits_minimal() {
        let config = SandboxConfig::builder()
            .backend(Backend::GVisor)
            .policy(SandboxPolicy::minimal())
            .build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        let linux = spec.linux().as_ref().unwrap();
        let resources = linux.resources().as_ref();
        // minimal policy has no memory/pids limits
        if let Some(r) = resources {
            assert!(r.memory().is_none());
            assert!(r.pids().is_none());
        }
    }

    #[test]
    fn write_spec_creates_config_json() {
        let config = SandboxConfig::builder().backend(Backend::GVisor).build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        let dir = tempfile::tempdir().unwrap();
        oci_spec::write_spec(&spec, dir.path()).unwrap();
        assert!(dir.path().join("config.json").exists());
    }

    #[test]
    fn write_spec_valid_json() {
        let config = SandboxConfig::builder().backend(Backend::GVisor).build();
        let spec = oci_spec::generate_spec(&config).unwrap();
        let dir = tempfile::tempdir().unwrap();
        oci_spec::write_spec(&spec, dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["ociVersion"], "1.0.2");
    }

    #[test]
    fn new_fails_without_runsc() {
        // Unless runsc is actually installed, this should fail
        if !Backend::GVisor.is_available() {
            let config = SandboxConfig::builder().backend(Backend::GVisor).build();
            let err = GVisorBackend::new(&config).unwrap_err();
            assert!(err.to_string().contains("runsc"));
        }
    }
}
