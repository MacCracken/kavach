//! gVisor (runsc) backend — user-space kernel isolation.
//!
//! Creates OCI bundles and executes commands via `runsc run`.

use crate::backend::oci_spec;
use crate::backend::oci_spec::oci_runtime::ProcessBuilder;
use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// gVisor-based sandbox backend using runsc.
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
        let start = std::time::Instant::now();
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
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

        let timeout = std::time::Duration::from_millis(self.config.timeout_ms);

        let mut child = cmd
            .spawn()
            .map_err(|e| crate::KavachError::ExecFailed(format!("runsc spawn failed: {e}")))?;

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

        let result = match tokio::time::timeout(timeout, collect).await {
            Ok(Ok((status, stdout_buf, stderr_buf))) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                ExecResult {
                    exit_code: status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
                    stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
                    duration_ms,
                    timed_out: false,
                }
            }
            Ok(Err(e)) => {
                return Err(crate::KavachError::ExecFailed(format!("runsc error: {e}")));
            }
            Err(_) => {
                let _ = tokio::process::Command::new("runsc")
                    .args(["kill", &container_id, "SIGKILL"])
                    .output()
                    .await;
                let duration_ms = start.elapsed().as_millis() as u64;
                ExecResult {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms,
                    timed_out: true,
                }
            }
        };

        // Cleanup container
        let _ = tokio::process::Command::new("runsc")
            .args(["delete", "--force", &container_id])
            .output()
            .await;

        Ok(result)
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
}
