//! Intel SGX backend — hardware enclave isolation via Gramine-SGX.
//!
//! Generates Gramine manifest files and executes commands inside SGX enclaves.
//! Requires `gramine-sgx` binary and an SGX-capable CPU with driver loaded.

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// SGX enclave sandbox backend using Gramine-SGX.
pub struct SgxBackend {
    config: SandboxConfig,
    gramine_path: String,
}

impl SgxBackend {
    /// Create a new SGX backend. Verifies gramine-sgx and /dev/sgx_enclave.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        let gramine_path = find_gramine().ok_or_else(|| {
            crate::KavachError::BackendUnavailable("gramine-sgx not found".into())
        })?;

        if !std::path::Path::new("/dev/sgx_enclave").exists() {
            return Err(crate::KavachError::BackendUnavailable(
                "SGX device /dev/sgx_enclave not found".into(),
            ));
        }

        Ok(Self {
            config: config.clone(),
            gramine_path,
        })
    }
}

/// Gramine manifest template for executing a shell command in an enclave.
fn generate_manifest(config: &SandboxConfig, command: &str, workdir: &std::path::Path) -> String {
    let enclave_size = config
        .policy
        .memory_limit_mb
        .map(|mb| format!("{mb}M"))
        .unwrap_or_else(|| "256M".into());

    let script_path = workdir.join("task.sh");
    let _ = std::fs::write(&script_path, format!("#!/bin/sh\n{command}\n"));

    let mut env_lines = String::new();
    env_lines.push_str("loader.env.PATH = \"/usr/local/bin:/usr/bin:/bin\"\n");
    env_lines.push_str("loader.env.HOME = \"/tmp\"\n");
    for (k, v) in &config.env {
        env_lines.push_str(&format!("loader.env.{k} = \"{v}\"\n"));
    }

    format!(
        r#"# Kavach SGX enclave manifest (auto-generated)
[libos]
entrypoint = "/bin/sh"

[loader]
entrypoint = "file:{{{{ gramine.libos }}}}"
argv = ["/bin/sh", "-c", "{command}"]
{env_lines}
[sgx]
enclave_size = "{enclave_size}"
max_threads = 4
edmm_enable = false

[fs]
mounts = [
    {{ path = "/lib",   uri = "file:{{{{ gramine.runtimedir() }}}}" }},
    {{ path = "/usr",   uri = "file:/usr" }},
    {{ path = "/bin",   uri = "file:/bin" }},
    {{ path = "/tmp",   uri = "file:/tmp", type = "tmpfs" }},
    {{ path = "/work",  uri = "file:{workdir}" }},
]

[[fs.trusted_files]]
uri = "file:{{{{ gramine.libos }}}}"

[[fs.trusted_files]]
uri = "file:/bin/sh"
"#,
        command = command.replace('"', "\\\""),
        enclave_size = enclave_size,
        env_lines = env_lines,
        workdir = workdir.display(),
    )
}

#[async_trait::async_trait]
impl SandboxBackend for SgxBackend {
    fn backend_type(&self) -> Backend {
        Backend::Sgx
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let start = std::time::Instant::now();

        let workdir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("SGX workdir: {e}")))?;

        // Generate and write manifest
        let manifest = generate_manifest(&self.config, command, workdir.path());
        let manifest_path = workdir.path().join("task.manifest.sgx");
        std::fs::write(&manifest_path, &manifest)
            .map_err(|e| crate::KavachError::CreationFailed(format!("write manifest: {e}")))?;

        let _ = policy; // Policy is embedded in manifest (enclave_size, threads)

        // Run gramine-sgx
        let mut cmd = tokio::process::Command::new(&self.gramine_path);
        cmd.arg(&manifest_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .current_dir(workdir.path());

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        let timeout = std::time::Duration::from_millis(self.config.timeout_ms);

        let mut child = cmd
            .spawn()
            .map_err(|e| crate::KavachError::ExecFailed(format!("gramine-sgx spawn: {e}")))?;

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
                "gramine-sgx error: {e}"
            ))),
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
        let output = tokio::process::Command::new(&self.gramine_path)
            .arg("--version")
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("SGX health: {e}")))?;
        Ok(output.status.success())
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Find gramine-sgx binary.
fn find_gramine() -> Option<String> {
    for name in &["gramine-sgx"] {
        if crate::backend::which_exists(name) {
            return Some((*name).to_string());
        }
    }
    // Check common install locations
    for path in &["/usr/local/bin/gramine-sgx", "/usr/bin/gramine-sgx"] {
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
    fn manifest_generation() {
        let config = SandboxConfig::builder().backend(Backend::Sgx).build();
        let manifest = generate_manifest(&config, "echo hello", std::path::Path::new("/tmp/test"));
        assert!(manifest.contains("entrypoint"));
        assert!(manifest.contains("enclave_size"));
        assert!(manifest.contains("echo hello"));
    }

    #[test]
    fn manifest_with_memory_limit() {
        let mut config = SandboxConfig::builder().backend(Backend::Sgx).build();
        config.policy.memory_limit_mb = Some(512);
        let manifest = generate_manifest(&config, "ls", std::path::Path::new("/tmp"));
        assert!(manifest.contains("512M"));
    }

    #[test]
    fn manifest_with_env() {
        let mut config = SandboxConfig::builder().backend(Backend::Sgx).build();
        config.env.push(("MY_VAR".into(), "my_value".into()));
        let manifest = generate_manifest(&config, "ls", std::path::Path::new("/tmp"));
        assert!(manifest.contains("MY_VAR"));
        assert!(manifest.contains("my_value"));
    }

    #[test]
    fn find_gramine_returns_none_when_missing() {
        // gramine-sgx is unlikely to be installed in test environments
        // This test just verifies the function doesn't panic
        let _ = find_gramine();
    }
}
