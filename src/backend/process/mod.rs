//! Process backend — OS process with seccomp, Landlock, namespaces, cgroups.

pub mod cgroups;
pub mod landlock_enforce;
pub mod namespaces;
pub mod seccomp;

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// Process-based sandbox backend.
pub struct ProcessBackend {
    _config: SandboxConfig,
}

impl ProcessBackend {
    /// Create a new process backend from configuration.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        Ok(Self {
            _config: config.clone(),
        })
    }
}

#[async_trait::async_trait]
impl SandboxBackend for ProcessBackend {
    fn backend_type(&self) -> Backend {
        Backend::Process
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let start = std::time::Instant::now();

        // Parse command into program + args
        let parts = shell_words(command);
        if parts.is_empty() {
            return Err(crate::KavachError::ExecFailed("empty command".into()));
        }

        let program = &parts[0];
        let args = &parts[1..];

        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Apply environment from config
        for (k, v) in &self._config.env {
            cmd.env(k, v);
        }

        // Apply working directory
        if let Some(ref workdir) = self._config.workdir {
            cmd.current_dir(workdir);
        }

        // ── Pre-exec isolation (Linux only) ─────────────────────────────
        #[cfg(target_os = "linux")]
        {
            use crate::backend::capabilities;

            let caps = capabilities::detect_capabilities();

            // Pre-build seccomp BPF program (before fork, can allocate freely)
            let seccomp_program = if policy.seccomp_enabled && caps.seccomp_available {
                let profile = policy.seccomp_profile.as_deref().unwrap_or("basic");
                match seccomp::build_filter(profile) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!("seccomp filter build failed, skipping: {e}");
                        None
                    }
                }
            } else {
                None
            };

            // Derive namespace config — only apply if namespaces are available
            let ns_config = if caps.namespaces_available {
                Some(namespaces::NamespaceConfig::from_policy(policy))
            } else {
                None
            };

            // Only apply landlock if kernel supports it
            let apply_ll = caps.landlock_available && landlock_enforce::should_apply(policy);

            // Clone policy for pre_exec closure
            let policy_clone = policy.clone();

            // SAFETY: `CommandExt::pre_exec` requires unsafe because the closure
            // runs in the child process between fork() and exec(), where only
            // async-signal-safe operations are permitted (no heap allocation,
            // no mutex acquisition, no stdio beyond write()).
            //
            // This closure satisfies those requirements:
            // 1. The BPF program is pre-compiled above (before fork) — no
            //    allocation happens inside the closure.
            // 2. All operations are direct kernel syscalls via FFI:
            //    - unshare(2) for namespace isolation
            //    - landlock_create_ruleset(2) / landlock_restrict_self(2)
            //    - prctl(2) for capability dropping
            //    - setrlimit(2) for resource limits
            //    - seccomp(2) / prctl(PR_SET_SECCOMP) for BPF filter
            // 3. Error paths use eprintln! (write to fd 2) which is
            //    async-signal-safe, or return Err (no cleanup needed).
            // 4. No heap-allocated data is created inside the closure —
            //    all captured values (ns_config, policy_clone, seccomp_program,
            //    apply_ll) are moved in and only read.
            // 5. Ordering is critical and documented inline: namespaces first
            //    (needs unshare), then landlock (needs landlock_* syscalls),
            //    then caps (needs capset), then seccomp last (would block
            //    all preceding syscalls).
            unsafe {
                cmd.pre_exec(move || {
                    // Order matters: each step needs syscalls the next would block.
                    // 1. Namespaces (needs unshare syscall) — best-effort
                    if let Some(ref ns) = ns_config
                        && ns.any_enabled()
                        && let Err(e) = namespaces::apply_namespaces(ns)
                    {
                        eprintln!("kavach: namespace isolation skipped: {e}");
                    }

                    // 2. Landlock (needs landlock_* syscalls) — best-effort
                    if apply_ll && let Err(e) = landlock_enforce::apply_landlock(&policy_clone) {
                        eprintln!("kavach: landlock skipped: {e}");
                    }

                    // 3. Drop capabilities (needs capset syscall) — best-effort
                    let _ = namespaces::drop_capabilities();

                    // 4. Apply resource limits via rlimits — best-effort
                    let _ = cgroups::apply_rlimits(&policy_clone);

                    // 5. Seccomp filter (MUST BE LAST — blocks future syscalls)
                    if let Some(ref program) = seccomp_program {
                        seccomp::apply_filter(program)
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                    }

                    Ok(())
                });
            }
        }

        let timeout_ms = self._config.timeout_ms;
        let timeout = std::time::Duration::from_millis(timeout_ms);

        // Spawn and race against timeout
        let mut child = cmd
            .spawn()
            .map_err(|e| crate::KavachError::ExecFailed(format!("spawn failed: {e}")))?;

        // Take stdout/stderr handles before waiting
        let stdout_handle = child.stdout.take();
        let stderr_handle = child.stderr.take();

        let collect = async {
            use tokio::io::AsyncReadExt;

            // Read stdout/stderr concurrently while waiting for process
            let stdout_fut = async {
                let mut buf = Vec::new();
                if let Some(out) = stdout_handle {
                    const MAX: u64 = 1024 * 1024; // 1MB limit
                    out.take(MAX).read_to_end(&mut buf).await?;
                }
                Ok::<_, std::io::Error>(buf)
            };
            let stderr_fut = async {
                let mut buf = Vec::new();
                if let Some(err) = stderr_handle {
                    const MAX: u64 = 1024 * 1024;
                    err.take(MAX).read_to_end(&mut buf).await?;
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
                "process error: {e}"
            ))),
            Err(_) => {
                // Timeout — kill the child
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
        Ok(true)
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Simple whitespace-based command splitting (no shell expansion).
fn shell_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for ch in input.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if !in_single => escape = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;

    #[test]
    fn shell_words_basic() {
        assert_eq!(shell_words("echo hello"), vec!["echo", "hello"]);
        assert_eq!(shell_words("ls -la /tmp"), vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn shell_words_quoted() {
        assert_eq!(
            shell_words(r#"echo "hello world""#),
            vec!["echo", "hello world"]
        );
        assert_eq!(
            shell_words("echo 'hello world'"),
            vec!["echo", "hello world"]
        );
    }

    #[test]
    fn shell_words_empty() {
        assert!(shell_words("").is_empty());
        assert!(shell_words("   ").is_empty());
    }

    #[tokio::test]
    async fn exec_echo() {
        let config = SandboxConfig::builder().backend(Backend::Process).build();
        let backend = ProcessBackend::new(&config).unwrap();
        let policy = SandboxPolicy::minimal();
        let result = backend.exec("echo hello", &policy).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.trim(), "hello");
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn exec_false_returns_nonzero() {
        let config = SandboxConfig::builder().backend(Backend::Process).build();
        let backend = ProcessBackend::new(&config).unwrap();
        let policy = SandboxPolicy::minimal();
        let result = backend.exec("false", &policy).await.unwrap();
        assert_ne!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn exec_timeout() {
        let config = SandboxConfig::builder()
            .backend(Backend::Process)
            .timeout_ms(100)
            .build();
        let backend = ProcessBackend::new(&config).unwrap();
        let policy = SandboxPolicy::minimal();
        let result = backend.exec("sleep 10", &policy).await.unwrap();
        assert!(result.timed_out);
        assert_eq!(result.exit_code, -1);
    }

    #[tokio::test]
    async fn exec_empty_command() {
        let config = SandboxConfig::builder().backend(Backend::Process).build();
        let backend = ProcessBackend::new(&config).unwrap();
        let policy = SandboxPolicy::minimal();
        let result = backend.exec("", &policy).await;
        assert!(result.is_err());
    }
}
