//! Process backend — OS process with seccomp, Landlock, namespaces, cgroups.

pub mod cgroups;
pub mod landlock_enforce;
pub mod namespaces;
pub mod seccomp;

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// Process-based sandbox backend.
#[derive(Debug)]
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

    /// Build a [`tokio::process::Command`] with env, workdir, and pre-exec
    /// isolation hooks applied. Shared between `exec` and `spawn`.
    fn build_command(
        &self,
        command: &str,
        policy: &SandboxPolicy,
    ) -> crate::Result<tokio::process::Command> {
        let parts = shell_words(command);
        if parts.is_empty() {
            return Err(crate::KavachError::ExecFailed("empty command".into()));
        }

        let program = &parts[0];
        let args = &parts[1..];

        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args);

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

            let caps = capabilities::cached_capabilities();

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

            // Extract only the fields needed by the pre_exec closure to avoid
            // cloning the entire SandboxPolicy (which includes Vec<LandlockRule>,
            // Vec<String>, etc.) on every exec call.
            let ll_policy = if apply_ll { Some(policy.clone()) } else { None };
            let rlimit_memory = policy.memory_limit_mb;
            let rlimit_pids = policy.max_pids;

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
            // 3. Error paths use libc::write(2, ...) which is
            //    async-signal-safe, or return Err (no cleanup needed).
            // 4. No heap-allocated data is created inside the closure —
            //    all captured values (ns_config, ll_policy, rlimit_memory,
            //    rlimit_pids, seccomp_program) are moved in and only read.
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
                        pre_exec_warn("kavach: namespace isolation skipped: ", &e);
                    }

                    // 2. Landlock (needs landlock_* syscalls) — best-effort
                    if let Some(ref ll_pol) = ll_policy
                        && let Err(e) = landlock_enforce::apply_landlock(ll_pol)
                    {
                        pre_exec_warn("kavach: landlock skipped: ", &e);
                    }

                    // 3. Drop capabilities (needs capset syscall) — best-effort
                    let _ = namespaces::drop_capabilities();

                    // 4. Apply resource limits via rlimits — best-effort
                    let _ = cgroups::apply_rlimits_raw(rlimit_memory, rlimit_pids);

                    // 5. Seccomp filter (MUST BE LAST — blocks future syscalls)
                    if let Some(ref program) = seccomp_program {
                        seccomp::apply_filter(program)
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                    }

                    Ok(())
                });
            }
        }

        // Suppress unused variable warning on non-Linux
        #[cfg(not(target_os = "linux"))]
        let _ = policy;

        Ok(cmd)
    }
}

#[async_trait::async_trait]
impl SandboxBackend for ProcessBackend {
    fn backend_type(&self) -> Backend {
        Backend::Process
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let mut cmd = self.build_command(command, policy)?;

        crate::backend::exec_util::execute_with_timeout(
            &mut cmd,
            self._config.timeout_ms,
            "process",
        )
        .await
    }

    async fn spawn(
        &self,
        command: &str,
        policy: &SandboxPolicy,
    ) -> crate::Result<Option<crate::backend::exec_util::SpawnedProcess>> {
        let mut cmd = self.build_command(command, policy)?;
        let proc = crate::backend::exec_util::spawn_process(&mut cmd, "process")?;
        Ok(Some(proc))
    }

    async fn health_check(&self) -> crate::Result<bool> {
        Ok(true)
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Write a warning message to stderr using async-signal-safe `libc::write`.
///
/// Unlike `eprintln!`, this does not acquire any mutex or allocate on the heap,
/// making it safe to call in the `pre_exec` context between fork() and exec().
/// Only writes the prefix (a static string) — the error detail is omitted to
/// avoid the heap allocation that `Display::to_string()` would require.
#[cfg(target_os = "linux")]
fn pre_exec_warn(prefix: &str, _err: &dyn std::fmt::Display) {
    // SAFETY: write(2, ...) is async-signal-safe per POSIX.
    unsafe {
        libc::write(2, prefix.as_ptr().cast(), prefix.len());
        libc::write(2, b"\n".as_ptr().cast(), 1);
    }
}

/// Simple whitespace-based command splitting (no shell expansion).
fn shell_words(input: &str) -> Vec<String> {
    let mut words = Vec::with_capacity(8);
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

    #[test]
    fn shell_words_escaped() {
        assert_eq!(
            shell_words(r"echo hello\ world"),
            vec!["echo", "hello world"]
        );
    }

    #[test]
    fn shell_words_mixed_quotes() {
        assert_eq!(
            shell_words(r#"echo "it's" 'a "test"'"#),
            vec!["echo", "it's", r#"a "test""#]
        );
    }

    #[test]
    fn shell_words_tabs() {
        assert_eq!(
            shell_words("echo\thello\tworld"),
            vec!["echo", "hello", "world"]
        );
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
