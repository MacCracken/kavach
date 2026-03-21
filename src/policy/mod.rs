//! Sandbox security policy — seccomp, Landlock, network, resource limits.

use serde::{Deserialize, Serialize};

/// A complete sandbox security policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Enable seccomp-bpf syscall filtering.
    pub seccomp_enabled: bool,
    /// Seccomp profile name (e.g. "basic", "desktop", "strict").
    pub seccomp_profile: Option<String>,
    /// Landlock filesystem access rules.
    pub landlock_rules: Vec<LandlockRule>,
    /// Network policy.
    pub network: NetworkPolicy,
    /// Read-only rootfs.
    pub read_only_rootfs: bool,
    /// Memory limit in MB.
    pub memory_limit_mb: Option<u64>,
    /// CPU limit (fractional cores, e.g. 0.5 = half a core).
    pub cpu_limit: Option<f64>,
    /// Maximum PIDs (process limit).
    pub max_pids: Option<u32>,
    /// Data directory inside the sandbox (writable).
    pub data_dir: Option<String>,
}

/// Seccomp profile presets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfile {
    pub name: String,
    /// Allowed syscall names.
    pub allowed_syscalls: Vec<String>,
    /// Whether to log blocked syscalls.
    pub log_blocked: bool,
}

/// Landlock filesystem access rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LandlockRule {
    /// Path to allow access to.
    pub path: String,
    /// Access mode: "ro" (read-only) or "rw" (read-write).
    pub access: String,
}

/// Network access policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Whether network access is allowed at all.
    pub enabled: bool,
    /// Allowed outbound hosts (empty = allow all if enabled).
    pub allowed_hosts: Vec<String>,
    /// Allowed outbound ports (empty = allow all if enabled).
    pub allowed_ports: Vec<u16>,
}

impl SandboxPolicy {
    /// Create a minimal policy (process isolation, no extras).
    pub fn minimal() -> Self {
        Self::default()
    }

    /// Create a basic policy (seccomp + no network).
    pub fn basic() -> Self {
        Self {
            seccomp_enabled: true,
            seccomp_profile: Some("basic".into()),
            network: NetworkPolicy {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create a strict policy (everything locked down).
    pub fn strict() -> Self {
        Self {
            seccomp_enabled: true,
            seccomp_profile: Some("strict".into()),
            network: NetworkPolicy {
                enabled: false,
                ..Default::default()
            },
            read_only_rootfs: true,
            memory_limit_mb: Some(512),
            cpu_limit: Some(1.0),
            max_pids: Some(64),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_policy() {
        let p = SandboxPolicy::minimal();
        assert!(!p.seccomp_enabled);
        assert!(!p.network.enabled);
        assert!(!p.read_only_rootfs);
    }

    #[test]
    fn basic_policy() {
        let p = SandboxPolicy::basic();
        assert!(p.seccomp_enabled);
        assert!(!p.network.enabled);
    }

    #[test]
    fn strict_policy() {
        let p = SandboxPolicy::strict();
        assert!(p.seccomp_enabled);
        assert!(p.read_only_rootfs);
        assert!(p.memory_limit_mb.is_some());
        assert!(p.max_pids.is_some());
    }

    #[test]
    fn serde_roundtrip() {
        let p = SandboxPolicy::strict();
        let json = serde_json::to_string(&p).unwrap();
        let back: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.seccomp_enabled);
        assert!(back.read_only_rootfs);
    }
}
