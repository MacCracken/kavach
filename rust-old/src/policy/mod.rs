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
    /// Landlock scoping (ABI v6) — restrict IPC and signals across sandbox boundary.
    pub landlock_scope: LandlockScope,
}

/// Seccomp profile presets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfile {
    /// Profile name (e.g. "basic", "strict").
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

/// Landlock scoping policy (ABI v6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LandlockScope {
    /// Block connecting to abstract UNIX sockets created outside the sandbox.
    pub abstract_unix_socket: bool,
    /// Block sending signals to processes outside the sandbox.
    pub signal: bool,
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
    /// TCP ports allowed for bind (Landlock ABI v4). Empty = no bind restriction.
    pub tcp_bind_ports: Vec<u16>,
    /// TCP ports allowed for connect (Landlock ABI v4). Empty = no connect restriction.
    pub tcp_connect_ports: Vec<u16>,
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
            landlock_scope: LandlockScope {
                abstract_unix_socket: true,
                signal: true,
            },
            ..Default::default()
        }
    }

    /// Create a policy from a preset name (case-insensitive).
    ///
    /// Known presets: `"minimal"`, `"basic"`, `"strict"`.
    pub fn from_preset(name: &str) -> std::result::Result<Self, String> {
        match name.to_lowercase().as_str() {
            "minimal" => Ok(Self::minimal()),
            "basic" => Ok(Self::basic()),
            "strict" => Ok(Self::strict()),
            other => Err(format!(
                "unknown policy: {other} (use minimal, basic, strict)"
            )),
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
    fn from_preset_all() {
        assert!(
            !SandboxPolicy::from_preset("minimal")
                .unwrap()
                .seccomp_enabled
        );
        assert!(SandboxPolicy::from_preset("basic").unwrap().seccomp_enabled);
        assert!(
            SandboxPolicy::from_preset("strict")
                .unwrap()
                .read_only_rootfs
        );
    }

    #[test]
    fn from_preset_case_insensitive() {
        assert!(
            SandboxPolicy::from_preset("STRICT")
                .unwrap()
                .read_only_rootfs
        );
        assert!(SandboxPolicy::from_preset("Basic").unwrap().seccomp_enabled);
    }

    #[test]
    fn from_preset_unknown() {
        let err = SandboxPolicy::from_preset("unknown").unwrap_err();
        assert!(err.contains("unknown policy"));
    }

    #[test]
    fn serde_roundtrip() {
        let p = SandboxPolicy::strict();
        let json = serde_json::to_string(&p).unwrap();
        let back: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.seccomp_enabled);
        assert!(back.read_only_rootfs);
    }

    #[test]
    fn network_policy_tcp_ports_serde() {
        let policy = NetworkPolicy {
            enabled: true,
            tcp_bind_ports: vec![8080, 9090],
            tcp_connect_ports: vec![80, 443],
            ..Default::default()
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tcp_bind_ports, vec![8080, 9090]);
        assert_eq!(back.tcp_connect_ports, vec![80, 443]);
    }

    #[test]
    fn network_policy_defaults_empty_tcp_ports() {
        let policy = NetworkPolicy::default();
        assert!(policy.tcp_bind_ports.is_empty());
        assert!(policy.tcp_connect_ports.is_empty());
    }

    #[test]
    fn landlock_scope_default_disabled() {
        let scope = LandlockScope::default();
        assert!(!scope.abstract_unix_socket);
        assert!(!scope.signal);
    }

    #[test]
    fn strict_policy_enables_scope() {
        let p = SandboxPolicy::strict();
        assert!(p.landlock_scope.abstract_unix_socket);
        assert!(p.landlock_scope.signal);
    }

    #[test]
    fn landlock_scope_serde() {
        let scope = LandlockScope {
            abstract_unix_socket: true,
            signal: true,
        };
        let json = serde_json::to_string(&scope).unwrap();
        let back: LandlockScope = serde_json::from_str(&json).unwrap();
        assert!(back.abstract_unix_socket);
        assert!(back.signal);
    }
}
