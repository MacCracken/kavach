//! Bridge types — sandbox configuration primitives.
//!
//! These types were originally defined in the `agnostik` crate.  Kavach now
//! owns them directly so the crate can be published to crates.io without
//! depending on git-only repositories.

use serde::{Deserialize, Serialize};

/// Filesystem access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FsAccess {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

/// Network access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetworkAccess {
    None,
    LocalhostOnly,
    Restricted,
    Full,
}

/// Seccomp filter action (OCI runtime spec aligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SeccompAction {
    Allow,
    /// Kill the thread (SECCOMP_RET_KILL_THREAD).
    Kill,
    /// Kill the process (SECCOMP_RET_KILL_PROCESS).
    KillProcess,
    /// Send SIGSYS (SECCOMP_RET_TRAP).
    Trap,
    /// Return an errno value (SECCOMP_RET_ERRNO).
    Errno(u32),
    /// Notify a tracing process (SECCOMP_RET_TRACE).
    Trace(u32),
    /// Log the syscall (SECCOMP_RET_LOG).
    Log,
}

/// Seccomp argument comparison operator (OCI runtime spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SeccompArgOp {
    NotEqual,
    LessThan,
    LessEqual,
    Equal,
    GreaterEqual,
    GreaterThan,
    MaskedEqual,
}

/// A condition on a syscall argument for seccomp filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompArg {
    /// Argument index (0-5).
    pub index: u32,
    /// Value to compare against.
    pub value: u64,
    /// Second value (for MaskedEqual: mask).
    #[serde(default)]
    pub value_two: u64,
    /// Comparison operator.
    pub op: SeccompArgOp,
}

/// Target architecture for seccomp filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SeccompArch {
    X86,
    X86_64,
    X32,
    Arm,
    Aarch64,
    Mips,
    Mips64,
    Mips64n32,
    Mipsel,
    Mipsel64,
    Mipsel64n32,
    Ppc,
    Ppc64,
    Ppc64le,
    S390,
    S390x,
    Riscv64,
}

/// Mount propagation type for filesystem rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum MountPropagation {
    /// Mount is private (changes do not propagate).
    #[default]
    Private,
    /// Mount propagates to and from peers.
    Shared,
    /// Mount receives propagation but does not send.
    Slave,
    /// Mount cannot be bind-mounted.
    Unbindable,
}

/// Filesystem access rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemRule {
    pub path: std::path::PathBuf,
    pub access: FsAccess,
    /// Read-only mount (overrides access for the mount itself).
    #[serde(default)]
    pub readonly: bool,
    /// Prevent execution of binaries.
    #[serde(default)]
    pub noexec: bool,
    /// Prevent setuid/setgid bits from taking effect.
    #[serde(default)]
    pub nosuid: bool,
    /// Prevent device special files from being accessed.
    #[serde(default)]
    pub nodev: bool,
    /// Mount propagation type.
    #[serde(default)]
    pub propagation: MountPropagation,
}

/// A seccomp syscall rule with optional argument conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompRule {
    /// Syscall names this rule applies to.
    pub names: Vec<String>,
    pub action: SeccompAction,
    /// Argument conditions (all must match for the action to apply).
    #[serde(default)]
    pub args: Vec<SeccompArg>,
}

/// Complete seccomp filter profile (OCI runtime spec aligned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfile {
    /// Action to take when no rule matches.
    pub default_action: SeccompAction,
    /// Architectures this profile applies to.
    #[serde(default)]
    pub architectures: Vec<SeccompArch>,
    /// Seccomp filter flags.
    #[serde(default)]
    pub flags: Vec<String>,
    /// Syscall rules (evaluated in order).
    #[serde(default)]
    pub syscalls: Vec<SeccompRule>,
}

/// Per-agent network firewall policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub allowed_outbound_ports: Vec<u16>,
    pub allowed_outbound_hosts: Vec<String>,
    pub allowed_inbound_ports: Vec<u16>,
    pub enable_nat: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allowed_outbound_ports: vec![80, 443],
            allowed_outbound_hosts: Vec::new(),
            allowed_inbound_ports: Vec::new(),
            enable_nat: true,
        }
    }
}

/// Encrypted storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedStorageConfig {
    pub enabled: bool,
    pub size_mb: u64,
    pub filesystem: String,
}

impl Default for EncryptedStorageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            size_mb: 256,
            filesystem: "ext4".into(),
        }
    }
}

/// Sandbox configuration for agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub filesystem_rules: Vec<FilesystemRule>,
    pub network_access: NetworkAccess,
    /// Full seccomp filter profile.
    #[serde(default)]
    pub seccomp: Option<SeccompProfile>,
    pub isolate_network: bool,
    #[serde(default)]
    pub network_policy: Option<NetworkPolicy>,
    /// AppArmor profile name (e.g., "runtime/default").
    #[serde(default)]
    pub apparmor_profile: Option<String>,
    /// SELinux process label (e.g., "system_u:system_r:container_t:s0").
    #[serde(default)]
    pub selinux_label: Option<String>,
    #[serde(default)]
    pub encrypted_storage: Option<EncryptedStorageConfig>,
    /// Paths hidden from the agent (OCI maskedPaths, e.g., "/proc/kcore").
    #[serde(default)]
    pub masked_paths: Vec<String>,
    /// Paths mounted read-only (OCI readonlyPaths, e.g., "/proc/sys").
    #[serde(default)]
    pub readonly_paths: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            filesystem_rules: vec![FilesystemRule {
                path: "/tmp".into(),
                access: FsAccess::ReadWrite,
                readonly: false,
                noexec: true,
                nosuid: true,
                nodev: true,
                propagation: MountPropagation::Private,
            }],
            network_access: NetworkAccess::LocalhostOnly,
            seccomp: None,
            isolate_network: true,
            network_policy: None,
            apparmor_profile: None,
            selinux_label: None,
            encrypted_storage: None,
            masked_paths: Vec::new(),
            readonly_paths: Vec::new(),
        }
    }
}
