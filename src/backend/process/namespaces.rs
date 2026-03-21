//! Linux namespace isolation — PID, mount, network, user namespaces.
//!
//! Uses `nix::sched::unshare()` to create new namespaces in the child
//! process's `pre_exec` hook.

#[cfg(target_os = "linux")]
use nix::sched::{CloneFlags, unshare};

use crate::policy::SandboxPolicy;

/// Namespace configuration derived from sandbox policy.
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub new_pid: bool,
    pub new_mount: bool,
    pub new_net: bool,
    pub new_user: bool,
}

impl NamespaceConfig {
    /// Derive namespace configuration from policy.
    pub fn from_policy(policy: &SandboxPolicy) -> Self {
        Self {
            new_pid: true,                    // Always isolate PIDs
            new_mount: true,                  // Always isolate mounts
            new_net: !policy.network.enabled, // Isolate network if disabled
            new_user: true,                   // Always use user namespace (unprivileged)
        }
    }

    /// Check if any namespace isolation is configured.
    pub fn any_enabled(&self) -> bool {
        self.new_pid || self.new_mount || self.new_net || self.new_user
    }

    /// Build clone flags from configuration.
    #[cfg(target_os = "linux")]
    pub fn clone_flags(&self) -> CloneFlags {
        let mut flags = CloneFlags::empty();
        if self.new_pid {
            flags |= CloneFlags::CLONE_NEWPID;
        }
        if self.new_mount {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.new_net {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        if self.new_user {
            flags |= CloneFlags::CLONE_NEWUSER;
        }
        flags
    }
}

/// Apply namespace isolation via unshare.
/// Must be called in `pre_exec` context (after fork, before exec).
#[cfg(target_os = "linux")]
pub fn apply_namespaces(config: &NamespaceConfig) -> crate::Result<()> {
    if !config.any_enabled() {
        return Ok(());
    }

    let flags = config.clone_flags();
    unshare(flags)
        .map_err(|e| crate::KavachError::ExecFailed(format!("namespace unshare failed: {e}")))?;

    tracing::debug!(?flags, "namespace isolation applied");
    Ok(())
}

/// Drop capabilities after namespace setup.
/// Removes dangerous capabilities that could escape the sandbox.
#[cfg(target_os = "linux")]
pub fn drop_capabilities() -> crate::Result<()> {
    use caps::{CapSet, Capability};

    // Capabilities to drop (dangerous for sandbox escape)
    let dangerous = [
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_SYS_PTRACE,
        Capability::CAP_NET_RAW,
        Capability::CAP_NET_ADMIN,
        Capability::CAP_SYS_MODULE,
        Capability::CAP_SYS_RAWIO,
        Capability::CAP_SYS_BOOT,
        Capability::CAP_SYS_CHROOT,
        Capability::CAP_MKNOD,
    ];

    for cap in &dangerous {
        // Best-effort: some capabilities may not be held
        let _ = caps::drop(None, CapSet::Effective, *cap);
        let _ = caps::drop(None, CapSet::Permitted, *cap);
        let _ = caps::drop(None, CapSet::Inheritable, *cap);
    }

    tracing::debug!("dangerous capabilities dropped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_policy_network_disabled() {
        let mut policy = SandboxPolicy::minimal();
        policy.network.enabled = false;
        let config = NamespaceConfig::from_policy(&policy);
        assert!(config.new_pid);
        assert!(config.new_mount);
        assert!(config.new_net); // network disabled → isolate
        assert!(config.new_user);
    }

    #[test]
    fn config_from_policy_network_enabled() {
        let mut policy = SandboxPolicy::minimal();
        policy.network.enabled = true;
        let config = NamespaceConfig::from_policy(&policy);
        assert!(!config.new_net); // network enabled → don't isolate
    }

    #[test]
    fn any_enabled_default() {
        let policy = SandboxPolicy::minimal();
        let config = NamespaceConfig::from_policy(&policy);
        assert!(config.any_enabled());
    }

    #[test]
    fn any_enabled_none() {
        let config = NamespaceConfig {
            new_pid: false,
            new_mount: false,
            new_net: false,
            new_user: false,
        };
        assert!(!config.any_enabled());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clone_flags_all() {
        let config = NamespaceConfig {
            new_pid: true,
            new_mount: true,
            new_net: true,
            new_user: true,
        };
        let flags = config.clone_flags();
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clone_flags_partial() {
        let config = NamespaceConfig {
            new_pid: true,
            new_mount: false,
            new_net: false,
            new_user: true,
        };
        let flags = config.clone_flags();
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(!flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(!flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }
}
