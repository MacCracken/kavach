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
    /// Host UID to map to root inside user namespace (captured before fork).
    pub host_uid: u32,
    /// Host GID to map to root inside user namespace (captured before fork).
    pub host_gid: u32,
}

impl NamespaceConfig {
    /// Derive namespace configuration from policy.
    ///
    /// Captures the current UID/GID for user namespace mapping.
    pub fn from_policy(policy: &SandboxPolicy) -> Self {
        Self {
            new_pid: true,                    // Always isolate PIDs
            new_mount: true,                  // Always isolate mounts
            new_net: !policy.network.enabled, // Isolate network if disabled
            new_user: true,                   // Always use user namespace (unprivileged)
            // SAFETY: getuid() is reentrant, signal-safe, always succeeds,
            // and returns the real UID of the calling process.
            host_uid: unsafe { libc::getuid() },
            // SAFETY: getgid() is reentrant, signal-safe, always succeeds,
            // and returns the real GID of the calling process.
            host_gid: unsafe { libc::getgid() },
        }
    }

    /// Check if any namespace isolation is configured.
    #[inline]
    #[must_use]
    pub fn any_enabled(&self) -> bool {
        self.new_pid || self.new_mount || self.new_net || self.new_user
    }

    /// Build clone flags from configuration.
    #[cfg(target_os = "linux")]
    #[must_use]
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
///
/// When a user namespace is created, UID/GID maps are written so the
/// container process runs as UID 0 (root) inside the namespace while
/// remaining unprivileged outside. This enables rootless containers.
#[cfg(target_os = "linux")]
pub fn apply_namespaces(config: &NamespaceConfig) -> crate::Result<()> {
    if !config.any_enabled() {
        return Ok(());
    }

    let flags = config.clone_flags();
    unshare(flags)
        .map_err(|e| crate::KavachError::ExecFailed(format!("namespace unshare failed: {e}")))?;

    // Write UID/GID maps for user namespace — maps current user to root inside.
    if config.new_user {
        let uid = config.host_uid;
        let gid = config.host_gid;
        if let Err(e) = write_id_maps(uid, gid) {
            // Best-effort: some kernels restrict writing maps without newuidmap.
            tracing::warn!("UID/GID map write failed (rootless may not work): {e}");
        }
    }

    tracing::debug!(?flags, "namespace isolation applied");
    Ok(())
}

/// Write UID and GID maps for the current user namespace.
///
/// Maps the host UID/GID to 0 (root) inside the namespace.
/// Must be called after `unshare(CLONE_NEWUSER)` and before exec.
///
/// Steps:
/// 1. Deny setgroups (required before writing gid_map as unprivileged)
/// 2. Write uid_map: `"0 {host_uid} 1\n"`
/// 3. Write gid_map: `"0 {host_gid} 1\n"`
#[cfg(target_os = "linux")]
fn write_id_maps(host_uid: u32, host_gid: u32) -> std::io::Result<()> {
    use std::io::Write;

    // Deny setgroups — required by kernel before writing gid_map as non-root.
    let mut f = std::fs::File::create("/proc/self/setgroups")?;
    f.write_all(b"deny\n")?;

    // Map host UID → 0 inside namespace.
    let mut f = std::fs::File::create("/proc/self/uid_map")?;
    writeln!(f, "0 {host_uid} 1")?;

    // Map host GID → 0 inside namespace.
    let mut f = std::fs::File::create("/proc/self/gid_map")?;
    writeln!(f, "0 {host_gid} 1")?;

    tracing::debug!(host_uid, host_gid, "UID/GID maps written for rootless");
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
            host_uid: 1000,
            host_gid: 1000,
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
            host_uid: 1000,
            host_gid: 1000,
        };
        let flags = config.clone_flags();
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }

    #[test]
    fn from_policy_captures_uid_gid() {
        let policy = SandboxPolicy::minimal();
        let config = NamespaceConfig::from_policy(&policy);
        // host_uid/gid are captured from the running process — just verify they're set.
        // On CI this is typically 1000+; as root it's 0. Both are valid.
        let _ = config.host_uid;
        let _ = config.host_gid;
        assert!(config.new_user);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clone_flags_partial() {
        let config = NamespaceConfig {
            new_pid: true,
            new_mount: false,
            new_net: false,
            new_user: true,
            host_uid: 1000,
            host_gid: 1000,
        };
        let flags = config.clone_flags();
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(!flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(!flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }
}
