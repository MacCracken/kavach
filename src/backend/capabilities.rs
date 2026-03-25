//! Platform capability detection — seccomp, Landlock, cgroup v2, namespaces.
//!
//! Ported from SecureYeoman's `sy-sandbox` crate. Detection functions read
//! from `/proc` and `/sys` on Linux. On other platforms, all capabilities
//! report as unavailable.

use serde::{Deserialize, Serialize};

/// Overall sandbox capabilities detected on this system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCapabilities {
    /// Whether seccomp-bpf is available.
    pub seccomp_available: bool,
    /// Current seccomp mode (disabled, strict, filter, unsupported).
    pub seccomp_mode: String,
    /// Whether Landlock LSM is available.
    pub landlock_available: bool,
    /// Landlock ABI version (0 if unavailable).
    pub landlock_abi: u32,
    /// Whether cgroup v2 (unified hierarchy) is active.
    pub cgroup_v2: bool,
    /// Whether user namespaces are available.
    pub namespaces_available: bool,
}

/// Detect all sandbox capabilities for the current system.
#[cfg(target_os = "linux")]
#[must_use]
pub fn detect_capabilities() -> SandboxCapabilities {
    SandboxCapabilities {
        seccomp_available: seccomp_is_available(),
        seccomp_mode: seccomp_current_mode(),
        landlock_available: landlock_is_available(),
        landlock_abi: landlock_abi_version(),
        cgroup_v2: cgroup_is_v2(),
        namespaces_available: namespaces_available(),
    }
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn detect_capabilities() -> SandboxCapabilities {
    SandboxCapabilities {
        seccomp_available: false,
        seccomp_mode: "unsupported".into(),
        landlock_available: false,
        landlock_abi: 0,
        cgroup_v2: false,
        namespaces_available: false,
    }
}

// ── Seccomp ─────────────────────────────────────────────────────────────

/// Check if seccomp is available on this system.
#[cfg(target_os = "linux")]
pub fn seccomp_is_available() -> bool {
    seccomp_current_mode() != "unsupported"
}

#[cfg(not(target_os = "linux"))]
pub fn seccomp_is_available() -> bool {
    false
}

/// Read the current seccomp mode from /proc/self/status.
#[cfg(target_os = "linux")]
pub fn seccomp_current_mode() -> String {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => parse_seccomp_mode(&s),
        Err(_) => "unsupported".into(),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn seccomp_current_mode() -> String {
    "unsupported".into()
}

/// Parse seccomp mode from /proc/self/status content.
#[must_use]
pub fn parse_seccomp_mode(status_content: &str) -> String {
    for line in status_content.lines() {
        if let Some(val) = line.strip_prefix("Seccomp:") {
            return match val.trim() {
                "0" => "disabled".into(),
                "1" => "strict".into(),
                "2" => "filter".into(),
                _ => "unknown".into(),
            };
        }
    }
    "unsupported".into()
}

// ── Landlock ────────────────────────────────────────────────────────────

/// Check if Landlock is available on this kernel.
#[cfg(target_os = "linux")]
pub fn landlock_is_available() -> bool {
    std::path::Path::new("/proc/sys/kernel/landlock_restrict_self").exists()
        || kernel_supports_landlock()
}

#[cfg(not(target_os = "linux"))]
pub fn landlock_is_available() -> bool {
    false
}

/// Get the Landlock ABI version (0 if unavailable).
#[cfg(target_os = "linux")]
pub fn landlock_abi_version() -> u32 {
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/landlock_restrict_self")
        && let Some(v) = parse_abi_from_proc(&content)
    {
        return v;
    }
    if kernel_supports_landlock() { 1 } else { 0 }
}

#[cfg(not(target_os = "linux"))]
pub fn landlock_abi_version() -> u32 {
    0
}

/// Parse ABI version from /proc/sys/kernel/landlock_restrict_self content.
#[must_use]
pub fn parse_abi_from_proc(content: &str) -> Option<u32> {
    let val: u32 = content.trim().parse().ok()?;
    if val > 0 { Some(val) } else { None }
}

/// Parse kernel version string and check if >= 5.13 (Landlock minimum).
#[must_use]
pub fn kernel_version_supports_landlock(release: &str) -> bool {
    let parts: Vec<u32> = release
        .trim()
        .split('.')
        .take(2)
        .filter_map(|s| s.split('-').next().and_then(|n| n.parse().ok()))
        .collect();

    if parts.len() >= 2 {
        (parts[0] > 5) || (parts[0] == 5 && parts[1] >= 13)
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
fn kernel_supports_landlock() -> bool {
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        return kernel_version_supports_landlock(&release);
    }
    false
}

// ── cgroup v2 ───────────────────────────────────────────────────────────

/// Check if cgroup v2 (unified hierarchy) is active.
#[cfg(target_os = "linux")]
pub fn cgroup_is_v2() -> bool {
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        return parse_mounts_for_cgroup2(&mounts);
    }
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_is_v2() -> bool {
    false
}

/// Parse /proc/mounts content for cgroup2 presence.
#[must_use]
pub fn parse_mounts_for_cgroup2(mounts: &str) -> bool {
    mounts
        .lines()
        .any(|line| line.contains("cgroup2") && line.contains("/sys/fs/cgroup"))
}

/// Read the current memory limit for this process's cgroup (bytes).
#[cfg(target_os = "linux")]
pub fn cgroup_memory_limit() -> Option<u64> {
    std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|s| parse_memory_max(&s))
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_memory_limit() -> Option<u64> {
    None
}

/// Read current memory usage for this process's cgroup (bytes).
#[cfg(target_os = "linux")]
pub fn cgroup_memory_current() -> Option<u64> {
    std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_memory_current() -> Option<u64> {
    None
}

/// Parse memory.max content. Returns None for "max" (unlimited).
#[must_use]
pub fn parse_memory_max(content: &str) -> Option<u64> {
    let trimmed = content.trim();
    if trimmed == "max" {
        None
    } else {
        trimmed.parse().ok()
    }
}

// ── Namespaces ──────────────────────────────────────────────────────────

/// Check if user namespaces are available.
#[cfg(target_os = "linux")]
pub fn namespaces_available() -> bool {
    std::path::Path::new("/proc/self/ns/user").exists()
}

#[cfg(not(target_os = "linux"))]
pub fn namespaces_available() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Seccomp parsing ──

    #[test]
    fn parse_mode_disabled() {
        let status = "Name:\ttest\nSeccomp:\t0\nSeccomp_filters:\t0\n";
        assert_eq!(parse_seccomp_mode(status), "disabled");
    }

    #[test]
    fn parse_mode_strict() {
        let status = "Name:\ttest\nSeccomp:\t1\n";
        assert_eq!(parse_seccomp_mode(status), "strict");
    }

    #[test]
    fn parse_mode_filter() {
        let status = "Name:\ttest\nSeccomp:\t2\n";
        assert_eq!(parse_seccomp_mode(status), "filter");
    }

    #[test]
    fn parse_mode_unknown_value() {
        let status = "Seccomp:\t99\n";
        assert_eq!(parse_seccomp_mode(status), "unknown");
    }

    #[test]
    fn parse_mode_no_seccomp_line() {
        let status = "Name:\ttest\nPid:\t1234\n";
        assert_eq!(parse_seccomp_mode(status), "unsupported");
    }

    #[test]
    fn parse_mode_empty() {
        assert_eq!(parse_seccomp_mode(""), "unsupported");
    }

    // ── Landlock parsing ──

    #[test]
    fn parse_abi_valid() {
        assert_eq!(parse_abi_from_proc("1\n"), Some(1));
        assert_eq!(parse_abi_from_proc("3"), Some(3));
        assert_eq!(parse_abi_from_proc("  4  "), Some(4));
    }

    #[test]
    fn parse_abi_zero() {
        assert_eq!(parse_abi_from_proc("0"), None);
        assert_eq!(parse_abi_from_proc("0\n"), None);
    }

    #[test]
    fn parse_abi_invalid() {
        assert_eq!(parse_abi_from_proc(""), None);
        assert_eq!(parse_abi_from_proc("abc"), None);
    }

    #[test]
    fn kernel_version_boundary() {
        assert!(!kernel_version_supports_landlock("5.12.0"));
        assert!(kernel_version_supports_landlock("5.13.0"));
        assert!(kernel_version_supports_landlock("5.14.0"));
        assert!(kernel_version_supports_landlock("6.0.0"));
    }

    #[test]
    fn kernel_version_with_suffix() {
        assert!(kernel_version_supports_landlock("6.12.71-1-lts"));
        assert!(kernel_version_supports_landlock("5.15.0-generic"));
        assert!(!kernel_version_supports_landlock("4.19.0-amd64"));
    }

    #[test]
    fn kernel_version_edge_cases() {
        assert!(!kernel_version_supports_landlock(""));
        assert!(!kernel_version_supports_landlock("invalid"));
        assert!(!kernel_version_supports_landlock("5"));
    }

    // ── cgroup parsing ──

    #[test]
    fn parse_mounts_with_cgroup2() {
        let mounts = "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0\n\
                       proc /proc proc rw,nosuid 0 0\n";
        assert!(parse_mounts_for_cgroup2(mounts));
    }

    #[test]
    fn parse_mounts_without_cgroup2() {
        let mounts = "tmpfs /sys/fs/cgroup tmpfs rw 0 0\n\
                       cgroup /sys/fs/cgroup/memory cgroup rw,memory 0 0\n";
        assert!(!parse_mounts_for_cgroup2(mounts));
    }

    #[test]
    fn parse_mounts_empty() {
        assert!(!parse_mounts_for_cgroup2(""));
    }

    #[test]
    fn parse_memory_max_unlimited() {
        assert_eq!(parse_memory_max("max\n"), None);
        assert_eq!(parse_memory_max("max"), None);
    }

    #[test]
    fn parse_memory_max_limited() {
        assert_eq!(parse_memory_max("1073741824\n"), Some(1_073_741_824));
        assert_eq!(parse_memory_max("536870912"), Some(536_870_912));
    }

    #[test]
    fn parse_memory_max_invalid() {
        assert_eq!(parse_memory_max("not_a_number"), None);
        assert_eq!(parse_memory_max(""), None);
    }

    // ── Live detection (does not panic) ──

    #[test]
    fn detect_does_not_panic() {
        let caps = detect_capabilities();
        assert!(!caps.seccomp_mode.is_empty());
    }

    #[test]
    fn capabilities_serialization() {
        let caps = detect_capabilities();
        let json = serde_json::to_string(&caps).unwrap();
        assert!(json.contains("seccomp_available"));
        let back: SandboxCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seccomp_mode, caps.seccomp_mode);
    }
}
