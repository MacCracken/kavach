//! cgroup v2 resource limit enforcement.
//!
//! Creates a per-sandbox cgroup scope under `/sys/fs/cgroup/kavach/<id>/`
//! and writes memory, CPU, and PID limits.

use crate::policy::SandboxPolicy;

/// cgroup scope for a sandbox instance.
pub struct CgroupScope {
    path: std::path::PathBuf,
    created: bool,
}

impl CgroupScope {
    /// Create a new cgroup scope. Does not create the directory yet.
    pub fn new(sandbox_id: &str) -> Self {
        Self {
            path: std::path::PathBuf::from(format!("/sys/fs/cgroup/kavach/{sandbox_id}")),
            created: false,
        }
    }

    /// Check if any resource limits are configured in the policy.
    #[inline]
    #[must_use]
    pub fn has_limits(policy: &SandboxPolicy) -> bool {
        policy.memory_limit_mb.is_some() || policy.cpu_limit.is_some() || policy.max_pids.is_some()
    }

    /// Create the cgroup directory and write limits.
    #[cfg(target_os = "linux")]
    pub fn create(&mut self, policy: &SandboxPolicy) -> crate::Result<()> {
        // Create parent dir if needed
        let parent = self.path.parent().unwrap();
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::KavachError::ExecFailed(format!(
                    "cgroup parent dir {}: {e}",
                    parent.display()
                ))
            })?;
        }

        std::fs::create_dir_all(&self.path).map_err(|e| {
            crate::KavachError::ExecFailed(format!("cgroup create {}: {e}", self.path.display()))
        })?;
        self.created = true;

        // Write memory limit
        if let Some(mb) = policy.memory_limit_mb {
            let bytes = mb * 1024 * 1024;
            self.write_limit("memory.max", &bytes.to_string())?;
        }

        // Write CPU limit
        if let Some(cpu) = policy.cpu_limit {
            let cpu_max = format_cpu_max(cpu);
            self.write_limit("cpu.max", &cpu_max)?;
        }

        // Write PID limit
        if let Some(pids) = policy.max_pids {
            self.write_limit("pids.max", &pids.to_string())?;
        }

        tracing::debug!(path = %self.path.display(), "cgroup scope created");
        Ok(())
    }

    /// Stub for non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn create(&mut self, _policy: &SandboxPolicy) -> crate::Result<()> {
        Ok(())
    }

    /// Add a process to this cgroup scope.
    #[cfg(target_os = "linux")]
    pub fn add_pid(&self, pid: u32) -> crate::Result<()> {
        if !self.created {
            return Ok(());
        }
        self.write_limit("cgroup.procs", &pid.to_string())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn add_pid(&self, _pid: u32) -> crate::Result<()> {
        Ok(())
    }

    /// Read current memory usage in bytes.
    #[cfg(target_os = "linux")]
    pub fn memory_current(&self) -> Option<u64> {
        if !self.created {
            return None;
        }
        std::fs::read_to_string(self.path.join("memory.current"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn memory_current(&self) -> Option<u64> {
        None
    }

    /// Cleanup: remove the cgroup directory.
    #[cfg(target_os = "linux")]
    pub fn destroy(&self) {
        if !self.created {
            return;
        }
        // Kill any remaining processes
        if let Ok(procs) = std::fs::read_to_string(self.path.join("cgroup.procs")) {
            for line in procs.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
            }
        }
        let _ = std::fs::remove_dir(&self.path);
        tracing::debug!(path = %self.path.display(), "cgroup scope destroyed");
    }

    #[cfg(not(target_os = "linux"))]
    pub fn destroy(&self) {}

    #[cfg(target_os = "linux")]
    fn write_limit(&self, file: &str, value: &str) -> crate::Result<()> {
        let path = self.path.join(file);
        std::fs::write(&path, value).map_err(|e| {
            crate::KavachError::ExecFailed(format!("cgroup write {}: {e}", path.display()))
        })
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// Format CPU limit as cgroup v2 `cpu.max` value.
/// `cpu_limit` is fractional cores (e.g., 0.5 = 50% of one core).
/// Format: "QUOTA PERIOD" where both are in microseconds.
#[must_use]
pub fn format_cpu_max(cpu_limit: f64) -> String {
    let period: u64 = 100_000; // 100ms period
    let quota = (cpu_limit * period as f64) as u64;
    format!("{quota} {period}")
}

/// Apply resource limits via setrlimit as a fallback when cgroups are unavailable.
#[cfg(target_os = "linux")]
pub fn apply_rlimits(policy: &SandboxPolicy) -> crate::Result<()> {
    use nix::sys::resource::{Resource, setrlimit};

    if let Some(mb) = policy.memory_limit_mb {
        let bytes = mb * 1024 * 1024;
        setrlimit(Resource::RLIMIT_AS, bytes, bytes)
            .map_err(|e| crate::KavachError::ExecFailed(format!("setrlimit AS: {e}")))?;
    }

    if let Some(pids) = policy.max_pids {
        setrlimit(Resource::RLIMIT_NPROC, pids as u64, pids as u64)
            .map_err(|e| crate::KavachError::ExecFailed(format!("setrlimit NPROC: {e}")))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_cpu_max_half_core() {
        assert_eq!(format_cpu_max(0.5), "50000 100000");
    }

    #[test]
    fn format_cpu_max_full_core() {
        assert_eq!(format_cpu_max(1.0), "100000 100000");
    }

    #[test]
    fn format_cpu_max_quarter_core() {
        assert_eq!(format_cpu_max(0.25), "25000 100000");
    }

    #[test]
    fn has_limits_none() {
        let policy = SandboxPolicy::minimal();
        assert!(!CgroupScope::has_limits(&policy));
    }

    #[test]
    fn has_limits_memory() {
        let mut policy = SandboxPolicy::minimal();
        policy.memory_limit_mb = Some(512);
        assert!(CgroupScope::has_limits(&policy));
    }

    #[test]
    fn has_limits_strict() {
        let policy = SandboxPolicy::strict();
        assert!(CgroupScope::has_limits(&policy));
    }

    #[test]
    fn scope_path() {
        let scope = CgroupScope::new("test-123");
        assert_eq!(
            scope.path,
            std::path::PathBuf::from("/sys/fs/cgroup/kavach/test-123")
        );
    }
}
