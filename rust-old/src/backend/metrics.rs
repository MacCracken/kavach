//! Sandbox execution metrics — CPU, memory, PID usage.

use serde::{Deserialize, Serialize};

/// Resource usage metrics captured during sandbox execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxMetrics {
    /// CPU time used in milliseconds.
    pub cpu_time_ms: u64,
    /// Peak memory usage in bytes.
    pub memory_peak_bytes: u64,
    /// Current memory usage in bytes (at time of measurement).
    pub memory_current_bytes: u64,
    /// Number of active processes.
    pub pids_current: u32,
}

impl SandboxMetrics {
    /// Create metrics from cgroup file contents.
    #[cfg(target_os = "linux")]
    pub fn from_cgroup_path(cgroup_path: &std::path::Path) -> Self {
        let mut metrics = Self::default();

        // Read memory.current
        if let Ok(content) = std::fs::read_to_string(cgroup_path.join("memory.current"))
            && let Ok(bytes) = content.trim().parse::<u64>()
        {
            metrics.memory_current_bytes = bytes;
            metrics.memory_peak_bytes = bytes; // Approximate — peak tracking needs memory.peak
        }

        // Read memory.peak (if available, kernel 5.19+)
        if let Ok(content) = std::fs::read_to_string(cgroup_path.join("memory.peak"))
            && let Ok(bytes) = content.trim().parse::<u64>()
        {
            metrics.memory_peak_bytes = bytes;
        }

        // Read pids.current
        if let Ok(content) = std::fs::read_to_string(cgroup_path.join("pids.current"))
            && let Ok(pids) = content.trim().parse::<u32>()
        {
            metrics.pids_current = pids;
        }

        // Read cpu.stat for usage_usec
        if let Ok(content) = std::fs::read_to_string(cgroup_path.join("cpu.stat")) {
            for line in content.lines() {
                if let Some(val) = line.strip_prefix("usage_usec ")
                    && let Ok(usec) = val.trim().parse::<u64>()
                {
                    metrics.cpu_time_ms = usec / 1000;
                }
            }
        }

        metrics
    }

    /// Parse CPU usage from a cpu.stat file content.
    #[must_use]
    pub fn parse_cpu_stat(content: &str) -> Option<u64> {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("usage_usec ") {
                return val.trim().parse().ok();
            }
        }
        None
    }
}

impl std::fmt::Display for SandboxMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cpu={}ms mem={}MB peak={}MB pids={}",
            self.cpu_time_ms,
            self.memory_current_bytes / 1024 / 1024,
            self.memory_peak_bytes / 1024 / 1024,
            self.pids_current
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_metrics() {
        let m = SandboxMetrics::default();
        assert_eq!(m.cpu_time_ms, 0);
        assert_eq!(m.memory_peak_bytes, 0);
        assert_eq!(m.pids_current, 0);
    }

    #[test]
    fn parse_cpu_stat() {
        let content = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n";
        assert_eq!(SandboxMetrics::parse_cpu_stat(content), Some(123456));
    }

    #[test]
    fn parse_cpu_stat_empty() {
        assert_eq!(SandboxMetrics::parse_cpu_stat(""), None);
    }

    #[test]
    fn parse_cpu_stat_no_usage() {
        let content = "user_usec 100000\nsystem_usec 23456\n";
        assert_eq!(SandboxMetrics::parse_cpu_stat(content), None);
    }

    #[test]
    fn display() {
        let m = SandboxMetrics {
            cpu_time_ms: 42,
            memory_peak_bytes: 10 * 1024 * 1024,
            memory_current_bytes: 5 * 1024 * 1024,
            pids_current: 3,
        };
        let s = m.to_string();
        assert!(s.contains("cpu=42ms"));
        assert!(s.contains("pids=3"));
    }

    #[test]
    fn serde_roundtrip() {
        let m = SandboxMetrics {
            cpu_time_ms: 100,
            memory_peak_bytes: 1024,
            memory_current_bytes: 512,
            pids_current: 1,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: SandboxMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cpu_time_ms, 100);
    }
}
