//! Scanning types — verdicts, findings, and externalization policy.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Scan verdict — what to do with the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScanVerdict {
    Pass,
    Warn,
    Quarantine,
    Block,
}

/// Finding severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single finding from a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub id: Uuid,
    pub scanner: String,
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub evidence: Option<String>,
}

/// Result of scanning an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub verdict: ScanVerdict,
    pub findings: Vec<ScanFinding>,
    pub worst_severity: Severity,
}

/// Policy for the externalization gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalizationPolicy {
    /// Whether the gate is enabled.
    pub enabled: bool,
    /// Maximum artifact size in bytes.
    pub max_artifact_size_bytes: usize,
    /// Severity threshold for blocking.
    pub block_threshold: Severity,
    /// Severity threshold for quarantine.
    pub quarantine_threshold: Severity,
    /// Whether to redact detected secrets.
    pub redact_secrets: bool,
}

impl Default for ExternalizationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_artifact_size_bytes: 50 * 1024 * 1024, // 50MB
            block_threshold: Severity::Critical,
            quarantine_threshold: Severity::High,
            redact_secrets: true,
        }
    }
}

impl std::fmt::Display for ScanVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Warn => write!(f, "warn"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Block => write!(f, "block"),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn verdict_ordering() {
        assert!(ScanVerdict::Pass < ScanVerdict::Warn);
        assert!(ScanVerdict::Warn < ScanVerdict::Quarantine);
        assert!(ScanVerdict::Quarantine < ScanVerdict::Block);
    }

    #[test]
    fn default_policy() {
        let policy = ExternalizationPolicy::default();
        assert!(policy.enabled);
        assert!(policy.redact_secrets);
        assert_eq!(policy.block_threshold, Severity::Critical);
    }

    #[test]
    fn serde_roundtrip() {
        let policy = ExternalizationPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: ExternalizationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.block_threshold, Severity::Critical);
    }
}
