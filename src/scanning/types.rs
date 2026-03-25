//! Scanning types — verdicts, findings, and externalization policy.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Scan verdict — what to do with the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ScanVerdict {
    /// Artifact is clean — no issues found.
    Pass,
    /// Minor issues detected — output may be redacted.
    Warn,
    /// Significant issues detected — output is quarantined.
    Quarantine,
    /// Critical issues detected — output is blocked.
    Block,
}

/// Finding severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Severity {
    /// Informational — no action needed.
    Info,
    /// Low severity finding.
    Low,
    /// Medium severity finding.
    Medium,
    /// High severity finding.
    High,
    /// Critical severity finding.
    Critical,
}

/// A single finding from a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    /// Unique identifier for this finding.
    pub id: Uuid,
    /// Name of the scanner that produced this finding.
    pub scanner: String,
    /// Severity level of the finding.
    pub severity: Severity,
    /// Category of the finding (e.g. "secret", "malware").
    pub category: String,
    /// Human-readable description of the finding.
    pub message: String,
    /// Optional evidence snippet that triggered the finding.
    pub evidence: Option<String>,
}

/// Result of scanning an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Overall verdict for the scanned artifact.
    pub verdict: ScanVerdict,
    /// Individual findings from all scanners.
    pub findings: Vec<ScanFinding>,
    /// Worst severity across all findings.
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

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn verdict_display() {
        assert_eq!(ScanVerdict::Pass.to_string(), "pass");
        assert_eq!(ScanVerdict::Warn.to_string(), "warn");
        assert_eq!(ScanVerdict::Quarantine.to_string(), "quarantine");
        assert_eq!(ScanVerdict::Block.to_string(), "block");
    }

    #[test]
    fn scan_finding_serde() {
        let finding = ScanFinding {
            id: uuid::Uuid::new_v4(),
            scanner: "test".into(),
            severity: Severity::High,
            category: "test_cat".into(),
            message: "test msg".into(),
            evidence: Some("evidence".into()),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: ScanFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.severity, Severity::High);
        assert_eq!(back.category, "test_cat");
    }

    #[test]
    fn scan_result_serde() {
        let result = ScanResult {
            verdict: ScanVerdict::Block,
            findings: vec![],
            worst_severity: Severity::Critical,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict, ScanVerdict::Block);
    }
}
