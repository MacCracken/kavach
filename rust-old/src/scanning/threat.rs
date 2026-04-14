//! Threat classification — intent scoring and kill-chain analysis.
//!
//! Aggregates scan findings into a threat assessment with:
//! - Intent score (0.0–1.0) based on severity weighting and co-occurrence
//! - Kill-chain stage tracking (reconnaissance → exfiltration)
//! - Classification tiers (benign/suspicious/likely_malicious/malicious)
//! - Escalation recommendations (log/alert/suspend/revoke)

use serde::{Deserialize, Serialize};

use super::types::{ScanFinding, Severity};

/// Kill-chain stage (ordered by progression).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KillChainStage {
    /// Information gathering (DNS, scanning).
    Reconnaissance,
    /// Building attack tools (obfuscation, encoding).
    Weaponization,
    /// Delivering payload (package install, remote script).
    Delivery,
    /// Exploiting vulnerability (command injection, eval).
    Exploitation,
    /// Establishing persistence (cron, startup scripts).
    Installation,
    /// Remote control (reverse shell, C2).
    CommandAndControl,
    /// Data theft (secret access, file read).
    Exfiltration,
}

impl std::fmt::Display for KillChainStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reconnaissance => write!(f, "reconnaissance"),
            Self::Weaponization => write!(f, "weaponization"),
            Self::Delivery => write!(f, "delivery"),
            Self::Exploitation => write!(f, "exploitation"),
            Self::Installation => write!(f, "installation"),
            Self::CommandAndControl => write!(f, "command_and_control"),
            Self::Exfiltration => write!(f, "exfiltration"),
        }
    }
}

/// Threat classification tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ThreatTier {
    /// No malicious intent detected.
    Benign,
    /// Some indicators present, likely false positive.
    Suspicious,
    /// Multiple indicators suggest malicious intent.
    LikelyMalicious,
    /// Strong evidence of malicious activity.
    Malicious,
}

/// Recommended escalation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EscalationTier {
    /// Log the event, no action.
    Tier1Log,
    /// Alert operators.
    Tier2Alert,
    /// Suspend the agent/sandbox.
    Tier3Suspend,
    /// Revoke access and register in risk system.
    Tier4Revoke,
}

/// Result of threat classification on a set of findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ThreatAssessment {
    /// Intent score (0.0 = benign, 1.0 = clearly malicious).
    pub intent_score: f64,
    /// Classification tier based on intent score.
    pub classification: ThreatTier,
    /// Recommended escalation action.
    pub escalation: EscalationTier,
    /// Kill-chain stages observed in the findings.
    pub kill_chain_stages: Vec<KillChainStage>,
    /// Number of findings analyzed.
    pub finding_count: usize,
}

/// Severity weight for intent score calculation.
#[inline]
fn severity_weight(severity: Severity) -> f64 {
    match severity {
        Severity::Info => 0.05,
        Severity::Low => 0.15,
        Severity::Medium => 0.35,
        Severity::High => 0.60,
        Severity::Critical => 0.90,
    }
}

/// Map a finding category to its kill-chain stage.
#[must_use]
fn category_to_stage(category: &str) -> Option<KillChainStage> {
    Some(match category {
        "pii_network" => KillChainStage::Reconnaissance,
        "obfuscation" | "crypto_misuse" => KillChainStage::Weaponization,
        "supply_chain" => KillChainStage::Delivery,
        "command_injection" | "privilege_escalation" => KillChainStage::Exploitation,
        "filesystem_abuse" => KillChainStage::Installation,
        "data_exfiltration" => KillChainStage::CommandAndControl,
        "cloud_credential" | "api_token" | "auth_token" | "private_key" | "connection_string"
        | "credential" | "pii" | "pii_financial" => KillChainStage::Exfiltration,
        _ => return None,
    })
}

/// Classify a set of scan findings into a threat assessment.
///
/// The intent score is computed as:
/// 1. Sum severity weights of all findings
/// 2. Apply co-occurrence amplifier (1.3x) when multiple kill-chain stages present
/// 3. Clamp to [0.0, 1.0]
#[must_use]
pub fn classify(findings: &[ScanFinding]) -> ThreatAssessment {
    if findings.is_empty() {
        return ThreatAssessment {
            intent_score: 0.0,
            classification: ThreatTier::Benign,
            escalation: EscalationTier::Tier1Log,
            kill_chain_stages: Vec::new(),
            finding_count: 0,
        };
    }

    // Sum severity weights
    let raw_score: f64 = findings.iter().map(|f| severity_weight(f.severity)).sum();

    // Collect unique kill-chain stages
    let mut stages: Vec<KillChainStage> = findings
        .iter()
        .filter_map(|f| category_to_stage(&f.category))
        .collect();
    stages.sort();
    stages.dedup();

    // Co-occurrence amplifier: multiple stages = more coordinated attack
    let amplifier = if stages.len() >= 3 {
        1.5
    } else if stages.len() >= 2 {
        1.3
    } else {
        1.0
    };

    let intent_score = (raw_score * amplifier).min(1.0);

    let classification = if intent_score < 0.2 {
        ThreatTier::Benign
    } else if intent_score < 0.5 {
        ThreatTier::Suspicious
    } else if intent_score < 0.8 {
        ThreatTier::LikelyMalicious
    } else {
        ThreatTier::Malicious
    };

    let escalation = match classification {
        ThreatTier::Benign => EscalationTier::Tier1Log,
        ThreatTier::Suspicious => EscalationTier::Tier2Alert,
        ThreatTier::LikelyMalicious => EscalationTier::Tier3Suspend,
        ThreatTier::Malicious => EscalationTier::Tier4Revoke,
    };

    ThreatAssessment {
        intent_score,
        classification,
        escalation,
        kill_chain_stages: stages,
        finding_count: findings.len(),
    }
}

// ─── Repeat Offender Tracking ────────────────────────────────────────

/// Record of a past violation for repeat offender tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationRecord {
    /// When the violation occurred (Unix timestamp seconds).
    pub timestamp: u64,
    /// Weighted severity score of the violation.
    pub score: f64,
    /// Agent or sandbox ID that committed the violation.
    pub agent_id: String,
}

/// Repeat offender tracker with rolling window and time decay.
///
/// Tracks violations per agent within a configurable time window.
/// Violations decay over time, and escalation is recommended when
/// the weighted violation count exceeds a threshold.
#[derive(Debug)]
pub struct OffenderTracker {
    /// Rolling window duration in seconds.
    window_secs: u64,
    /// Time decay multiplier (applied per half-window elapsed).
    decay_factor: f64,
    /// Number of weighted violations to trigger escalation.
    escalation_threshold: f64,
    /// Violation records (not pruned automatically — call `prune` periodically).
    records: Vec<ViolationRecord>,
}

impl OffenderTracker {
    /// Create a tracker with default settings (1 hour window, 0.5 decay, threshold 3.0).
    #[must_use]
    pub fn new() -> Self {
        Self {
            window_secs: 3600,
            decay_factor: 0.5,
            escalation_threshold: 3.0,
            records: Vec::new(),
        }
    }

    /// Create a tracker with custom settings.
    ///
    /// # Panics
    /// Panics if `window_secs` is 0.
    #[must_use]
    pub fn with_config(window_secs: u64, decay_factor: f64, threshold: f64) -> Self {
        assert!(window_secs > 0, "window_secs must be > 0");
        Self {
            window_secs,
            decay_factor,
            escalation_threshold: threshold,
            records: Vec::new(),
        }
    }

    /// Record a violation.
    pub fn record(&mut self, agent_id: &str, assessment: &ThreatAssessment) {
        let now = now_secs();
        self.records.push(ViolationRecord {
            timestamp: now,
            score: assessment.intent_score,
            agent_id: agent_id.to_owned(),
        });
    }

    /// Get the weighted violation score for an agent within the rolling window.
    #[must_use]
    pub fn agent_score(&self, agent_id: &str) -> f64 {
        let now = now_secs();
        let cutoff = now.saturating_sub(self.window_secs);

        self.records
            .iter()
            .filter(|r| r.agent_id == agent_id && r.timestamp >= cutoff)
            .map(|r| {
                let age_secs = now.saturating_sub(r.timestamp);
                let half_windows = age_secs as f64 / (self.window_secs as f64 / 2.0);
                r.score * self.decay_factor.powf(half_windows)
            })
            .sum()
    }

    /// Check if an agent should be escalated based on accumulated violations.
    #[must_use]
    pub fn should_escalate(&self, agent_id: &str) -> bool {
        self.agent_score(agent_id) >= self.escalation_threshold
    }

    /// Recommend an escalation tier for an agent.
    #[must_use]
    pub fn recommend_escalation(&self, agent_id: &str) -> EscalationTier {
        let score = self.agent_score(agent_id);
        if score >= self.escalation_threshold * 2.0 {
            EscalationTier::Tier4Revoke
        } else if score >= self.escalation_threshold {
            EscalationTier::Tier3Suspend
        } else if score >= self.escalation_threshold * 0.5 {
            EscalationTier::Tier2Alert
        } else {
            EscalationTier::Tier1Log
        }
    }

    /// Remove violations older than the window.
    pub fn prune(&mut self) {
        let cutoff = now_secs().saturating_sub(self.window_secs);
        self.records.retain(|r| r.timestamp >= cutoff);
    }

    /// Number of tracked violation records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the tracker has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Default for OffenderTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Current time in seconds since Unix epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanning::types::ScanFinding;
    use uuid::Uuid;

    fn make_finding(category: &str, severity: Severity) -> ScanFinding {
        ScanFinding {
            id: Uuid::new_v4(),
            scanner: "test".into(),
            severity,
            category: category.into(),
            message: "test".into(),
            evidence: None,
        }
    }

    // ── Threat classification ────────────────────────────────────────

    #[test]
    fn empty_findings_benign() {
        let a = classify(&[]);
        assert_eq!(a.classification, ThreatTier::Benign);
        assert_eq!(a.escalation, EscalationTier::Tier1Log);
        assert_eq!(a.intent_score, 0.0);
    }

    #[test]
    fn single_low_finding_benign() {
        let findings = vec![make_finding("pii", Severity::Low)];
        let a = classify(&findings);
        assert!(a.intent_score < 0.2);
        assert_eq!(a.classification, ThreatTier::Benign);
    }

    #[test]
    fn critical_finding_malicious() {
        let findings = vec![
            make_finding("command_injection", Severity::Critical),
            make_finding("data_exfiltration", Severity::Critical),
        ];
        let a = classify(&findings);
        assert!(a.intent_score >= 0.8);
        assert_eq!(a.classification, ThreatTier::Malicious);
        assert_eq!(a.escalation, EscalationTier::Tier4Revoke);
    }

    #[test]
    fn co_occurrence_amplifies() {
        let single = vec![make_finding("command_injection", Severity::High)];
        let multi = vec![
            make_finding("command_injection", Severity::High),
            make_finding("data_exfiltration", Severity::Medium),
        ];
        let score_single = classify(&single).intent_score;
        let score_multi = classify(&multi).intent_score;
        assert!(
            score_multi > score_single,
            "multi-stage should amplify: {score_multi} vs {score_single}"
        );
    }

    #[test]
    fn kill_chain_stages_collected() {
        let findings = vec![
            make_finding("command_injection", Severity::High),
            make_finding("data_exfiltration", Severity::High),
            make_finding("supply_chain", Severity::Medium),
        ];
        let a = classify(&findings);
        assert!(a.kill_chain_stages.len() >= 2);
    }

    #[test]
    fn intent_score_clamped() {
        let findings: Vec<_> = (0..20)
            .map(|_| make_finding("command_injection", Severity::Critical))
            .collect();
        let a = classify(&findings);
        assert!(a.intent_score <= 1.0);
    }

    #[test]
    fn severity_weights_ordered() {
        assert!(severity_weight(Severity::Info) < severity_weight(Severity::Low));
        assert!(severity_weight(Severity::Low) < severity_weight(Severity::Medium));
        assert!(severity_weight(Severity::Medium) < severity_weight(Severity::High));
        assert!(severity_weight(Severity::High) < severity_weight(Severity::Critical));
    }

    #[test]
    fn kill_chain_display() {
        assert_eq!(KillChainStage::Reconnaissance.to_string(), "reconnaissance");
        assert_eq!(KillChainStage::Exfiltration.to_string(), "exfiltration");
    }

    #[test]
    fn threat_assessment_serde() {
        let a = classify(&[make_finding("command_injection", Severity::High)]);
        let json = serde_json::to_string(&a).unwrap();
        let back: ThreatAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(a.classification, back.classification);
    }

    // ── Offender tracking ────────────────────────────────────────────

    #[test]
    fn empty_tracker() {
        let tracker = OffenderTracker::new();
        assert!(tracker.is_empty());
        assert!(!tracker.should_escalate("agent-1"));
    }

    #[test]
    fn record_and_score() {
        let mut tracker = OffenderTracker::new();
        let assessment = classify(&[make_finding("command_injection", Severity::Critical)]);
        tracker.record("agent-1", &assessment);
        assert!(!tracker.is_empty());
        assert!(tracker.agent_score("agent-1") > 0.0);
        assert_eq!(tracker.agent_score("agent-2"), 0.0);
    }

    #[test]
    fn escalation_after_repeated_violations() {
        let mut tracker = OffenderTracker::with_config(3600, 0.5, 2.0);
        let bad = classify(&[
            make_finding("command_injection", Severity::Critical),
            make_finding("data_exfiltration", Severity::Critical),
        ]);
        // Record multiple violations
        tracker.record("agent-1", &bad);
        tracker.record("agent-1", &bad);
        tracker.record("agent-1", &bad);
        assert!(tracker.should_escalate("agent-1"));
        assert!(tracker.recommend_escalation("agent-1") >= EscalationTier::Tier3Suspend);
    }

    #[test]
    fn different_agents_isolated() {
        let mut tracker = OffenderTracker::new();
        let bad = classify(&[make_finding("command_injection", Severity::Critical)]);
        tracker.record("agent-1", &bad);
        assert!(tracker.agent_score("agent-1") > 0.0);
        assert_eq!(tracker.agent_score("agent-2"), 0.0);
    }

    #[test]
    fn prune_removes_old() {
        let mut tracker = OffenderTracker::with_config(1, 0.5, 3.0); // 1 second window
        let bad = classify(&[make_finding("command_injection", Severity::High)]);
        // Manually insert an old record
        tracker.records.push(ViolationRecord {
            timestamp: 1000,
            score: 0.9,
            agent_id: "agent-1".into(),
        });
        tracker.record("agent-1", &bad);
        assert_eq!(tracker.len(), 2);
        tracker.prune();
        assert_eq!(tracker.len(), 1); // Old record pruned
    }

    #[test]
    fn recommend_tiers() {
        let tracker = OffenderTracker::with_config(3600, 0.5, 3.0);
        assert_eq!(
            tracker.recommend_escalation("nobody"),
            EscalationTier::Tier1Log
        );
    }
}
