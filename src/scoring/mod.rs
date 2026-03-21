//! Quantitative security strength scoring (0–100).
//!
//! Each backend gets a base score. Policy modifiers adjust up/down
//! based on the specific security configuration applied.

use serde::{Deserialize, Serialize};

use crate::backend::Backend;
use crate::policy::SandboxPolicy;

/// Strength score: 0 (no isolation) to 100 (maximum isolation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StrengthScore(pub u8);

impl StrengthScore {
    pub fn value(&self) -> u8 {
        self.0
    }

    pub fn label(&self) -> &'static str {
        match self.0 {
            0..=29 => "minimal",
            30..=49 => "basic",
            50..=69 => "standard",
            70..=84 => "hardened",
            85..=100 => "fortress",
            _ => "unknown",
        }
    }
}

impl std::fmt::Display for StrengthScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.0, self.label())
    }
}

/// Base strength score for each backend.
pub fn base_score(backend: Backend) -> StrengthScore {
    StrengthScore(match backend {
        Backend::Noop => 0,
        Backend::Process => 50,
        Backend::Oci => 55,
        Backend::Wasm => 65,
        Backend::GVisor => 70,
        Backend::Sgx => 80,
        Backend::Sev => 82,
        Backend::Firecracker => 90,
    })
}

/// Score a backend with policy modifiers applied.
pub fn score_backend(backend: Backend, policy: &SandboxPolicy) -> StrengthScore {
    let mut score = base_score(backend).0 as i16;

    // Seccomp adds isolation
    if policy.seccomp_enabled {
        score += 5;
    }

    // Landlock filesystem restrictions
    if !policy.landlock_rules.is_empty() {
        score += 3;
    }

    // No network = more isolated
    if !policy.network.enabled {
        score += 5;
    }

    // Read-only rootfs
    if policy.read_only_rootfs {
        score += 3;
    }

    // Resource limits
    if policy.memory_limit_mb.is_some() || policy.cpu_limit.is_some() {
        score += 2;
    }

    StrengthScore(score.clamp(0, 100) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SandboxPolicy;

    #[test]
    fn base_scores() {
        assert_eq!(base_score(Backend::Noop).value(), 0);
        assert_eq!(base_score(Backend::Process).value(), 50);
        assert_eq!(base_score(Backend::Firecracker).value(), 90);
    }

    #[test]
    fn score_labels() {
        assert_eq!(StrengthScore(0).label(), "minimal");
        assert_eq!(StrengthScore(50).label(), "standard");
        assert_eq!(StrengthScore(70).label(), "hardened");
        assert_eq!(StrengthScore(90).label(), "fortress");
    }

    #[test]
    fn policy_modifiers_increase_score() {
        let mut policy = SandboxPolicy::default();
        let base = score_backend(Backend::Process, &policy);

        policy.seccomp_enabled = true;
        policy.read_only_rootfs = true;
        let hardened = score_backend(Backend::Process, &policy);

        assert!(hardened.value() > base.value());
    }

    #[test]
    fn score_display() {
        let s = StrengthScore(75);
        assert_eq!(s.to_string(), "75 (hardened)");
    }

    #[test]
    fn score_clamped_to_100() {
        let policy = SandboxPolicy {
            seccomp_enabled: true,
            read_only_rootfs: true,
            memory_limit_mb: Some(512),
            ..Default::default()
        };
        let score = score_backend(Backend::Firecracker, &policy);
        assert!(score.value() <= 100);
    }
}
