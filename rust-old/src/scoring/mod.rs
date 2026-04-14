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
    /// Return the raw numeric score.
    #[inline]
    #[must_use]
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Return a human-readable label for the score range.
    #[inline]
    #[must_use]
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
#[must_use]
pub fn base_score(backend: Backend) -> StrengthScore {
    StrengthScore(match backend {
        Backend::Noop => 0,
        Backend::Process => 50,
        Backend::Oci => 55,
        Backend::Wasm => 65,
        Backend::GVisor => 70,
        Backend::Sgx => 80,
        Backend::Sev => 82,
        Backend::Tdx => 85,
        Backend::SyAgnos => 80, // Base; tier detection can raise to 85 (dm-verity) or 88 (TPM)
        Backend::Firecracker => 90,
    })
}

/// Score a backend with policy modifiers applied.
#[must_use]
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

    // Landlock TCP port restrictions (ABI v4)
    if !policy.network.tcp_bind_ports.is_empty() || !policy.network.tcp_connect_ports.is_empty() {
        score += 3;
    }

    // Landlock scoping (ABI v6)
    if policy.landlock_scope.abstract_unix_socket {
        score += 2;
    }
    if policy.landlock_scope.signal {
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
        assert_eq!(StrengthScore(29).label(), "minimal");
        assert_eq!(StrengthScore(30).label(), "basic");
        assert_eq!(StrengthScore(49).label(), "basic");
        assert_eq!(StrengthScore(50).label(), "standard");
        assert_eq!(StrengthScore(69).label(), "standard");
        assert_eq!(StrengthScore(70).label(), "hardened");
        assert_eq!(StrengthScore(84).label(), "hardened");
        assert_eq!(StrengthScore(85).label(), "fortress");
        assert_eq!(StrengthScore(100).label(), "fortress");
    }

    #[test]
    fn landlock_rules_increase_score() {
        let mut policy = SandboxPolicy::default();
        let without = score_backend(Backend::Process, &policy);
        policy.landlock_rules.push(crate::policy::LandlockRule {
            path: "/tmp".into(),
            access: "ro".into(),
        });
        let with = score_backend(Backend::Process, &policy);
        assert!(
            with.value() > without.value(),
            "landlock rules should increase score"
        );
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
    fn score_label_above_100() {
        // StrengthScore has a pub field — verify label handles values > 100
        let s = StrengthScore(150);
        assert_eq!(s.label(), "unknown");
    }

    #[test]
    fn noop_minimal_score() {
        // Noop base is 0, but minimal policy has network disabled (+5)
        let score = score_backend(Backend::Noop, &SandboxPolicy::minimal());
        assert_eq!(score.value(), 5);
        assert_eq!(base_score(Backend::Noop).value(), 0);
    }

    #[test]
    fn all_backends_scored() {
        let policy = SandboxPolicy::strict();
        for backend in Backend::all() {
            let score = score_backend(*backend, &policy);
            assert!(score.value() <= 100, "{backend} scored {}", score.value());
        }
    }

    /// SY reference scores for validation.
    /// These are the expected scores from SecureYeoman's reference implementation
    /// for each (backend, policy_preset) combination.
    struct SyReference {
        backend: Backend,
        policy: &'static str,
        expected_min: u8,
        expected_max: u8,
    }

    const SY_REFERENCE: &[SyReference] = &[
        SyReference {
            backend: Backend::Noop,
            policy: "minimal",
            expected_min: 0,
            expected_max: 10,
        },
        SyReference {
            backend: Backend::Process,
            policy: "minimal",
            expected_min: 50,
            expected_max: 60,
        },
        SyReference {
            backend: Backend::Process,
            policy: "basic",
            expected_min: 55,
            expected_max: 70,
        },
        SyReference {
            backend: Backend::Process,
            policy: "strict",
            expected_min: 60,
            expected_max: 75,
        },
        SyReference {
            backend: Backend::Oci,
            policy: "minimal",
            expected_min: 55,
            expected_max: 65,
        },
        SyReference {
            backend: Backend::GVisor,
            policy: "minimal",
            expected_min: 70,
            expected_max: 80,
        },
        SyReference {
            backend: Backend::Wasm,
            policy: "minimal",
            expected_min: 65,
            expected_max: 75,
        },
        SyReference {
            backend: Backend::Firecracker,
            policy: "minimal",
            expected_min: 90,
            expected_max: 100,
        },
        SyReference {
            backend: Backend::Firecracker,
            policy: "strict",
            expected_min: 95,
            expected_max: 100,
        },
        SyReference {
            backend: Backend::Sgx,
            policy: "minimal",
            expected_min: 80,
            expected_max: 90,
        },
        SyReference {
            backend: Backend::Sev,
            policy: "minimal",
            expected_min: 82,
            expected_max: 92,
        },
        SyReference {
            backend: Backend::SyAgnos,
            policy: "minimal",
            expected_min: 80,
            expected_max: 90,
        },
    ];

    #[test]
    fn validate_against_sy_reference() {
        for entry in SY_REFERENCE {
            let policy = match entry.policy {
                "minimal" => SandboxPolicy::minimal(),
                "basic" => SandboxPolicy::basic(),
                "strict" => SandboxPolicy::strict(),
                _ => unreachable!(),
            };
            let score = score_backend(entry.backend, &policy);
            assert!(
                score.value() >= entry.expected_min && score.value() <= entry.expected_max,
                "{:?}/{}: scored {} (expected {}..={})",
                entry.backend,
                entry.policy,
                score.value(),
                entry.expected_min,
                entry.expected_max,
            );
        }
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
