//! Composite backend — stack multiple isolation layers for defense-in-depth.
//!
//! Composes an outer backend (VM/container runtime boundary) with an inner
//! policy layer (seccomp, landlock, resource limits). The outer backend
//! handles execution; the inner's policy is merged to tighten isolation.
//!
//! # Example
//!
//! ```rust,no_run
//! use kavach::{Backend, SandboxConfig, SandboxPolicy};
//!
//! let config = SandboxConfig::builder()
//!     .backend(Backend::GVisor)          // outer: gVisor container
//!     .inner_backend(Backend::Process)   // inner: seccomp + landlock
//!     .policy(SandboxPolicy::strict())
//!     .build();
//! ```

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::ExecResult;
use crate::policy::SandboxPolicy;

/// A backend that composes an outer isolation boundary with an inner policy layer.
///
/// The outer backend provides the runtime boundary (VM, container, etc.).
/// The inner policy adds additional isolation constraints (seccomp, landlock,
/// resource limits) that are merged into the outer's execution context.
pub struct CompositeBackend {
    outer: Box<dyn SandboxBackend>,
    inner_policy: SandboxPolicy,
    outer_backend: Backend,
    inner_backend: Backend,
}

impl std::fmt::Debug for CompositeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeBackend")
            .field("outer", &self.outer_backend)
            .field("inner", &self.inner_backend)
            .finish()
    }
}

impl CompositeBackend {
    /// Create a composite backend from an outer backend and inner policy.
    pub fn new(
        outer: Box<dyn SandboxBackend>,
        outer_backend: Backend,
        inner_backend: Backend,
        inner_policy: SandboxPolicy,
    ) -> Self {
        Self {
            outer,
            inner_policy,
            outer_backend,
            inner_backend,
        }
    }

    /// The outer backend type.
    #[must_use]
    pub fn outer_type(&self) -> Backend {
        self.outer_backend
    }

    /// The inner backend type (provides additional policy).
    #[must_use]
    pub fn inner_type(&self) -> Backend {
        self.inner_backend
    }
}

#[async_trait::async_trait]
impl SandboxBackend for CompositeBackend {
    fn backend_type(&self) -> Backend {
        self.outer_backend
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        // Merge the caller's policy with the inner backend's policy
        let merged = merge_policies(policy, &self.inner_policy);
        tracing::debug!(
            outer = %self.outer_backend,
            inner = %self.inner_backend,
            "composite exec with merged policy"
        );
        self.outer.exec(command, &merged).await
    }

    async fn health_check(&self) -> crate::Result<bool> {
        self.outer.health_check().await
    }

    async fn spawn(
        &self,
        command: &str,
        policy: &SandboxPolicy,
    ) -> crate::Result<Option<crate::backend::exec_util::SpawnedProcess>> {
        let merged = merge_policies(policy, &self.inner_policy);
        self.outer.spawn(command, &merged).await
    }

    async fn destroy(&self) -> crate::Result<()> {
        self.outer.destroy().await
    }
}

/// Merge two policies, taking the stricter option for each field.
///
/// Rules:
/// - `seccomp_enabled`: true if either is true; profile = stricter
/// - `landlock_rules`: concatenate both sets
/// - `network.enabled`: false if either disables it
/// - `read_only_rootfs`: true if either requires it
/// - Resource limits: take the smaller (stricter) value
#[must_use]
pub fn merge_policies(base: &SandboxPolicy, overlay: &SandboxPolicy) -> SandboxPolicy {
    SandboxPolicy {
        seccomp_enabled: base.seccomp_enabled || overlay.seccomp_enabled,
        seccomp_profile: match (&base.seccomp_profile, &overlay.seccomp_profile) {
            (Some(b), Some(o)) => {
                // "strict" is stricter than "basic"
                Some(if o == "strict" || b == "strict" {
                    "strict".into()
                } else {
                    b.clone()
                })
            }
            (Some(p), None) | (None, Some(p)) => Some(p.clone()),
            (None, None) => None,
        },
        // Landlock rules are additive: the composite can access paths from
        // either policy. This is correct because landlock defines allowed paths
        // (not denied paths) — the outer backend's runtime boundary provides
        // the hard restriction, and the inner may need additional paths.
        landlock_rules: {
            let mut rules = base.landlock_rules.clone();
            rules.extend(overlay.landlock_rules.iter().cloned());
            rules
        },
        network: crate::policy::NetworkPolicy {
            enabled: base.network.enabled && overlay.network.enabled,
            // Intersect allowlists — only hosts/ports allowed by BOTH policies pass.
            // Empty list = "no restriction" in the source policy, so non-empty wins.
            allowed_hosts: intersect_or_nonempty(
                &base.network.allowed_hosts,
                &overlay.network.allowed_hosts,
            ),
            allowed_ports: intersect_or_nonempty_ports(
                &base.network.allowed_ports,
                &overlay.network.allowed_ports,
            ),
        },
        read_only_rootfs: base.read_only_rootfs || overlay.read_only_rootfs,
        memory_limit_mb: match (base.memory_limit_mb, overlay.memory_limit_mb) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(v), None) | (None, Some(v)) => Some(v),
            (None, None) => None,
        },
        cpu_limit: match (base.cpu_limit, overlay.cpu_limit) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(v), None) | (None, Some(v)) => Some(v),
            (None, None) => None,
        },
        max_pids: match (base.max_pids, overlay.max_pids) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(v), None) | (None, Some(v)) => Some(v),
            (None, None) => None,
        },
        data_dir: base.data_dir.clone().or_else(|| overlay.data_dir.clone()),
    }
}

/// Intersect two host allowlists. Empty list = "allow all" in that policy.
fn intersect_or_nonempty(a: &[String], b: &[String]) -> Vec<String> {
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    a.iter().filter(|h| b.contains(h)).cloned().collect()
}

/// Intersect two port allowlists. Empty list = "allow all" in that policy.
fn intersect_or_nonempty_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    a.iter().filter(|p| b.contains(p)).copied().collect()
}

/// Score a composite backend — bonus for layered isolation.
///
/// Composite score = max(outer_base, inner_base) + 5, clamped to 100.
#[must_use]
pub fn score_composite(
    outer: Backend,
    inner: Backend,
    policy: &SandboxPolicy,
) -> crate::scoring::StrengthScore {
    let outer_score = crate::scoring::score_backend(outer, policy).value();
    let inner_score = crate::scoring::score_backend(inner, policy).value();
    let composite = outer_score.max(inner_score).saturating_add(5);
    crate::scoring::StrengthScore(composite.min(100))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::NoopBackend;
    use crate::policy::LandlockRule;

    #[test]
    fn merge_seccomp_strict_wins() {
        let base = SandboxPolicy {
            seccomp_enabled: true,
            seccomp_profile: Some("basic".into()),
            ..Default::default()
        };
        let overlay = SandboxPolicy {
            seccomp_enabled: true,
            seccomp_profile: Some("strict".into()),
            ..Default::default()
        };
        let merged = merge_policies(&base, &overlay);
        assert!(merged.seccomp_enabled);
        assert_eq!(merged.seccomp_profile.as_deref(), Some("strict"));
    }

    #[test]
    fn merge_seccomp_either_enables() {
        let off = SandboxPolicy::default();
        let on = SandboxPolicy {
            seccomp_enabled: true,
            seccomp_profile: Some("basic".into()),
            ..Default::default()
        };
        let merged = merge_policies(&off, &on);
        assert!(merged.seccomp_enabled);
    }

    #[test]
    fn merge_network_stricter() {
        let net_on = SandboxPolicy {
            network: crate::policy::NetworkPolicy {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let net_off = SandboxPolicy::default(); // network disabled by default
        let merged = merge_policies(&net_on, &net_off);
        assert!(!merged.network.enabled);
    }

    #[test]
    fn merge_resource_limits_min() {
        let a = SandboxPolicy {
            memory_limit_mb: Some(1024),
            cpu_limit: Some(2.0),
            max_pids: Some(128),
            ..Default::default()
        };
        let b = SandboxPolicy {
            memory_limit_mb: Some(512),
            cpu_limit: Some(4.0),
            max_pids: Some(64),
            ..Default::default()
        };
        let merged = merge_policies(&a, &b);
        assert_eq!(merged.memory_limit_mb, Some(512));
        assert_eq!(merged.cpu_limit, Some(2.0));
        assert_eq!(merged.max_pids, Some(64));
    }

    #[test]
    fn merge_landlock_concatenated() {
        let a = SandboxPolicy {
            landlock_rules: vec![LandlockRule {
                path: "/tmp".into(),
                access: "rw".into(),
            }],
            ..Default::default()
        };
        let b = SandboxPolicy {
            landlock_rules: vec![LandlockRule {
                path: "/var".into(),
                access: "ro".into(),
            }],
            ..Default::default()
        };
        let merged = merge_policies(&a, &b);
        assert_eq!(merged.landlock_rules.len(), 2);
    }

    #[test]
    fn merge_readonly_rootfs() {
        let a = SandboxPolicy::default();
        let b = SandboxPolicy {
            read_only_rootfs: true,
            ..Default::default()
        };
        let merged = merge_policies(&a, &b);
        assert!(merged.read_only_rootfs);
    }

    #[tokio::test]
    async fn composite_exec_noop() {
        let outer = Box::new(NoopBackend);
        let inner_policy = SandboxPolicy::strict();
        let composite = CompositeBackend::new(outer, Backend::Noop, Backend::Process, inner_policy);

        let policy = SandboxPolicy::basic();
        let result = composite.exec("echo hello", &policy).await.unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn composite_health_check() {
        let outer = Box::new(NoopBackend);
        let composite = CompositeBackend::new(
            outer,
            Backend::Noop,
            Backend::Process,
            SandboxPolicy::default(),
        );
        assert!(composite.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn composite_destroy() {
        let outer = Box::new(NoopBackend);
        let composite = CompositeBackend::new(
            outer,
            Backend::Noop,
            Backend::Process,
            SandboxPolicy::default(),
        );
        composite.destroy().await.unwrap();
    }

    #[test]
    fn composite_debug() {
        let outer = Box::new(NoopBackend);
        let composite = CompositeBackend::new(
            outer,
            Backend::Firecracker,
            Backend::Process,
            SandboxPolicy::default(),
        );
        let debug = format!("{composite:?}");
        assert!(debug.contains("Firecracker"));
        assert!(debug.contains("Process"));
    }

    #[test]
    fn composite_score_bonus() {
        let policy = SandboxPolicy::strict();
        let outer_only = crate::scoring::score_backend(Backend::GVisor, &policy);
        let composite = score_composite(Backend::GVisor, Backend::Process, &policy);
        assert!(composite.value() > outer_only.value());
    }

    #[test]
    fn composite_score_clamped() {
        let policy = SandboxPolicy::strict();
        let score = score_composite(Backend::Firecracker, Backend::Process, &policy);
        assert!(score.value() <= 100);
    }

    #[test]
    fn outer_inner_types() {
        let outer = Box::new(NoopBackend);
        let composite = CompositeBackend::new(
            outer,
            Backend::GVisor,
            Backend::Process,
            SandboxPolicy::default(),
        );
        assert_eq!(composite.outer_type(), Backend::GVisor);
        assert_eq!(composite.inner_type(), Backend::Process);
    }
}
