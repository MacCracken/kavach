//! Landlock filesystem restriction enforcement.
//!
//! Converts `SandboxPolicy` Landlock rules into kernel-enforced filesystem
//! access restrictions using the `landlock` crate.

#[cfg(target_os = "linux")]
use landlock::{
    ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus,
};

use crate::policy::{LandlockRule, SandboxPolicy};

/// Build and apply Landlock rules from a sandbox policy.
/// Must be called in `pre_exec` context (after fork, before exec).
#[cfg(target_os = "linux")]
pub fn apply_landlock(policy: &SandboxPolicy) -> crate::Result<()> {
    let abi = ABI::V5;
    let access_all = AccessFs::from_all(abi);
    let access_read = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(access_all)
        .map_err(|e| crate::KavachError::ExecFailed(format!("landlock ruleset: {e}")))?
        .create()
        .map_err(|e| crate::KavachError::ExecFailed(format!("landlock create: {e}")))?;

    // If no explicit rules but read_only_rootfs is set, apply defaults
    let default_rules;
    let rules = if policy.landlock_rules.is_empty() && policy.read_only_rootfs {
        default_rules = default_readonly_rules(policy);
        &default_rules
    } else {
        &policy.landlock_rules
    };

    for rule in rules {
        let access = match rule.access.as_str() {
            "rw" => access_all,
            _ => access_read,
        };

        let fd = PathFd::new(&rule.path).map_err(|e| {
            crate::KavachError::ExecFailed(format!("landlock path {}: {e}", rule.path))
        })?;

        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| crate::KavachError::ExecFailed(format!("landlock add_rule: {e}")))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| crate::KavachError::ExecFailed(format!("landlock restrict_self: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::debug!("landlock fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::warn!("landlock partially enforced (older kernel ABI)");
        }
        RulesetStatus::NotEnforced => {
            tracing::warn!("landlock not enforced");
        }
    }

    Ok(())
}

/// Check if Landlock rules should be applied for this policy.
#[inline]
#[must_use]
pub fn should_apply(policy: &SandboxPolicy) -> bool {
    !policy.landlock_rules.is_empty() || policy.read_only_rootfs
}

/// Generate default rules when read_only_rootfs is true but no explicit rules given.
fn default_readonly_rules(policy: &SandboxPolicy) -> Vec<LandlockRule> {
    let mut rules = vec![
        LandlockRule {
            path: "/".into(),
            access: "ro".into(),
        },
        LandlockRule {
            path: "/tmp".into(),
            access: "rw".into(),
        },
        LandlockRule {
            path: "/dev/null".into(),
            access: "rw".into(),
        },
        LandlockRule {
            path: "/dev/urandom".into(),
            access: "ro".into(),
        },
    ];

    if let Some(ref data_dir) = policy.data_dir {
        rules.push(LandlockRule {
            path: data_dir.clone(),
            access: "rw".into(),
        });
    }

    rules
}

/// Convert a LandlockRule access string to a human-readable description.
#[must_use]
pub fn access_description(access: &str) -> &'static str {
    match access {
        "rw" => "read-write",
        "ro" => "read-only",
        _ => "read-only",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_apply_with_rules() {
        let mut policy = SandboxPolicy::minimal();
        assert!(!should_apply(&policy));

        policy.landlock_rules.push(LandlockRule {
            path: "/tmp".into(),
            access: "rw".into(),
        });
        assert!(should_apply(&policy));
    }

    #[test]
    fn should_apply_with_readonly_rootfs() {
        let mut policy = SandboxPolicy::minimal();
        policy.read_only_rootfs = true;
        assert!(should_apply(&policy));
    }

    #[test]
    fn default_rules_include_root() {
        let mut policy = SandboxPolicy::minimal();
        policy.read_only_rootfs = true;
        let rules = default_readonly_rules(&policy);
        assert!(rules.iter().any(|r| r.path == "/" && r.access == "ro"));
        assert!(rules.iter().any(|r| r.path == "/tmp" && r.access == "rw"));
    }

    #[test]
    fn default_rules_include_data_dir() {
        let mut policy = SandboxPolicy::minimal();
        policy.read_only_rootfs = true;
        policy.data_dir = Some("/data".into());
        let rules = default_readonly_rules(&policy);
        assert!(rules.iter().any(|r| r.path == "/data" && r.access == "rw"));
    }

    #[test]
    fn access_descriptions() {
        assert_eq!(access_description("rw"), "read-write");
        assert_eq!(access_description("ro"), "read-only");
        assert_eq!(access_description("unknown"), "read-only");
    }
}
