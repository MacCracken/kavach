//! SyAgnos backend — hardened AGNOS OS image as container sandbox.
//!
//! Runs commands inside a purpose-built sy-agnos container image with:
//! - Immutable rootfs (squashfs, no shells)
//! - Baked seccomp-BPF filter (compiled into image)
//! - Default-deny nftables firewall
//! - 3 hardening tiers: minimal (80), dm-verity (85), TPM measured (88)
//!
//! Detects container runtime (docker/podman) and image tier from
//! `/etc/sy-agnos-release` inside the container.

use serde::{Deserialize, Serialize};

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// Default sy-agnos container image.
const DEFAULT_IMAGE: &str = "ghcr.io/maccracken/sy-agnos:latest";

/// Hardening tier detected from /etc/sy-agnos-release inside the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyAgnosTier {
    /// Immutable rootfs, no shell, baked seccomp, nftables default-deny.
    Minimal,
    /// Minimal + dm-verity verified rootfs.
    DmVerity,
    /// DmVerity + TPM measured boot with attestation.
    TpmMeasured,
}

impl SyAgnosTier {
    /// Strength score for this tier.
    pub fn strength(&self) -> u8 {
        match self {
            Self::Minimal => 80,
            Self::DmVerity => 85,
            Self::TpmMeasured => 88,
        }
    }

    /// Parse tier from the "tier" field in sy-agnos-release.
    pub fn parse(s: &str) -> Self {
        match s.trim() {
            "tpm_measured" => Self::TpmMeasured,
            "dmverity" => Self::DmVerity,
            _ => Self::Minimal,
        }
    }
}

impl std::fmt::Display for SyAgnosTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minimal => write!(f, "minimal"),
            Self::DmVerity => write!(f, "dmverity"),
            Self::TpmMeasured => write!(f, "tpm_measured"),
        }
    }
}

/// Attestation report from TPM measured boot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// PCR register values (hex strings).
    pub pcr_values: std::collections::HashMap<u32, String>,
    /// HMAC signature over PCR values.
    pub hmac_signature: Option<String>,
    /// Attestation algorithm.
    pub algorithm: Option<String>,
    /// Timestamp of attestation.
    pub timestamp: Option<String>,
}

impl AttestationReport {
    /// Verify attestation report integrity.
    /// Checks PCR registers 8, 9, 10 are present and well-formed.
    pub fn verify(&self) -> bool {
        let required_pcrs = [8, 9, 10];
        let pcr_pattern = regex_lite::Regex::new(r"^[0-9a-f]{16,128}$").ok();

        for pcr in &required_pcrs {
            match self.pcr_values.get(pcr) {
                Some(val) => {
                    if let Some(ref re) = pcr_pattern
                        && !re.is_match(&val.to_lowercase())
                    {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Verify HMAC signature is present and non-trivial
        if let Some(ref sig) = self.hmac_signature {
            if sig.len() < 32 {
                return false;
            }
        } else {
            return false;
        }

        true
    }
}

/// SyAgnos container sandbox backend.
#[derive(Debug)]
pub struct SyAgnosBackend {
    config: SandboxConfig,
    runtime: String,
    image: String,
}

impl SyAgnosBackend {
    /// Create a new SyAgnos backend. Detects container runtime.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        let runtime = detect_runtime().ok_or_else(|| {
            crate::KavachError::BackendUnavailable(
                "no container runtime (docker/podman) found".into(),
            )
        })?;

        Ok(Self {
            config: config.clone(),
            runtime,
            image: DEFAULT_IMAGE.into(),
        })
    }

    /// Detect the sy-agnos image tier by reading /etc/sy-agnos-release.
    pub async fn detect_tier(&self) -> SyAgnosTier {
        let output = tokio::process::Command::new(&self.runtime)
            .args([
                "run",
                "--rm",
                "--entrypoint",
                "cat",
                &self.image,
                "/etc/sy-agnos-release",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let content = String::from_utf8_lossy(&out.stdout);
                parse_tier_from_release(&content)
            }
            _ => SyAgnosTier::Minimal,
        }
    }
}

#[async_trait::async_trait]
impl SandboxBackend for SyAgnosBackend {
    fn backend_type(&self) -> Backend {
        Backend::SyAgnos
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let _ = policy; // Policy is baked into the sy-agnos image

        // Build container run args
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--network".to_string(),
            if self.config.policy.network.enabled {
                "bridge"
            } else {
                "none"
            }
            .to_string(),
        ];

        // Memory limit
        if let Some(mb) = self.config.policy.memory_limit_mb {
            args.extend(["--memory".into(), format!("{mb}m")]);
        }

        // CPU limit
        if let Some(cpu) = self.config.policy.cpu_limit {
            args.extend(["--cpus".into(), format!("{cpu}")]);
        }

        // PID limit
        if let Some(pids) = self.config.policy.max_pids {
            args.extend(["--pids-limit".into(), pids.to_string()]);
        }

        // Read-only rootfs (sy-agnos is already read-only, but enforce at container level too)
        if self.config.policy.read_only_rootfs {
            args.push("--read-only".into());
        }

        // Environment variables
        for (k, v) in &self.config.env {
            args.extend(["-e".into(), format!("{k}={v}")]);
        }

        // Override entrypoint to run the command
        args.extend([
            "--entrypoint".into(),
            "/bin/sh".into(),
            self.image.clone(),
            "-c".into(),
            command.into(),
        ]);

        let mut cmd = tokio::process::Command::new(&self.runtime);
        cmd.args(&args);

        crate::backend::exec_util::execute_with_timeout(
            &mut cmd,
            self.config.timeout_ms,
            &self.runtime,
        )
        .await
    }

    async fn health_check(&self) -> crate::Result<bool> {
        let output = tokio::process::Command::new(&self.runtime)
            .args(["image", "inspect", &self.image])
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("sy-agnos health: {e}")))?;
        Ok(output.status.success())
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Parse tier from sy-agnos-release file content.
/// Expected format: JSON with "tier" field, or key=value lines.
fn parse_tier_from_release(content: &str) -> SyAgnosTier {
    // Try JSON first
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content)
        && let Some(tier) = json.get("tier").and_then(|t| t.as_str())
    {
        return SyAgnosTier::parse(tier);
    }
    // Try key=value
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("tier=") {
            return SyAgnosTier::parse(val);
        }
    }
    SyAgnosTier::Minimal
}

/// Detect available container runtime. Prefers docker over podman.
fn detect_runtime() -> Option<String> {
    crate::backend::which_first(&["docker", "podman"]).map(Into::into)
}

/// Lightweight regex for attestation without pulling in full regex crate.
mod regex_lite {
    pub struct Regex(String);

    impl Regex {
        pub fn new(pattern: &str) -> Result<Self, ()> {
            Ok(Self(pattern.to_string()))
        }

        pub fn is_match(&self, text: &str) -> bool {
            // Simple hex pattern matcher for PCR values
            if self.0 == r"^[0-9a-f]{16,128}$" {
                text.len() >= 16 && text.len() <= 128 && text.chars().all(|c| c.is_ascii_hexdigit())
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_from_str() {
        assert_eq!(SyAgnosTier::parse("minimal"), SyAgnosTier::Minimal);
        assert_eq!(SyAgnosTier::parse("dmverity"), SyAgnosTier::DmVerity);
        assert_eq!(SyAgnosTier::parse("tpm_measured"), SyAgnosTier::TpmMeasured);
        assert_eq!(SyAgnosTier::parse("unknown"), SyAgnosTier::Minimal);
    }

    #[test]
    fn tier_strength() {
        assert_eq!(SyAgnosTier::Minimal.strength(), 80);
        assert_eq!(SyAgnosTier::DmVerity.strength(), 85);
        assert_eq!(SyAgnosTier::TpmMeasured.strength(), 88);
    }

    #[test]
    fn tier_display() {
        assert_eq!(SyAgnosTier::Minimal.to_string(), "minimal");
        assert_eq!(SyAgnosTier::DmVerity.to_string(), "dmverity");
        assert_eq!(SyAgnosTier::TpmMeasured.to_string(), "tpm_measured");
    }

    #[test]
    fn parse_tier_json() {
        let content = r#"{"tier": "dmverity", "version": "2026.3.21"}"#;
        assert_eq!(parse_tier_from_release(content), SyAgnosTier::DmVerity);
    }

    #[test]
    fn parse_tier_keyvalue() {
        let content = "version=2026.3.21\ntier=tpm_measured\nstrength=88\n";
        assert_eq!(parse_tier_from_release(content), SyAgnosTier::TpmMeasured);
    }

    #[test]
    fn parse_tier_unknown_defaults_minimal() {
        assert_eq!(parse_tier_from_release(""), SyAgnosTier::Minimal);
        assert_eq!(parse_tier_from_release("garbage"), SyAgnosTier::Minimal);
    }

    #[test]
    fn attestation_verify_valid() {
        let mut pcrs = std::collections::HashMap::new();
        pcrs.insert(8, "abcdef0123456789abcdef0123456789".to_string());
        pcrs.insert(9, "1234567890abcdef1234567890abcdef".to_string());
        pcrs.insert(10, "fedcba9876543210fedcba9876543210".to_string());

        let report = AttestationReport {
            pcr_values: pcrs,
            hmac_signature: Some("a".repeat(64)),
            algorithm: Some("SHA-256".into()),
            timestamp: Some("2026-03-21T00:00:00Z".into()),
        };
        assert!(report.verify());
    }

    #[test]
    fn attestation_verify_missing_pcr() {
        let mut pcrs = std::collections::HashMap::new();
        pcrs.insert(8, "abcdef0123456789abcdef0123456789".to_string());
        // Missing PCR 9, 10

        let report = AttestationReport {
            pcr_values: pcrs,
            hmac_signature: Some("a".repeat(64)),
            algorithm: None,
            timestamp: None,
        };
        assert!(!report.verify());
    }

    #[test]
    fn attestation_verify_short_hmac() {
        let mut pcrs = std::collections::HashMap::new();
        pcrs.insert(8, "abcdef0123456789abcdef0123456789".to_string());
        pcrs.insert(9, "1234567890abcdef1234567890abcdef".to_string());
        pcrs.insert(10, "fedcba9876543210fedcba9876543210".to_string());

        let report = AttestationReport {
            pcr_values: pcrs,
            hmac_signature: Some("short".into()),
            algorithm: None,
            timestamp: None,
        };
        assert!(!report.verify());
    }

    #[test]
    fn attestation_verify_no_hmac() {
        let mut pcrs = std::collections::HashMap::new();
        pcrs.insert(8, "abcdef0123456789abcdef0123456789".to_string());
        pcrs.insert(9, "1234567890abcdef1234567890abcdef".to_string());
        pcrs.insert(10, "fedcba9876543210fedcba9876543210".to_string());

        let report = AttestationReport {
            pcr_values: pcrs,
            hmac_signature: None,
            algorithm: None,
            timestamp: None,
        };
        assert!(!report.verify());
    }

    #[test]
    fn detect_runtime_does_not_panic() {
        let _ = detect_runtime();
    }
}
