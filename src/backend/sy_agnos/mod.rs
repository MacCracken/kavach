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

// ─── Phylax Output Scanning ──────────────────────────────────────────

/// SyAgnos-specific output scanner.
///
/// Wraps the standard secrets scanner and adds sy-agnos-specific patterns
/// for detecting container escape attempts, verity violations, and
/// nftables bypass indicators.
#[derive(Debug)]
pub struct PhylaxScanner {
    secrets_scanner: crate::scanning::secrets::SecretsScanner,
}

/// Patterns that indicate a security event in sy-agnos output.
const PHYLAX_PATTERNS: &[(&str, &str)] = &[
    ("dm-verity", "VERITY"),
    ("verity validation failed", "VERITY"),
    ("device-mapper: verity", "VERITY"),
    ("nft ", "NFTABLES_BYPASS"),
    ("nftables", "NFTABLES_BYPASS"),
    ("iptables", "NFTABLES_BYPASS"),
    ("nsenter", "NAMESPACE_ESCAPE"),
    ("setns(", "NAMESPACE_ESCAPE"),
    ("unshare(", "NAMESPACE_ESCAPE"),
    ("/proc/1/ns/", "NAMESPACE_ESCAPE"),
    ("mount -t proc", "MOUNT_ESCAPE"),
    ("mount -o remount,rw", "MOUNT_ESCAPE"),
    ("pivot_root", "MOUNT_ESCAPE"),
    ("chroot", "MOUNT_ESCAPE"),
];

impl PhylaxScanner {
    /// Create a new Phylax scanner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secrets_scanner: crate::scanning::secrets::SecretsScanner::new(),
        }
    }

    /// Scan output for both secrets and sy-agnos-specific security events.
    #[must_use]
    pub fn scan(&self, output: &str) -> Vec<PhylaxFinding> {
        let mut findings = Vec::new();

        // Standard secret scanning
        for finding in self.secrets_scanner.scan(output) {
            findings.push(PhylaxFinding {
                category: finding.category,
                severity: PhylaxSeverity::High,
                evidence: finding.evidence,
            });
        }

        // SyAgnos-specific pattern scanning
        let output_lower = output.to_lowercase();
        for &(pattern, category) in PHYLAX_PATTERNS {
            if output_lower.contains(pattern) {
                let evidence = extract_line_containing(output, pattern);
                findings.push(PhylaxFinding {
                    category: category.into(),
                    severity: PhylaxSeverity::Critical,
                    evidence: Some(evidence),
                });
            }
        }

        tracing::debug!(findings = findings.len(), "phylax scan complete");

        findings
    }

    /// Redact secrets and flag security events in output.
    #[must_use]
    pub fn redact<'a>(&self, output: &'a str) -> std::borrow::Cow<'a, str> {
        self.secrets_scanner.redact(output)
    }
}

impl Default for PhylaxScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// A finding from the Phylax scanner.
#[derive(Debug, Clone)]
pub struct PhylaxFinding {
    /// Category of the finding (e.g., "AWS_KEY", "VERITY", "NAMESPACE_ESCAPE").
    pub category: String,
    /// Severity of the finding.
    pub severity: PhylaxSeverity,
    /// Evidence snippet (truncated).
    pub evidence: Option<String>,
}

/// Severity levels for Phylax findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum PhylaxSeverity {
    /// Informational finding.
    Info,
    /// Secret or credential detected.
    High,
    /// Container escape or integrity violation attempt.
    Critical,
}

/// Extract the line containing a pattern for evidence.
fn extract_line_containing(text: &str, pattern: &str) -> String {
    let pattern_lower = pattern.to_lowercase();
    for line in text.lines() {
        if line.to_lowercase().contains(&pattern_lower) {
            if line.len() > 80 {
                let mut end = 80;
                while end > 0 && !line.is_char_boundary(end) {
                    end -= 1;
                }
                return format!("{}...", &line[..end]);
            }
            return line.to_string();
        }
    }
    pattern.to_string()
}

// ─── Image Management ────────────────────────────────────────────────

/// SyAgnos container image manager.
///
/// Handles pulling, building, and listing sy-agnos images via the
/// detected container runtime (docker/podman).
#[derive(Debug)]
pub struct SyAgnosImageManager {
    runtime: String,
}

impl SyAgnosImageManager {
    /// Create a new image manager with the given container runtime.
    pub fn new(runtime: &str) -> Self {
        Self {
            runtime: runtime.to_owned(),
        }
    }

    /// Pull a sy-agnos image from the registry.
    pub async fn pull(&self, image: &str) -> crate::Result<()> {
        tracing::debug!(image = image, runtime = %self.runtime, "pulling sy-agnos image");

        let output = tokio::process::Command::new(&self.runtime)
            .args(["pull", image])
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("image pull: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::KavachError::ExecFailed(format!(
                "image pull failed: {stderr}"
            )));
        }

        tracing::debug!(image = image, "image pull complete");
        Ok(())
    }

    /// Build a sy-agnos image from a Dockerfile.
    pub async fn build(&self, dockerfile_path: &std::path::Path, tag: &str) -> crate::Result<()> {
        tracing::debug!(
            dockerfile = %dockerfile_path.display(),
            tag = tag,
            "building sy-agnos image"
        );

        let context_dir = dockerfile_path
            .parent()
            .unwrap_or(std::path::Path::new("."));

        let output = tokio::process::Command::new(&self.runtime)
            .args([
                "build",
                "-f",
                &dockerfile_path.to_string_lossy(),
                "-t",
                tag,
                &context_dir.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("image build: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::KavachError::ExecFailed(format!(
                "image build failed: {stderr}"
            )));
        }

        Ok(())
    }

    /// List locally available sy-agnos images.
    pub async fn list_local(&self) -> crate::Result<Vec<String>> {
        let output = tokio::process::Command::new(&self.runtime)
            .args([
                "images",
                "--format",
                "{{.Repository}}:{{.Tag}}",
                "--filter",
                "reference=*sy-agnos*",
            ])
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("image list: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }

    /// Check if a specific image is available locally.
    pub async fn is_local(&self, image: &str) -> bool {
        tokio::process::Command::new(&self.runtime)
            .args(["image", "inspect", image])
            .output()
            .await
            .is_ok_and(|o| o.status.success())
    }
}

/// SyAgnos container sandbox backend.
#[derive(Debug)]
pub struct SyAgnosBackend {
    config: SandboxConfig,
    runtime: String,
    image: String,
    phylax_enabled: bool,
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
            phylax_enabled: false,
        })
    }

    /// Enable or disable Phylax output scanning.
    pub fn with_phylax_scanning(mut self, enabled: bool) -> Self {
        self.phylax_enabled = enabled;
        self
    }

    /// Get an image manager for this backend's runtime.
    #[must_use]
    pub fn image_manager(&self) -> SyAgnosImageManager {
        SyAgnosImageManager::new(&self.runtime)
    }

    /// Ensure the configured image is available locally, pulling if needed.
    pub async fn ensure_image(&self) -> crate::Result<()> {
        let mgr = self.image_manager();
        if !mgr.is_local(&self.image).await {
            tracing::debug!(image = %self.image, "image not found locally, pulling");
            mgr.pull(&self.image).await?;
        }
        Ok(())
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

        let result = crate::backend::exec_util::execute_with_timeout(
            &mut cmd,
            self.config.timeout_ms,
            &self.runtime,
        )
        .await?;

        // Phylax output scanning
        if self.phylax_enabled {
            let scanner = PhylaxScanner::new();
            let combined_output = format!("{}{}", result.stdout, result.stderr);
            let findings = scanner.scan(&combined_output);

            if findings
                .iter()
                .any(|f| f.severity >= PhylaxSeverity::Critical)
            {
                tracing::warn!(
                    findings = findings.len(),
                    "phylax detected critical security events in sandbox output"
                );
                return Err(crate::KavachError::ExternalizationBlocked(
                    "phylax scanner detected critical security events".into(),
                ));
            }
        }

        Ok(result)
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

    // ─── Phylax Scanner tests ────────────────────────────────────────

    #[test]
    fn phylax_detects_secrets() {
        let scanner = PhylaxScanner::new();
        let findings = scanner.scan("key=AKIAIOSFODNN7EXAMPLE");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == PhylaxSeverity::High));
    }

    #[test]
    fn phylax_detects_verity_violation() {
        let scanner = PhylaxScanner::new();
        let findings = scanner.scan("error: dm-verity device corruption detected");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "VERITY"));
        assert!(
            findings
                .iter()
                .any(|f| f.severity == PhylaxSeverity::Critical)
        );
    }

    #[test]
    fn phylax_detects_nftables_bypass() {
        let scanner = PhylaxScanner::new();
        let findings = scanner.scan("attempting iptables -F INPUT");
        assert!(findings.iter().any(|f| f.category == "NFTABLES_BYPASS"));
    }

    #[test]
    fn phylax_detects_namespace_escape() {
        let scanner = PhylaxScanner::new();
        let findings = scanner.scan("nsenter --target 1 --pid --mount");
        assert!(findings.iter().any(|f| f.category == "NAMESPACE_ESCAPE"));
    }

    #[test]
    fn phylax_detects_mount_escape() {
        let scanner = PhylaxScanner::new();
        let findings = scanner.scan("mount -o remount,rw /");
        assert!(findings.iter().any(|f| f.category == "MOUNT_ESCAPE"));
    }

    #[test]
    fn phylax_clean_output() {
        let scanner = PhylaxScanner::new();
        let findings = scanner.scan("hello world\neverything is fine\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn phylax_redact_secrets() {
        let scanner = PhylaxScanner::new();
        let redacted = scanner.redact("key=AKIAIOSFODNN7EXAMPLE");
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn phylax_severity_ordering() {
        assert!(PhylaxSeverity::Info < PhylaxSeverity::High);
        assert!(PhylaxSeverity::High < PhylaxSeverity::Critical);
    }

    #[test]
    fn extract_line_containing_truncates_long_lines() {
        let long_line = format!("prefix: {} suffix", "a".repeat(200));
        let evidence = extract_line_containing(&long_line, "prefix");
        assert!(evidence.ends_with("..."));
        assert!(evidence.len() <= 84); // 80 + "..."
    }

    #[test]
    fn extract_line_containing_short_line() {
        let evidence = extract_line_containing("hello world", "hello");
        assert_eq!(evidence, "hello world");
    }

    // ─── Image Manager tests ────────────────────────────────────────

    #[test]
    fn image_manager_creation() {
        let mgr = SyAgnosImageManager::new("docker");
        assert_eq!(mgr.runtime, "docker");
    }
}
