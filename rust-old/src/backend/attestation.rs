//! Unified attestation — standardized attestation results via EAR (EAT Attestation Results).
//!
//! Provides a backend-agnostic attestation result format based on the IETF RATS
//! EAR specification (draft-ietf-rats-ear). Each confidential computing backend
//! (SGX, SEV, TDX) can produce an `AttestationResult` that consumers interpret
//! uniformly regardless of the underlying hardware.
//!
//! Requires the `attestation` feature flag.

#[cfg(feature = "attestation")]
use ear::{Ear, TrustVector};

use serde::{Deserialize, Serialize};

use super::Backend;

/// Unified attestation result for any confidential computing backend.
///
/// Abstracts over SGX/SEV/TDX-specific attestation formats into a single
/// structure that consumers can evaluate without backend-specific knowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AttestationResult {
    /// Which backend produced this attestation.
    pub backend: Backend,
    /// Overall trust tier (none/affirming/warning/contraindicated).
    pub trust_tier: AttestationTrust,
    /// Instance identity measurement (MRENCLAVE, launch measurement, etc.).
    pub measurement: String,
    /// Signer identity (MRSIGNER, ID key digest, etc.).
    pub signer: Option<String>,
    /// Whether the attestation was cryptographically verified.
    pub verified: bool,
    /// Human-readable summary.
    pub summary: String,
    /// Raw EAR token (JWT/CWT) if available.
    #[cfg(feature = "attestation")]
    pub ear_token: Option<String>,
}

/// Trust tier for attestation results.
///
/// Ordered by trust level: `Contraindicated < Warning < None < Affirming`.
/// Higher = more trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttestationTrust {
    /// Attestation failed — environment should not be trusted.
    Contraindicated,
    /// Attestation passed with warnings — environment may be degraded.
    Warning,
    /// No trust information available.
    None,
    /// Attestation passed — environment is trusted.
    Affirming,
}

impl std::fmt::Display for AttestationTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Affirming => write!(f, "affirming"),
            Self::Warning => write!(f, "warning"),
            Self::Contraindicated => write!(f, "contraindicated"),
        }
    }
}

/// Convert a backend-specific attestation into a unified result.
///
/// This is the trait that confidential computing backends implement
/// to participate in the unified attestation framework.
pub trait Attestable {
    /// Produce a unified attestation result from backend-specific evidence.
    fn to_attestation_result(&self) -> AttestationResult;
}

// ── SGX ──────────────────────────────────────────────────────────────

#[cfg(feature = "sgx")]
impl Attestable for super::sgx::SgxAttestationReport {
    fn to_attestation_result(&self) -> AttestationResult {
        let verified = self.verify();
        AttestationResult {
            backend: Backend::Sgx,
            trust_tier: if verified {
                AttestationTrust::Affirming
            } else {
                AttestationTrust::Contraindicated
            },
            measurement: self.mrenclave.clone(),
            signer: Some(self.mrsigner.clone()),
            verified,
            summary: format!("SGX enclave ISV_SVN={} verified={}", self.isv_svn, verified),
            #[cfg(feature = "attestation")]
            ear_token: None,
        }
    }
}

// ── SEV ──────────────────────────────────────────────────────────────

#[cfg(feature = "sev")]
impl Attestable for super::sev::SevAttestationReport {
    fn to_attestation_result(&self) -> AttestationResult {
        let verified = self.verify();
        AttestationResult {
            backend: Backend::Sev,
            trust_tier: if verified {
                if self.vmpl == 0 {
                    AttestationTrust::Affirming
                } else {
                    AttestationTrust::Warning
                }
            } else {
                AttestationTrust::Contraindicated
            },
            measurement: self.measurement.clone(),
            signer: Some(self.id_key_digest.clone()),
            verified,
            summary: format!(
                "SEV-SNP VMPL={} guest_svn={} verified={}",
                self.vmpl, self.guest_svn, verified
            ),
            #[cfg(feature = "attestation")]
            ear_token: None,
        }
    }
}

// ── SyAgnos TPM ──────────────────────────────────────────────────────

#[cfg(feature = "sy-agnos")]
impl Attestable for super::sy_agnos::AttestationReport {
    fn to_attestation_result(&self) -> AttestationResult {
        let verified = self.verify();
        let pcr8 = self
            .pcr_values
            .get(&8)
            .cloned()
            .unwrap_or_else(|| "missing".into());
        AttestationResult {
            backend: Backend::SyAgnos,
            trust_tier: if verified {
                AttestationTrust::Affirming
            } else {
                AttestationTrust::Contraindicated
            },
            measurement: pcr8,
            signer: None,
            verified,
            summary: format!(
                "TPM measured boot PCRs={} verified={}",
                self.pcr_values.len(),
                verified
            ),
            #[cfg(feature = "attestation")]
            ear_token: None,
        }
    }
}

// ── EAR conversion ───────────────────────────────────────────────────

#[cfg(feature = "attestation")]
impl AttestationResult {
    /// Convert this result into an EAR (EAT Attestation Results) structure.
    ///
    /// The EAR can be serialized to JWT or CBOR for interoperability with
    /// other attestation verification systems (e.g., Veraison).
    #[must_use]
    pub fn to_ear(&self) -> Ear {
        let mut ear_obj = Ear {
            profile: "tag:kavach.agnos.org,2026:ear".to_string(),
            iat: chrono::Utc::now().timestamp(),
            vid: ear::VerifierID {
                build: format!("kavach {}", env!("CARGO_PKG_VERSION")),
                developer: "AGNOS".to_string(),
            },
            ..Ear::default()
        };

        let tier_val: i8 = trust_tier_to_ear(self.trust_tier);

        let mut tv = TrustVector::default();
        tv.instance_identity.set(tier_val);
        tv.executables.set(tier_val);
        // Hardware trust based on backend type
        if matches!(self.backend, Backend::Sgx | Backend::Sev | Backend::Tdx) {
            tv.hardware.set(tier_val);
        }

        let mut appraisal = ear::Appraisal {
            trust_vector: tv,
            ..Default::default()
        };
        // Embed measurement as annotated evidence
        appraisal.annotated_evidence.insert(
            "measurement".to_string(),
            ear::RawValue::String(self.measurement.clone()),
        );
        if let Some(ref signer) = self.signer {
            appraisal
                .annotated_evidence
                .insert("signer".to_string(), ear::RawValue::String(signer.clone()));
        }

        ear_obj.submods.insert(self.backend.to_string(), appraisal);

        ear_obj
    }

    /// Sign the EAR as a JWT using a PEM-encoded private key.
    ///
    /// Returns the signed JWT string suitable for transmission to a
    /// Veraison relying party or other IETF RATS consumer.
    pub fn sign_ear_jwt(
        &self,
        alg: ear::Algorithm,
        pem_key: &[u8],
    ) -> Result<String, crate::KavachError> {
        let ear_obj = self.to_ear();
        ear_obj
            .sign_jwt_pem(alg, pem_key)
            .map_err(|e| crate::KavachError::ExecFailed(format!("EAR JWT signing failed: {e}")))
    }

    /// Sign the EAR as a COSE token using a PEM-encoded private key.
    ///
    /// Returns the signed COSE bytes suitable for constrained environments
    /// (IoT, embedded) or CBOR-native attestation verifiers.
    pub fn sign_ear_cose(
        &self,
        alg: ear::Algorithm,
        pem_key: &[u8],
    ) -> Result<Vec<u8>, crate::KavachError> {
        let ear_obj = self.to_ear();
        ear_obj
            .sign_cose_pem(alg, pem_key)
            .map_err(|e| crate::KavachError::ExecFailed(format!("EAR COSE signing failed: {e}")))
    }

    /// Verify and decode an EAR JWT token.
    ///
    /// Returns an `AttestationResult` reconstructed from the verified EAR claims.
    pub fn from_ear_jwt(
        token: &str,
        alg: ear::Algorithm,
        jwk_key: &[u8],
    ) -> Result<Ear, crate::KavachError> {
        Ear::from_jwt_jwk(token, alg, jwk_key).map_err(|e| {
            crate::KavachError::ExecFailed(format!("EAR JWT verification failed: {e}"))
        })
    }

    /// Verify and decode an EAR COSE token.
    pub fn from_ear_cose(
        token: &[u8],
        alg: ear::Algorithm,
        jwk_key: &[u8],
    ) -> Result<Ear, crate::KavachError> {
        Ear::from_cose_jwk(token, alg, jwk_key).map_err(|e| {
            crate::KavachError::ExecFailed(format!("EAR COSE verification failed: {e}"))
        })
    }
}

/// Map kavach trust tier to EAR trust tier i8 value.
#[cfg(feature = "attestation")]
#[inline]
#[must_use]
fn trust_tier_to_ear(tier: AttestationTrust) -> i8 {
    match tier {
        AttestationTrust::Affirming => 2,
        AttestationTrust::Warning => 32,
        AttestationTrust::Contraindicated => 96,
        AttestationTrust::None => 0,
    }
}

// ── Image signature verification ────────────────────────────────────

/// Result of an OCI image signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ImageVerification {
    /// Image reference (e.g. "registry.example.com/app:v1.0").
    pub image_ref: String,
    /// Whether the image signature was valid.
    pub verified: bool,
    /// Digest of the verified image manifest.
    pub digest: Option<String>,
    /// Who signed the image (certificate subject or key ID).
    pub signer_identity: Option<String>,
    /// Human-readable summary.
    pub summary: String,
}

impl ImageVerification {
    /// Create a verified result.
    #[must_use]
    pub fn verified(
        image_ref: impl Into<String>,
        digest: impl Into<String>,
        signer: impl Into<String>,
    ) -> Self {
        let image_ref = image_ref.into();
        let digest = digest.into();
        let signer = signer.into();
        Self {
            summary: format!("Image '{}' verified (signer: {})", image_ref, signer),
            image_ref,
            verified: true,
            digest: Some(digest),
            signer_identity: Some(signer),
        }
    }

    /// Create a failed verification result.
    #[must_use]
    pub fn rejected(image_ref: impl Into<String>, reason: impl Into<String>) -> Self {
        let image_ref = image_ref.into();
        let reason = reason.into();
        Self {
            summary: format!("Image '{}' REJECTED: {}", image_ref, reason),
            image_ref,
            verified: false,
            digest: None,
            signer_identity: None,
        }
    }

    /// Convert to an `AttestationResult` for unified attestation reporting.
    #[must_use]
    pub fn to_attestation_result(&self) -> AttestationResult {
        AttestationResult {
            backend: Backend::Oci,
            trust_tier: if self.verified {
                AttestationTrust::Affirming
            } else {
                AttestationTrust::Contraindicated
            },
            measurement: self.digest.clone().unwrap_or_default(),
            signer: self.signer_identity.clone(),
            verified: self.verified,
            summary: self.summary.clone(),
            #[cfg(feature = "attestation")]
            ear_token: None,
        }
    }
}

/// Policy for image signature verification.
///
/// Configures which images require signatures and which signers are trusted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ImageVerificationPolicy {
    /// Whether to enforce signature verification (reject unsigned images).
    pub enforce: bool,
    /// Trusted signer identities (key IDs or certificate subjects).
    /// Empty = accept any valid signature.
    pub trusted_signers: Vec<String>,
    /// Image reference patterns that require verification (glob-style).
    /// Empty = verify all images.
    pub required_patterns: Vec<String>,
}

impl ImageVerificationPolicy {
    /// Create a policy that enforces verification for all images.
    #[must_use]
    pub fn enforce_all() -> Self {
        Self {
            enforce: true,
            trusted_signers: Vec::new(),
            required_patterns: Vec::new(),
        }
    }

    /// Check if an image reference matches the policy's required patterns.
    #[must_use]
    pub fn requires_verification(&self, image_ref: &str) -> bool {
        if !self.enforce {
            return false;
        }
        if self.required_patterns.is_empty() {
            return true;
        }
        self.required_patterns
            .iter()
            .any(|p| pattern_matches(p, image_ref))
    }

    /// Check if a signer identity is trusted by this policy.
    #[must_use]
    pub fn is_trusted_signer(&self, signer: &str) -> bool {
        self.trusted_signers.is_empty() || self.trusted_signers.iter().any(|s| s == signer)
    }

    /// Evaluate an `ImageVerification` against this policy.
    ///
    /// Returns `Ok(())` if the image passes, or `Err` with reason if rejected.
    pub fn evaluate(&self, result: &ImageVerification) -> crate::Result<()> {
        if !self.enforce {
            return Ok(());
        }
        if !self.requires_verification(&result.image_ref) {
            return Ok(());
        }
        if !result.verified {
            return Err(crate::KavachError::ExecFailed(format!(
                "Image '{}' has no valid signature",
                result.image_ref
            )));
        }
        if let Some(ref signer) = result.signer_identity
            && !self.is_trusted_signer(signer)
        {
            return Err(crate::KavachError::ExecFailed(format!(
                "Image '{}' signed by untrusted signer: {}",
                result.image_ref, signer
            )));
        }
        Ok(())
    }
}

/// Simple glob-style pattern matching (supports `*` wildcard).
fn pattern_matches(pattern: &str, input: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return input.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return input.starts_with(prefix);
    }
    pattern == input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_trust_display() {
        assert_eq!(AttestationTrust::None.to_string(), "none");
        assert_eq!(AttestationTrust::Affirming.to_string(), "affirming");
        assert_eq!(AttestationTrust::Warning.to_string(), "warning");
        assert_eq!(
            AttestationTrust::Contraindicated.to_string(),
            "contraindicated"
        );
    }

    #[test]
    fn trust_ordering() {
        assert!(AttestationTrust::Contraindicated < AttestationTrust::Warning);
        assert!(AttestationTrust::Warning < AttestationTrust::None);
        assert!(AttestationTrust::None < AttestationTrust::Affirming);
    }

    #[test]
    fn attestation_result_serde() {
        let result = AttestationResult {
            backend: Backend::Sgx,
            trust_tier: AttestationTrust::Affirming,
            measurement: "a".repeat(64),
            signer: Some("b".repeat(64)),
            verified: true,
            summary: "test".into(),
            #[cfg(feature = "attestation")]
            ear_token: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: AttestationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trust_tier, AttestationTrust::Affirming);
        assert!(back.verified);
    }

    #[cfg(feature = "sgx")]
    #[test]
    fn sgx_attestable() {
        let report = super::super::sgx::SgxAttestationReport {
            mrenclave: "a".repeat(64),
            mrsigner: "b".repeat(64),
            isv_prod_id: 1,
            isv_svn: 2,
            report_data: vec![0; 64],
            ias_signature: Some("c".repeat(64)),
            timestamp: None,
        };
        let result = report.to_attestation_result();
        assert_eq!(result.backend, Backend::Sgx);
        assert_eq!(result.trust_tier, AttestationTrust::Affirming);
        assert!(result.verified);
    }

    #[cfg(feature = "sev")]
    #[test]
    fn sev_attestable() {
        let report = super::super::sev::SevAttestationReport {
            report_version: 2,
            guest_svn: 1,
            policy: 0x30000,
            measurement: "a".repeat(96),
            host_data: "b".repeat(64),
            id_key_digest: "c".repeat(64),
            report_id: "d".repeat(64),
            vmpl: 0,
            signature: vec![0xAB; 96],
        };
        let result = report.to_attestation_result();
        assert_eq!(result.backend, Backend::Sev);
        assert_eq!(result.trust_tier, AttestationTrust::Affirming);
    }

    #[cfg(feature = "attestation")]
    #[test]
    fn to_ear_conversion() {
        let result = AttestationResult {
            backend: Backend::Sgx,
            trust_tier: AttestationTrust::Affirming,
            measurement: "test_measurement".into(),
            signer: Some("test_signer".into()),
            verified: true,
            summary: "test".into(),
            ear_token: None,
        };
        let ear = result.to_ear();
        assert!(ear.submods.contains_key("sgx"));
        let appraisal = &ear.submods["sgx"];
        assert_eq!(
            appraisal.annotated_evidence.get("measurement"),
            Some(&ear::RawValue::String("test_measurement".into()))
        );
        assert_eq!(
            appraisal.annotated_evidence.get("signer"),
            Some(&ear::RawValue::String("test_signer".into()))
        );
        assert!(!ear.profile.is_empty());
        assert!(ear.iat > 0);
    }

    #[cfg(feature = "attestation")]
    #[test]
    fn trust_tier_ear_mapping() {
        assert_eq!(trust_tier_to_ear(AttestationTrust::Affirming), 2);
        assert_eq!(trust_tier_to_ear(AttestationTrust::Warning), 32);
        assert_eq!(trust_tier_to_ear(AttestationTrust::Contraindicated), 96);
        assert_eq!(trust_tier_to_ear(AttestationTrust::None), 0);
    }

    // -- Image verification --

    #[test]
    fn image_verified() {
        let v = ImageVerification::verified("registry/app:v1", "sha256:abc", "dev@example.com");
        assert!(v.verified);
        assert_eq!(v.digest.as_deref(), Some("sha256:abc"));
        assert!(v.summary.contains("verified"));
    }

    #[test]
    fn image_rejected() {
        let v = ImageVerification::rejected("registry/app:v1", "no signature found");
        assert!(!v.verified);
        assert!(v.summary.contains("REJECTED"));
    }

    #[test]
    fn image_to_attestation_result() {
        let v = ImageVerification::verified("registry/app:v1", "sha256:abc", "dev@example.com");
        let r = v.to_attestation_result();
        assert_eq!(r.backend, Backend::Oci);
        assert_eq!(r.trust_tier, AttestationTrust::Affirming);
        assert!(r.verified);
    }

    #[test]
    fn image_rejected_to_attestation() {
        let v = ImageVerification::rejected("registry/app:v1", "tampered");
        let r = v.to_attestation_result();
        assert_eq!(r.trust_tier, AttestationTrust::Contraindicated);
        assert!(!r.verified);
    }

    // -- Image verification policy --

    #[test]
    fn policy_enforce_all() {
        let policy = ImageVerificationPolicy::enforce_all();
        assert!(policy.requires_verification("any/image:latest"));
    }

    #[test]
    fn policy_not_enforced() {
        let policy = ImageVerificationPolicy::default();
        assert!(!policy.requires_verification("any/image:latest"));
    }

    #[test]
    fn policy_pattern_matching() {
        let policy = ImageVerificationPolicy {
            enforce: true,
            required_patterns: vec!["registry.internal/*".into()],
            ..Default::default()
        };
        assert!(policy.requires_verification("registry.internal/app:v1"));
        assert!(!policy.requires_verification("docker.io/library/alpine:latest"));
    }

    #[test]
    fn policy_trusted_signers() {
        let policy = ImageVerificationPolicy {
            enforce: true,
            trusted_signers: vec!["trusted@example.com".into()],
            ..Default::default()
        };
        assert!(policy.is_trusted_signer("trusted@example.com"));
        assert!(!policy.is_trusted_signer("random@evil.com"));
    }

    #[test]
    fn policy_evaluate_verified() {
        let policy = ImageVerificationPolicy::enforce_all();
        let v = ImageVerification::verified("app:v1", "sha256:abc", "dev@example.com");
        assert!(policy.evaluate(&v).is_ok());
    }

    #[test]
    fn policy_evaluate_rejected() {
        let policy = ImageVerificationPolicy::enforce_all();
        let v = ImageVerification::rejected("app:v1", "no signature");
        assert!(policy.evaluate(&v).is_err());
    }

    #[test]
    fn policy_evaluate_untrusted_signer() {
        let policy = ImageVerificationPolicy {
            enforce: true,
            trusted_signers: vec!["trusted@example.com".into()],
            ..Default::default()
        };
        let v = ImageVerification::verified("app:v1", "sha256:abc", "evil@example.com");
        assert!(policy.evaluate(&v).is_err());
    }

    #[test]
    fn policy_evaluate_not_enforced_passes() {
        let policy = ImageVerificationPolicy::default();
        let v = ImageVerification::rejected("app:v1", "no signature");
        assert!(policy.evaluate(&v).is_ok()); // not enforced
    }

    #[test]
    fn image_verification_serde() {
        let v = ImageVerification::verified("app:v1", "sha256:abc", "dev@example.com");
        let json = serde_json::to_string(&v).unwrap();
        let back: ImageVerification = serde_json::from_str(&json).unwrap();
        assert!(back.verified);
        assert_eq!(back.image_ref, "app:v1");
    }

    #[test]
    fn policy_serde() {
        let policy = ImageVerificationPolicy {
            enforce: true,
            trusted_signers: vec!["a@b.com".into()],
            required_patterns: vec!["registry/*".into()],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: ImageVerificationPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.enforce);
        assert_eq!(back.trusted_signers.len(), 1);
    }

    #[test]
    fn pattern_matches_star() {
        assert!(pattern_matches("*", "anything"));
    }

    #[test]
    fn pattern_matches_prefix() {
        assert!(pattern_matches("registry/*", "registry/app:v1"));
        assert!(!pattern_matches("registry/*", "docker.io/app"));
    }

    #[test]
    fn pattern_matches_suffix() {
        assert!(pattern_matches("*:latest", "app:latest"));
        assert!(!pattern_matches("*:latest", "app:v1"));
    }

    #[test]
    fn pattern_matches_exact() {
        assert!(pattern_matches("exact", "exact"));
        assert!(!pattern_matches("exact", "other"));
    }
}
