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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttestationTrust {
    /// No trust information available.
    None,
    /// Attestation passed — environment is trusted.
    Affirming,
    /// Attestation passed with warnings — environment may be degraded.
    Warning,
    /// Attestation failed — environment should not be trusted.
    Contraindicated,
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
        let mut ear_obj = Ear::default();

        // Map trust tier to EAR trust vector
        // Map our trust tier to EAR trust tier i8 values
        let tier_val: i8 = match self.trust_tier {
            AttestationTrust::Affirming => 2,        // TrustTier::Affirming
            AttestationTrust::Warning => 32,         // TrustTier::Warning
            AttestationTrust::Contraindicated => 96, // TrustTier::Contraindicated
            AttestationTrust::None => 0,             // TrustTier::None
        };

        // Set trust vector claims
        let mut tv = TrustVector::default();
        tv.instance_identity.set(tier_val);
        tv.executables.set(tier_val);

        ear_obj.submods.insert(
            self.backend.to_string(),
            ear::Appraisal {
                trust_vector: tv,
                ..Default::default()
            },
        );

        ear_obj
    }
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
        assert!(AttestationTrust::None < AttestationTrust::Affirming);
        assert!(AttestationTrust::Affirming < AttestationTrust::Warning);
        assert!(AttestationTrust::Warning < AttestationTrust::Contraindicated);
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
            measurement: "test".into(),
            signer: None,
            verified: true,
            summary: "test".into(),
            ear_token: None,
        };
        let ear = result.to_ear();
        assert!(ear.submods.contains_key("sgx"));
    }
}
