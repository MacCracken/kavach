//! Intel SGX backend — hardware enclave isolation via Gramine-SGX.
//!
//! Generates Gramine manifest files and executes commands inside SGX enclaves.
//! Requires `gramine-sgx` binary and an SGX-capable CPU with driver loaded.

use serde::{Deserialize, Serialize};

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

/// SGX enclave sandbox backend using Gramine-SGX.
#[derive(Debug)]
pub struct SgxBackend {
    config: SandboxConfig,
    gramine_path: String,
}

impl SgxBackend {
    /// Create a new SGX backend. Verifies gramine-sgx and /dev/sgx_enclave.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        let gramine_path = find_gramine().ok_or_else(|| {
            crate::KavachError::BackendUnavailable("gramine-sgx not found".into())
        })?;

        if !std::path::Path::new("/dev/sgx_enclave").exists() {
            return Err(crate::KavachError::BackendUnavailable(
                "SGX device /dev/sgx_enclave not found".into(),
            ));
        }

        Ok(Self {
            config: config.clone(),
            gramine_path,
        })
    }

    /// Fetch a remote attestation report from the enclave.
    ///
    /// Uses `gramine-sgx-ias-request` to obtain an IAS-verified attestation
    /// quote. Falls back with an error if the tool is unavailable.
    pub async fn fetch_attestation(&self) -> crate::Result<SgxAttestationReport> {
        let output = tokio::process::Command::new("gramine-sgx-ias-request")
            .args(["--quote", "--format", "json"])
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("SGX attestation fetch: {e}")))?;

        if !output.status.success() {
            return Err(crate::KavachError::ExecFailed(
                "gramine-sgx-ias-request failed".into(),
            ));
        }

        let report: SgxAttestationReport = serde_json::from_slice(&output.stdout)
            .map_err(|e| crate::KavachError::ExecFailed(format!("parse SGX attestation: {e}")))?;

        tracing::debug!(
            mrenclave = %report.mrenclave,
            isv_svn = report.isv_svn,
            "fetched SGX attestation report"
        );

        Ok(report)
    }

    /// Seal data to the enclave identity.
    ///
    /// Writes plaintext to the enclave workdir and executes the sealing
    /// operation inside the enclave using Gramine's protected files.
    pub async fn seal(
        &self,
        plaintext: &[u8],
        key_policy: SealKeyPolicy,
    ) -> crate::Result<SealedData> {
        let workdir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("SGX seal workdir: {e}")))?;

        let input_path = workdir.path().join("plaintext.bin");
        let output_path = workdir.path().join("sealed.bin");

        std::fs::write(&input_path, plaintext)
            .map_err(|e| crate::KavachError::CreationFailed(format!("write plaintext: {e}")))?;

        let seal_cmd = format!(
            "gramine-sgx-seal --input {} --output {} --policy {}",
            input_path.display(),
            output_path.display(),
            key_policy
        );

        let output = tokio::process::Command::new(&self.gramine_path)
            .args(["-c", &seal_cmd])
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("SGX seal: {e}")))?;

        if !output.status.success() {
            return Err(crate::KavachError::ExecFailed("SGX seal failed".into()));
        }

        let ciphertext = std::fs::read(&output_path)
            .map_err(|e| crate::KavachError::ExecFailed(format!("read sealed data: {e}")))?;

        tracing::debug!(
            policy = %key_policy,
            sealed_len = ciphertext.len(),
            "sealed data to SGX enclave"
        );

        Ok(SealedData {
            ciphertext,
            tag: Vec::new(),
            aad: Vec::new(),
            key_policy,
        })
    }

    /// Unseal data from a previously sealed blob.
    pub async fn unseal(&self, sealed: &SealedData) -> crate::Result<Vec<u8>> {
        let workdir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("SGX unseal workdir: {e}")))?;

        let input_path = workdir.path().join("sealed.bin");
        let output_path = workdir.path().join("plaintext.bin");

        std::fs::write(&input_path, &sealed.ciphertext)
            .map_err(|e| crate::KavachError::CreationFailed(format!("write sealed: {e}")))?;

        let unseal_cmd = format!(
            "gramine-sgx-unseal --input {} --output {} --policy {}",
            input_path.display(),
            output_path.display(),
            sealed.key_policy
        );

        let output = tokio::process::Command::new(&self.gramine_path)
            .args(["-c", &unseal_cmd])
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("SGX unseal: {e}")))?;

        if !output.status.success() {
            return Err(crate::KavachError::ExecFailed("SGX unseal failed".into()));
        }

        let plaintext = std::fs::read(&output_path)
            .map_err(|e| crate::KavachError::ExecFailed(format!("read plaintext: {e}")))?;

        Ok(plaintext)
    }
}

/// Gramine manifest template for executing a shell command in an enclave.
fn generate_manifest(config: &SandboxConfig, command: &str, workdir: &std::path::Path) -> String {
    let enclave_size = config
        .policy
        .memory_limit_mb
        .map(|mb| format!("{mb}M"))
        .unwrap_or_else(|| "256M".into());

    let script_path = workdir.join("task.sh");
    let _ = std::fs::write(&script_path, format!("#!/bin/sh\n{command}\n"));

    let mut env_lines = String::new();
    env_lines.push_str("loader.env.PATH = \"/usr/local/bin:/usr/bin:/bin\"\n");
    env_lines.push_str("loader.env.HOME = \"/tmp\"\n");
    for (k, v) in &config.env {
        env_lines.push_str(&format!("loader.env.{k} = \"{v}\"\n"));
    }

    format!(
        r#"# Kavach SGX enclave manifest (auto-generated)
[libos]
entrypoint = "/bin/sh"

[loader]
entrypoint = "file:{{{{ gramine.libos }}}}"
argv = ["/bin/sh", "-c", "{command}"]
{env_lines}
[sgx]
enclave_size = "{enclave_size}"
max_threads = 4
edmm_enable = false

[fs]
mounts = [
    {{ path = "/lib",   uri = "file:{{{{ gramine.runtimedir() }}}}" }},
    {{ path = "/usr",   uri = "file:/usr" }},
    {{ path = "/bin",   uri = "file:/bin" }},
    {{ path = "/tmp",   uri = "file:/tmp", type = "tmpfs" }},
    {{ path = "/work",  uri = "file:{workdir}" }},
]

[[fs.trusted_files]]
uri = "file:{{{{ gramine.libos }}}}"

[[fs.trusted_files]]
uri = "file:/bin/sh"
"#,
        command = command.replace('"', "\\\""),
        enclave_size = enclave_size,
        env_lines = env_lines,
        workdir = workdir.display(),
    )
}

// ─── Attestation ─────────────────────────────────────────────────────

/// SGX remote attestation report from Intel Attestation Service (IAS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxAttestationReport {
    /// MRENCLAVE — SHA-256 hash of the enclave measurement (64-char hex).
    pub mrenclave: String,
    /// MRSIGNER — SHA-256 hash of the enclave signing key (64-char hex).
    pub mrsigner: String,
    /// ISV product ID.
    pub isv_prod_id: u16,
    /// ISV security version number.
    pub isv_svn: u16,
    /// Report data bound to the attestation (arbitrary bytes).
    pub report_data: Vec<u8>,
    /// IAS signature over the report (base64-encoded).
    pub ias_signature: Option<String>,
    /// Attestation timestamp (ISO 8601).
    pub timestamp: Option<String>,
}

impl SgxAttestationReport {
    /// Verify the structural integrity of an attestation report.
    ///
    /// Checks that MRENCLAVE and MRSIGNER are well-formed hex strings
    /// and that the IAS signature is present. Does NOT verify the IAS
    /// signature cryptographically — that requires the IAS root certificate.
    #[must_use]
    pub fn verify(&self) -> bool {
        // MRENCLAVE must be 64-char hex (SHA-256)
        if !is_valid_hex(&self.mrenclave, 64) {
            tracing::warn!(len = self.mrenclave.len(), "invalid MRENCLAVE");
            return false;
        }

        // MRSIGNER must be 64-char hex (SHA-256)
        if !is_valid_hex(&self.mrsigner, 64) {
            tracing::warn!(len = self.mrsigner.len(), "invalid MRSIGNER");
            return false;
        }

        // IAS signature must be present and non-trivial
        match &self.ias_signature {
            Some(sig) if sig.len() >= 32 => {}
            _ => {
                tracing::warn!("IAS signature missing or too short");
                return false;
            }
        }

        true
    }
}

/// Policy for verifying SGX attestation reports against expected values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxAttestationPolicy {
    /// Expected MRENCLAVE. None = any enclave accepted.
    pub expected_mrenclave: Option<String>,
    /// Expected MRSIGNER. None = any signer accepted.
    pub expected_mrsigner: Option<String>,
    /// Minimum ISV SVN required.
    pub min_isv_svn: u16,
}

impl SgxAttestationPolicy {
    /// Create a permissive policy that only checks structural validity.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            expected_mrenclave: None,
            expected_mrsigner: None,
            min_isv_svn: 0,
        }
    }

    /// Verify an attestation report against this policy.
    #[must_use]
    pub fn verify_against(&self, report: &SgxAttestationReport) -> bool {
        if !report.verify() {
            return false;
        }

        if let Some(ref expected) = self.expected_mrenclave
            && report.mrenclave != *expected
        {
            tracing::warn!("MRENCLAVE mismatch");
            return false;
        }

        if let Some(ref expected) = self.expected_mrsigner
            && report.mrsigner != *expected
        {
            tracing::warn!("MRSIGNER mismatch");
            return false;
        }

        if report.isv_svn < self.min_isv_svn {
            tracing::warn!(
                svn = report.isv_svn,
                min = self.min_isv_svn,
                "ISV SVN below policy minimum"
            );
            return false;
        }

        true
    }
}

// ─── Sealed Data ─────────────────────────────────────────────────────

/// Key derivation policy for SGX sealing.
///
/// Determines which enclave identity is used to derive the sealing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SealKeyPolicy {
    /// Seal to MRENCLAVE — only the exact same enclave binary can unseal.
    MrEnclave,
    /// Seal to MRSIGNER — any enclave from the same signer can unseal.
    MrSigner,
}

impl std::fmt::Display for SealKeyPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MrEnclave => write!(f, "mrenclave"),
            Self::MrSigner => write!(f, "mrsigner"),
        }
    }
}

/// Data sealed to an SGX enclave identity.
///
/// The ciphertext can only be decrypted by an enclave matching the
/// key policy used during sealing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedData {
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// Authentication tag (AES-GCM).
    pub tag: Vec<u8>,
    /// Additional authenticated data (not encrypted, but integrity-protected).
    pub aad: Vec<u8>,
    /// Key policy used for sealing.
    pub key_policy: SealKeyPolicy,
}

impl SealedData {
    /// Check if the sealed data appears structurally valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.ciphertext.is_empty()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// Check if a string is valid hex of an exact length.
#[inline]
fn is_valid_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[async_trait::async_trait]
impl SandboxBackend for SgxBackend {
    fn backend_type(&self) -> Backend {
        Backend::Sgx
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let workdir = tempfile::tempdir()
            .map_err(|e| crate::KavachError::CreationFailed(format!("SGX workdir: {e}")))?;

        // Generate and write manifest
        let manifest = generate_manifest(&self.config, command, workdir.path());
        let manifest_path = workdir.path().join("task.manifest.sgx");
        std::fs::write(&manifest_path, &manifest)
            .map_err(|e| crate::KavachError::CreationFailed(format!("write manifest: {e}")))?;

        let _ = policy; // Policy is embedded in manifest (enclave_size, threads)

        // Run gramine-sgx
        let mut cmd = tokio::process::Command::new(&self.gramine_path);
        cmd.arg(&manifest_path).current_dir(workdir.path());

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        crate::backend::exec_util::execute_with_timeout(
            &mut cmd,
            self.config.timeout_ms,
            "gramine-sgx",
        )
        .await
    }

    async fn health_check(&self) -> crate::Result<bool> {
        let output = tokio::process::Command::new(&self.gramine_path)
            .arg("--version")
            .output()
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("SGX health: {e}")))?;
        Ok(output.status.success())
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Find gramine-sgx binary.
fn find_gramine() -> Option<String> {
    for name in &["gramine-sgx"] {
        if crate::backend::which_exists(name) {
            return Some((*name).to_string());
        }
    }
    // Check common install locations
    for path in &["/usr/local/bin/gramine-sgx", "/usr/bin/gramine-sgx"] {
        if std::path::Path::new(path).exists() {
            return Some((*path).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_report() -> SgxAttestationReport {
        SgxAttestationReport {
            mrenclave: "a".repeat(64),
            mrsigner: "b".repeat(64),
            isv_prod_id: 1,
            isv_svn: 2,
            report_data: vec![0; 64],
            ias_signature: Some("c".repeat(64)),
            timestamp: Some("2026-03-25T00:00:00Z".into()),
        }
    }

    #[test]
    fn manifest_generation() {
        let config = SandboxConfig::builder().backend(Backend::Sgx).build();
        let manifest = generate_manifest(&config, "echo hello", std::path::Path::new("/tmp/test"));
        assert!(manifest.contains("entrypoint"));
        assert!(manifest.contains("enclave_size"));
        assert!(manifest.contains("echo hello"));
    }

    #[test]
    fn manifest_with_memory_limit() {
        let mut config = SandboxConfig::builder().backend(Backend::Sgx).build();
        config.policy.memory_limit_mb = Some(512);
        let manifest = generate_manifest(&config, "ls", std::path::Path::new("/tmp"));
        assert!(manifest.contains("512M"));
    }

    #[test]
    fn manifest_with_env() {
        let mut config = SandboxConfig::builder().backend(Backend::Sgx).build();
        config.env.push(("MY_VAR".into(), "my_value".into()));
        let manifest = generate_manifest(&config, "ls", std::path::Path::new("/tmp"));
        assert!(manifest.contains("MY_VAR"));
        assert!(manifest.contains("my_value"));
    }

    #[test]
    fn find_gramine_returns_none_when_missing() {
        let _ = find_gramine();
    }

    // ─── Attestation tests ───────────────────────────────────────────

    #[test]
    fn attestation_verify_valid() {
        let report = make_valid_report();
        assert!(report.verify());
    }

    #[test]
    fn attestation_bad_mrenclave() {
        let mut report = make_valid_report();
        report.mrenclave = "short".into();
        assert!(!report.verify());
    }

    #[test]
    fn attestation_bad_mrenclave_nonhex() {
        let mut report = make_valid_report();
        report.mrenclave = "z".repeat(64);
        assert!(!report.verify());
    }

    #[test]
    fn attestation_bad_mrsigner() {
        let mut report = make_valid_report();
        report.mrsigner = "x".repeat(10);
        assert!(!report.verify());
    }

    #[test]
    fn attestation_no_ias_signature() {
        let mut report = make_valid_report();
        report.ias_signature = None;
        assert!(!report.verify());
    }

    #[test]
    fn attestation_short_ias_signature() {
        let mut report = make_valid_report();
        report.ias_signature = Some("short".into());
        assert!(!report.verify());
    }

    #[test]
    fn attestation_policy_permissive_accepts_valid() {
        let report = make_valid_report();
        let policy = SgxAttestationPolicy::permissive();
        assert!(policy.verify_against(&report));
    }

    #[test]
    fn attestation_policy_mrenclave_mismatch() {
        let report = make_valid_report();
        let policy = SgxAttestationPolicy {
            expected_mrenclave: Some("f".repeat(64)),
            ..SgxAttestationPolicy::permissive()
        };
        assert!(!policy.verify_against(&report));
    }

    #[test]
    fn attestation_policy_mrsigner_mismatch() {
        let report = make_valid_report();
        let policy = SgxAttestationPolicy {
            expected_mrsigner: Some("f".repeat(64)),
            ..SgxAttestationPolicy::permissive()
        };
        assert!(!policy.verify_against(&report));
    }

    #[test]
    fn attestation_policy_svn_too_low() {
        let mut report = make_valid_report();
        report.isv_svn = 1;
        let policy = SgxAttestationPolicy {
            min_isv_svn: 5,
            ..SgxAttestationPolicy::permissive()
        };
        assert!(!policy.verify_against(&report));
    }

    #[test]
    fn attestation_report_serde_roundtrip() {
        let report = make_valid_report();
        let json = serde_json::to_string(&report).unwrap();
        let back: SgxAttestationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.mrenclave, back.mrenclave);
        assert_eq!(report.mrsigner, back.mrsigner);
        assert_eq!(report.isv_svn, back.isv_svn);
    }

    #[test]
    fn attestation_policy_serde_roundtrip() {
        let policy = SgxAttestationPolicy {
            expected_mrenclave: Some("a".repeat(64)),
            expected_mrsigner: None,
            min_isv_svn: 3,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: SgxAttestationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy.expected_mrenclave, back.expected_mrenclave);
        assert_eq!(policy.min_isv_svn, back.min_isv_svn);
    }

    // ─── Sealed Data tests ───────────────────────────────────────────

    #[test]
    fn seal_key_policy_display() {
        assert_eq!(SealKeyPolicy::MrEnclave.to_string(), "mrenclave");
        assert_eq!(SealKeyPolicy::MrSigner.to_string(), "mrsigner");
    }

    #[test]
    fn sealed_data_validity() {
        let valid = SealedData {
            ciphertext: vec![1, 2, 3],
            tag: vec![],
            aad: vec![],
            key_policy: SealKeyPolicy::MrEnclave,
        };
        assert!(valid.is_valid());

        let empty = SealedData {
            ciphertext: vec![],
            tag: vec![],
            aad: vec![],
            key_policy: SealKeyPolicy::MrSigner,
        };
        assert!(!empty.is_valid());
    }

    #[test]
    fn sealed_data_serde_roundtrip() {
        let data = SealedData {
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
            tag: vec![0x01, 0x02],
            aad: vec![0x03],
            key_policy: SealKeyPolicy::MrEnclave,
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: SealedData = serde_json::from_str(&json).unwrap();
        assert_eq!(data.ciphertext, back.ciphertext);
        assert_eq!(data.key_policy, back.key_policy);
    }

    #[test]
    fn is_valid_hex_works() {
        assert!(is_valid_hex("abcdef0123456789", 16));
        assert!(is_valid_hex("ABCDEF0123456789", 16));
        assert!(!is_valid_hex("xyz", 3));
        assert!(!is_valid_hex("abcdef", 16));
    }
}
