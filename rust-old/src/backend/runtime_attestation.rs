//! Runtime binary attestation — verify backend executables before trusting them.
//!
//! Before kavach delegates sandbox isolation to an external binary (runc, runsc,
//! firecracker, gramine-sgx, etc.), this module can verify the binary's SHA-256
//! hash against a trusted manifest.  If the hash doesn't match, the binary is
//! rejected and the backend reports as unavailable.
//!
//! Consumers (e.g. stiva) supply known-good hashes — typically derived from
//! dm-verity root hashes or signed build artifacts.
//!
//! # Example
//!
//! ```rust,no_run
//! use kavach::backend::runtime_attestation::{RuntimeManifest, BinaryEntry};
//!
//! let mut manifest = RuntimeManifest::new();
//! manifest.add(BinaryEntry::new(
//!     "runc",
//!     "a1b2c3d4e5f6...64-hex-chars...",
//! ));
//!
//! // Returns Ok(VerifyResult) — trusted if hash matches the on-disk binary.
//! let result = manifest.verify("runc", "/usr/bin/runc");
//! ```

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// A trusted manifest of known-good runtime binary hashes.
///
/// Consumers register expected SHA-256 hashes for each backend binary.
/// Before execution, kavach verifies the on-disk binary matches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeManifest {
    entries: HashMap<String, BinaryEntry>,
}

/// A single trusted binary entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BinaryEntry {
    /// Binary name (e.g. "runc", "runsc", "firecracker").
    pub name: String,
    /// Expected SHA-256 hex digest (64 lowercase hex chars).
    pub expected_sha256: String,
    /// Optional version string for logging.
    pub version: Option<String>,
}

impl BinaryEntry {
    /// Create a new entry with a name and expected SHA-256 hash.
    #[must_use]
    pub fn new(name: impl Into<String>, expected_sha256: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expected_sha256: expected_sha256.into(),
            version: None,
        }
    }

    /// Set the version string.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}

/// Result of a binary verification check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VerifyResult {
    /// Binary name.
    pub name: String,
    /// Path that was checked.
    pub path: String,
    /// Whether the hash matched.
    pub trusted: bool,
    /// Actual SHA-256 of the on-disk binary.
    pub actual_sha256: String,
    /// Expected SHA-256 from the manifest.
    pub expected_sha256: String,
}

impl fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.trusted {
            write!(f, "{} ({}): trusted", self.name, self.path)
        } else {
            write!(
                f,
                "{} ({}): UNTRUSTED (expected {}, got {})",
                self.name,
                self.path,
                &self.expected_sha256[..16],
                &self.actual_sha256[..16.min(self.actual_sha256.len())]
            )
        }
    }
}

impl RuntimeManifest {
    /// Create an empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted binary entry.
    pub fn add(&mut self, entry: BinaryEntry) {
        debug!(binary = %entry.name, "Registered trusted binary hash");
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Check if a binary name is in the manifest.
    #[inline]
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Number of entries in the manifest.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the manifest is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verify a binary at the given path against the manifest.
    ///
    /// Returns `Ok(VerifyResult)` with `trusted: true` if the hash matches,
    /// or `trusted: false` if it doesn't.  Returns `Err` if the binary
    /// is not in the manifest or can't be read.
    pub fn verify(&self, name: &str, path: impl AsRef<Path>) -> crate::Result<VerifyResult> {
        let path = path.as_ref();

        let entry = self.entries.get(name).ok_or_else(|| {
            crate::KavachError::ExecFailed(format!("binary '{}' not in attestation manifest", name))
        })?;

        let actual = sha256_file(path)?;
        let trusted = actual == entry.expected_sha256;

        if trusted {
            info!(
                binary = name,
                path = %path.display(),
                "Runtime binary attestation passed"
            );
        } else {
            warn!(
                binary = name,
                path = %path.display(),
                expected = %entry.expected_sha256,
                actual = %actual,
                "Runtime binary attestation FAILED"
            );
        }

        Ok(VerifyResult {
            name: name.to_string(),
            path: path.display().to_string(),
            trusted,
            actual_sha256: actual,
            expected_sha256: entry.expected_sha256.clone(),
        })
    }

    /// Resolve a binary name to its PATH location and verify it.
    ///
    /// Searches `$PATH` for the binary, then verifies its hash.
    /// Returns `None` if the binary isn't found in PATH.
    pub fn resolve_and_verify(&self, name: &str) -> Option<VerifyResult> {
        let path = resolve_binary_path(name)?;
        match self.verify(name, &path) {
            Ok(result) => Some(result),
            Err(e) => {
                warn!(binary = name, error = %e, "Failed to verify runtime binary");
                None
            }
        }
    }

    /// Verify all binaries in the manifest.
    ///
    /// Returns a list of results for each binary found in PATH.
    /// Binaries not found in PATH are skipped.
    #[must_use]
    pub fn verify_all(&self) -> Vec<VerifyResult> {
        self.entries
            .keys()
            .filter_map(|name| self.resolve_and_verify(name))
            .collect()
    }
}

/// Compute SHA-256 of a file and return lowercase hex string.
fn sha256_file(path: &Path) -> crate::Result<String> {
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(path).map_err(|e| {
        crate::KavachError::ExecFailed(format!("cannot read {}: {}", path.display(), e))
    })?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|e| {
            crate::KavachError::ExecFailed(format!("read error {}: {}", path.display(), e))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let hash = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in hash.iter() {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Resolve a binary name to its full path via `$PATH`.
#[must_use]
fn resolve_binary_path(name: &str) -> Option<String> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        let full = std::path::Path::new(dir).join(name);
        if full.exists() {
            return Some(full.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_manifest() {
        let m = RuntimeManifest::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
        assert!(!m.contains("runc"));
    }

    #[test]
    fn add_and_contains() {
        let mut m = RuntimeManifest::new();
        m.add(BinaryEntry::new("runc", "a".repeat(64)));
        assert!(m.contains("runc"));
        assert!(!m.contains("crun"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn verify_self_binary() {
        // Verify the current test binary against its own hash.
        let exe = std::env::current_exe().unwrap();
        let hash = sha256_file(&exe).unwrap();
        assert_eq!(hash.len(), 64);

        let mut m = RuntimeManifest::new();
        m.add(BinaryEntry::new("test-bin", &hash));

        let result = m.verify("test-bin", &exe).unwrap();
        assert!(result.trusted);
        assert_eq!(result.actual_sha256, hash);
    }

    #[test]
    fn verify_mismatch() {
        let exe = std::env::current_exe().unwrap();
        let mut m = RuntimeManifest::new();
        m.add(BinaryEntry::new("test-bin", "0".repeat(64)));

        let result = m.verify("test-bin", &exe).unwrap();
        assert!(!result.trusted);
        assert_ne!(result.actual_sha256, "0".repeat(64));
    }

    #[test]
    fn verify_not_in_manifest() {
        let m = RuntimeManifest::new();
        assert!(m.verify("missing", "/bin/true").is_err());
    }

    #[test]
    fn verify_nonexistent_file() {
        let mut m = RuntimeManifest::new();
        m.add(BinaryEntry::new("ghost", "a".repeat(64)));
        assert!(m.verify("ghost", "/nonexistent/path").is_err());
    }

    #[test]
    fn binary_entry_with_version() {
        let e = BinaryEntry::new("runc", "a".repeat(64)).with_version("1.1.12");
        assert_eq!(e.version.as_deref(), Some("1.1.12"));
    }

    #[test]
    fn verify_result_display_trusted() {
        let r = VerifyResult {
            name: "runc".into(),
            path: "/usr/bin/runc".into(),
            trusted: true,
            actual_sha256: "a".repeat(64),
            expected_sha256: "a".repeat(64),
        };
        assert!(r.to_string().contains("trusted"));
    }

    #[test]
    fn verify_result_display_untrusted() {
        let r = VerifyResult {
            name: "runc".into(),
            path: "/usr/bin/runc".into(),
            trusted: false,
            actual_sha256: "b".repeat(64),
            expected_sha256: "a".repeat(64),
        };
        assert!(r.to_string().contains("UNTRUSTED"));
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let mut m = RuntimeManifest::new();
        m.add(BinaryEntry::new("runc", "a".repeat(64)).with_version("1.1.12"));
        m.add(BinaryEntry::new("runsc", "b".repeat(64)));

        let json = serde_json::to_string(&m).unwrap();
        let back: RuntimeManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.contains("runc"));
        assert!(back.contains("runsc"));
    }

    #[test]
    fn sha256_file_consistent() {
        let exe = std::env::current_exe().unwrap();
        let h1 = sha256_file(&exe).unwrap();
        let h2 = sha256_file(&exe).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn resolve_and_verify_missing_binary() {
        let mut m = RuntimeManifest::new();
        m.add(BinaryEntry::new("nonexistent_xyz_789", "a".repeat(64)));
        assert!(m.resolve_and_verify("nonexistent_xyz_789").is_none());
    }

    #[test]
    fn verify_all_empty() {
        let m = RuntimeManifest::new();
        assert!(m.verify_all().is_empty());
    }
}
