//! Cryptographic audit chain — append-only HMAC-SHA256 signed event log.
//!
//! Each entry links to the previous via HMAC-SHA256, forming a tamper-evident
//! chain. The chain can be verified end-to-end to detect missing or modified
//! entries. Forging an entry requires knowledge of the HMAC key.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A single entry in the audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Sequential entry number (0 = genesis).
    pub serial: u64,
    /// Event type (e.g., "sandbox_created", "exec", "scan_blocked").
    pub event_type: String,
    /// Event payload (JSON-serializable).
    pub payload: serde_json::Value,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// HMAC-SHA256 of this entry's content (hex).
    pub hmac: String,
    /// HMAC of the previous entry (hex). Empty for genesis.
    pub prev_hmac: String,
}

/// Append-only audit chain with HMAC-SHA256 integrity.
///
/// Each entry is signed with HMAC-SHA256 and links to the previous entry's
/// HMAC, forming a tamper-evident chain. Modifying any entry invalidates
/// the chain from that point forward.
pub struct AuditChain {
    log_path: PathBuf,
    hmac_key: Vec<u8>,
    last_hmac: String,
    next_serial: u64,
}

impl AuditChain {
    /// Create a new audit chain at the given file path.
    ///
    /// If the file exists, the chain is loaded and verified.
    /// If not, a genesis entry is created.
    pub fn open(log_path: impl Into<PathBuf>, hmac_key: &[u8]) -> crate::Result<Self> {
        let log_path = log_path.into();
        let hmac_key = hmac_key.to_vec();

        if log_path.exists() {
            let content = std::fs::read_to_string(&log_path)
                .map_err(|e| crate::KavachError::ExecFailed(format!("audit chain read: {e}")))?;

            let entries: Vec<AuditEntry> = content
                .lines()
                .filter(|l| !l.is_empty())
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|e| crate::KavachError::ExecFailed(format!("audit chain parse: {e}")))?;

            // Verify chain integrity
            verify_chain(&entries, &hmac_key)?;

            let last_hmac = entries.last().map(|e| e.hmac.clone()).unwrap_or_default();
            let next_serial = entries.len() as u64;

            Ok(Self {
                log_path,
                hmac_key,
                last_hmac,
                next_serial,
            })
        } else {
            let mut chain = Self {
                log_path,
                hmac_key,
                last_hmac: String::new(),
                next_serial: 0,
            };
            // Write genesis entry
            chain.record(
                "genesis",
                serde_json::json!({"message": "audit chain initialized"}),
            )?;
            Ok(chain)
        }
    }

    /// Record an event to the audit chain.
    pub fn record(
        &mut self,
        event_type: &str,
        payload: serde_json::Value,
    ) -> crate::Result<AuditEntry> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let serial = self.next_serial;

        // Compute hash over: serial + event_type + payload + timestamp + prev_hmac
        // Use sorted payload for deterministic serialization
        let payload_str = sorted_json(&payload);
        let content = format!(
            "{}:{}:{}:{}:{}",
            serial, event_type, payload_str, timestamp, self.last_hmac
        );
        let hmac = compute_hmac(&self.hmac_key, content.as_bytes());

        let entry = AuditEntry {
            serial,
            event_type: event_type.to_owned(),
            payload,
            timestamp,
            hmac: hmac.clone(),
            prev_hmac: self.last_hmac.clone(),
        };

        // Append to log file (one JSON line per entry)
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| crate::KavachError::ExecFailed(format!("audit chain write: {e}")))?;

        let line = serde_json::to_string(&entry)
            .map_err(|e| crate::KavachError::ExecFailed(format!("audit chain serialize: {e}")))?;
        writeln!(file, "{line}")
            .map_err(|e| crate::KavachError::ExecFailed(format!("audit chain append: {e}")))?;

        self.last_hmac = hmac;
        self.next_serial += 1;

        tracing::debug!(serial, event_type, "audit chain entry recorded");
        Ok(entry)
    }

    /// Number of entries in the chain.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.next_serial
    }

    /// Whether the chain is empty (no entries, not even genesis).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.next_serial == 0
    }

    /// Path to the log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.log_path
    }
}

impl std::fmt::Debug for AuditChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChain")
            .field("log_path", &self.log_path)
            .field("entries", &self.next_serial)
            .finish()
    }
}

/// Verify the integrity of an audit chain.
pub fn verify_chain(entries: &[AuditEntry], hmac_key: &[u8]) -> crate::Result<()> {
    let mut prev_hmac = String::new();

    for (i, entry) in entries.iter().enumerate() {
        if entry.serial != i as u64 {
            return Err(crate::KavachError::ExecFailed(format!(
                "audit chain serial gap: expected {i}, got {}",
                entry.serial
            )));
        }

        if entry.prev_hmac != prev_hmac {
            return Err(crate::KavachError::ExecFailed(format!(
                "audit chain broken at serial {}: prev_hmac mismatch",
                entry.serial
            )));
        }

        // Recompute HMAC
        let content = format!(
            "{}:{}:{}:{}:{}",
            entry.serial,
            entry.event_type,
            sorted_json(&entry.payload),
            entry.timestamp,
            entry.prev_hmac
        );
        let expected_hmac = compute_hmac(hmac_key, content.as_bytes());

        if entry.hmac != expected_hmac {
            return Err(crate::KavachError::ExecFailed(format!(
                "audit chain HMAC mismatch at serial {}",
                entry.serial
            )));
        }

        prev_hmac = entry.hmac.clone();
    }

    Ok(())
}

/// Serialize a JSON value with keys sorted for deterministic output.
fn sorted_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
            serde_json::to_string(&sorted).unwrap_or_default()
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Compute HMAC-SHA256 and return hex string.
fn compute_hmac(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .unwrap_or_else(|_| HmacSha256::new_from_slice(&[0]).unwrap());
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();

    // Convert to hex string
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter() {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut chain = AuditChain::open(&path, b"test-key").unwrap();
        assert_eq!(chain.len(), 1); // genesis

        chain
            .record("sandbox_created", serde_json::json!({"id": "sb-1"}))
            .unwrap();
        assert_eq!(chain.len(), 2);

        chain
            .record("exec", serde_json::json!({"cmd": "echo hello"}))
            .unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn chain_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        {
            let mut chain = AuditChain::open(&path, b"key").unwrap();
            chain
                .record("event1", serde_json::json!({"data": 1}))
                .unwrap();
            chain
                .record("event2", serde_json::json!({"data": 2}))
                .unwrap();
        }

        // Reopen — should verify and continue
        let chain = AuditChain::open(&path, b"key").unwrap();
        assert_eq!(chain.len(), 3); // genesis + 2 events
    }

    #[test]
    fn tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        {
            let mut chain = AuditChain::open(&path, b"key").unwrap();
            chain.record("event", serde_json::json!({})).unwrap();
        }

        // Tamper with the file
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("event", "tampered_event");
        std::fs::write(&path, tampered).unwrap();

        // Reopen should fail verification
        let result = AuditChain::open(&path, b"key");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        {
            let mut chain = AuditChain::open(&path, b"key-1").unwrap();
            chain.record("event", serde_json::json!({})).unwrap();
        }

        let result = AuditChain::open(&path, b"key-2");
        assert!(result.is_err());
    }

    #[test]
    fn entries_linked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut chain = AuditChain::open(&path, b"key").unwrap();
        let e1 = chain.record("a", serde_json::json!({})).unwrap();
        let e2 = chain.record("b", serde_json::json!({})).unwrap();

        // e2 should reference e1's HMAC
        assert_eq!(e2.prev_hmac, e1.hmac);
        assert_ne!(e1.hmac, e2.hmac);
    }

    #[test]
    fn debug_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let chain = AuditChain::open(&path, b"key").unwrap();
        let debug = format!("{chain:?}");
        assert!(debug.contains("AuditChain"));
    }

    #[test]
    fn verify_empty() {
        assert!(verify_chain(&[], b"key").is_ok());
    }

    #[test]
    fn audit_entry_serde() {
        let entry = AuditEntry {
            serial: 0,
            event_type: "test".into(),
            payload: serde_json::json!({}),
            timestamp: "2026-03-25T00:00:00Z".into(),
            hmac: "abc".into(),
            prev_hmac: String::new(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.serial, 0);
    }
}
