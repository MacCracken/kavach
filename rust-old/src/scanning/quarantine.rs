//! Quarantine storage — persist blocked/suspicious artifacts for review.
//!
//! Blocked sandbox outputs are stored under `<data_dir>/quarantine/<uuid>/`
//! with a metadata sidecar and the raw artifact. Supports an approval
//! workflow: quarantined → approved → released.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::types::ScanResult;

/// Quarantine entry status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QuarantineStatus {
    /// Blocked and awaiting review.
    Quarantined,
    /// Reviewed and approved for release.
    Approved,
    /// Released to the caller.
    Released,
    /// Permanently rejected.
    Rejected,
}

/// Metadata for a quarantined artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMetadata {
    /// Unique quarantine entry ID.
    pub id: Uuid,
    /// Sandbox ID that produced this artifact.
    pub sandbox_id: Option<String>,
    /// Agent ID that owns the sandbox.
    pub agent_id: Option<String>,
    /// Scan result that triggered quarantine.
    pub scan_result: ScanResult,
    /// Current status.
    pub status: QuarantineStatus,
    /// When the artifact was quarantined (ISO 8601).
    pub quarantined_at: String,
    /// Who approved the release (if approved).
    pub approved_by: Option<String>,
    /// When approved (ISO 8601).
    pub approved_at: Option<String>,
}

/// File-based quarantine storage.
///
/// Layout:
/// ```text
/// <base_dir>/
///   <uuid>/
///     metadata.json
///     artifact.bin
/// ```
#[derive(Debug)]
pub struct QuarantineStorage {
    base_dir: PathBuf,
}

impl QuarantineStorage {
    /// Create a new quarantine storage at the given directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Store an artifact in quarantine. Returns the quarantine entry ID.
    pub fn quarantine(
        &self,
        artifact: &[u8],
        scan_result: ScanResult,
        sandbox_id: Option<&str>,
        agent_id: Option<&str>,
    ) -> crate::Result<Uuid> {
        let id = Uuid::new_v4();
        let entry_dir = self.base_dir.join(id.to_string());

        std::fs::create_dir_all(&entry_dir)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine dir: {e}")))?;

        // Write artifact
        std::fs::write(entry_dir.join("artifact.bin"), artifact)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine artifact: {e}")))?;

        // Write metadata
        let metadata = QuarantineMetadata {
            id,
            sandbox_id: sandbox_id.map(Into::into),
            agent_id: agent_id.map(Into::into),
            scan_result,
            status: QuarantineStatus::Quarantined,
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            approved_by: None,
            approved_at: None,
        };

        let json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine metadata: {e}")))?;
        std::fs::write(entry_dir.join("metadata.json"), json)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine write: {e}")))?;

        tracing::debug!(%id, "artifact quarantined");
        Ok(id)
    }

    /// Read quarantine metadata for an entry.
    pub fn get(&self, id: Uuid) -> crate::Result<QuarantineMetadata> {
        let path = self.base_dir.join(id.to_string()).join("metadata.json");
        let json = std::fs::read_to_string(&path)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine read {id}: {e}")))?;
        serde_json::from_str(&json)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine parse {id}: {e}")))
    }

    /// Approve a quarantined artifact for release.
    pub fn approve(&self, id: Uuid, approved_by: &str) -> crate::Result<()> {
        let mut metadata = self.get(id)?;
        metadata.status = QuarantineStatus::Approved;
        metadata.approved_by = Some(approved_by.to_owned());
        metadata.approved_at = Some(chrono::Utc::now().to_rfc3339());
        self.write_metadata(id, &metadata)
    }

    /// Reject a quarantined artifact permanently.
    pub fn reject(&self, id: Uuid) -> crate::Result<()> {
        let mut metadata = self.get(id)?;
        metadata.status = QuarantineStatus::Rejected;
        self.write_metadata(id, &metadata)
    }

    /// List all quarantine entry IDs.
    pub fn list(&self) -> crate::Result<Vec<Uuid>> {
        let mut ids = Vec::new();
        if !self.base_dir.exists() {
            return Ok(ids);
        }
        let entries = std::fs::read_dir(&self.base_dir)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine list: {e}")))?;
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && let Ok(id) = Uuid::parse_str(name)
            {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Remove a quarantine entry from disk.
    pub fn remove(&self, id: Uuid) -> crate::Result<()> {
        let entry_dir = self.base_dir.join(id.to_string());
        if entry_dir.exists() {
            std::fs::remove_dir_all(&entry_dir).map_err(|e| {
                crate::KavachError::ExecFailed(format!("quarantine remove {id}: {e}"))
            })?;
        }
        Ok(())
    }

    /// Write metadata back to disk.
    fn write_metadata(&self, id: Uuid, metadata: &QuarantineMetadata) -> crate::Result<()> {
        let path = self.base_dir.join(id.to_string()).join("metadata.json");
        let json = serde_json::to_string_pretty(metadata)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine write: {e}")))?;
        std::fs::write(&path, json)
            .map_err(|e| crate::KavachError::ExecFailed(format!("quarantine write: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanning::types::{ScanVerdict, Severity};

    fn make_scan_result() -> ScanResult {
        ScanResult {
            verdict: ScanVerdict::Block,
            findings: vec![],
            worst_severity: Severity::Critical,
        }
    }

    #[test]
    fn quarantine_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let storage = QuarantineStorage::new(dir.path());

        let id = storage
            .quarantine(
                b"secret data",
                make_scan_result(),
                Some("sb-1"),
                Some("agent-1"),
            )
            .unwrap();

        let metadata = storage.get(id).unwrap();
        assert_eq!(metadata.status, QuarantineStatus::Quarantined);
        assert_eq!(metadata.sandbox_id.as_deref(), Some("sb-1"));
    }

    #[test]
    fn approve_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let storage = QuarantineStorage::new(dir.path());

        let id = storage
            .quarantine(b"data", make_scan_result(), None, None)
            .unwrap();
        storage.approve(id, "admin@example.com").unwrap();

        let metadata = storage.get(id).unwrap();
        assert_eq!(metadata.status, QuarantineStatus::Approved);
        assert_eq!(metadata.approved_by.as_deref(), Some("admin@example.com"));
        assert!(metadata.approved_at.is_some());
    }

    #[test]
    fn reject_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let storage = QuarantineStorage::new(dir.path());

        let id = storage
            .quarantine(b"data", make_scan_result(), None, None)
            .unwrap();
        storage.reject(id).unwrap();

        let metadata = storage.get(id).unwrap();
        assert_eq!(metadata.status, QuarantineStatus::Rejected);
    }

    #[test]
    fn list_entries() {
        let dir = tempfile::tempdir().unwrap();
        let storage = QuarantineStorage::new(dir.path());

        let id1 = storage
            .quarantine(b"a", make_scan_result(), None, None)
            .unwrap();
        let id2 = storage
            .quarantine(b"b", make_scan_result(), None, None)
            .unwrap();

        let ids = storage.list().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn remove_entry() {
        let dir = tempfile::tempdir().unwrap();
        let storage = QuarantineStorage::new(dir.path());

        let id = storage
            .quarantine(b"data", make_scan_result(), None, None)
            .unwrap();
        storage.remove(id).unwrap();

        assert!(storage.get(id).is_err());
        assert!(storage.list().unwrap().is_empty());
    }

    #[test]
    fn list_empty() {
        let dir = tempfile::tempdir().unwrap();
        let storage = QuarantineStorage::new(dir.path());
        assert!(storage.list().unwrap().is_empty());
    }

    #[test]
    fn get_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let storage = QuarantineStorage::new(dir.path());
        assert!(storage.get(Uuid::new_v4()).is_err());
    }
}
