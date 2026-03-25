//! Snapshot and restore — checkpoint/migrate Firecracker microVMs.
//!
//! Firecracker supports full and diff snapshots via its API. Since kavach
//! uses `--no-api` mode, snapshots require switching to API mode or using
//! the snapshot action in the config file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Snapshot type for Firecracker VMs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SnapshotType {
    /// Full snapshot — captures all VM state and memory.
    Full,
    /// Differential snapshot — captures only changed pages since last snapshot.
    Diff,
}

impl std::fmt::Display for SnapshotType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Diff => write!(f, "diff"),
        }
    }
}

/// Configuration for creating or restoring a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Path to the snapshot state file.
    pub snapshot_path: PathBuf,
    /// Path to the memory backing file.
    pub mem_file_path: PathBuf,
    /// Snapshot type (full or diff).
    pub snapshot_type: SnapshotType,
    /// VM version string (for compatibility checking).
    pub version: Option<String>,
}

impl SnapshotConfig {
    /// Create a snapshot config for a full snapshot in the given directory.
    #[must_use]
    pub fn full_in(dir: &Path) -> Self {
        Self {
            snapshot_path: dir.join("snapshot.bin"),
            mem_file_path: dir.join("mem.bin"),
            snapshot_type: SnapshotType::Full,
            version: None,
        }
    }

    /// Create a snapshot config for a diff snapshot in the given directory.
    #[must_use]
    pub fn diff_in(dir: &Path) -> Self {
        Self {
            snapshot_path: dir.join("snapshot_diff.bin"),
            mem_file_path: dir.join("mem_diff.bin"),
            snapshot_type: SnapshotType::Diff,
            version: None,
        }
    }

    /// Check if snapshot files exist on disk.
    #[must_use]
    pub fn files_exist(&self) -> bool {
        self.snapshot_path.exists() && self.mem_file_path.exists()
    }

    /// Generate the Firecracker API-compatible snapshot create request body.
    #[must_use]
    pub fn to_create_request(&self) -> serde_json::Value {
        serde_json::json!({
            "snapshot_type": self.snapshot_type.to_string(),
            "snapshot_path": self.snapshot_path.to_string_lossy(),
            "mem_file_path": self.mem_file_path.to_string_lossy(),
        })
    }

    /// Generate the Firecracker API-compatible snapshot load request body.
    #[must_use]
    pub fn to_load_request(&self) -> serde_json::Value {
        serde_json::json!({
            "snapshot_path": self.snapshot_path.to_string_lossy(),
            "mem_backend": {
                "backend_type": "File",
                "backend_path": self.mem_file_path.to_string_lossy(),
            },
        })
    }

    /// Estimate the snapshot size from file sizes on disk.
    pub fn estimated_size_bytes(&self) -> std::io::Result<u64> {
        let snap = std::fs::metadata(&self.snapshot_path)?.len();
        let mem = std::fs::metadata(&self.mem_file_path)?.len();
        Ok(snap + mem)
    }
}

/// Create a snapshot of a running Firecracker VM via its API socket.
///
/// Requires the VM to be in API mode (not `--no-api`).
pub async fn checkpoint(api_socket: &Path, config: &SnapshotConfig) -> crate::Result<()> {
    tracing::debug!(
        snapshot_type = %config.snapshot_type,
        path = %config.snapshot_path.display(),
        "creating VM snapshot"
    );

    let body = config.to_create_request();
    let body_str = serde_json::to_string(&body)
        .map_err(|e| crate::KavachError::CreationFailed(format!("snapshot json: {e}")))?;

    // Use curl to PUT to the Firecracker API socket
    let output = tokio::process::Command::new("curl")
        .args([
            "--unix-socket",
            &api_socket.to_string_lossy(),
            "-X",
            "PUT",
            "http://localhost/snapshot/create",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body_str,
        ])
        .output()
        .await
        .map_err(|e| crate::KavachError::ExecFailed(format!("snapshot checkpoint: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::KavachError::ExecFailed(format!(
            "snapshot checkpoint failed: {stderr}"
        )));
    }

    tracing::debug!("snapshot created successfully");
    Ok(())
}

/// Restore a Firecracker VM from a snapshot via its API socket.
pub async fn restore(api_socket: &Path, config: &SnapshotConfig) -> crate::Result<()> {
    if !config.files_exist() {
        return Err(crate::KavachError::ExecFailed(format!(
            "snapshot files not found: {} / {}",
            config.snapshot_path.display(),
            config.mem_file_path.display()
        )));
    }

    tracing::debug!(
        path = %config.snapshot_path.display(),
        "restoring VM from snapshot"
    );

    let body = config.to_load_request();
    let body_str = serde_json::to_string(&body)
        .map_err(|e| crate::KavachError::CreationFailed(format!("snapshot json: {e}")))?;

    let output = tokio::process::Command::new("curl")
        .args([
            "--unix-socket",
            &api_socket.to_string_lossy(),
            "-X",
            "PUT",
            "http://localhost/snapshot/load",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body_str,
        ])
        .output()
        .await
        .map_err(|e| crate::KavachError::ExecFailed(format!("snapshot restore: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::KavachError::ExecFailed(format!(
            "snapshot restore failed: {stderr}"
        )));
    }

    tracing::debug!("VM restored from snapshot");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_snapshot_config() {
        let config = SnapshotConfig::full_in(Path::new("/tmp/snap"));
        assert_eq!(config.snapshot_type, SnapshotType::Full);
        assert_eq!(
            config.snapshot_path,
            PathBuf::from("/tmp/snap/snapshot.bin")
        );
        assert_eq!(config.mem_file_path, PathBuf::from("/tmp/snap/mem.bin"));
    }

    #[test]
    fn diff_snapshot_config() {
        let config = SnapshotConfig::diff_in(Path::new("/tmp/snap"));
        assert_eq!(config.snapshot_type, SnapshotType::Diff);
    }

    #[test]
    fn snapshot_type_display() {
        assert_eq!(SnapshotType::Full.to_string(), "full");
        assert_eq!(SnapshotType::Diff.to_string(), "diff");
    }

    #[test]
    fn files_exist_false() {
        let config = SnapshotConfig::full_in(Path::new("/tmp/nonexistent_snap"));
        assert!(!config.files_exist());
    }

    #[test]
    fn create_request_json() {
        let config = SnapshotConfig::full_in(Path::new("/tmp/snap"));
        let req = config.to_create_request();
        assert_eq!(req["snapshot_type"], "full");
        assert!(
            req["snapshot_path"]
                .as_str()
                .unwrap()
                .contains("snapshot.bin")
        );
    }

    #[test]
    fn load_request_json() {
        let config = SnapshotConfig::full_in(Path::new("/tmp/snap"));
        let req = config.to_load_request();
        assert!(
            req["snapshot_path"]
                .as_str()
                .unwrap()
                .contains("snapshot.bin")
        );
        assert!(req["mem_backend"]["backend_type"].as_str().unwrap() == "File");
    }

    #[test]
    fn serde_roundtrip() {
        let config = SnapshotConfig::full_in(Path::new("/tmp/snap"));
        let json = serde_json::to_string(&config).unwrap();
        let back: SnapshotConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.snapshot_type, back.snapshot_type);
        assert_eq!(config.snapshot_path, back.snapshot_path);
    }
}
