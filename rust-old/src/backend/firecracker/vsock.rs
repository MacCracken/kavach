//! Vsock communication — host ↔ Firecracker VM IPC over AF_VSOCK.
//!
//! Firecracker exposes vsock as a Unix domain socket on the host side.
//! The guest connects via AF_VSOCK to the assigned CID/port.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Default guest CID for Firecracker vsock.
pub const DEFAULT_GUEST_CID: u32 = 3;

/// Connection handle for host ↔ guest vsock communication.
///
/// On the host side, Firecracker proxies vsock traffic through a Unix domain
/// socket. This struct manages the UDS path and provides send/recv operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockConnection {
    /// Path to the UDS socket that Firecracker creates.
    pub uds_path: PathBuf,
    /// Guest CID (Context Identifier).
    pub guest_cid: u32,
    /// Port number for the vsock connection.
    pub port: u32,
}

impl VsockConnection {
    /// Create a new vsock connection descriptor.
    #[must_use]
    pub fn new(uds_path: PathBuf, guest_cid: u32, port: u32) -> Self {
        Self {
            uds_path,
            guest_cid,
            port,
        }
    }

    /// Create a connection from a workdir (uses default socket name).
    #[must_use]
    pub fn from_workdir(workdir: &Path, port: u32) -> Self {
        Self {
            uds_path: workdir.join("vsock.sock"),
            guest_cid: DEFAULT_GUEST_CID,
            port,
        }
    }

    /// Connect to the vsock UDS socket.
    ///
    /// Returns a tokio `UnixStream` for async read/write.
    pub async fn connect(&self) -> crate::Result<tokio::net::UnixStream> {
        tracing::debug!(
            uds = %self.uds_path.display(),
            cid = self.guest_cid,
            port = self.port,
            "connecting to vsock"
        );

        let stream = tokio::net::UnixStream::connect(&self.uds_path)
            .await
            .map_err(|e| {
                crate::KavachError::ExecFailed(format!(
                    "vsock connect {}: {e}",
                    self.uds_path.display()
                ))
            })?;

        // Firecracker vsock protocol: send "CONNECT <port>\n" to initiate
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let connect_msg = format!("CONNECT {}\n", self.port);
        let mut stream = stream;
        stream
            .write_all(connect_msg.as_bytes())
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("vsock handshake: {e}")))?;

        // Read response — Firecracker sends "OK <port>\n" on success
        let mut reader = BufReader::new(&mut stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("vsock response: {e}")))?;

        if !response.starts_with("OK") {
            return Err(crate::KavachError::ExecFailed(format!(
                "vsock connect rejected: {response}"
            )));
        }

        tracing::debug!(port = self.port, "vsock connected");
        Ok(stream)
    }

    /// Send data over an established vsock connection.
    pub async fn send(stream: &mut tokio::net::UnixStream, data: &[u8]) -> crate::Result<()> {
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(data)
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("vsock send: {e}")))?;
        Ok(())
    }

    /// Receive data from an established vsock connection.
    pub async fn recv(stream: &mut tokio::net::UnixStream, buf: &mut [u8]) -> crate::Result<usize> {
        use tokio::io::AsyncReadExt;
        let n = stream
            .read(buf)
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("vsock recv: {e}")))?;
        Ok(n)
    }

    /// Check if the UDS socket file exists.
    #[must_use]
    pub fn socket_exists(&self) -> bool {
        self.uds_path.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_connection() {
        let conn = VsockConnection::new("/tmp/vsock.sock".into(), 3, 5000);
        assert_eq!(conn.guest_cid, 3);
        assert_eq!(conn.port, 5000);
    }

    #[test]
    fn from_workdir() {
        let conn = VsockConnection::from_workdir(Path::new("/tmp/fc"), 8080);
        assert_eq!(conn.uds_path, PathBuf::from("/tmp/fc/vsock.sock"));
        assert_eq!(conn.guest_cid, DEFAULT_GUEST_CID);
        assert_eq!(conn.port, 8080);
    }

    #[test]
    fn serde_roundtrip() {
        let conn = VsockConnection::new("/tmp/vs.sock".into(), 5, 9000);
        let json = serde_json::to_string(&conn).unwrap();
        let back: VsockConnection = serde_json::from_str(&json).unwrap();
        assert_eq!(conn.guest_cid, back.guest_cid);
        assert_eq!(conn.port, back.port);
    }

    #[test]
    fn socket_exists_false_for_nonexistent() {
        let conn = VsockConnection::new("/tmp/nonexistent_vsock_test.sock".into(), 3, 5000);
        assert!(!conn.socket_exists());
    }

    #[test]
    fn default_cid() {
        assert_eq!(DEFAULT_GUEST_CID, 3);
    }
}
