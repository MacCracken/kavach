//! Shared command execution with timeout, stdout/stderr capture, and cleanup.
//!
//! Eliminates the duplicated spawn → collect → timeout → kill pattern
//! across all backends.

use crate::lifecycle::ExecResult;

/// Maximum bytes to capture per output stream (1 MiB).
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

/// Convert bytes to String, avoiding a copy when already valid UTF-8.
#[inline]
fn lossy_utf8(buf: Vec<u8>) -> String {
    String::from_utf8(buf).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Execute a pre-configured [`tokio::process::Command`] with timeout and output capture.
///
/// Handles:
/// - Piped stdout/stderr with 1 MiB cap per stream
/// - Concurrent collection via `tokio::try_join!`
/// - Timeout enforcement with child kill on expiry
/// - UTF-8 lossy conversion
///
/// The caller is responsible for configuring the command (program, args, env,
/// working directory, pre_exec hooks, etc.) before passing it here.
pub async fn execute_with_timeout(
    cmd: &mut tokio::process::Command,
    timeout_ms: u64,
    label: &str,
) -> crate::Result<ExecResult> {
    let start = std::time::Instant::now();

    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| crate::KavachError::ExecFailed(format!("{label} spawn failed: {e}")))?;

    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let collect = async {
        use tokio::io::AsyncReadExt;

        let stdout_fut = async {
            let mut buf = Vec::new();
            if let Some(out) = stdout_handle {
                out.take(MAX_OUTPUT_BYTES).read_to_end(&mut buf).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };
        let stderr_fut = async {
            let mut buf = Vec::new();
            if let Some(err) = stderr_handle {
                err.take(MAX_OUTPUT_BYTES).read_to_end(&mut buf).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };

        let (stdout_buf, stderr_buf) = tokio::try_join!(stdout_fut, stderr_fut)?;
        Ok::<_, std::io::Error>((stdout_buf, stderr_buf))
    };

    let timeout = std::time::Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, collect).await {
        Ok(Ok((stdout_buf, stderr_buf))) => {
            // I/O collected — now wait for child exit with remaining timeout budget.
            let elapsed = start.elapsed();
            let remaining = timeout.saturating_sub(elapsed);
            match tokio::time::timeout(remaining, child.wait()).await {
                Ok(Ok(status)) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    Ok(ExecResult {
                        exit_code: status.code().unwrap_or(-1),
                        stdout: lossy_utf8(stdout_buf),
                        stderr: lossy_utf8(stderr_buf),
                        duration_ms,
                        timed_out: false,
                    })
                }
                Ok(Err(e)) => Err(crate::KavachError::ExecFailed(format!("{label} wait: {e}"))),
                Err(_) => {
                    // Process hung on exit after I/O completed — kill it.
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    let duration_ms = start.elapsed().as_millis() as u64;
                    Ok(ExecResult {
                        exit_code: -1,
                        stdout: lossy_utf8(stdout_buf),
                        stderr: lossy_utf8(stderr_buf),
                        duration_ms,
                        timed_out: true,
                    })
                }
            }
        }
        Ok(Err(e)) => {
            // I/O error — kill the child to prevent zombie
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(crate::KavachError::ExecFailed(format!(
                "{label} error: {e}"
            )))
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let duration_ms = start.elapsed().as_millis() as u64;
            Ok(ExecResult {
                exit_code: -1,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms,
                timed_out: true,
            })
        }
    }
}

/// A spawned long-running process with stdout/stderr capture handles.
///
/// Unlike `execute_with_timeout`, this does not wait for completion.
/// The caller manages the lifecycle via `wait`, `kill`, and `try_wait`.
pub struct SpawnedProcess {
    child: tokio::process::Child,
    started_at: std::time::Instant,
}

impl std::fmt::Debug for SpawnedProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnedProcess")
            .field("pid", &self.child.id())
            .field(
                "elapsed_ms",
                &(self.started_at.elapsed().as_millis() as u64),
            )
            .finish()
    }
}

impl SpawnedProcess {
    /// Get the OS process ID.
    #[inline]
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Wait for the process to exit, capturing stdout/stderr.
    pub async fn wait(mut self) -> crate::Result<ExecResult> {
        let stdout_handle = self.child.stdout.take();
        let stderr_handle = self.child.stderr.take();

        use tokio::io::AsyncReadExt;

        let stdout_fut = async {
            let mut buf = Vec::new();
            if let Some(out) = stdout_handle {
                out.take(MAX_OUTPUT_BYTES).read_to_end(&mut buf).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };
        let stderr_fut = async {
            let mut buf = Vec::new();
            if let Some(err) = stderr_handle {
                err.take(MAX_OUTPUT_BYTES).read_to_end(&mut buf).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };

        let (stdout_buf, stderr_buf, status) =
            tokio::try_join!(stdout_fut, stderr_fut, self.child.wait())
                .map_err(|e| crate::KavachError::ExecFailed(format!("wait failed: {e}")))?;

        let duration_ms = self.started_at.elapsed().as_millis() as u64;

        Ok(ExecResult {
            exit_code: status.code().unwrap_or(-1),
            stdout: lossy_utf8(stdout_buf),
            stderr: lossy_utf8(stderr_buf),
            duration_ms,
            timed_out: false,
        })
    }

    /// Send SIGTERM, wait up to `grace_ms`, then SIGKILL if still alive.
    pub async fn kill(mut self, grace_ms: u64) -> crate::Result<ExecResult> {
        // Close stdout/stderr pipes before signaling. If the process is blocked
        // on a pipe write (buffer full), closing the read end unblocks it with
        // EPIPE/SIGPIPE, allowing SIGTERM to be delivered.
        drop(self.child.stdout.take());
        drop(self.child.stderr.take());

        // Send SIGTERM first.
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            // SAFETY: Sending a signal to a known-valid PID is safe. The PID
            // was obtained from `self.child.id()` which returns the OS-assigned
            // PID of the spawned child process.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill().await;
        }

        // Wait for graceful exit or force kill.
        let grace = std::time::Duration::from_millis(grace_ms);
        match tokio::time::timeout(grace, self.child.wait()).await {
            Ok(Ok(status)) => {
                let duration_ms = self.started_at.elapsed().as_millis() as u64;
                Ok(ExecResult {
                    exit_code: status.code().unwrap_or(-1),
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms,
                    timed_out: false,
                })
            }
            _ => {
                // Grace period expired — force kill.
                let _ = self.child.kill().await;
                let _ = self.child.wait().await;
                let duration_ms = self.started_at.elapsed().as_millis() as u64;
                Ok(ExecResult {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms,
                    timed_out: true,
                })
            }
        }
    }

    /// Check if the process is still running (non-blocking).
    pub fn try_wait(&mut self) -> crate::Result<Option<i32>> {
        match self.child.try_wait() {
            Ok(Some(status)) => Ok(Some(status.code().unwrap_or(-1))),
            Ok(None) => Ok(None),
            Err(e) => Err(crate::KavachError::ExecFailed(format!(
                "try_wait failed: {e}"
            ))),
        }
    }

    /// How long the process has been running.
    #[inline]
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }
}

/// Spawn a pre-configured command without waiting for completion.
///
/// Returns a [`SpawnedProcess`] that can be waited on, killed, or inspected.
pub fn spawn_process(
    cmd: &mut tokio::process::Command,
    label: &str,
) -> crate::Result<SpawnedProcess> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let child = cmd
        .spawn()
        .map_err(|e| crate::KavachError::ExecFailed(format!("{label} spawn failed: {e}")))?;

    tracing::debug!(%label, "spawned long-running process");

    Ok(SpawnedProcess {
        child,
        started_at: std::time::Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exec_echo() {
        let mut cmd = tokio::process::Command::new("echo");
        cmd.arg("hello");
        let result = execute_with_timeout(&mut cmd, 5_000, "test").await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.trim(), "hello");
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn exec_timeout() {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("10");
        let result = execute_with_timeout(&mut cmd, 100, "test").await.unwrap();
        assert!(result.timed_out);
        assert_eq!(result.exit_code, -1);
    }

    #[tokio::test]
    async fn exec_nonzero_exit() {
        let mut cmd = tokio::process::Command::new("false");
        let result = execute_with_timeout(&mut cmd, 5_000, "test").await.unwrap();
        assert_ne!(result.exit_code, 0);
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn exec_captures_stderr() {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.args(["-c", "echo err >&2"]);
        let result = execute_with_timeout(&mut cmd, 5_000, "test").await.unwrap();
        assert_eq!(result.stderr.trim(), "err");
    }

    #[tokio::test]
    async fn exec_bad_binary() {
        let mut cmd = tokio::process::Command::new("nonexistent_binary_xyz_123");
        let result = execute_with_timeout(&mut cmd, 5_000, "test").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("spawn failed"));
    }

    #[tokio::test]
    async fn spawn_and_wait() {
        let mut cmd = tokio::process::Command::new("echo");
        cmd.arg("spawned");
        let proc = spawn_process(&mut cmd, "test").unwrap();
        let result = proc.wait().await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.trim(), "spawned");
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn spawn_pid_is_some() {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("5");
        let proc = spawn_process(&mut cmd, "test").unwrap();
        assert!(proc.pid().is_some());
        // Clean up
        let _ = proc.kill(100).await;
    }

    #[tokio::test]
    async fn spawn_and_kill() {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("60");
        let proc = spawn_process(&mut cmd, "test").unwrap();
        let result = proc.kill(200).await.unwrap();
        // Process should have been terminated
        assert!(result.duration_ms < 60_000);
    }

    #[tokio::test]
    async fn spawn_try_wait_running() {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("5");
        let mut proc = spawn_process(&mut cmd, "test").unwrap();
        // Should still be running
        let status = proc.try_wait().unwrap();
        assert!(status.is_none());
        // Clean up
        let _ = proc.kill(100).await;
    }

    #[tokio::test]
    async fn spawn_try_wait_finished() {
        let mut cmd = tokio::process::Command::new("true");
        let mut proc = spawn_process(&mut cmd, "test").unwrap();
        // Give it a moment to finish
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let status = proc.try_wait().unwrap();
        assert!(status.is_some());
        assert_eq!(status.unwrap(), 0);
    }

    #[tokio::test]
    async fn spawn_elapsed_ms() {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("5");
        let proc = spawn_process(&mut cmd, "test").unwrap();
        // Should have some small elapsed time
        assert!(proc.elapsed_ms() < 1000);
        let _ = proc.kill(100).await;
    }

    #[tokio::test]
    async fn spawn_bad_binary() {
        let mut cmd = tokio::process::Command::new("nonexistent_binary_xyz_123");
        let result = spawn_process(&mut cmd, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("spawn failed"));
    }
}
