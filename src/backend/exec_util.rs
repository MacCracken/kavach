//! Shared command execution with timeout, stdout/stderr capture, and cleanup.
//!
//! Eliminates the duplicated spawn → collect → timeout → kill pattern
//! across all backends.

use crate::lifecycle::ExecResult;

/// Maximum bytes to capture per output stream (1 MiB).
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

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

        let (stdout_buf, stderr_buf, status) =
            tokio::try_join!(stdout_fut, stderr_fut, child.wait())?;
        Ok::<_, std::io::Error>((status, stdout_buf, stderr_buf))
    };

    let timeout = std::time::Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, collect).await {
        Ok(Ok((status, stdout_buf, stderr_buf))) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            Ok(ExecResult {
                exit_code: status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
                stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
                duration_ms,
                timed_out: false,
            })
        }
        Ok(Err(e)) => Err(crate::KavachError::ExecFailed(format!(
            "{label} error: {e}"
        ))),
        Err(_) => {
            let _ = child.kill().await;
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
}
