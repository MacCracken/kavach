//! Error types for kavach.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KavachError {
    #[error("backend not available: {0}")]
    BackendUnavailable(String),

    #[error("sandbox creation failed: {0}")]
    CreationFailed(String),

    #[error("sandbox execution failed: {0}")]
    ExecFailed(String),

    #[error("sandbox timeout after {0}ms")]
    Timeout(u64),

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("credential error: {0}")]
    CredentialError(String),

    #[error("lifecycle error: {state} -> {target}: {reason}")]
    InvalidTransition {
        state: String,
        target: String,
        reason: String,
    },

    #[error("externalization blocked: {0}")]
    ExternalizationBlocked(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_backend_unavailable() {
        let e = KavachError::BackendUnavailable("runsc not found".into());
        assert_eq!(e.to_string(), "backend not available: runsc not found");
    }

    #[test]
    fn display_creation_failed() {
        let e = KavachError::CreationFailed("OOM".into());
        assert_eq!(e.to_string(), "sandbox creation failed: OOM");
    }

    #[test]
    fn display_exec_failed() {
        let e = KavachError::ExecFailed("segfault".into());
        assert_eq!(e.to_string(), "sandbox execution failed: segfault");
    }

    #[test]
    fn display_timeout() {
        let e = KavachError::Timeout(5000);
        assert_eq!(e.to_string(), "sandbox timeout after 5000ms");
    }

    #[test]
    fn display_policy_violation() {
        let e = KavachError::PolicyViolation("blocked syscall".into());
        assert_eq!(e.to_string(), "policy violation: blocked syscall");
    }

    #[test]
    fn display_credential_error() {
        let e = KavachError::CredentialError("missing secret".into());
        assert_eq!(e.to_string(), "credential error: missing secret");
    }

    #[test]
    fn display_invalid_transition() {
        let e = KavachError::InvalidTransition {
            state: "Created".into(),
            target: "Destroyed".into(),
            reason: "must stop first".into(),
        };
        assert_eq!(
            e.to_string(),
            "lifecycle error: Created -> Destroyed: must stop first"
        );
    }

    #[test]
    fn display_externalization_blocked() {
        let e = KavachError::ExternalizationBlocked("secret detected".into());
        assert_eq!(e.to_string(), "externalization blocked: secret detected");
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: KavachError = io_err.into();
        assert!(e.to_string().contains("file missing"));
    }

    #[test]
    fn from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("something went wrong");
        let e: KavachError = anyhow_err.into();
        assert!(e.to_string().contains("something went wrong"));
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KavachError>();
    }
}
