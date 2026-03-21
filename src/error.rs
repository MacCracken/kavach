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
