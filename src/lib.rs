//! # Kavach — Sandbox Execution Framework
//!
//! Kavach (कवच, Sanskrit: armor/shield) provides a unified sandbox abstraction
//! for executing untrusted code across multiple isolation backends. Extracted
//! from [SecureYeoman](https://github.com/MacCracken/SecureYeoman)'s production
//! sandbox framework.
//!
//! ## Modules
//!
//! - [`backend`] — Sandbox backend trait and implementations (process, gVisor, Firecracker, WASM, OCI, SGX, SEV)
//! - [`scoring`] — Quantitative security strength scoring (0–100)
//! - [`policy`] — Seccomp profiles, Landlock rules, network allowlists, resource limits
//! - [`credential`] — Secrets injection without exposing to sandboxed processes
//! - [`lifecycle`] — Create, start, checkpoint, migrate, destroy with audit hooks
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use kavach::{Sandbox, SandboxConfig, Backend};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = SandboxConfig::builder()
//!     .backend(Backend::Process)
//!     .policy_seccomp("basic")
//!     .network(false)
//!     .build();
//!
//! let sandbox = Sandbox::create(config).await?;
//! let result = sandbox.exec("echo hello").await?;
//! println!("exit: {}, stdout: {}", result.exit_code, result.stdout);
//! sandbox.destroy().await?;
//! # Ok(())
//! # }
//! ```

pub mod backend;
pub mod credential;
pub mod lifecycle;
pub mod policy;
pub mod scanning;
pub mod scoring;

mod error;
pub use error::KavachError;

pub use backend::exec_util::SpawnedProcess;
pub use backend::health::HealthStatus;
pub use backend::metrics::SandboxMetrics;
pub use backend::{Backend, SandboxBackend};
pub use credential::{CredentialProxy, FileInjection, SecretRef};
pub use lifecycle::{ExecResult, Sandbox, SandboxConfig, SandboxState};
pub use policy::{LandlockRule, NetworkPolicy, SandboxPolicy, SeccompProfile};
pub use scanning::{ExternalizationGate, ExternalizationPolicy, ScanVerdict, Severity};
pub use scoring::{StrengthScore, score_backend};

/// Result type alias for kavach operations.
pub type Result<T> = std::result::Result<T, KavachError>;

#[cfg(test)]
mod tests;
