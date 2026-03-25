//! Output scanning and externalization gate.
//!
//! Scans sandbox output for secrets, credentials, and sensitive data
//! before allowing it to leave the sandbox boundary.

#[cfg(feature = "process")]
pub mod gate;
#[cfg(feature = "process")]
pub mod secrets;
pub mod types;

#[cfg(feature = "process")]
pub use gate::ExternalizationGate;
pub use types::{ExternalizationPolicy, ScanFinding, ScanResult, ScanVerdict, Severity};
