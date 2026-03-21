//! Output scanning and externalization gate.
//!
//! Scans sandbox output for secrets, credentials, and sensitive data
//! before allowing it to leave the sandbox boundary.

pub mod gate;
pub mod secrets;
pub mod types;

pub use gate::ExternalizationGate;
pub use types::{ExternalizationPolicy, ScanFinding, ScanResult, ScanVerdict, Severity};
