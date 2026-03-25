//! Output scanning and externalization gate.
//!
//! Multi-stage scanning pipeline for sandbox output:
//! - **Secrets scanner** — AWS keys, GitHub tokens, JWTs, private keys, PII
//! - **Code scanner** — command injection, exfiltration, privilege escalation, supply chain
//! - **Data scanner** — credit cards, phone numbers, HIPAA/GDPR/PCI-DSS compliance
//!
//! All scanners feed into the externalization gate which applies verdict
//! (pass/warn/quarantine/block) based on the worst finding severity.

pub mod audit;
#[cfg(feature = "process")]
pub mod code;
#[cfg(feature = "process")]
pub mod data;
#[cfg(feature = "process")]
pub mod gate;
pub mod quarantine;
pub mod runtime;
#[cfg(feature = "process")]
pub mod secrets;
#[cfg(feature = "process")]
pub mod threat;
pub mod types;

#[cfg(feature = "process")]
pub use code::CodeScanner;
#[cfg(feature = "process")]
pub use data::DataScanner;
#[cfg(feature = "process")]
pub use gate::ExternalizationGate;
pub use types::{ExternalizationPolicy, ScanFinding, ScanResult, ScanVerdict, Severity};
