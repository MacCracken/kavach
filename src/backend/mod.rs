//! Sandbox backend trait and implementations.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::lifecycle::ExecResult;
use crate::policy::SandboxPolicy;

/// Available sandbox backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Backend {
    /// OS process with seccomp + Landlock + namespaces.
    Process,
    /// Google gVisor (runsc) — user-space kernel.
    GVisor,
    /// AWS Firecracker — lightweight microVM.
    Firecracker,
    /// WebAssembly (wasmtime) — language-level sandbox.
    Wasm,
    /// OCI container (runc/crun).
    Oci,
    /// Intel SGX enclave — hardware-level isolation.
    Sgx,
    /// AMD SEV — encrypted VM memory.
    Sev,
    /// No isolation — for testing only.
    Noop,
}

impl Backend {
    /// Whether this backend is available on the current system.
    pub fn is_available(&self) -> bool {
        match self {
            Self::Process => true, // Always available
            Self::Noop => true,
            Self::GVisor => which_exists("runsc"),
            Self::Firecracker => which_exists("firecracker"),
            Self::Wasm => cfg!(feature = "wasm"),
            Self::Oci => which_exists("runc") || which_exists("crun"),
            Self::Sgx => std::path::Path::new("/dev/sgx_enclave").exists(),
            Self::Sev => std::path::Path::new("/dev/sev").exists(),
        }
    }

    /// All known backends.
    pub fn all() -> &'static [Backend] {
        &[
            Self::Process,
            Self::GVisor,
            Self::Firecracker,
            Self::Wasm,
            Self::Oci,
            Self::Sgx,
            Self::Sev,
            Self::Noop,
        ]
    }

    /// All backends available on this system.
    pub fn available() -> Vec<Backend> {
        Self::all()
            .iter()
            .filter(|b| b.is_available())
            .copied()
            .collect()
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process => write!(f, "process"),
            Self::GVisor => write!(f, "gvisor"),
            Self::Firecracker => write!(f, "firecracker"),
            Self::Wasm => write!(f, "wasm"),
            Self::Oci => write!(f, "oci"),
            Self::Sgx => write!(f, "sgx"),
            Self::Sev => write!(f, "sev"),
            Self::Noop => write!(f, "noop"),
        }
    }
}

/// Trait that all sandbox backends implement.
#[async_trait::async_trait]
pub trait SandboxBackend: Send + Sync {
    /// Backend identifier.
    fn backend_type(&self) -> Backend;

    /// Execute a command inside the sandbox.
    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult>;

    /// Check if the sandbox is healthy.
    async fn health_check(&self) -> crate::Result<bool>;

    /// Destroy the sandbox and release resources.
    async fn destroy(&self) -> crate::Result<()>;
}

fn which_exists(name: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if std::path::Path::new(dir).join(name).exists() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_always_available() {
        assert!(Backend::Process.is_available());
        assert!(Backend::Noop.is_available());
    }

    #[test]
    fn available_includes_process() {
        let avail = Backend::available();
        assert!(avail.contains(&Backend::Process));
    }

    #[test]
    fn display() {
        assert_eq!(Backend::Process.to_string(), "process");
        assert_eq!(Backend::GVisor.to_string(), "gvisor");
        assert_eq!(Backend::Firecracker.to_string(), "firecracker");
        assert_eq!(Backend::Wasm.to_string(), "wasm");
    }

    #[test]
    fn all_backends_count() {
        assert_eq!(Backend::all().len(), 8);
    }

    #[test]
    fn serde_roundtrip() {
        for b in Backend::all() {
            let json = serde_json::to_string(b).unwrap();
            let back: Backend = serde_json::from_str(&json).unwrap();
            assert_eq!(*b, back);
        }
    }
}
