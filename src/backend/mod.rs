//! Sandbox backend trait and implementations.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

pub mod capabilities;
pub mod exec_util;
#[cfg(feature = "firecracker")]
pub mod firecracker;
#[cfg(feature = "gvisor")]
pub mod gvisor;
pub mod health;
pub mod metrics;
#[cfg(feature = "oci")]
pub mod oci;
#[cfg(any(feature = "gvisor", feature = "oci"))]
pub mod oci_spec;
#[cfg(all(feature = "process", target_os = "linux"))]
pub mod process;
#[cfg(feature = "sev")]
pub mod sev;
#[cfg(feature = "sgx")]
pub mod sgx;
#[cfg(feature = "sy-agnos")]
pub mod sy_agnos;
#[cfg(feature = "wasm")]
pub mod wasm;

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
    /// Intel TDX — Trust Domain Extensions (full-VM encryption).
    Tdx,
    /// Hardened AGNOS OS image — OS-level sandbox (strength 80–88).
    SyAgnos,
    /// No isolation — for testing only.
    Noop,
}

impl Backend {
    /// Whether this backend is available on the current system.
    #[must_use]
    pub fn is_available(&self) -> bool {
        match self {
            Self::Process => cfg!(all(feature = "process", target_os = "linux")),
            Self::Noop => true,
            Self::GVisor => which_exists("runsc"),
            Self::Firecracker => which_exists("firecracker"),
            Self::Wasm => cfg!(feature = "wasm"),
            Self::Oci => which_exists("runc") || which_exists("crun"),
            Self::Sgx => std::path::Path::new("/dev/sgx_enclave").exists(),
            Self::Sev => std::path::Path::new("/dev/sev").exists(),
            Self::Tdx => std::path::Path::new("/dev/tdx_guest").exists(),
            Self::SyAgnos => which_exists("docker") || which_exists("podman"),
        }
    }

    /// All known backends.
    #[must_use]
    pub fn all() -> &'static [Backend] {
        &[
            Self::Process,
            Self::GVisor,
            Self::Firecracker,
            Self::Wasm,
            Self::Oci,
            Self::Sgx,
            Self::Sev,
            Self::Tdx,
            Self::SyAgnos,
            Self::Noop,
        ]
    }

    /// All backends available on this system.
    #[must_use]
    pub fn available() -> Vec<Backend> {
        Self::all()
            .iter()
            .filter(|b| b.is_available())
            .copied()
            .collect()
    }
}

impl std::str::FromStr for Backend {
    type Err = String;

    /// Parse a backend name (case-insensitive).
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "process" => Ok(Self::Process),
            "gvisor" => Ok(Self::GVisor),
            "firecracker" => Ok(Self::Firecracker),
            "wasm" => Ok(Self::Wasm),
            "oci" => Ok(Self::Oci),
            "sgx" => Ok(Self::Sgx),
            "sev" => Ok(Self::Sev),
            "tdx" => Ok(Self::Tdx),
            "sy-agnos" | "syagnos" => Ok(Self::SyAgnos),
            "noop" => Ok(Self::Noop),
            other => Err(format!("unknown backend: {other}")),
        }
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
            Self::Tdx => write!(f, "tdx"),
            Self::SyAgnos => write!(f, "sy-agnos"),
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

    /// Spawn a long-running command without waiting for completion.
    ///
    /// Returns `None` if the backend does not support spawning.
    async fn spawn(
        &self,
        _command: &str,
        _policy: &SandboxPolicy,
    ) -> crate::Result<Option<exec_util::SpawnedProcess>> {
        Ok(None)
    }

    /// Destroy the sandbox and release resources.
    async fn destroy(&self) -> crate::Result<()>;
}

/// No-op backend — no isolation, for testing only.
#[derive(Debug)]
pub struct NoopBackend;

#[async_trait::async_trait]
impl SandboxBackend for NoopBackend {
    fn backend_type(&self) -> Backend {
        Backend::Noop
    }

    async fn exec(&self, _command: &str, _policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        Ok(ExecResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
            timed_out: false,
        })
    }

    async fn health_check(&self) -> crate::Result<bool> {
        Ok(true)
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Create a backend instance from configuration.
pub fn create_backend(config: &SandboxConfig) -> crate::Result<Box<dyn SandboxBackend>> {
    match config.backend {
        Backend::Noop => Ok(Box::new(NoopBackend)),
        #[cfg(all(feature = "process", target_os = "linux"))]
        Backend::Process => Ok(Box::new(process::ProcessBackend::new(config)?)),
        #[cfg(not(all(feature = "process", target_os = "linux")))]
        Backend::Process => Err(crate::KavachError::BackendUnavailable(
            "process backend requires Linux with the 'process' feature".into(),
        )),
        #[cfg(feature = "gvisor")]
        Backend::GVisor => Ok(Box::new(gvisor::GVisorBackend::new(config)?)),
        #[cfg(feature = "firecracker")]
        Backend::Firecracker => Ok(Box::new(firecracker::FirecrackerBackend::new(config)?)),
        #[cfg(feature = "oci")]
        Backend::Oci => Ok(Box::new(oci::OciBackend::new(config)?)),
        #[cfg(feature = "wasm")]
        Backend::Wasm => Ok(Box::new(wasm::WasmBackend::new(config)?)),
        #[cfg(feature = "sgx")]
        Backend::Sgx => Ok(Box::new(sgx::SgxBackend::new(config)?)),
        #[cfg(feature = "sev")]
        Backend::Sev => Ok(Box::new(sev::SevBackend::new(config)?)),
        #[cfg(feature = "sy-agnos")]
        Backend::SyAgnos => Ok(Box::new(sy_agnos::SyAgnosBackend::new(config)?)),
        #[allow(unreachable_patterns)]
        _ => Err(crate::KavachError::BackendUnavailable(
            config.backend.to_string(),
        )),
    }
}

/// Find the first available binary from a list of candidates.
/// Returns the name of the first binary found in PATH.
#[cfg(any(feature = "oci", feature = "sy-agnos"))]
pub(crate) fn which_first<'a>(names: &[&'a str]) -> Option<&'a str> {
    names.iter().copied().find(|n| which_exists(n))
}

pub(crate) fn which_exists(name: &str) -> bool {
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
    fn noop_always_available() {
        assert!(Backend::Noop.is_available());
    }

    #[cfg(all(feature = "process", target_os = "linux"))]
    #[test]
    fn process_available_on_linux() {
        assert!(Backend::Process.is_available());
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
        assert_eq!(Backend::all().len(), 10);
    }

    #[test]
    fn serde_roundtrip() {
        for b in Backend::all() {
            let json = serde_json::to_string(b).unwrap();
            let back: Backend = serde_json::from_str(&json).unwrap();
            assert_eq!(*b, back);
        }
    }

    #[tokio::test]
    async fn noop_backend_exec() {
        let noop = NoopBackend;
        let policy = SandboxPolicy::minimal();
        let result = noop.exec("anything", &policy).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty());
    }

    #[tokio::test]
    async fn noop_backend_health() {
        let noop = NoopBackend;
        assert!(noop.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn create_backend_noop() {
        let config = SandboxConfig::builder().backend(Backend::Noop).build();
        let backend = create_backend(&config).unwrap();
        assert_eq!(backend.backend_type(), Backend::Noop);
    }

    #[test]
    fn display_all_backends() {
        let displays: Vec<String> = Backend::all().iter().map(|b| b.to_string()).collect();
        assert!(displays.contains(&"process".to_string()));
        assert!(displays.contains(&"gvisor".to_string()));
        assert!(displays.contains(&"firecracker".to_string()));
        assert!(displays.contains(&"wasm".to_string()));
        assert!(displays.contains(&"oci".to_string()));
        assert!(displays.contains(&"sgx".to_string()));
        assert!(displays.contains(&"sev".to_string()));
        assert!(displays.contains(&"sy-agnos".to_string()));
        assert!(displays.contains(&"noop".to_string()));
    }

    #[test]
    fn which_exists_finds_common_binary() {
        assert!(which_exists("sh") || which_exists("bash"));
    }

    #[test]
    fn which_exists_missing_binary() {
        assert!(!which_exists("nonexistent_binary_xyz_123_kavach"));
    }

    #[tokio::test]
    async fn noop_backend_destroy() {
        let noop = NoopBackend;
        noop.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn noop_backend_spawn_returns_none() {
        let noop = NoopBackend;
        let policy = SandboxPolicy::minimal();
        let result = noop.spawn("anything", &policy).await.unwrap();
        assert!(result.is_none(), "NoopBackend::spawn should return None");
    }

    #[test]
    fn from_str_all_backends() {
        assert_eq!("process".parse::<Backend>().unwrap(), Backend::Process);
        assert_eq!("gvisor".parse::<Backend>().unwrap(), Backend::GVisor);
        assert_eq!(
            "firecracker".parse::<Backend>().unwrap(),
            Backend::Firecracker
        );
        assert_eq!("wasm".parse::<Backend>().unwrap(), Backend::Wasm);
        assert_eq!("oci".parse::<Backend>().unwrap(), Backend::Oci);
        assert_eq!("sgx".parse::<Backend>().unwrap(), Backend::Sgx);
        assert_eq!("sev".parse::<Backend>().unwrap(), Backend::Sev);
        assert_eq!("sy-agnos".parse::<Backend>().unwrap(), Backend::SyAgnos);
        assert_eq!("syagnos".parse::<Backend>().unwrap(), Backend::SyAgnos);
        assert_eq!("noop".parse::<Backend>().unwrap(), Backend::Noop);
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!("Process".parse::<Backend>().unwrap(), Backend::Process);
        assert_eq!("GVISOR".parse::<Backend>().unwrap(), Backend::GVisor);
        assert_eq!("Noop".parse::<Backend>().unwrap(), Backend::Noop);
    }

    #[test]
    fn from_str_unknown() {
        let err = "unknown".parse::<Backend>().unwrap_err();
        assert!(err.contains("unknown backend"));
    }

    #[test]
    fn create_backend_unavailable() {
        // Try a backend that's unlikely to be available
        let config = SandboxConfig::builder().backend(Backend::Sgx).build();
        if !Backend::Sgx.is_available() {
            let result = create_backend(&config);
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.to_string().contains("not available") || err.to_string().contains("not found")
            );
        }
    }
}
