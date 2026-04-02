//! Runtime sandbox modules — monitoring, credential proxy, egress gate,
//! capability-based security (v2), and WASM runtime integration.
//!
//! These modules provide the runtime-specific sandbox infrastructure
//! absorbed from the AGNOS agent-runtime monolith.

pub mod credential_proxy;
pub mod egress_gate;
pub mod monitor;
pub mod v2;
pub mod wasm_runtime;

pub use credential_proxy::{CredentialProxyConfig, CredentialProxyManager, ProxyDecision};
pub use egress_gate::{ExternalizationGate, ExternalizationGateConfig, GateDecision};
pub use monitor::{MonitorConfig, OffenderTracker, SandboxMonitor};
pub use v2::{
    CapabilityToken, EnvironmentProfile, SandboxBackend as SandboxBackendV2, SandboxCapability,
    SandboxEnvironment,
};
