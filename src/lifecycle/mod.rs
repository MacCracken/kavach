//! Sandbox lifecycle — create, start, exec, checkpoint, migrate, destroy.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::backend::{Backend, SandboxBackend};
use crate::credential::SecretRef;
use crate::policy::SandboxPolicy;
use crate::scanning::ExternalizationPolicy;

/// Unique sandbox identifier.
pub type SandboxId = Uuid;

/// Sandbox lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxState {
    /// Created but not yet started.
    Created,
    /// Running and accepting exec calls.
    Running,
    /// Paused (checkpointed).
    Paused,
    /// Stopped — no further execution possible.
    Stopped,
    /// Destroyed — resources released.
    Destroyed,
}

impl SandboxState {
    pub fn valid_transition(&self, to: &SandboxState) -> bool {
        matches!(
            (self, to),
            (Self::Created, Self::Running)
                | (Self::Running, Self::Paused)
                | (Self::Running, Self::Stopped)
                | (Self::Running, Self::Destroyed)
                | (Self::Paused, Self::Running)
                | (Self::Paused, Self::Stopped)
                | (Self::Paused, Self::Destroyed)
                | (Self::Stopped, Self::Destroyed)
        )
    }
}

impl fmt::Display for SandboxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Running => write!(f, "running"),
            Self::Paused => write!(f, "paused"),
            Self::Stopped => write!(f, "stopped"),
            Self::Destroyed => write!(f, "destroyed"),
        }
    }
}

/// Configuration for creating a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Backend to use.
    pub backend: Backend,
    /// Security policy.
    pub policy: SandboxPolicy,
    /// Secrets to inject.
    pub secrets: Vec<SecretRef>,
    /// Timeout for exec calls in milliseconds.
    pub timeout_ms: u64,
    /// Working directory inside the sandbox.
    pub workdir: Option<String>,
    /// Environment variables.
    pub env: Vec<(String, String)>,
    /// Agent ID that owns this sandbox.
    pub agent_id: Option<String>,
    /// Externalization policy for output scanning.
    pub externalization: Option<ExternalizationPolicy>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            backend: Backend::Process,
            policy: SandboxPolicy::basic(),
            secrets: Vec::new(),
            timeout_ms: 30_000,
            workdir: None,
            env: Vec::new(),
            agent_id: None,
            externalization: None,
        }
    }
}

impl SandboxConfig {
    pub fn builder() -> SandboxConfigBuilder {
        SandboxConfigBuilder::default()
    }
}

/// Builder for SandboxConfig.
#[derive(Debug, Default)]
pub struct SandboxConfigBuilder {
    config: SandboxConfig,
}

impl SandboxConfigBuilder {
    pub fn backend(mut self, backend: Backend) -> Self {
        self.config.backend = backend;
        self
    }

    pub fn policy(mut self, policy: SandboxPolicy) -> Self {
        self.config.policy = policy;
        self
    }

    pub fn policy_seccomp(mut self, profile: &str) -> Self {
        self.config.policy.seccomp_enabled = true;
        self.config.policy.seccomp_profile = Some(profile.into());
        self
    }

    pub fn network(mut self, enabled: bool) -> Self {
        self.config.policy.network.enabled = enabled;
        self
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.config.timeout_ms = ms;
        self
    }

    pub fn agent_id(mut self, id: impl Into<String>) -> Self {
        self.config.agent_id = Some(id.into());
        self
    }

    pub fn externalization(mut self, policy: ExternalizationPolicy) -> Self {
        self.config.externalization = Some(policy);
        self
    }

    pub fn build(self) -> SandboxConfig {
        self.config
    }
}

/// Result of executing a command inside a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the execution was killed due to timeout.
    pub timed_out: bool,
}

/// A sandbox instance with lifecycle management.
pub struct Sandbox {
    pub id: SandboxId,
    pub config: SandboxConfig,
    pub state: SandboxState,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub stopped_at: Option<DateTime<Utc>>,
    backend: Box<dyn SandboxBackend>,
}

impl fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sandbox")
            .field("id", &self.id)
            .field("config", &self.config)
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .field("started_at", &self.started_at)
            .field("stopped_at", &self.stopped_at)
            .field("backend", &self.config.backend.to_string())
            .finish()
    }
}

impl Sandbox {
    /// Create a new sandbox (does not start it).
    pub async fn create(config: SandboxConfig) -> crate::Result<Self> {
        if !config.backend.is_available() {
            return Err(crate::KavachError::BackendUnavailable(
                config.backend.to_string(),
            ));
        }

        let backend = crate::backend::create_backend(&config)?;

        Ok(Self {
            id: Uuid::new_v4(),
            config,
            state: SandboxState::Created,
            created_at: Utc::now(),
            started_at: None,
            stopped_at: None,
            backend,
        })
    }

    /// Transition to a new state.
    pub fn transition(&mut self, to: SandboxState) -> crate::Result<()> {
        if !self.state.valid_transition(&to) {
            return Err(crate::KavachError::InvalidTransition {
                state: self.state.to_string(),
                target: to.to_string(),
                reason: "invalid state transition".into(),
            });
        }
        tracing::debug!(sandbox_id = %self.id, from = %self.state, to = %to, "sandbox state transition");
        self.state = to;
        match to {
            SandboxState::Running => self.started_at = Some(Utc::now()),
            SandboxState::Stopped | SandboxState::Destroyed => self.stopped_at = Some(Utc::now()),
            _ => {}
        }
        Ok(())
    }

    /// Execute a command — delegates to the backend, then applies externalization gate.
    pub async fn exec(&self, command: &str) -> crate::Result<ExecResult> {
        if self.state != SandboxState::Running {
            return Err(crate::KavachError::ExecFailed(format!(
                "sandbox is {}, not running",
                self.state
            )));
        }

        let result = self.backend.exec(command, &self.config.policy).await?;

        // Apply externalization gate if configured (requires process feature for regex scanning)
        #[cfg(feature = "process")]
        if let Some(ref ext_policy) = self.config.externalization {
            let gate = crate::scanning::ExternalizationGate::new();
            return gate.apply(result, ext_policy);
        }

        Ok(result)
    }

    /// Spawn a long-running command in the sandbox.
    ///
    /// Unlike `exec`, this returns immediately with a handle to the running process.
    /// The caller is responsible for managing the process lifecycle.
    pub async fn spawn(
        &self,
        command: &str,
    ) -> crate::Result<crate::backend::exec_util::SpawnedProcess> {
        if self.state != SandboxState::Running {
            return Err(crate::KavachError::ExecFailed(format!(
                "sandbox is {}, not running",
                self.state
            )));
        }

        self.backend
            .spawn(command, &self.config.policy)
            .await?
            .ok_or_else(|| crate::KavachError::ExecFailed("backend does not support spawn".into()))
    }

    /// Destroy the sandbox and release backend resources.
    pub async fn destroy(mut self) -> crate::Result<()> {
        self.backend.destroy().await?;
        self.transition(SandboxState::Destroyed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions() {
        assert!(SandboxState::Created.valid_transition(&SandboxState::Running));
        assert!(SandboxState::Running.valid_transition(&SandboxState::Stopped));
        assert!(SandboxState::Running.valid_transition(&SandboxState::Paused));
        assert!(SandboxState::Paused.valid_transition(&SandboxState::Running));
        assert!(!SandboxState::Destroyed.valid_transition(&SandboxState::Running));
        assert!(!SandboxState::Created.valid_transition(&SandboxState::Stopped));
    }

    #[test]
    fn config_builder() {
        let config = SandboxConfig::builder()
            .backend(Backend::GVisor)
            .policy_seccomp("strict")
            .network(false)
            .timeout_ms(60_000)
            .agent_id("agent-123")
            .build();

        assert_eq!(config.backend, Backend::GVisor);
        assert!(config.policy.seccomp_enabled);
        assert!(!config.policy.network.enabled);
        assert_eq!(config.timeout_ms, 60_000);
        assert_eq!(config.agent_id.unwrap(), "agent-123");
    }

    #[test]
    fn config_default() {
        let config = SandboxConfig::default();
        assert_eq!(config.backend, Backend::Process);
        assert!(config.policy.seccomp_enabled); // basic() enables seccomp
        assert_eq!(config.timeout_ms, 30_000);
    }

    #[tokio::test]
    async fn create_sandbox() {
        let config = SandboxConfig::builder().backend(Backend::Noop).build();
        let sandbox = Sandbox::create(config).await.unwrap();
        assert_eq!(sandbox.state, SandboxState::Created);
    }

    #[tokio::test]
    async fn sandbox_lifecycle() {
        let config = SandboxConfig::builder().backend(Backend::Noop).build();
        let mut sandbox = Sandbox::create(config).await.unwrap();

        sandbox.transition(SandboxState::Running).unwrap();
        assert!(sandbox.started_at.is_some());

        sandbox.transition(SandboxState::Stopped).unwrap();
        assert!(sandbox.stopped_at.is_some());

        sandbox.transition(SandboxState::Destroyed).unwrap();
        assert_eq!(sandbox.state, SandboxState::Destroyed);
    }

    #[tokio::test]
    async fn exec_requires_running() {
        let config = SandboxConfig::builder().backend(Backend::Noop).build();
        let sandbox = Sandbox::create(config).await.unwrap();
        // Not started yet
        assert!(sandbox.exec("echo hello").await.is_err());
    }

    #[test]
    fn state_display() {
        assert_eq!(SandboxState::Running.to_string(), "running");
        assert_eq!(SandboxState::Destroyed.to_string(), "destroyed");
    }

    #[test]
    fn exec_result_serde() {
        let result = ExecResult {
            exit_code: 0,
            stdout: "hello".into(),
            stderr: String::new(),
            duration_ms: 42,
            timed_out: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ExecResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.exit_code, 0);
        assert_eq!(back.duration_ms, 42);
    }
}
