//! Backend health monitoring — periodic liveness probes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Health status of a sandbox backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Whether the backend is healthy.
    pub healthy: bool,
    /// Timestamp of the last health check.
    pub last_checked: DateTime<Utc>,
    /// Duration of the health check in milliseconds.
    pub check_duration_ms: u64,
    /// Error message if unhealthy.
    pub error: Option<String>,
}

impl HealthStatus {
    /// Create a healthy status.
    #[must_use]
    pub fn healthy(duration_ms: u64) -> Self {
        Self {
            healthy: true,
            last_checked: Utc::now(),
            check_duration_ms: duration_ms,
            error: None,
        }
    }

    /// Create an unhealthy status.
    #[must_use]
    pub fn unhealthy(duration_ms: u64, error: String) -> Self {
        Self {
            healthy: false,
            last_checked: Utc::now(),
            check_duration_ms: duration_ms,
            error: Some(error),
        }
    }
}

/// Run a health check on a backend and return the status.
pub async fn check_health(backend: &dyn super::SandboxBackend) -> HealthStatus {
    let start = std::time::Instant::now();
    match backend.health_check().await {
        Ok(true) => HealthStatus::healthy(start.elapsed().as_millis() as u64),
        Ok(false) => HealthStatus::unhealthy(
            start.elapsed().as_millis() as u64,
            "health check returned false".into(),
        ),
        Err(e) => HealthStatus::unhealthy(start.elapsed().as_millis() as u64, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_status() {
        let status = HealthStatus::healthy(42);
        assert!(status.healthy);
        assert_eq!(status.check_duration_ms, 42);
        assert!(status.error.is_none());
    }

    #[test]
    fn unhealthy_status() {
        let status = HealthStatus::unhealthy(100, "timeout".into());
        assert!(!status.healthy);
        assert_eq!(status.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn serde_roundtrip() {
        let status = HealthStatus::healthy(10);
        let json = serde_json::to_string(&status).unwrap();
        let back: HealthStatus = serde_json::from_str(&json).unwrap();
        assert!(back.healthy);
    }

    #[tokio::test]
    async fn check_noop_health() {
        let noop = crate::backend::NoopBackend;
        let status = check_health(&noop).await;
        assert!(status.healthy);
    }
}
