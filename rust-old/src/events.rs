//! Sandbox event bus — pub/sub for lifecycle, policy, and attestation events.
//!
//! Bridges kavach sandbox operations with majra's [`TypedPubSub`] for
//! topic-based event distribution with MQTT-style wildcard subscriptions.
//!
//! Requires the `events` feature flag.
//!
//! # Topic hierarchy
//!
//! ```text
//! sandbox/{id}/lifecycle/created
//! sandbox/{id}/lifecycle/started
//! sandbox/{id}/lifecycle/paused
//! sandbox/{id}/lifecycle/stopped
//! sandbox/{id}/lifecycle/destroyed
//! sandbox/{id}/policy/violation
//! sandbox/{id}/policy/blocked
//! sandbox/{id}/attestation/passed
//! sandbox/{id}/attestation/failed
//! sandbox/{id}/scan/blocked
//! sandbox/{id}/scan/warning
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use kavach::events::{SandboxEventBus, SandboxEvent, EventKind};
//!
//! let bus = SandboxEventBus::new();
//!
//! // Subscribe to all lifecycle events across all sandboxes
//! let mut rx = bus.subscribe("sandbox/*/lifecycle/#");
//!
//! // Emit an event
//! bus.emit("sandbox-42", EventKind::Created, serde_json::json!({"backend": "process"}));
//! ```

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;

/// A sandbox lifecycle/security event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SandboxEvent {
    /// Sandbox identifier.
    pub sandbox_id: String,
    /// Event classification.
    pub kind: EventKind,
    /// Structured event details.
    pub details: serde_json::Value,
}

/// Classification of sandbox events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EventKind {
    // Lifecycle
    Created,
    Started,
    Paused,
    Stopped,
    Destroyed,

    // Policy
    PolicyViolation,
    PolicyBlocked,

    // Attestation
    AttestationPassed,
    AttestationFailed,

    // Scanning
    ScanBlocked,
    ScanWarning,
}

impl EventKind {
    /// Topic segment for this event kind.
    #[must_use]
    fn topic_segment(&self) -> &'static str {
        match self {
            Self::Created => "lifecycle/created",
            Self::Started => "lifecycle/started",
            Self::Paused => "lifecycle/paused",
            Self::Stopped => "lifecycle/stopped",
            Self::Destroyed => "lifecycle/destroyed",
            Self::PolicyViolation => "policy/violation",
            Self::PolicyBlocked => "policy/blocked",
            Self::AttestationPassed => "attestation/passed",
            Self::AttestationFailed => "attestation/failed",
            Self::ScanBlocked => "scan/blocked",
            Self::ScanWarning => "scan/warning",
        }
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.topic_segment())
    }
}

/// Sandbox event bus backed by majra's typed pub/sub.
///
/// Provides topic-based event distribution with MQTT-style wildcard
/// subscriptions (`*` = one segment, `#` = zero or more trailing segments).
#[derive(Clone)]
pub struct SandboxEventBus {
    inner: Arc<majra::pubsub::TypedPubSub<SandboxEvent>>,
}

impl SandboxEventBus {
    /// Create a new event bus with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(majra::pubsub::TypedPubSub::new()),
        }
    }

    /// Create with custom configuration (channel capacity, replay, etc.).
    #[must_use]
    pub fn with_config(config: majra::pubsub::TypedPubSubConfig) -> Self {
        Self {
            inner: Arc::new(majra::pubsub::TypedPubSub::with_config(config)),
        }
    }

    /// Publish a sandbox event.
    ///
    /// The topic is automatically constructed as `sandbox/{sandbox_id}/{kind}`.
    /// Returns the number of subscribers the message was delivered to.
    pub fn emit(&self, sandbox_id: &str, kind: EventKind, details: serde_json::Value) -> usize {
        let topic = format!("sandbox/{}/{}", sandbox_id, kind.topic_segment());
        debug!(
            sandbox_id = sandbox_id,
            kind = %kind,
            "Sandbox event emitted"
        );
        self.inner.publish(
            &topic,
            SandboxEvent {
                sandbox_id: sandbox_id.to_string(),
                kind,
                details,
            },
        )
    }

    /// Subscribe to events matching a topic pattern.
    ///
    /// Patterns use MQTT-style wildcards:
    /// - `sandbox/*/lifecycle/#` — all lifecycle events for all sandboxes
    /// - `sandbox/my-id/#` — all events for a specific sandbox
    /// - `sandbox/*/policy/violation` — policy violations across all sandboxes
    pub fn subscribe(
        &self,
        pattern: &str,
    ) -> tokio::sync::broadcast::Receiver<majra::pubsub::TypedMessage<SandboxEvent>> {
        self.inner.subscribe(pattern)
    }

    /// Subscribe with a predicate filter.
    ///
    /// Only events where `filter(&event)` returns `true` are delivered.
    pub fn subscribe_filtered(
        &self,
        pattern: &str,
        filter: impl Fn(&SandboxEvent) -> bool + Send + Sync + 'static,
    ) -> tokio::sync::broadcast::Receiver<majra::pubsub::TypedMessage<SandboxEvent>> {
        self.inner.subscribe_filtered(pattern, filter)
    }

    /// Subscribe to all events for a specific sandbox.
    pub fn subscribe_sandbox(
        &self,
        sandbox_id: &str,
    ) -> tokio::sync::broadcast::Receiver<majra::pubsub::TypedMessage<SandboxEvent>> {
        self.inner.subscribe(&format!("sandbox/{sandbox_id}/#"))
    }

    /// Subscribe to lifecycle events only for a specific sandbox.
    pub fn subscribe_lifecycle(
        &self,
        sandbox_id: &str,
    ) -> tokio::sync::broadcast::Receiver<majra::pubsub::TypedMessage<SandboxEvent>> {
        self.inner
            .subscribe(&format!("sandbox/{sandbox_id}/lifecycle/#"))
    }

    /// Unsubscribe all subscribers matching a pattern.
    pub fn unsubscribe_all(&self, pattern: &str) {
        self.inner.unsubscribe_all(pattern);
    }

    /// Remove dead subscribers. Returns count removed.
    pub fn cleanup(&self) -> usize {
        self.inner.cleanup_dead_subscribers()
    }

    /// Total messages published.
    #[must_use]
    pub fn messages_published(&self) -> u64 {
        self.inner.messages_published()
    }

    /// Total messages dropped (backpressure).
    #[must_use]
    pub fn messages_dropped(&self) -> u64 {
        self.inner.messages_dropped()
    }

    /// Current subscriber count.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.inner.subscriber_count()
    }

    /// Access the underlying majra pub/sub instance.
    #[must_use]
    pub fn inner(&self) -> &majra::pubsub::TypedPubSub<SandboxEvent> {
        &self.inner
    }

    /// Create a tenant-scoped view of the event bus.
    ///
    /// All topics are automatically prefixed with the tenant namespace,
    /// isolating events between different sandbox owners.
    #[must_use]
    pub fn scoped(&self, tenant_id: &str) -> ScopedEventBus {
        ScopedEventBus {
            bus: self.clone(),
            ns: majra::namespace::Namespace::new(tenant_id),
        }
    }
}

/// A tenant-scoped view of the event bus.
///
/// All operations are automatically namespaced — events from one tenant
/// cannot be seen by subscribers of another tenant.
#[derive(Clone)]
pub struct ScopedEventBus {
    bus: SandboxEventBus,
    ns: majra::namespace::Namespace,
}

impl ScopedEventBus {
    /// Emit an event scoped to this tenant.
    pub fn emit(&self, sandbox_id: &str, kind: EventKind, details: serde_json::Value) -> usize {
        let topic = self
            .ns
            .topic(&format!("sandbox/{}/{}", sandbox_id, kind.topic_segment()));
        self.bus.inner.publish(
            &topic,
            SandboxEvent {
                sandbox_id: sandbox_id.to_string(),
                kind,
                details,
            },
        )
    }

    /// Subscribe to events within this tenant's namespace.
    pub fn subscribe(
        &self,
        pattern: &str,
    ) -> tokio::sync::broadcast::Receiver<majra::pubsub::TypedMessage<SandboxEvent>> {
        self.bus.inner.subscribe(&self.ns.pattern(pattern))
    }

    /// Subscribe to all events for a sandbox within this tenant.
    pub fn subscribe_sandbox(
        &self,
        sandbox_id: &str,
    ) -> tokio::sync::broadcast::Receiver<majra::pubsub::TypedMessage<SandboxEvent>> {
        self.bus
            .inner
            .subscribe(&self.ns.topic(&format!("sandbox/{sandbox_id}/#")))
    }
}

impl Default for SandboxEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SandboxEventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxEventBus")
            .field("subscribers", &self.subscriber_count())
            .field("published", &self.messages_published())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kind_display() {
        assert_eq!(EventKind::Created.to_string(), "lifecycle/created");
        assert_eq!(EventKind::PolicyViolation.to_string(), "policy/violation");
        assert_eq!(EventKind::ScanBlocked.to_string(), "scan/blocked");
        assert_eq!(
            EventKind::AttestationPassed.to_string(),
            "attestation/passed"
        );
    }

    #[test]
    fn event_kind_all_segments_unique() {
        let kinds = [
            EventKind::Created,
            EventKind::Started,
            EventKind::Paused,
            EventKind::Stopped,
            EventKind::Destroyed,
            EventKind::PolicyViolation,
            EventKind::PolicyBlocked,
            EventKind::AttestationPassed,
            EventKind::AttestationFailed,
            EventKind::ScanBlocked,
            EventKind::ScanWarning,
        ];
        let segments: Vec<&str> = kinds.iter().map(|k| k.topic_segment()).collect();
        let mut deduped = segments.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(segments.len(), deduped.len(), "duplicate topic segments");
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = SandboxEvent {
            sandbox_id: "test-42".into(),
            kind: EventKind::Created,
            details: serde_json::json!({"backend": "process"}),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: SandboxEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sandbox_id, "test-42");
        assert_eq!(back.kind, EventKind::Created);
    }

    #[test]
    fn bus_default() {
        let bus = SandboxEventBus::new();
        assert_eq!(bus.messages_published(), 0);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn bus_clone_shares_state() {
        let bus1 = SandboxEventBus::new();
        let bus2 = bus1.clone();
        bus1.emit("s1", EventKind::Created, serde_json::Value::Null);
        assert_eq!(bus2.messages_published(), 1);
    }

    #[test]
    fn bus_debug() {
        let bus = SandboxEventBus::new();
        let dbg = format!("{bus:?}");
        assert!(dbg.contains("SandboxEventBus"));
    }

    #[tokio::test]
    async fn emit_and_receive() {
        let bus = SandboxEventBus::new();
        let mut rx = bus.subscribe("sandbox/test-1/#");

        bus.emit(
            "test-1",
            EventKind::Started,
            serde_json::json!({"pid": 1234}),
        );

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.payload.sandbox_id, "test-1");
        assert_eq!(msg.payload.kind, EventKind::Started);
        assert_eq!(msg.topic, "sandbox/test-1/lifecycle/started");
    }

    #[tokio::test]
    async fn wildcard_subscription() {
        let bus = SandboxEventBus::new();
        let mut rx = bus.subscribe("sandbox/*/lifecycle/#");

        bus.emit("a", EventKind::Created, serde_json::Value::Null);
        bus.emit("b", EventKind::Started, serde_json::Value::Null);
        bus.emit("c", EventKind::PolicyViolation, serde_json::Value::Null); // not lifecycle

        let m1 = rx.recv().await.unwrap();
        let m2 = rx.recv().await.unwrap();
        assert_eq!(m1.payload.sandbox_id, "a");
        assert_eq!(m2.payload.sandbox_id, "b");
        assert_eq!(bus.messages_published(), 3);
    }

    #[tokio::test]
    async fn subscribe_sandbox_all() {
        let bus = SandboxEventBus::new();
        let mut rx = bus.subscribe_sandbox("my-sandbox");

        bus.emit("my-sandbox", EventKind::Created, serde_json::Value::Null);
        bus.emit(
            "my-sandbox",
            EventKind::PolicyViolation,
            serde_json::Value::Null,
        );
        bus.emit("other", EventKind::Created, serde_json::Value::Null); // different sandbox

        let m1 = rx.recv().await.unwrap();
        let m2 = rx.recv().await.unwrap();
        assert_eq!(m1.payload.kind, EventKind::Created);
        assert_eq!(m2.payload.kind, EventKind::PolicyViolation);
    }

    #[tokio::test]
    async fn subscribe_lifecycle_only() {
        let bus = SandboxEventBus::new();
        let mut rx = bus.subscribe_lifecycle("s1");

        bus.emit("s1", EventKind::Created, serde_json::Value::Null);
        bus.emit("s1", EventKind::ScanBlocked, serde_json::Value::Null); // not lifecycle

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.payload.kind, EventKind::Created);
    }

    #[tokio::test]
    async fn filtered_subscription() {
        let bus = SandboxEventBus::new();
        let mut rx =
            bus.subscribe_filtered("sandbox/s1/#", |e| e.kind == EventKind::PolicyViolation);

        bus.emit("s1", EventKind::Created, serde_json::Value::Null);
        bus.emit(
            "s1",
            EventKind::PolicyViolation,
            serde_json::json!({"rule": "egress"}),
        );

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.payload.kind, EventKind::PolicyViolation);
    }

    #[test]
    fn emit_returns_subscriber_count() {
        let bus = SandboxEventBus::new();
        let _rx1 = bus.subscribe("sandbox/s1/#");
        let _rx2 = bus.subscribe("sandbox/s1/#");

        let count = bus.emit("s1", EventKind::Created, serde_json::Value::Null);
        assert_eq!(count, 2);
    }

    #[test]
    fn unsubscribe_all() {
        let bus = SandboxEventBus::new();
        let _rx = bus.subscribe("sandbox/s1/#");
        assert_eq!(bus.subscriber_count(), 1);

        bus.unsubscribe_all("sandbox/s1/#");
        assert_eq!(bus.subscriber_count(), 0);
    }
}
