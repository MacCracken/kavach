//! Integration tests for kavach.

use crate::*;

#[test]
fn backend_availability() {
    let avail = Backend::available();
    assert!(avail.contains(&Backend::Noop));
    #[cfg(all(feature = "process", target_os = "linux"))]
    assert!(avail.contains(&Backend::Process));
}

#[test]
fn strength_scoring_ordering() {
    let noop = scoring::base_score(Backend::Noop);
    let process = scoring::base_score(Backend::Process);
    let gvisor = scoring::base_score(Backend::GVisor);
    let firecracker = scoring::base_score(Backend::Firecracker);

    assert!(noop < process);
    assert!(process < gvisor);
    assert!(gvisor < firecracker);
}

#[test]
fn policy_presets() {
    let minimal = SandboxPolicy::minimal();
    let basic = SandboxPolicy::basic();
    let strict = SandboxPolicy::strict();

    let s_minimal = scoring::score_backend(Backend::Process, &minimal);
    let s_basic = scoring::score_backend(Backend::Process, &basic);
    let s_strict = scoring::score_backend(Backend::Process, &strict);

    assert!(s_minimal < s_basic);
    assert!(s_basic < s_strict);
}

#[tokio::test]
async fn full_lifecycle() {
    let config = SandboxConfig::builder()
        .backend(Backend::Noop)
        .policy_seccomp("basic")
        .network(false)
        .agent_id("test-agent")
        .build();

    let mut sandbox = Sandbox::create(config).await.unwrap();
    assert_eq!(sandbox.state, SandboxState::Created);

    sandbox.transition(SandboxState::Running).unwrap();
    assert_eq!(sandbox.state, SandboxState::Running);

    let result = sandbox.exec("echo hello").await.unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(!result.timed_out);

    sandbox.transition(SandboxState::Stopped).unwrap();
    sandbox.destroy().await.unwrap();
}

#[test]
fn credential_proxy_lifecycle() {
    let mut proxy = CredentialProxy::new();
    proxy.register("DB_URL", "postgres://localhost/test");
    proxy.register("API_KEY", "sk-secret");

    assert_eq!(proxy.len(), 2);

    let refs = vec![SecretRef {
        name: "API_KEY".into(),
        inject_via: crate::credential::InjectionMethod::EnvVar {
            var_name: "OPENAI_KEY".into(),
        },
    }];

    let vars = proxy.env_vars(&refs);
    assert_eq!(vars.len(), 1);
    assert_eq!(vars[0].0, "OPENAI_KEY");
    assert_eq!(vars[0].1, "sk-secret");
}

#[test]
fn config_serde_roundtrip() {
    let config = SandboxConfig::builder()
        .backend(Backend::GVisor)
        .policy(SandboxPolicy::strict())
        .timeout_ms(60_000)
        .build();

    let json = serde_json::to_string(&config).unwrap();
    let back: SandboxConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.backend, Backend::GVisor);
    assert!(back.policy.seccomp_enabled);
    assert!(back.policy.read_only_rootfs);
}

#[test]
fn error_display() {
    let err = KavachError::BackendUnavailable("firecracker".into());
    assert!(err.to_string().contains("firecracker"));

    let err = KavachError::InvalidTransition {
        state: "created".into(),
        target: "stopped".into(),
        reason: "must start first".into(),
    };
    assert!(err.to_string().contains("created"));
    assert!(err.to_string().contains("stopped"));
}
