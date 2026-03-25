use criterion::{Criterion, criterion_group, criterion_main};
use kavach::backend::Backend;
use kavach::credential::{CredentialProxy, InjectionMethod, SecretRef};
use kavach::lifecycle::{ExecResult, SandboxConfig, SandboxState};
use kavach::policy::SandboxPolicy;
use kavach::scanning::gate::ExternalizationGate;
use kavach::scanning::secrets::SecretsScanner;
use kavach::scanning::types::ExternalizationPolicy;
use kavach::{StrengthScore, scoring};

// ── Scoring ─────────────────────────────────────────────────────────────

fn bench_strength_scoring(c: &mut Criterion) {
    let policy = SandboxPolicy::strict();
    c.bench_function("score_backend_process_strict", |b| {
        b.iter(|| scoring::score_backend(Backend::Process, &policy))
    });
}

fn bench_score_all_backends(c: &mut Criterion) {
    let policy = SandboxPolicy::strict();
    c.bench_function("score_all_backends_strict", |b| {
        b.iter(|| {
            Backend::all()
                .iter()
                .map(|backend| scoring::score_backend(*backend, &policy))
                .collect::<Vec<StrengthScore>>()
        })
    });
}

// ── Backend Detection ───────────────────────────────────────────────────

fn bench_backend_availability(c: &mut Criterion) {
    c.bench_function("backend_available_all", |b| b.iter(Backend::available));
}

fn bench_capability_detection(c: &mut Criterion) {
    use kavach::backend::capabilities;
    c.bench_function("detect_capabilities", |b| {
        b.iter(capabilities::detect_capabilities)
    });
}

// ── Policy ──────────────────────────────────────────────────────────────

fn bench_policy_creation(c: &mut Criterion) {
    c.bench_function("policy_strict_create", |b| b.iter(SandboxPolicy::strict));
}

fn bench_policy_serde(c: &mut Criterion) {
    let policy = SandboxPolicy::strict();
    let json = serde_json::to_string(&policy).unwrap();
    c.bench_function("policy_serialize", |b| {
        b.iter(|| serde_json::to_string(&policy).unwrap())
    });
    c.bench_function("policy_deserialize", |b| {
        b.iter(|| serde_json::from_str::<SandboxPolicy>(&json).unwrap())
    });
}

// ── Config Builder ──────────────────────────────────────────────────────

fn bench_config_builder(c: &mut Criterion) {
    c.bench_function("config_builder_full", |b| {
        b.iter(|| {
            SandboxConfig::builder()
                .backend(Backend::Process)
                .policy_seccomp("strict")
                .network(false)
                .timeout_ms(30_000)
                .agent_id("bench-agent")
                .build()
        })
    });
}

fn bench_config_serde(c: &mut Criterion) {
    let config = SandboxConfig::builder()
        .backend(Backend::Process)
        .policy(SandboxPolicy::strict())
        .timeout_ms(30_000)
        .build();
    let json = serde_json::to_string(&config).unwrap();
    c.bench_function("config_serialize", |b| {
        b.iter(|| serde_json::to_string(&config).unwrap())
    });
    c.bench_function("config_deserialize", |b| {
        b.iter(|| serde_json::from_str::<SandboxConfig>(&json).unwrap())
    });
}

// ── Credential Proxy ────────────────────────────────────────────────────

fn bench_credential_proxy(c: &mut Criterion) {
    let mut proxy = CredentialProxy::new();
    for i in 0..100 {
        proxy.register(format!("SECRET_{i}"), format!("value-{i}"));
    }
    let refs: Vec<SecretRef> = (0..100)
        .map(|i| SecretRef {
            name: format!("SECRET_{i}"),
            inject_via: InjectionMethod::EnvVar {
                var_name: format!("ENV_{i}"),
            },
        })
        .collect();

    c.bench_function("credential_env_vars_100", |b| {
        b.iter(|| proxy.env_vars(&refs))
    });
}

fn bench_credential_file_injections(c: &mut Criterion) {
    let mut proxy = CredentialProxy::new();
    for i in 0..20 {
        proxy.register(
            format!("CERT_{i}"),
            format!("-----BEGIN CERTIFICATE-----\n{i}"),
        );
    }
    let refs: Vec<SecretRef> = (0..20)
        .map(|i| SecretRef {
            name: format!("CERT_{i}"),
            inject_via: InjectionMethod::File {
                path: format!("/etc/ssl/cert_{i}.pem"),
                mode: 0o600,
            },
        })
        .collect();

    c.bench_function("credential_file_injections_20", |b| {
        b.iter(|| proxy.file_injections(&refs))
    });
}

// ── Scanning / Externalization Gate ─────────────────────────────────────

fn bench_secrets_scanner_clean(c: &mut Criterion) {
    let scanner = SecretsScanner::new();
    let clean_text = "This is a perfectly normal log output with no secrets whatsoever. \
                      Status: OK. Temperature: 72F. Users: 1,234. Uptime: 99.9%.";
    c.bench_function("secrets_scan_clean_text", |b| {
        b.iter(|| scanner.scan(clean_text))
    });
}

fn bench_secrets_scanner_with_secrets(c: &mut Criterion) {
    let scanner = SecretsScanner::new();
    let dirty_text = "Config: AKIAIOSFODNN7EXAMPLE and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij \
                      postgres://user:pass@localhost/db password='hunter2hunter2'";
    c.bench_function("secrets_scan_with_secrets", |b| {
        b.iter(|| scanner.scan(dirty_text))
    });
}

fn bench_secrets_redact(c: &mut Criterion) {
    let scanner = SecretsScanner::new();
    let text = "key: AKIAIOSFODNN7EXAMPLE and token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    c.bench_function("secrets_redact", |b| b.iter(|| scanner.redact(text)));
}

fn bench_externalization_gate(c: &mut Criterion) {
    let gate = ExternalizationGate::new();
    let policy = ExternalizationPolicy::default();
    let clean_result = ExecResult {
        exit_code: 0,
        stdout: "hello world\nstatus: ok\n".repeat(100),
        stderr: String::new(),
        duration_ms: 42,
        timed_out: false,
    };
    c.bench_function("gate_clean_output", |b| {
        b.iter(|| gate.apply(clean_result.clone(), &policy))
    });
}

// ── Lifecycle FSM ───────────────────────────────────────────────────────

fn bench_state_transitions(c: &mut Criterion) {
    c.bench_function("state_valid_transition_check", |b| {
        b.iter(|| {
            SandboxState::Created.valid_transition(&SandboxState::Running)
                && SandboxState::Running.valid_transition(&SandboxState::Stopped)
                && SandboxState::Stopped.valid_transition(&SandboxState::Destroyed)
                && !SandboxState::Destroyed.valid_transition(&SandboxState::Running)
        })
    });
}

// ── Process Backend (Linux only) ────────────────────────────────────────

#[cfg(target_os = "linux")]
fn bench_seccomp_filter_build(c: &mut Criterion) {
    use kavach::backend::process::seccomp;
    c.bench_function("seccomp_build_basic", |b| {
        b.iter(|| seccomp::build_filter("basic").unwrap())
    });
    c.bench_function("seccomp_build_strict", |b| {
        b.iter(|| seccomp::build_filter("strict").unwrap())
    });
}

#[cfg(target_os = "linux")]
fn bench_process_exec(c: &mut Criterion) {
    use kavach::backend::SandboxBackend;
    use kavach::backend::process::ProcessBackend;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = SandboxConfig::builder()
        .backend(Backend::Process)
        .timeout_ms(5_000)
        .build();
    let backend = ProcessBackend::new(&config).unwrap();
    let policy = SandboxPolicy::minimal();

    c.bench_function("process_exec_echo", |b| {
        b.iter(|| rt.block_on(backend.exec("echo bench", &policy)).unwrap())
    });
}

#[cfg(target_os = "linux")]
fn bench_process_exec_with_seccomp(c: &mut Criterion) {
    use kavach::backend::SandboxBackend;
    use kavach::backend::process::ProcessBackend;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = SandboxConfig::builder()
        .backend(Backend::Process)
        .policy_seccomp("basic")
        .timeout_ms(5_000)
        .build();
    let backend = ProcessBackend::new(&config).unwrap();
    let policy = SandboxPolicy::basic();

    c.bench_function("process_exec_echo_with_seccomp", |b| {
        b.iter(|| rt.block_on(backend.exec("echo bench", &policy)).unwrap())
    });
}

// ── Sandbox Lifecycle (full create → exec → destroy) ────────────────────

fn bench_sandbox_lifecycle(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("sandbox_full_lifecycle", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = SandboxConfig::builder()
                    .backend(Backend::Process)
                    .timeout_ms(5_000)
                    .build();
                let mut sandbox = kavach::Sandbox::create(config).await.unwrap();
                sandbox.transition(SandboxState::Running).unwrap();
                let result = sandbox.exec("echo bench").await.unwrap();
                assert_eq!(result.exit_code, 0);
                sandbox.transition(SandboxState::Stopped).unwrap();
                sandbox.destroy().await.unwrap();
            })
        })
    });
}

// ── Health Check ────────────────────────────────────────────────────────

fn bench_health_check(c: &mut Criterion) {
    use kavach::backend::NoopBackend;
    use kavach::backend::health;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let backend = NoopBackend;
    c.bench_function("health_check_noop", |b| {
        b.iter(|| rt.block_on(health::check_health(&backend)))
    });
}

// ── Overhead Measurement ─────────────────────────────────────────────────

/// Measure kavach overhead vs direct process spawn.
/// Compares: direct `tokio::process::Command::new("echo")` vs kavach Process backend.
#[cfg(target_os = "linux")]
fn bench_overhead_vs_direct(c: &mut Criterion) {
    use kavach::backend::SandboxBackend;
    use kavach::backend::process::ProcessBackend;

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Direct spawn (baseline)
    c.bench_function("direct_spawn_echo", |b| {
        b.iter(|| {
            rt.block_on(async {
                let output = tokio::process::Command::new("echo")
                    .arg("bench")
                    .output()
                    .await
                    .unwrap();
                assert!(output.status.success());
            })
        })
    });

    // Kavach Process backend with minimal policy (no seccomp)
    let config_minimal = SandboxConfig::builder()
        .backend(Backend::Process)
        .timeout_ms(5_000)
        .build();
    let backend_minimal = ProcessBackend::new(&config_minimal).unwrap();
    let policy_minimal = SandboxPolicy::minimal();

    c.bench_function("kavach_process_echo_minimal", |b| {
        b.iter(|| {
            rt.block_on(backend_minimal.exec("echo bench", &policy_minimal))
                .unwrap()
        })
    });
}

// ── Group Registration ──────────────────────────────────────────────────

criterion_group!(
    scoring_benches,
    bench_strength_scoring,
    bench_score_all_backends,
);

criterion_group!(
    detection_benches,
    bench_backend_availability,
    bench_capability_detection,
);

criterion_group!(policy_benches, bench_policy_creation, bench_policy_serde,);

criterion_group!(config_benches, bench_config_builder, bench_config_serde,);

criterion_group!(
    credential_benches,
    bench_credential_proxy,
    bench_credential_file_injections,
);

criterion_group!(
    scanning_benches,
    bench_secrets_scanner_clean,
    bench_secrets_scanner_with_secrets,
    bench_secrets_redact,
    bench_externalization_gate,
);

criterion_group!(
    lifecycle_benches,
    bench_state_transitions,
    bench_sandbox_lifecycle,
    bench_health_check,
);

#[cfg(target_os = "linux")]
criterion_group!(
    process_benches,
    bench_seccomp_filter_build,
    bench_process_exec,
    bench_process_exec_with_seccomp,
);

#[cfg(target_os = "linux")]
criterion_group!(overhead_benches, bench_overhead_vs_direct,);

#[cfg(target_os = "linux")]
criterion_main!(
    scoring_benches,
    detection_benches,
    policy_benches,
    config_benches,
    credential_benches,
    scanning_benches,
    lifecycle_benches,
    process_benches,
    overhead_benches,
);

#[cfg(not(target_os = "linux"))]
criterion_main!(
    scoring_benches,
    detection_benches,
    policy_benches,
    config_benches,
    credential_benches,
    scanning_benches,
    lifecycle_benches,
);
