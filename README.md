# kavach

**Sandbox execution framework for Rust.**

Backend abstraction, strength scoring, policy engine, credential proxy, and lifecycle management — in a single crate. Execute untrusted code across 8 isolation backends with quantitative security guarantees.

> **Name**: Kavach (कवच, Sanskrit) — armor, shield. Protects both what's inside and what's outside.
> Extracted from [SecureYeoman](https://github.com/MacCracken/SecureYeoman)'s production sandbox framework.

[![Crates.io](https://img.shields.io/crates/v/kavach.svg)](https://crates.io/crates/kavach)
[![CI](https://github.com/MacCracken/kavach/actions/workflows/ci.yml/badge.svg)](https://github.com/MacCracken/kavach/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

---

## What it does

kavach is the **execution sandbox** — it wraps untrusted code in isolation and gives you a number (0–100) that tells you how protected you are. Applications build their agent execution on top of kavach.

| Capability | Details |
|------------|---------|
| **8 backends** | Process, gVisor, Firecracker, WASM, OCI, SGX, SEV, Noop |
| **Strength scoring** | Quantitative 0–100 score per sandbox (not "secure"/"insecure") |
| **Policy engine** | Seccomp, Landlock, network allowlists, resource limits, presets |
| **Credential proxy** | Inject secrets via env/pipe — never touches sandbox filesystem |
| **Lifecycle FSM** | Created → Running → Paused → Stopped → Destroyed with audit hooks |
| **Externalization gate** | Nothing leaves the sandbox without policy approval |
| **Builder pattern** | Fluent config: `.backend(GVisor).policy_seccomp("strict").network(false)` |

---

## Architecture

```
Consumer (SY, daimon, AgnosAI)
    │
    ▼
Sandbox::create(config) → exec("command") → destroy()
    │
    ├── Policy Engine (seccomp, Landlock, network, resources)
    ├── Strength Scoring (0-100 per backend + modifiers)
    ├── Credential Proxy (secrets injection)
    │
    ▼
Backend Dispatch
    ├── Process (50)      — seccomp + namespaces + cgroups
    ├── OCI (55)          — runc/crun container
    ├── WASM (65)         — wasmtime + WASI
    ├── gVisor (70)       — user-space kernel (runsc)
    ├── SGX (80)          — Intel hardware enclave
    ├── SEV (82)          — AMD encrypted VM
    └── Firecracker (90)  — lightweight microVM
```

See [docs/architecture/overview.md](docs/architecture/overview.md) for the full architecture.

---

## Quick start

```toml
[dependencies]
kavach = "0.21"
```

```rust
use kavach::{Sandbox, SandboxConfig, Backend, SandboxState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Build a sandboxed execution environment
    let config = SandboxConfig::builder()
        .backend(Backend::Process)
        .policy_seccomp("basic")
        .network(false)
        .timeout_ms(30_000)
        .agent_id("agent-123")
        .build();

    // Create and start
    let mut sandbox = Sandbox::create(config).await?;
    sandbox.transition(SandboxState::Running)?;

    // Execute
    let result = sandbox.exec("echo hello world").await?;
    println!("exit: {}, stdout: {}", result.exit_code, result.stdout);

    // Cleanup
    sandbox.destroy().await?;
    Ok(())
}
```

### Strength scoring

```rust
use kavach::{Backend, SandboxPolicy, scoring};

// Base score per backend
let process_score = scoring::base_score(Backend::Process);    // 50
let gvisor_score = scoring::base_score(Backend::GVisor);      // 70
let firecracker_score = scoring::base_score(Backend::Firecracker); // 90

// Policy modifiers raise the score
let strict = SandboxPolicy::strict();
let score = scoring::score_backend(Backend::Process, &strict);
println!("{}", score); // "63 (standard)" — seccomp + ro rootfs + limits
```

### Credential proxy

```rust
use kavach::credential::{CredentialProxy, SecretRef, InjectionMethod};

let mut proxy = CredentialProxy::new();
proxy.register("API_KEY", "sk-secret-12345");

let refs = vec![SecretRef {
    name: "API_KEY".into(),
    inject_via: InjectionMethod::EnvVar { var_name: "OPENAI_API_KEY".into() },
}];

let env_vars = proxy.env_vars(&refs);
// env_vars = [("OPENAI_API_KEY", "sk-secret-12345")]
// The secret never touches the sandbox filesystem
```

### Policy presets

```rust
use kavach::SandboxPolicy;

let minimal = SandboxPolicy::minimal();  // No restrictions
let basic = SandboxPolicy::basic();      // Seccomp + no network
let strict = SandboxPolicy::strict();    // Everything locked down
```

---

## Features

| Flag | Backend | Default |
|------|---------|---------|
| `process` | Process isolation (seccomp, Landlock, namespaces) | yes |
| `gvisor` | gVisor user-space kernel | no |
| `firecracker` | Firecracker microVM | no |
| `wasm` | WebAssembly (wasmtime + WASI) | no |
| `oci` | OCI container (runc/crun) | no |
| `sgx` | Intel SGX enclave | no |
| `sev` | AMD SEV encrypted VM | no |
| `full` | All backends | no |

```toml
# Just process + WASM sandboxing
kavach = { version = "0.21", features = ["wasm"] }

# Everything
kavach = { version = "0.21", features = ["full"] }
```

---

## Strength scoring scale

| Score | Label | Example |
|-------|-------|---------|
| 0–29 | minimal | Noop (testing only) |
| 30–49 | basic | Process without seccomp |
| 50–69 | standard | Process + seccomp, OCI, WASM |
| 70–84 | hardened | gVisor, SGX, SEV, sy-agnos |
| 85–100 | fortress | Firecracker + full policy |

---

## Who uses this

| Project | Usage |
|---------|-------|
| **[SecureYeoman](https://github.com/MacCracken/SecureYeoman)** | All agent execution — 279 MCP tools sandboxed |
| **[AGNOS](https://github.com/MacCracken/agnosticos)** (daimon) | Agent sandbox lifecycle, 7 backend dispatch |
| **[AgnosAI](https://github.com/MacCracken/agnosai)** | Sandboxed crew execution (WASM/OCI agents) |
| **[aethersafta](https://github.com/MacCracken/aethersafta)** | Sandboxed compositor plugin execution |
| **[sutra](https://github.com/MacCracken/sutra)** | Sandboxed remote command execution on fleet |

---

## Roadmap

| Version | Milestone | Key features |
|---------|-----------|--------------|
| **0.21.3** | Foundation | Backend trait, scoring, policy, credentials, lifecycle FSM |
| **0.22.3** | Process backend | seccomp-bpf, Landlock, namespaces, cgroups, externalization gate |
| **0.23.3** | gVisor + OCI | runsc integration, OCI spec generation, container lifecycle |
| **0.24.3** | Firecracker + WASM | microVM, wasmtime + WASI, checkpoint/restore |
| **0.25.3** | Hardware enclaves | Intel SGX, AMD SEV-SNP, attestation |
| **0.26.3** | Consumer adoption | SY, daimon, AgnosAI integration |
| **1.0.0** | Stable API | All 8 backends, 90%+ coverage, formally verified FSM |

Full details: [docs/development/roadmap.md](docs/development/roadmap.md)

---

## Building from source

```bash
git clone https://github.com/MacCracken/kavach.git
cd kavach

# Build (process backend only — no system deps)
cargo build

# Build with WASM support
cargo build --features wasm

# Run tests
cargo test

# Run all CI checks
make check
```

---

## Versioning

Pre-1.0 releases use `0.D.M` SemVer — e.g. `0.21.3` = March 21st.
Post-1.0 follows standard SemVer.

---

## License

AGPL-3.0-only. See [LICENSE](LICENSE) for details.
