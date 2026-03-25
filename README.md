# kavach

**Sandbox execution framework for Rust.**

10 isolation backends, strength scoring (0-100), 3-scanner pipeline, credential proxy, runtime guards, threat classification, audit chain — in a single crate.

> **Name**: Kavach (कवच, Sanskrit) — armor, shield. Protects both what's inside and what's outside.
> Extracted from [SecureYeoman](https://github.com/MacCracken/SecureYeoman)'s production sandbox framework.

[![Crates.io](https://img.shields.io/crates/v/kavach.svg)](https://crates.io/crates/kavach)
[![CI](https://github.com/MacCracken/kavach/actions/workflows/ci.yml/badge.svg)](https://github.com/MacCracken/kavach/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

---

## What it does

kavach wraps untrusted code in isolation and gives you a number (0-100) that tells you how protected you are.

| Capability | Details |
|------------|---------|
| **10 backends** | Process, gVisor, Firecracker, WASM, OCI, SGX, SEV, TDX, SyAgnos, Noop |
| **Strength scoring** | Quantitative 0-100 score per sandbox |
| **3-scanner pipeline** | Secrets (17 patterns + entropy), code violations (25 groups), data/compliance (PII, HIPAA, GDPR, PCI) |
| **Credential proxy** | Direct injection (env/file/stdin) + HTTP proxy with header injection |
| **Runtime guards** | Fork bomb detection, command blocklist, sensitive path blocking, integrity monitoring |
| **Threat classification** | Intent scoring (0.0-1.0), kill-chain tracking, 4-tier escalation |
| **Quarantine + audit** | File-based quarantine with approval workflow, HMAC-SHA256 audit chain |
| **Sandbox pooling** | Pre-warmed `SandboxPool` with claim/replenish for fast startup |
| **Composite backends** | Stack isolation layers (e.g., gVisor + Process) with merged policies |
| **Auto-selection** | `Backend::resolve_best()` picks the strongest available backend |
| **Lifecycle FSM** | Created -> Running -> Paused -> Stopped -> Destroyed |
| **Builder pattern** | `.backend(GVisor).inner_backend(Process).policy_seccomp("strict")` |

---

## Architecture

```
Consumer (SY, stiva, kiran, AgnosAI, hoosh)
    |
    v
Sandbox::create(config) -> exec("command") -> destroy()
    |
    |-- Scanning Pipeline (secrets + code + data)
    |-- Threat Classifier (intent score, kill-chain, escalation)
    |-- Runtime Guards (fork bomb, path blocklist, command blocklist)
    |-- Credential Proxy (env/file/stdin + HTTP proxy)
    |-- Strength Scoring (0-100 per backend + policy modifiers)
    |
    v
Backend Dispatch (or CompositeBackend for layered isolation)
    |-- Process (50)      -- seccomp + namespaces + landlock + cgroups
    |-- OCI (55)          -- runc/crun container
    |-- WASM (65)         -- wasmtime + WASI + fuel metering
    |-- gVisor (70)       -- user-space kernel (runsc)
    |-- SGX (80)          -- Intel hardware enclave (Gramine)
    |-- SEV (82)          -- AMD encrypted VM (QEMU + SNP)
    |-- TDX (85)          -- Intel Trust Domain Extensions
    |-- SyAgnos (80-88)   -- Hardened AGNOS OS (3 tiers)
    |-- Firecracker (90)  -- lightweight microVM + jailer
    '-- Noop (0)          -- testing only
```

---

## Quick start

```toml
[dependencies]
kavach = "1.0"
```

```rust
use kavach::{Sandbox, SandboxConfig, Backend, SandboxState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = SandboxConfig::builder()
        .backend(Backend::Process)
        .policy_seccomp("basic")
        .network(false)
        .timeout_ms(30_000)
        .build();

    let mut sandbox = Sandbox::create(config).await?;
    sandbox.transition(SandboxState::Running)?;

    let result = sandbox.exec("echo hello world").await?;
    println!("exit: {}, stdout: {}", result.exit_code, result.stdout);

    sandbox.destroy().await?;
    Ok(())
}
```

### Auto-select the strongest backend

```rust
use kavach::{Backend, SandboxPolicy, SandboxConfig};

let policy = SandboxPolicy::strict();
let best = Backend::resolve_best(&policy);
// Returns Firecracker if available, else gVisor, else Process, etc.

let config = SandboxConfig::builder()
    .backend(best)
    .policy(policy)
    .build();
```

### Composite isolation (defense-in-depth)

```rust
use kavach::{Backend, SandboxConfig, SandboxPolicy};

let config = SandboxConfig::builder()
    .backend(Backend::GVisor)          // outer: gVisor container
    .inner_backend(Backend::Process)   // inner: seccomp + landlock
    .policy(SandboxPolicy::strict())
    .build();
// Score: gVisor(70) + Process policy merged + composite bonus = ~80
```

### Sandbox pooling (fast startup)

```rust
use kavach::{SandboxConfig, SandboxState, SandboxPool, Backend};

let config = SandboxConfig::builder().backend(Backend::Noop).build();
let mut pool = SandboxPool::new(config, 10).await?; // Pre-warm 10

let mut sandbox = pool.claim().await?;               // Instant
sandbox.transition(SandboxState::Running)?;
let result = sandbox.exec("echo fast").await?;

pool.replenish().await?;                              // Refill pool
```

### HTTP credential proxy

```rust
use kavach::credential::http_proxy::{HttpProxyConfig, CredentialRule, start_proxy};

let mut config = HttpProxyConfig::default();
config.credential_rules.insert(
    "api.openai.com".into(),
    CredentialRule {
        header_name: "Authorization".into(),
        header_value: "Bearer sk-...".into(),
    },
);
config.enforce_allowlist = true;
config.allowed_hosts = vec!["api.openai.com".into()];

let handle = start_proxy(config).await?;
// Set http_proxy=http://127.0.0.1:{handle.port()} on sandboxed process
// Credentials injected automatically, never exposed to sandbox
```

### Strength scoring

```rust
use kavach::{Backend, SandboxPolicy, scoring};

let score = scoring::score_backend(Backend::Process, &SandboxPolicy::strict());
println!("{}", score); // "68 (standard)"

let score = scoring::score_backend(Backend::Firecracker, &SandboxPolicy::strict());
println!("{}", score); // "100 (fortress)"
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
| `sy-agnos` | Hardened AGNOS OS | no |
| `attestation` | EAR attestation (veraison) | no |
| `sigstore` | OCI image signing | no |
| `full` | All core backends | no |

```toml
kavach = { version = "1.0", features = ["wasm"] }        # Process + WASM
kavach = { version = "1.0", features = ["full"] }         # All backends
kavach = { version = "1.0", features = ["attestation"] }  # + EAR tokens
```

---

## Scanning pipeline

The externalization gate runs three scanners on every sandbox output:

| Scanner | Patterns | Severity |
|---------|----------|----------|
| **Secrets** | AWS keys, GitHub tokens, Stripe, Slack, JWTs, private keys, connection strings, SSN, email + Shannon entropy | Critical-Low |
| **Code** | Command injection, data exfiltration, privilege escalation, supply chain, obfuscation, filesystem abuse, crypto misuse | Critical-Low |
| **Data** | Credit cards (Visa/MC/Amex), phone numbers, IBAN, IPv4, HIPAA, GDPR, PCI-DSS, SOC2 | Critical-Low |

Plus: threat classification (intent score 0.0-1.0, kill-chain stages), repeat offender tracking, quarantine storage, HMAC-SHA256 audit chain.

---

## Strength scoring scale

| Score | Label | Example |
|-------|-------|---------|
| 0-29 | minimal | Noop (testing only) |
| 30-49 | basic | Process without seccomp |
| 50-69 | standard | Process + seccomp, OCI, WASM |
| 70-84 | hardened | gVisor, SGX, SEV, SyAgnos |
| 85-100 | fortress | Firecracker + strict policy, TDX |

---

## Consumers

| Project | Usage |
|---------|-------|
| **[stiva](https://github.com/MacCracken/stiva)** | Container runtime isolation (`kavach >= 1.0`) |
| **[kiran](https://github.com/MacCracken/kiran)** | WASM scripting sandbox (`kavach = 1.0`) |
| **[SecureYeoman](https://github.com/MacCracken/SecureYeoman)** | Agent sandboxing (279 MCP tools) |
| **[AgnosAI](https://github.com/MacCracken/agnosai)** | Sandboxed crew execution (planned) |
| **[hoosh](https://github.com/MacCracken/hoosh)** | LLM tool sandboxing (planned) |
| **[bote](https://github.com/MacCracken/bote)** | MCP tool handler isolation (planned) |
| **[aethersafta](https://github.com/MacCracken/aethersafta)** | Plugin isolation (planned) |

---

## Building from source

```bash
git clone https://github.com/MacCracken/kavach.git
cd kavach

cargo build                          # Process backend only
cargo build --features full          # All backends
cargo test --all-features            # 561 tests
make check                           # fmt + clippy + test + audit
make semver                          # cargo-semver-checks
./scripts/bench-history.sh           # Benchmark with CSV history
```

---

## License

AGPL-3.0-only. See [LICENSE](LICENSE) for details.
