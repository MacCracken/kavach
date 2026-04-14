# kavach

**Sandbox execution framework — Cyrius edition.**

10-backend dispatch, strength scoring, 3-scanner externalization pipeline, threat
classification, credential proxy, HMAC-SHA256 audit chain — all in pure Cyrius.

> **Name**: Kavach (कवच, Sanskrit) — armor, shield. Protects both what's inside
> the sandbox and what flows out of it.

---

## v2.0 status

Cyrius port of the Rust v1.x framework. See
[ADR-001](docs/adr/001-cyrius-port-architecture.md) for the port philosophy
and [ADR-004](docs/adr/004-deferred-features.md) for what's intentionally
deferred.

| | v1.x (Rust) | v2.0 (Cyrius) |
|--|--|--|
| Lines | ~26K | ~3K |
| Backends registered | 10 | 10 — full set with real dispatch contracts |
| Scanner pipeline | 3 scanners | 3 scanners |
| Audit chain | HMAC-SHA256 via hmac/sha2 crates | HMAC-SHA256 via [sigil](https://github.com/MacCracken/sigil) |
| Tests | 872 | 262 |
| Async | tokio | synchronous (ADR-004 §1) |

---

## What it does

| Capability | Details |
|------------|---------|
| **Dispatch table** | `backend_X_register()` plugs in; dispatch is O(1) via `fncall2` |
| **Strength scoring** | Quantitative 0-100 score per sandbox, policy modifiers applied |
| **3-scanner pipeline** | Secrets (7 families) + code (26 pattern groups) + data (PII + HIPAA/GDPR/PCI/SOC2) |
| **Runtime guards** | Fork bomb, sensitive path, command blocklist, shell metacharacters, time anomaly |
| **Threat classification** | Intent 0..1000 (fixed-point), 7 kill-chain stages, 4 tiers, escalation |
| **Credential proxy** | In-memory `CredentialProxy` + env/file/stdin injection |
| **Audit chain** | HMAC-SHA256 signed, prev-linked, JSONL on disk, tamper-detectable |
| **Quarantine** | File-based storage with status lifecycle (quarantined/approved/released/rejected) |
| **Lifecycle FSM** | Created → Running → Paused → Stopped → Destroyed |
| **Sandbox pool** | Pre-warmed `SandboxPool` with `claim()`/`replenish()` |

---

## Build

```sh
# Requires Cyrius ≥ 4.0.0
cyrius build src/main.cyr build/kavach
./build/kavach

# Run the test suite (201 tests)
cyrius test tests/kavach.tcyr

# Audit (fmt + lint + vet + deny + test + bench + doc)
cyrius audit
```

Dependencies (declared in [`cyrius.toml`](cyrius.toml)):
- Cyrius stdlib — `string, fmt, alloc, vec, str, syscalls, io, args, assert, bigint, chrono, hashmap, freelist, fnptr, process`
- [sigil](https://github.com/MacCracken/sigil) ≥ 2.1.2 — SHA-256, HMAC-SHA256

---

## Quick start

```cyrius
include "src/main.cyr"    # brings in the full include manifest

fn app() {
    kavach_init();

    # 1. Configure
    var cfg = config_new();
    config_backend(cfg, Backend.PROCESS);
    config_policy_seccomp(cfg, "strict");
    config_network(cfg, 0);

    # 2. Wire the trust layer
    var chain = audit_chain_open("/var/log/kavach.audit",
                                 "my-hmac-key", 11);
    sandbox_exec_set_audit_chain(chain);

    # 3. Create and run
    var sb = sandbox_create(cfg);
    sandbox_transition(sb, SandboxState.RUNNING);

    var result = sandbox_exec(sb, "/bin/echo hello");
    if (result == 0) {
        # BLOCK or QUARANTINE verdict — details on last_scan_result
        var sr = sandbox_exec_last_scan_result();
        # ... inspect findings
    }

    sandbox_destroy(sb);
    return 0;
}
```

---

## Backend scoreboard

| Backend | Base score | Tier | v2.0 status |
|---------|-----------:|------|-------------|
| Noop | 0 | minimal | **registered** (testing only) |
| Process | 50 | standard | **registered** (fork+exec+capture + guard precheck) |
| OCI | 55 | standard | **registered** (`runc`/`crun` shell-out via shared OCI spec) |
| WASM | 65 | standard | **registered** (`wasmtime` CLI with fuel + memory + preopens) |
| gVisor | 70 | hardened | **registered** (OCI bundle + `runsc run` + auto-cleanup) |
| SGX | 80 | hardened | **registered** (`gramine-sgx` + auto-generated manifest) |
| SEV | 82 | hardened | **registered** (`qemu-system-x86_64` with SEV-SNP object) |
| SyAgnos | 80 | hardened | **registered** (docker/podman + hardened AGNOS image + Phylax) |
| TDX | 85 | fortress | **registered** (`qemu-system-x86_64` with TDX object) |
| Firecracker | 90 | fortress | **registered** (microVM config.json + `firecracker --no-api`) |

Adding a backend is a single-file extension: see
[docs/architecture/overview.md § Extension pattern](docs/architecture/overview.md#extension-pattern-adding-a-backend)
and [ADR-002](docs/adr/002-backend-dispatch-fnptr-table.md).

---

## Scanner pipeline

```
exec() → ExecResult ↓
                     gate_apply(result, policy)
                        ├── secrets scanner
                        ├── code scanner
                        ├── data scanner
                        └── verdict = PASS / WARN / QUARANTINE / BLOCK

Separate paths:
  check_command(cmd, guard_cfg)  → runtime guard violations
  check_fork_bomb(pid_count, cfg)
  check_time_anomaly(ms, expected_ms, cfg)
  classify_threat(findings)       → ThreatAssessment{ intent_score_x1000,
                                                      classification,
                                                      kill_chain_stages,
                                                      escalation }
```

### Strength scoring scale

| Score | Label |
|-------|-------|
| 0-29 | minimal |
| 30-49 | basic |
| 50-69 | standard |
| 70-84 | hardened |
| 85-100 | fortress |

---

## Consumers

| Project | Usage |
|---------|-------|
| **SY** | Agent sandboxing (279 MCP tools) |
| **stiva** | Container runtime isolation |
| **kiran** | WASM scripting sandbox |
| **AgnosAI** | Sandboxed crew execution |
| **hoosh** | LLM tool sandboxing |
| **bote** | MCP tool handler isolation |
| **aethersafta** | Plugin isolation |

---

## Docs

- [Architecture overview](docs/architecture/overview.md) — module map, data flow, extension pattern
- [ADR-001](docs/adr/001-cyrius-port-architecture.md) — port architecture
- [ADR-002](docs/adr/002-backend-dispatch-fnptr-table.md) — dispatch table
- [ADR-003](docs/adr/003-fixed-point-threat-scoring.md) — fixed-point threat scoring
- [ADR-004](docs/adr/004-deferred-features.md) — deferred features + unblocking

---

## License

GPL-3.0-only. See [LICENSE](LICENSE).
