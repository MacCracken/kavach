# kavach

**Sandbox execution framework — Cyrius edition.**

10-backend dispatch, strength scoring, 3-scanner externalization pipeline, threat
classification, credential proxy, HMAC-SHA256 audit chain — all in pure Cyrius.

> **Name**: Kavach (कवच, Sanskrit) — armor, shield. Protects both what's inside
> the sandbox and what flows out of it.

---

## Status

**v3.1 — modernization arc.** Behavior-preserving repo modernization on top
of the v3.0 surface: Cyrius pin 4.5.0 → 5.10.34, manifest format
`cyrius.toml` → `cyrius.cyml`, `lib/` resolved by `cyrius deps` (no longer
committed), CI/release rewritten to match the rest of the first-party tree
(majra, nein, agnosys). The sandbox runtime, scanners, audit chain, and
threat classifier are unchanged from v3.0. See
[`CHANGELOG.md`](CHANGELOG.md) for the full v3.1.0 stanza and
[`docs/development/roadmap.md`](docs/development/roadmap.md) for the
cascaded v3.2 unblocking queue.

**v3.0 — Cyrius port.** Full Rust → Cyrius migration: 10 backends, 3
scanners, audit chain, credential proxy, threat classifier — plus the
P(-1) security hardening pass ([ADR-005](docs/adr/005-v2-hardening-pass.md))
that closed 9 CWE-class findings (constant-time HMAC verify, full RFC 8259
JSON escape, symlink TOCTOU on /tmp, sensitive-artifact mode 0600, secret
evidence redaction, argument-smuggling guards, HMAC-key zeroization,
integer overflow guards). See [ADR-001](docs/adr/001-cyrius-port-architecture.md)
for the port philosophy and [ADR-004](docs/adr/004-deferred-features.md)
for what's intentionally deferred.

| | v1.x (Rust) | v3.x (Cyrius) |
|--|--|--|
| Lines | ~26K | ~3K |
| Backends registered | 10 | 10 — full set with real dispatch contracts |
| Scanner pipeline | 3 scanners | 3 scanners |
| Audit chain | HMAC-SHA256 via hmac/sha2 crates | HMAC-SHA256 via [sigil](https://github.com/MacCracken/sigil) |
| Tests | 872 | 349 |
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
# Requires Cyrius 5.10.34 (pinned in cyrius.cyml; first-party tree gate
# from the sigil-NI asm-offset bisect — same pin as majra / nein /
# agnosys).

# 1. Resolve deps — populates lib/ (gitignored) with the cc 5.10.34
#    stdlib snapshot + sigil 2.9.0 at the pinned tag.
cyrius deps

# 2. Build the binary.
cyrius build src/main.cyr build/kavach
./build/kavach

# Run the test suite (349 tests).
cyrius test tests/kavach.tcyr

# Run the bench harness (15 benches).
cyrius bench tests/kavach.bcyr

# Audit (fmt + lint + vet + deny + test + bench + doc).
cyrius audit
```

Dependencies (declared in [`cyrius.cyml`](cyrius.cyml)):
- **Cyrius stdlib** — `alloc, args, assert, bench, bigint, chrono, fmt, fnptr, freelist, hashmap, io, process, str, string, syscalls, tagged, vec` (resolved by `cyrius deps` into `lib/`, which is gitignored)
- **[sigil](https://github.com/MacCracken/sigil) 2.9.0** — SHA-256, HMAC-SHA256, constant-time compare (pinned tag; 2.9.1+ SIGILL on the ed25519-NI / aes-gcm-NI paths under cc 5.10.x — see [doc-health.md](docs/doc-health.md) for the bisect context)

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

| Backend | Base score | Tier | v3.x status |
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
- [Guides](docs/guides/) — getting started, composite backends, threat tracking
- [Worked examples](docs/examples/) — four progressive walkthroughs
- [Benchmarks — Rust v2.0 vs Cyrius v3.0](benchmarks-rust-v-cyrius.md) — honest per-op comparison (frozen at the v3.0 cutover)
- [Doc Health](docs/doc-health.md) — currency ledger for the prose docs
- [ADR-001](docs/adr/001-cyrius-port-architecture.md) — port architecture
- [ADR-002](docs/adr/002-backend-dispatch-fnptr-table.md) — dispatch table
- [ADR-003](docs/adr/003-fixed-point-threat-scoring.md) — fixed-point threat scoring
- [ADR-004](docs/adr/004-deferred-features.md) — deferred features + unblocking
- [ADR-005](docs/adr/005-v2-hardening-pass.md) — P(-1) security hardening pass

---

## License

GPL-3.0-only. See [LICENSE](LICENSE).
