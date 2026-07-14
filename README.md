# kavach

**Sandbox execution framework — Cyrius edition.**

10-backend dispatch, strength scoring, 3-scanner externalization pipeline, threat
classification, credential proxy, HMAC-SHA256 audit chain — all in pure Cyrius.

> **Name**: Kavach (कवच, Sanskrit) — armor, shield. Protects both what's inside
> the sandbox and what flows out of it.

---

## Status

**v3.7.1 — toolchain + dependency refresh.** Cyrius pin `6.3.40` → `6.4.62`
and sigil `3.9.8` → `3.11.1`, both to the latest ecosystem. No source or API
change; the `dist/kavach.cyr` consumable surface is byte-identical apart from
the version-header restamp. Build + the **422-assertion** suite green under cc
`6.4.62`; 22 benches recorded.

**v3.5.2 — cyrius toolchain pin `6.2.11` → `6.2.36`.** Aligns with the latest
cyrius. Host + `--agnos` builds re-verified clean (the 3.5.1 Linux-MAC agnos
gating holds at 6.2.36).

**v3.5.1 — AGNOS build support.** The Linux MAC stack (Landlock / seccomp-BPF /
namespaces) in `src/security.cyr` is now `#ifdef CYRIUS_TARGET_AGNOS`-gated to
return a structured `err_not_supported` — AGNOS has none of these mechanisms, so
the unconditional `SYS_LANDLOCK_*` / `SYS_PRCTL` / `SYS_UNSHARE` references made
an agnos build fail to even link. On AGNOS, sandbox confinement is the
**capability layer's** responsibility; this is transitional until AGNOS ships
native confinement primitives. Linux behaviour is byte-unchanged. kavach now
builds clean for both host and `--agnos`.

**v3.5.0 — internalizes the Linux security backends; drops the agnosys
dependency.** Part of the `agnosys → agnodrm` ecosystem decomposition. kavach was
the heavy consumer of agnosys's Landlock/seccomp, MAC, and Linux-audit code and
now owns those backends directly: `security.cyr` (Landlock/seccomp/namespaces),
`mac.cyr` (SELinux/AppArmor), `kernel_audit.cyr` (Linux audit) + their
`sys_error`/`sys_util` support and `sys_security_syscalls.cyr`. `[deps.agnosys]`
dropped; `[deps.sigil]` `3.7.14` → `3.8.1` (picks up sigil's own agnosys drop).

**v3.4.0 — Aho-Corasick scanner.** New `src/aho_corasick.cyr` (trie + failure
+ dict links, single O(n) pass). The code scanner's ~109 per-pattern
`cstr_contains` re-scans (O(patterns × n × m)) collapse into one pass +
per-pattern hit-table lookups — behavior-preserving (full scanner suite green),
with a `cstr_contains` fallback so the pattern list can only cost speed, never
correctness. Benchmarked **~12×** faster on a 16 KB artifact (6.60 ms → 0.54
ms), scaling with size. 413 tests.

**v3.3.4 — bounds-checked input validation (closes the v3.3.x arc).** The
untrusted-command-string screens (`is_safe_text`/`is_safe_argument`) now read
through a bounds-checked `[u8]` slice — an OOB read traps instead of touching
attacker-influenced memory. This is the last cc 6.0 modernization-arc item;
broader slice adoption was evaluated and deliberately bounded (subscripting is
read-only in 6.0.43; hot scanner paths excluded). 406 tests. The remaining
audit-flagged perf item — a kavach-side Aho-Corasick to replace the scanners'
per-pattern re-scan — is tracked as the next substantive investment.

**v3.3.3 — toolchain refresh + Result `_r`.** Cyrius pin `6.0.40` → `6.0.43`
(patch refresh, re-validated; drift warning cleared). Added a Result-returning
hardened secure write (`file_write_secure_r`) that preserves `O_EXCL|O_NOFOLLOW`
while surfacing a distinguishable `IoError` instead of `-1`; `quarantine_store`
now logs *why* a write failed. 402 tests.

**v3.3.2 — cc 6.0 stdlib adoption.** Container-ID entropy moved from
hand-rolled `/dev/urandom` open/read/close to the kernel CSPRNG via
`getrandom(2)` (stdlib `random.cyr`) — no fd lifecycle, one syscall, works
without `/dev` mounted (chroot/landlocked/minimal mount ns), strengthening the
unpredictable-id property. Cyrius pin stays `6.0.40`. 397 tests.

**v3.3.1 — memory-safety + hardening patch.** Post-3.3.0 source audit: fixed a
heap overflow in all nine exec-capture backends (NUL written one byte past the
capture buffer on full output) and the same off-by-one in the `/proc` integrity
readers; hardened the SGX/Firecracker `/tmp` workdir against symlink TOCTOU
(random name + `O_EXCL|O_NOFOLLOW`); bounds-checked backend dispatch; whole-token
cgroup controller match; corrected data-scanner evidence. Consolidated the
duplicated exec-backend epilogue into `backend.cyr` (so the overflow fix lands
once), and adopted the first cc 6.0 stdlib APIs (`getenv` for the wasm
`$HOME/.cargo/bin` probe, `chrono.clock_now_ns`). 394 tests; benchmarks flat vs
3.3.0. See CHANGELOG.

**v3.3.0 — Cyrius 6.0 toolchain + dependency jump.** Cyrius pin `5.10.44`
→ `6.0.40` and sigil `2.9.0` → `3.5.9` (latest), moving the repo onto the
cc 6.0 line and off the retired 5.10.x sigil-NI asm-offset bisect. Includes
the cc 6.0 symbol migration (sigil's `ct_eq` → stdlib `ct_eq_bytes_lens`;
renamed kavach helpers that collided with new stdlib/sigil symbols), an
agnosys `1.3.0` transitive override for cc 6.0.40 compatibility, and the
release-benchmark discipline (a `benches/bench-history.csv` row per
release). 384 tests, 20 benches. (The Landlock + `sandbox_fork_exec` + OCI
cgroup feature cut deferred from here is tracked in the
[roadmap](docs/development/roadmap.md) as v3.5.0.)

**v3.2 — cgroups v2 + HTTP credential proxy.** Two new feature modules:
[`src/cgroup.cyr`](src/cgroup.cyr) wires `SandboxPolicy.{memory_limit_mb,
cpu_limit_tenths, max_pids}` into per-sandbox cgroups via a race-tolerant
shell-prepend placement; [`src/credential_http.cyr`](src/credential_http.cyr)
exposes `GET /v1/secret/<name>` on a loopback HTTP listener with per-instance
allowlist + audit-chain integration (closes ADR-004 §4).

**v3.1 — modernization arc + closeout.** v3.1.0 brought the repo onto the
first-party-tree baseline (Cyrius pin 5.10.34, `cyrius.cyml` manifest,
`lib/` via `cyrius deps`, CI/release rewritten). v3.1.1 added the
`FileInjection.mode` honoring helper (ADR-005 §M2), cleared 37 lint
warnings, and removed the `rust-old/` archive (1.4 MB / 26K lines).
v3.1.2 filed coordinated P1 upstream issues for the remaining sandbox
blockers ([cyrius syscall wrappers](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md),
[sigil TEE attestation modules](https://github.com/MacCracken/sigil/blob/main/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md)).

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
| Lines | ~26K | ~6.5K |
| Backends registered | 10 | 10 — full set with real dispatch contracts |
| Scanner pipeline | 3 scanners | 3 scanners |
| Audit chain | HMAC-SHA256 via hmac/sha2 crates | HMAC-SHA256 via [sigil](https://github.com/MacCracken/sigil) |
| Tests | 872 | 422 |
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
| **Credential proxy** | In-memory `CredentialProxy` + env/file/stdin injection — plus loopback HTTP via `CredentialHttpProxy` (v3.2+, allowlist-gated, audit-logged) |
| **cgroups v2 limits** | `memory.max` / `cpu.max` (quota+period) / `pids.max` from `SandboxPolicy` (v3.2+, race-tolerant shell-prepend placement) |
| **Audit chain** | HMAC-SHA256 signed, prev-linked, JSONL on disk, tamper-detectable |
| **Quarantine** | File-based storage with status lifecycle (quarantined/approved/released/rejected) |
| **Lifecycle FSM** | Created → Running → Paused → Stopped → Destroyed |
| **Sandbox pool** | Pre-warmed `SandboxPool` with `claim()`/`replenish()` |

---

## Build

```sh
# Requires Cyrius 6.4.62 (pinned in cyrius.cyml; the first-party tree is
# on the cc 6.4 line — the old 5.10.x sigil-NI asm-offset bisect is
# retired). The pin matches the installed cycc; if cycc later drifts ahead,
# skip local fmt writes to avoid minor-version drift.

# 1. Resolve deps — populates lib/ (gitignored) with the cc 6.4.62
#    stdlib snapshot + sigil 3.11.1 at the pinned tag (the agnosys
#    dependency was dropped at 3.5.0; see cyrius.cyml).
cyrius deps

# 2. Build the binary.
cyrius build src/main.cyr build/kavach
./build/kavach

# Run the test suite (422 tests).
cyrius test tests/kavach.tcyr

# Run the bench harness (22 benches).
cyrius bench tests/kavach.bcyr

# Audit (fmt + lint + vet + deny + test + bench + doc).
cyrius audit
```

Dependencies (declared in [`cyrius.cyml`](cyrius.cyml)):
- **Cyrius stdlib** — `alloc, args, assert, async, bayan, bench, chrono, ct, dynlib, fdlopen, fmt, fnptr, freelist, fs, hashmap, hashmap_fast, io, keccak, mmap, net, process, random, result, sandhi, slice, str, string, syscalls, tagged, thread, thread_local, tls, vec` (resolved by `cyrius deps` into `lib/`, which is gitignored). The 6.2 line folded the standalone `json`/`base64` modules into `bayan` and retired `bigint` (sigil bundles its own `u256`/`u384`).
- **[sigil](https://github.com/MacCracken/sigil) 3.11.1** — SHA-256, HMAC-SHA256 (constant-time compare now via the stdlib `ct` module — sigil retired its own `ct_eq` in the 3.x line). Latest tag; the 5.10.x SIGILL bisect that capped it at 2.9.0 no longer applies under cc 6.4.62. The agnosys dependency was dropped at 3.5.0 — kavach internalized the Linux security backends it used (Landlock/seccomp, MAC, Linux-audit) as `src/` modules; see [`cyrius.cyml`](cyrius.cyml).

## Consume kavach as a library (v3.6.0+)

kavach ships a committed single-file source bundle, `dist/kavach.cyr`, so
downstream Cyrius projects can embed the sandbox surface at the source
level (the same shape the tree uses for sigil/patra/bhumi). In the
consumer's `cyrius.cyml`:

```toml
[deps.kavach]
git     = "https://github.com/MacCracken/kavach.git"
path    = "../kavach"          # local sibling checkout (optional)
tag     = "3.6.0"
modules = ["dist/kavach.cyr"]

# REQUIRED: kavach's transitive stdlib. `cyrius distlib` records only
# kavach's *direct* leaves in dist/kavach.deps; the bundle also pulls sigil
# (crypto: ct/keccak/thread/thread_local) and, via the credential proxy,
# sandhi (→ tls, and async) + bayan + the dynlib/fdlopen/mmap load paths.
# Per the Cyrius model the CONSUMER declares stdlib (distlib prints "stdlib
# is supplied by the consumer's [deps] stdlib list"); a consumer that omits
# these fails to LINK — undefined thread_local_* / sandhi_server_* /
# async_* / fdlopen_* / TLS_BACKEND_LIBSSL. Curating a minimal subset is
# fragile (the transitive needs cascade), so mirror kavach's own
# [deps].stdlib. The verified-working set (kavach's [deps].stdlib minus the
# test-only args/assert/bench) is:
[deps]
stdlib = [
    "alloc", "async", "bayan", "chrono", "ct", "dynlib", "fdlopen", "fmt",
    "fnptr", "freelist", "fs", "hashmap", "hashmap_fast", "io", "keccak",
    "mmap", "net", "process", "random", "result", "sandhi", "slice", "str",
    "string", "syscalls", "tagged", "thread", "thread_local", "tls", "vec",
]
```

Then `cyrius deps` materializes the bundle as the consumer's
`lib/kavach.cyr` and vendors the stdlib above (the transitive **sigil**
dep — and its own transitive sandhi/sakshi — resolve from kavach's
`[deps.sigil]`). Source-include it and call the surface:

```cyrius
include "lib/kavach.cyr"

fn app() {
    kavach_init();
    var cfg = config_new();
    config_backend(cfg, Backend.PROCESS);
    var sb = sandbox_create(cfg);
    sandbox_transition(sb, SandboxState.RUNNING);
    var r = sandbox_exec(sb, "echo hello");
    sandbox_destroy(sb);
    return 0;
}
```

The bundle excludes the program surface (`main()`, the demo, the top-level
`syscall(SYS_EXIT)`) that lives in `src/main.cyr`. Maintainers regenerate
the bundle after any `[lib]` module change with **`cyrius distlib`** (the
standard first-party dist flow, same as sigil/patra/bhumi); CI gates its
freshness. See
[ADR-006](docs/adr/006-library-surface-and-bundle-generation.md).

**Known integration caveats** (kavach is a heavy security engine — see
ADR-006 §Consequences):

- **Benign symbol overlaps.** kavach and sigil each internalized an
  `sys_error`/`sys_util` (the agnosys→agnodrm split), so a consumer sees
  `duplicate fn 'err_*' / 'agnosys_*' / 'syserr_*'` (`last definition
  wins`) warnings — the same ones kavach's own build emits. Non-fatal.
- **Namespaced error kinds (no `ERR_UNKNOWN` collision).** kavach's
  `SysErrorKind` members are prefixed `KAVACH_ERR_*` — e.g.
  `KAVACH_ERR_UNKNOWN = 7`, `KAVACH_ERR_SYSCALL_FAILED = 1` — precisely so
  they cannot collide with the generic `ERR_*` constants other deps mint,
  notably sakshi (sigil's tracing dep), whose `ERR_UNKNOWN = 1` would
  otherwise clash under last-def-wins. A consumer can distinguish every
  kavach error kind, and the generic `ERR_*` names stay free for sakshi and
  friends. (The constructor/accessor API — `err_unknown()`, `syserr_kind()`,
  … — is unchanged; only the enum constant names carry the prefix.)
- **~13 MB static scan tables** ride along; build with `CYRIUS_DCE=1` to
  drop the unreachable surface.

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
