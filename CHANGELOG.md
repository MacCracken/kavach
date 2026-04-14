# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0-cyrius] — 2026-04-13 (in progress)

### Added (gap-close wave)
- **CompositeBackend port** (`src/composite.cyr`) — `merge_policies(base, overlay)` with stricter-wins semantics, `score_composite(outer, inner, policy)` returning the layered score with +5 defense-in-depth bonus, and `composite_exec(...)` for executing through an outer backend with a merged inner policy.
- **Observability types** (`src/observability.cyr`) — `HealthStatus`, `HealthState` enum, `health_probe(sandbox)`, `SandboxMetrics` struct (CPU/memory/PID/IO/wall fields; cgroup-backed populator pending), `sandbox_metrics_from_result`, `SpawnedProcess` handle for fire-and-forget execs.
- **Attestation types** (`src/attestation.cyr`) — `AttestationResult` + `AttestationTrust` enum (Contraindicated < Warning < None < Affirming), `attestation_is_acceptable(result, min_trust)`, `SgxAttestationReport` with `sgx_report_verify_structure` (MRENCLAVE/MRSIGNER hex + IAS signature length check; full cryptographic verify deferred to v2.1 sigil EAR helpers).
- **33 Cyrius modules total** — added composite.cyr + observability.cyr + attestation.cyr.

### Documentation
- **Benchmarks — Rust v1.x vs Cyrius v2.1** (`benchmarks-rust-v-cyrius.md`) — apples-to-apples per-op comparison with honest commentary on where Cyrius is slower (unoptimized codegen tax) and where it's faster (no tokio startup on sandbox lifecycle).
- **Guides** (`docs/guides/`): getting-started (build → configure → execute), composite-backends (defense-in-depth merge rules), threat-tracking (intent scoring + OffenderTracker + decay tuning).
- **Worked examples** (`docs/examples/`): 4 progressive walkthroughs covering Noop, Process+audit, scanner verdicts with WARN redaction, offender tracking across execs.
- **rust-old removal readiness** (`docs/development/rust-old-removal.md`) — per-symbol audit confirming Cyrius coverage, pre-removal checklist, removal command.
- **Benchmark harness** (`tests/kavach.bcyr`) — 15 benches via `lib/bench.cyr` covering scoring, policy build, credentials, scanners, gate, lifecycle, audit.
- **349 tests** (was 326) — 23 new tests for composite merge + score, health probe, metrics, attestation trust ordering, SGX report structure.

### Feature closeout wave (v2.0 → v2.1 ready queue)

Drains 5 of the 7 "ready" items from the internal roadmap; leaves
`FileInjection.mode` helper and `cyrius audit` for future sweep.

- **UUID v4 IDs** — Sandbox, ScanFinding, and Quarantine entry ids are now 64-bit random values from `/dev/urandom` via new `util.cyr::rand_u64`. Monotonic counters removed. Collision probability across 2^32 entries is ~2^-32.
- **Secret redaction on WARN verdict** — `secrets_redact(text)` walks the text once, rewrites every secret-pattern span to `[REDACTED:CATEGORY]`, returns the cleaned cstr. `gate_apply` now invokes it on `stdout`/`stderr` when the verdict is WARN and `policy.redact_secrets == 1`.
- **OffenderTracker** — `offender_tracker_new/with_config/record/prune/agent_score/should_escalate/count`. Per-agent violation score accumulates with integer-only half-life decay (score × decay_factor^(age / half_window)). Defaults match the Rust original: 1h window, decay 0.5 per half-window, escalation threshold 3.0.
- **Sandbox integrity monitoring** — `check_integrity()` returns an `IntegrityReport{intact, checks[3], checked_at}` verifying PID namespace (`/proc/1/cmdline` not systemd/init), mount namespace (`/proc/mounts` no host `/home` without overlay), and user namespace (`/proc/self/uid_map` populated).
- **Integer-overflow guards completed (M1 closeout)** — new `checked_sum4` + `alloc_checked` wired through audit `_sign_input`/`_entry_to_jsonl`, quarantine `_qpath`/`_meta_jsonl`, and `oci_generate_spec`. Every multi-term allocation refuses negative sizes or anything over 64 MiB per single allocation.

### Changed
- **`QuarantineStorage.next_id` field retained for ABI** but no longer incremented. Entry IDs come from `rand_u64()` per `quarantine_store()` call.
- **349 tests passing, 0 failing** (was 262 at start of v2.1 cycle).
- **33 Cyrius modules** (v2.0 shipped 30, v2.1 added composite + observability + attestation).

---

## [2.0.0-cyrius] — 2026-04-13

Full language migration — Rust v1.x → Cyrius. This is a ground-up rewrite
preserving the public API surface but rebuilding the internals on the Cyrius
toolchain. 25,935 lines of Rust → 20 Cyrius modules. See
[ADR-001](docs/adr/001-cyrius-port-architecture.md) for the port rationale.

### Security
- **P(-1) hardening pass completed** — see [ADR-005](docs/adr/005-v2-hardening-pass.md). Fixes applied, with CWE/CVE analogs:
  - **Constant-time HMAC verification** (CWE-208, CVE-2016-2107 class) — `audit_entry_verify` now uses sigil `ct_eq` via new `util.cyr::ct_streq`. HMAC-signing-key extraction via verify-latency oracle is closed.
  - **Full RFC 8259 JSON escape** (CWE-116, CVE-2021-44228 class) — `oci_json_escape` now escapes all control chars 0x00–0x1F as `\uXXXX` with short forms for `\b\f\t\n\r`. Audit JSONL routes `event_type` + `payload` through it; quarantine metadata escapes `sandbox_id`. Log forgery via control chars in user-controlled strings is closed.
  - **Symlink TOCTOU on /tmp** (CWE-59, CVE-2024-21626 class) — container IDs include 16 random hex chars from `/dev/urandom`. `oci_prepare_bundle` uses mode 0700 + checks `sys_mkdir` returns; files via new `file_write_secure()` with `O_CREAT|O_EXCL|O_NOFOLLOW`. Symlink-preseed redirection of config writes is closed.
  - **Sensitive artifacts mode 0600** (CWE-276) — audit log + quarantine `.bin`/`.meta` + OCI/FC/SGX configs now created with mode 0600 (not stdlib default 0644). Audit log additionally `sys_chmod`-tightened after `file_append_locked`.
  - **Secret evidence redaction** (CWE-532) — `_evidence_copy` in scanner now keeps first 4 + `****` + last 4; full secrets never land in findings, audit logs, or quarantine files. Prefix preserves signal (`AKIA****…`) without leaking the secret.
  - **Argument smuggling via control chars** (CWE-88) — `backend_process.cyr::process_exec` rejects commands with any byte < 0x20 except tab. Newline-smuggled second tokens past the runtime guard are closed.
  - **HMAC key lifetime** (CWE-316, CVE-2019-1559 class) — new `audit_chain_close(chain)` calls sigil `zeroize_key` on the key buffer and clears the chain's pointer.
  - **Integer overflow guards** (CWE-190, partial) — new `util.cyr::checked_add` + `checked_mul`. `oci_json_escape` caps input at 1 MiB before the ×6 expansion.
- **32 new hardening-specific tests** added to `tests/kavach.tcyr` (constant-time comparator, JSON control-char escape, argument-smuggling rejection, overflow guards, redacted evidence, key zeroing).

### Added
- **All 10 backends registered** — Noop, Process, gVisor, OCI, WASM, SyAgnos, SGX, SEV, TDX, Firecracker. Dispatch table fully populated; ADR-002's extension pattern is fully demonstrated.
- **SyAgnos backend** (`src/backend_sy_agnos.cyr`) — docker/podman shell-out against the hardened AGNOS container image (`ghcr.io/maccracken/agnos:latest`), with Phylax scanner extending the secrets scanner to detect verity violations, nftables bypass, namespace escape, and mount-escape attempts.
- **SGX backend** (`src/backend_sgx.cyr`) — `gramine-sgx` with an auto-generated Gramine manifest. Requires `/dev/sgx_enclave`.
- **SEV backend** (`src/backend_sev.cyr`) — `qemu-system-x86_64` with SEV-SNP confidential-guest object. Requires `/dev/sev`.
- **TDX backend** (`src/backend_tdx.cyr`) — `qemu-system-x86_64` with tdx-guest object. Requires `/dev/tdx_guest`.
- **Firecracker backend** (`src/backend_firecracker.cyr`) — minimal microVM config.json + `firecracker --no-api --config-file`. Jailer/vsock/snapshot deferred.
- **WASM backend** (`src/backend_wasm.cyr`) — `wasmtime run` shell-out with fuel-based CPU metering (`--fuel`), memory limit (`--max-memory-size`), and directory preopens (`--dir`). Takes a `.wasm` file path as the command. Registers into the dispatch table.
- **OCI backend** (`src/backend_oci.cyr`) — `runc`/`crun` shell-out against the shared OCI bundle. Picks first available runtime from PATH. Same dispatch registration pattern as gVisor.
- **Shared OCI spec module** (`src/oci_spec.cyr`) — extracted from the gVisor backend: container-id generation, JSON escape, minimal runtime spec v1.0.2, bundle mkdir, and cleanup (unlink config.json, rmdir rootfs/, rmdir bundle/). Both gVisor and OCI backends call into this.
- **Bundle cleanup on exit** — `oci_cleanup_bundle(bundle)` called after every exec regardless of outcome. Prevents `/tmp/kavach-gvisor-*` and `/tmp/kavach-oci-*` accumulation.
- **gVisor backend** (`src/backend_gvisor.cyr`) — OCI bundle generation + `runsc run` + auto-cleanup. Registers into the dispatch table via `backend_gvisor_register()`. Proves ADR-002's "3-line extension" pattern: same dispatch slot layout, different `exec_fn`.
- **`path_exists` + `which_exists`** (real implementations via `access(2)` syscall) — replaces the v2.0-alpha stubs that always returned 0. Enables meaningful `backend_is_available()` probes and `resolve_best_backend()` ranking.
- **30 Cyrius modules** (was 20)

### Fixed
- **`cyrius.toml` sigil path** — switched from `path = "../sigil"` to
  absolute path to work around a `cyrius deps` bug where relative `path`
  entries produce broken symlinks in `lib/`. Symptom was
  `undefined function 'hmac_sha256'` despite successful dep resolution.
  Fix is temporary; file upstream for cyrius 4.4.0.: `error`, `util`, `backend`, `policy`, `scoring`,
  `lifecycle`, `scanning_types/_secrets/_code/_data/_gate/_runtime/_threat`,
  `audit`, `credential`, `quarantine`, `backend_dispatch/_noop/_process`,
  `sandbox_exec`
- **Function-pointer dispatch table** for backends — O(1) lookup, O(3-line)
  extension cost. See [ADR-002](docs/adr/002-backend-dispatch-fnptr-table.md).
- **Fixed-point threat scoring** — intent_score is `_x1000` (0..1000). See
  [ADR-003](docs/adr/003-fixed-point-threat-scoring.md).
- **HMAC-SHA256 audit chain** via [sigil](https://github.com/MacCracken/sigil) ≥ 2.1.2
- **End-to-end demo** (`./build/kavach`): backend dispatch → gate → threat →
  audit, writes `/tmp/kavach-demo.audit` with linked HMAC chain.
- **Architecture docs**: [overview](docs/architecture/overview.md) +
  4 ADRs + README rewrite for the Cyrius edition.
- **Integration tests**: real `/bin/echo` fork+exec via PROCESS backend;
  full scanner pipeline validated with synthetic inputs.

### Changed
- **Language**: Rust 2021 → Cyrius 4.0.0+
- **Async → sync**: all exec paths are synchronous in v2.0. See
  [ADR-004 §1](docs/adr/004-deferred-features.md).
- **Build tool**: `cargo` → `cyrius build`
- **Dependency model**: `Cargo.toml` → `cyrius.toml`; binary deps via sigil
- **Test runner**: `cargo test` → `cyrius test tests/kavach.tcyr`
- **Module layout**: nested `src/<module>/mod.rs` → flat `src/<module>.cyr`

### Deferred — see [ADR-004](docs/adr/004-deferred-features.md)
- 8 of 10 backends (Noop + Process shipped; slots reserved for the other 8)
- Seccomp / Landlock / cgroups kernel-level enforcement hooks
- HTTP credential proxy (direct env/file/stdin injection shipped)
- OffenderTracker (per-exec threat classification shipped)
- Sandbox integrity monitoring (`/proc` readers)
- Secret redaction on WARN verdict
- UUID v4 (monotonic counters shipped — audit HMAC covers trust boundary)
- Full PCRE regex (literal-prefix + char-class matchers shipped for all
  distinctive secret/data patterns)

### Removed
- `rust-old/` contains the entire v1.x Rust source (25,935 lines) preserved
  for reference. Will be deleted in v2.1 once port reaches feature parity.
- Cargo workspace, Makefile, `deny.toml`, `rust-toolchain.toml` —
  replaced by `cyrius.toml`.

---

## [2.0.0] — 2026-04-02 (Rust, superseded by 2.0.0-cyrius)

### Added
- **Firewall types in agnosys** — `TrafficDirection`, `Protocol`, `FirewallAction` enums, `FirewallRule` and `FirewallPolicy` structs with constructors, `apply_firewall_rules()` function, nftables ruleset rendering
- **`sandbox_core` module enabled** — unblocked by agnosys firewall API; `#[cfg(feature = "agnostik")]` now compiles and links
- **Delegation depth limit** — capability token delegation chains capped at 5 levels to prevent unbounded chains
- **Process substitution detection** — `<(` and `>(` patterns added to code scanner shell metacharacter group
- **`shell_words()` validation** — now returns `Result` and rejects unclosed quotes instead of silently accepting malformed input
- **Namespace check fail-safe** — `is_in_separate_namespace()` returns `true` (assume isolated) when namespace inodes are unreadable, preventing false-negative escape verdicts
- **Exec timeout enforcement** — `child.wait()` now bounded by remaining timeout budget; prevents zombie processes hanging indefinitely after I/O completes
- 5 new tests: unclosed quote rejection, process substitution detection, delegation depth, cascade revocation, namespace fail-safe

### Changed
- **Dependencies updated** — hmac 0.12→0.13, sha2 0.10→0.11, nix 0.29→0.31, seccompiler 0.4→0.5, oci-spec 0.7→0.9, wasmtime 42→43, criterion 0.5→0.8, libc 0.2.183→0.2.184
- **HMAC `KeyInit` import** — adapted `scanning::audit` for hmac 0.13 API change
- **`deny.toml`** — added `GPL-3.0-only` and `CDLA-Permissive-2.0` to license allowlist
- **agnos-common workspace license** — corrected from deprecated `GPL-3.0` to `GPL-3.0-only`
- Dependency count reduced from 513 to 448 crates

### Fixed
- 6 collapsible-if clippy warnings in `v2.rs` and `credential_proxy.rs`
- 2 collapsible-if clippy warnings in `sandbox_core.rs` teardown

### Security
- P(-1) scaffold hardening audit completed — 13 findings across security, correctness, and performance
- 872 tests passing (up from 561 at v1.0.0)

## [1.0.0] — 2026-03-25

### Added
- **TDX backend** (`Backend::Tdx`) — Intel Trust Domain Extensions, 10th backend variant (strength 85)
- **Backend auto-selection** — `Backend::resolve_best()` ranks by strength; `resolve_min_strength()` filters by minimum
- **`SandboxPool`** — pre-warmed sandbox pool with `claim()`/`replenish()` for fast startup
- **`CompositeBackend`** — stack isolation layers with policy merging (stricter-wins, intersected allowlists, +5 scoring bonus)
- **`Backend::FromStr`** — parse backend names case-insensitively, returns `KavachError`
- **`SandboxPolicy::from_preset()`** — parse policy preset by name
- **Code scanner** (`scanning::code`) — 25 pattern groups: command injection, exfiltration, privilege escalation, supply chain, obfuscation, filesystem abuse, crypto misuse
- **Data scanner** (`scanning::data`) — PII (Visa/MC/Amex/IBAN, phone, IPv4) and compliance (HIPAA, GDPR, PCI-DSS, SOC2)
- **Threat classifier** (`scanning::threat`) — intent scoring (0.0-1.0), 7 kill-chain stages, co-occurrence amplification, 4-tier escalation
- **Repeat offender tracker** — rolling window + time decay + per-agent scoring
- **Quarantine storage** (`scanning::quarantine`) — file-based with metadata sidecar, approval/reject workflow
- **Audit chain** (`scanning::audit`) — HMAC-SHA256 append-only log with chain verification and tamper detection
- **Runtime guards** (`scanning::runtime`) — fork bomb detection, 15-path sensitive blocklist, 26-command blocklist, shell metacharacter detection, time anomaly checks
- **Sandbox integrity monitoring** — PID/mount/user namespace isolation verification
- **Entropy-based secret detection** — Shannon entropy > 4.5 on unrecognized high-entropy strings
- **Multi-scanner gate** — ExternalizationGate runs secrets + code + data scanners on every exec
- **HTTP credential proxy** (`credential::http_proxy`) — transparent proxy on 127.0.0.1, Authorization header injection, CONNECT tunneling, host allowlist
- **SEV attestation** — `SevAttestationReport`, `SevAttestationPolicy`, `SevGuestPolicy` with composable bit flags
- **SGX attestation** — `SgxAttestationReport`, `SgxAttestationPolicy`, sealed data API (`SealedData`, `SealKeyPolicy`)
- **Unified attestation** (`backend::attestation`) — `Attestable` trait, `AttestationResult`, EAR conversion for Veraison/IETF RATS
- **Phylax scanner** (SyAgnos) — verity violation + nftables bypass + namespace/mount escape detection
- **Image managers** — `SyAgnosImageManager` and `OciImageManager` for pull/build/list
- **Firecracker** — vsock communication, snapshot/restore, network TAP with iptables isolation
- **Dependencies** — `hmac` v0.12, `sha2` v0.10, `ear` v0.5 (optional), `sigstore` v0.13 (optional)
- **Infrastructure** — `scripts/bench-history.sh`, `make semver`, overhead benchmark, `.cargo/audit.toml`

### Changed
- **Seccomp blocklist** expanded from 14 to 17 entries (added `io_uring_setup`, `io_uring_enter`, `io_uring_register`)
- **Audit chain** upgraded from SipHash to cryptographic HMAC-SHA256
- **`AttestationTrust` ordering** — now `Contraindicated < Warning < None < Affirming` (higher = more trusted)

### Fixed
- Zombie process leak on I/O error path in `execute_with_timeout`
- `eprintln!` in pre_exec replaced with `libc::write(2)` for async-signal-safety
- All `tracing::*` calls removed from post-fork path (namespaces, landlock, capabilities)
- iptables rule ordering — ACCEPT ESTABLISHED before DROP in TAP config
- IP overflow in `TapConfig::for_vm()` for > 60 VMs
- Gate stdout/stderr boundary — newline separator prevents false positives
- SGX seal/unseal — direct tool invocation instead of shell command
- Vsock CONNECT response validation
- Audit chain — `sorted_json` propagates errors instead of swallowing
- HTTP proxy — CRLF sanitization, 8 KiB request line cap, exact/suffix host matching
- Composite network allowlists intersected (not unioned)
- `cgroups.rs` — `.unwrap()` replaced with `.unwrap_or()`

### Performance
- Seccomp BPF cache — 61-71x faster filter retrieval via `LazyLock`
- Capabilities cache — `OnceLock` eliminates 5 `/proc` reads per exec
- UTF-8 zero-copy — `lossy_utf8()` avoids 1 MiB copy for valid output
- Cow redact — `SecretsScanner::redact()` returns `Cow<str>`, zero-copy when clean
- Gate caching — `ExternalizationGate` created once per sandbox
- Policy clone optimization — `LandlockParams` extracts only needed fields; rlimits use raw scalars
- Code scanner patterns pre-lowercased, no per-match allocation
- `resolve_min_strength` scores each backend once via `filter_map`

### Security
- `#[non_exhaustive]` on all 18 public enums and key structs
- `#[must_use]` on ~35 pure functions
- `#[inline]` on ~12 hot-path functions
- `// SAFETY:` comments on all 4 unsafe blocks
- All public items documented (0 `missing_docs` warnings)
- 561 tests across 35 source files

## [0.22.3] — 2026-03-22

### Changed
- Version bump for stiva 0.22.3 ecosystem release

## [0.21.4] — 2026-03-21

### Fixed
- aarch64 Linux build — legacy syscalls mapped to modern equivalents via `#[cfg(target_arch)]`
- cargo-deny license failure — added `MPL-2.0` for `sized-chunks` (wasmtime)
- Release workflow packages platform binaries as `kavach-{version}-{arch}.tar.gz`

## [0.21.3] — 2026-03-21

### Added
- `#[derive(Debug)]` on all backend structs
- `#[must_use]` on `Backend::is_available()` and `Backend::available()`
- 39 tests (error.rs, gVisor, OCI, exec_util)
- Benchmark history log

### Changed
- Extracted `execute_with_timeout()` — eliminated ~250 lines of duplication across 7 backends
- `which_first()` returns `&str` instead of allocating

### Fixed
- OCI backend missing `#[derive(Debug)]` with `--features full`

### Performance
- `secrets_redact` 2.4x faster (single-pass replacement)
- LazyLock regex caching
- `shell_words()` pre-allocates capacity

## [0.21.2] — 2026-03-21

### Added
- Benchmark suite — 23 benchmarks
- Adversarial integration tests — 30 tests

## [0.21.1] — 2026-03-21

### Added
- gVisor and OCI backends
- Health monitoring, sandbox metrics, OCI spec generation, Firecracker config

## [0.21.0] — 2026-03-21

### Added
- Initial release — Backend trait, 7 backends, strength scoring, policy engine, credential proxy, secrets scanner, externalization gate, lifecycle FSM
