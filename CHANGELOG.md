# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0-cyrius] — 2026-04-13 (in progress)

Full language migration — Rust v1.x → Cyrius. This is a ground-up rewrite
preserving the public API surface but rebuilding the internals on the Cyrius
toolchain. 25,935 lines of Rust → 20 Cyrius modules. See
[ADR-001](docs/adr/001-cyrius-port-architecture.md) for the port rationale.

### Added
- **WASM backend** (`src/backend_wasm.cyr`) — `wasmtime run` shell-out with fuel-based CPU metering (`--fuel`), memory limit (`--max-memory-size`), and directory preopens (`--dir`). Takes a `.wasm` file path as the command. Registers into the dispatch table.
- **OCI backend** (`src/backend_oci.cyr`) — `runc`/`crun` shell-out against the shared OCI bundle. Picks first available runtime from PATH. Same dispatch registration pattern as gVisor.
- **Shared OCI spec module** (`src/oci_spec.cyr`) — extracted from the gVisor backend: container-id generation, JSON escape, minimal runtime spec v1.0.2, bundle mkdir, and cleanup (unlink config.json, rmdir rootfs/, rmdir bundle/). Both gVisor and OCI backends call into this.
- **Bundle cleanup on exit** — `oci_cleanup_bundle(bundle)` called after every exec regardless of outcome. Prevents `/tmp/kavach-gvisor-*` and `/tmp/kavach-oci-*` accumulation.
- **gVisor backend** (`src/backend_gvisor.cyr`) — OCI bundle generation + `runsc run` + auto-cleanup. Registers into the dispatch table via `backend_gvisor_register()`. Proves ADR-002's "3-line extension" pattern: same dispatch slot layout, different `exec_fn`.
- **`path_exists` + `which_exists`** (real implementations via `access(2)` syscall) — replaces the v2.0-alpha stubs that always returned 0. Enables meaningful `backend_is_available()` probes and `resolve_best_backend()` ranking.
- **24 Cyrius modules** (was 20)

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
