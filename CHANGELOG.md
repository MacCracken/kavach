# Changelog

All notable changes to kavach are documented here.

## [1.0.0] — 2026-03-25

### Added — Backends
- **TDX backend** (`Backend::Tdx`) — Intel Trust Domain Extensions, 10th backend variant (strength 85)
- **Backend auto-selection** — `Backend::resolve_best()` ranks available backends by strength score; `resolve_min_strength()` filters by minimum threshold
- **`SandboxPool`** — pre-warmed sandbox pool with `claim()`/`replenish()` for fast startup
- **`Backend::FromStr`** — parse backend names from strings (case-insensitive)
- **`SandboxPolicy::from_preset()`** — parse policy preset by name

### Added — Scanning Pipeline
- **Code scanner** (`scanning::code`) — 25 pattern groups detecting command injection, data exfiltration, privilege escalation, supply chain attacks, obfuscation, filesystem abuse, crypto misuse
- **Data scanner** (`scanning::data`) — PII detection (Visa/MC/Amex/IBAN, phone, IPv4) and compliance keywords (HIPAA, GDPR, PCI-DSS, SOC2)
- **Threat classifier** (`scanning::threat`) — intent scoring (0.0–1.0), kill-chain stage tracking (7 stages), co-occurrence amplification, 4-tier classification (benign/suspicious/likely_malicious/malicious)
- **Repeat offender tracker** (`scanning::threat::OffenderTracker`) — rolling window + time decay + per-agent scoring + escalation recommendations
- **Quarantine storage** (`scanning::quarantine`) — file-based artifact quarantine with metadata sidecar, approval/reject workflow, list/remove
- **Audit chain** (`scanning::audit`) — keyed-hash append-only event log with chain verification and tamper detection
- **Runtime guards** (`scanning::runtime`) — fork bomb detection, sensitive path blocklist (15 paths), command blocklist (26 blocked), shell metacharacter detection, time anomaly checks
- **Sandbox integrity monitoring** (`scanning::runtime::check_integrity`) — PID/mount/user namespace isolation verification
- **Entropy-based detection** — Shannon entropy analysis (> 4.5) for unrecognized high-entropy strings
- **Multi-scanner gate** — ExternalizationGate now runs secrets + code + data scanners on every exec

### Added — Credential Proxy
- **HTTP credential proxy** (`credential::http_proxy`) — transparent HTTP/HTTPS proxy on 127.0.0.1 ephemeral port with Authorization header injection for known hosts, CONNECT tunneling for HTTPS, host allowlist enforcement

### Added — Hardware Enclaves
- **SEV attestation** — `SevAttestationReport`, `SevAttestationPolicy`, structural verification (SHA-384 measurement, VMPL, signature length)
- **SEV guest policy** — `SevGuestPolicy` with composable bit flags (SMT, migration, debug, single-socket, ABI version), replaces hardcoded 0x30000
- **SGX attestation** — `SgxAttestationReport`, `SgxAttestationPolicy`, MRENCLAVE/MRSIGNER/IAS signature verification
- **SGX sealed data** — `SealedData`, `SealKeyPolicy` (MrEnclave/MrSigner) for encrypt/decrypt to enclave identity

### Added — SyAgnos
- **Phylax scanner** — secrets + verity violation + nftables bypass + namespace/mount escape detection
- **Image manager** — `SyAgnosImageManager` with pull/build/list_local via container runtime

### Added — Firecracker
- **Vsock communication** — `VsockConnection` with CONNECT handshake + response validation
- **Snapshot/restore** — `SnapshotConfig` with full/diff types, checkpoint/restore via Firecracker API
- **Network TAP** — `TapConfig` with iptables isolation rules (ESTABLISHED before DROP)

### Added — OCI
- **Image pull** — `OciImageManager` with skopeo/crane/runtime pull + tar unpack

### Added — Infrastructure
- `scripts/bench-history.sh` — benchmark CSV history tracking
- `make semver` target — cargo-semver-checks in Makefile
- Overhead benchmark — `direct_spawn_echo` vs `kavach_process_echo_minimal`

### Performance
- **Seccomp BPF cache** — compiled filters cached via `LazyLock`, 61–71x faster on subsequent calls
- **Capabilities cache** — `OnceLock` eliminates 5 `/proc` reads per exec
- **UTF-8 zero-copy** — `lossy_utf8()` avoids 1 MiB copy when output is valid UTF-8
- **Cow redact** — `SecretsScanner::redact()` returns `Cow<str>`, zero-copy when no secrets found
- **Gate caching** — `ExternalizationGate` created once per sandbox, not per exec
- **Code scanner** — patterns pre-lowercased, eliminates per-match allocation

### Fixed
- **Zombie process leak** — child process now killed on I/O error path in `execute_with_timeout`
- **`eprintln!` in pre_exec** — replaced with `libc::write(2)` for true async-signal-safety
- **iptables rule ordering** — ACCEPT ESTABLISHED before DROP in TAP config
- **IP overflow** — `TapConfig::for_vm()` now supports > 60 VMs with multi-octet addressing
- **Gate boundary** — stdout/stderr joined with newline separator to prevent false positives
- **SGX seal/unseal** — direct tool invocation instead of shell command
- **Vsock** — CONNECT response validation (checks for "OK" before proceeding)
- **Audit chain** — sorted JSON for deterministic HMAC computation

### Hardening
- `#[non_exhaustive]` on all public enums and key structs (SandboxState, InjectionMethod, ScanVerdict, Severity, KillChainStage, ThreatTier, EscalationTier, SealKeyPolicy, SnapshotType, ViolationType, QuarantineStatus, RuntimeGuardConfig, IntegrityReport, ThreatAssessment)
- `#[must_use]` on ~35 pure functions
- `#[inline]` on ~12 hot-path functions
- `// SAFETY:` comments on all 4 unsafe blocks
- io_uring syscalls (`io_uring_setup/enter/register`) added to seccomp blocklist
- All public items documented (0 `missing_docs` warnings)
- 541 tests across 33 source files

### v1.0 Criteria Met
- [x] 10 backends implemented and tested
- [x] Strength scoring validated against SY reference scores
- [x] CredentialProxy handles all injection methods + HTTP proxy
- [x] Externalization gate tested with adversarial inputs (30+ patterns)
- [x] 541 tests passing (adversarial, unit, integration, doc)
- [x] Lifecycle FSM formally verified (exhaustive 5×5 matrix)
- [x] 3+ downstream consumers (stiva >=0.25, kiran 0.25, SY)
- [x] docs.rs complete
- [x] No unsafe without SAFETY comments
- [x] cargo-semver-checks in CI

## [0.22.3] — 2026-03-22

### Changed
- Version bump for stiva 0.22.3 ecosystem release

## [0.21.4] — 2026-03-21

### Fixed
- **aarch64 Linux build** — map legacy syscalls (`open`, `stat`, `lstat`, `poll`, `access`, `pipe`, `select`, `dup2`, `fork`, `vfork`, `getdents`, `rename`, `mkdir`, `rmdir`, `link`, `unlink`, `symlink`, `readlink`, `chmod`, `chown`, `getrlimit`, `epoll_create`, `epoll_wait`, `sendfile`) to modern equivalents (`openat`, `newfstatat`, `ppoll`, `faccessat`, etc.) via `#[cfg(target_arch)]` in seccomp filter
- **cargo-deny license failure** — added `MPL-2.0` to allowed licenses for `sized-chunks` dependency (via wasmtime)
- **Release artifacts** — release workflow now packages platform binaries as `kavach-{version}-{arch}.tar.gz` with SHA-256 checksums attached to GitHub releases

## [0.21.3] — 2026-03-21

### Performance
- **secrets_redact 2.4x faster** — single-pass replacement instead of 16 sequential `replace_all()` calls
- LazyLock regex caching — compiled patterns shared globally, zero-cost scanner construction
- Landlock rules borrowed instead of cloned in pre_exec path
- `shell_words()` pre-allocates capacity
- `which_first()` returns `&str` instead of allocating

### Refactored
- Extracted `backend::exec_util::execute_with_timeout()` — eliminated ~250 lines of duplicated spawn/collect/timeout/kill across 7 backends
- Consolidated runtime detection via `backend::which_first()` for OCI and SyAgnos
- Narrowed `oci_spec::network_mode()`, `container_id()`, `build_env()` from `pub` to `pub(crate)`

### Added
- `#[derive(Debug)]` on all backend structs (ProcessBackend, FirecrackerBackend, GVisorBackend, OciBackend, SgxBackend, SevBackend, SyAgnosBackend, NoopBackend)
- `#[must_use]` on `Backend::is_available()` and `Backend::available()`
- 11 tests for `error.rs` (all error variants, Display impls, From conversions, Send+Sync)
- 11 tests for gVisor backend (env, network, OCI spec generation, write_spec, container IDs)
- 12 tests for OCI backend (env, network, runtime detection, spec generation, write_spec)
- 5 tests for `exec_util` (echo, timeout, nonzero exit, stderr capture, bad binary)
- Benchmark history log (`benches/BENCHMARK_HISTORY.md`)

### Fixed
- OCI backend missing `#[derive(Debug)]` causing compile error with `--features full`

## [0.21.2] — 2026-03-21

### Added
- Benchmark suite (`benches/sandbox.rs`) — 23 benchmarks covering scoring, detection, policy, config, credentials, scanning, lifecycle, seccomp, and process execution
- Adversarial integration tests (`tests/adversarial.rs`) — 30 tests for seccomp, externalization gate, TPM attestation, and composition

## [0.21.1] — 2026-03-21

### Added
- gVisor (`runsc`) and OCI (`runc`/`crun`) backends
- Health monitoring (`backend::health`)
- Sandbox metrics (`backend::metrics`) — CPU, memory, cgroup stats
- OCI runtime spec generation (`backend::oci_spec`)
- Firecracker VM config generation (`backend::firecracker::config`)

## [0.21.0] — 2026-03-21

### Added
- Initial release
- Backend trait abstraction (`SandboxBackend`) with Process, Firecracker, WASM, SGX, SEV, SyAgnos, Noop backends
- Strength scoring engine (0–100)
- Policy engine — seccomp profiles, Landlock rules, network allowlists, resource limits
- Credential proxy — secrets injection via env vars, files, stdin
- Secrets scanner — 17 patterns (AWS keys, GitHub tokens, JWTs, private keys, connection strings, PII)
- Externalization gate — scan/redact/block sandbox output before release
- Sandbox lifecycle FSM — create, start, pause, stop, destroy
