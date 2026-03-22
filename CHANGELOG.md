# Changelog

All notable changes to kavach are documented here.

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
