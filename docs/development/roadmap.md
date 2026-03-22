# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## v0.21.3 — Foundation

- [x] Backend enum (8 variants: Process, gVisor, Firecracker, WASM, OCI, SGX, SEV, Noop)
- [x] SandboxBackend trait (exec, health_check, destroy)
- [x] Backend availability detection (PATH check, sysfs, feature flags)
- [x] StrengthScore (0-100) with base scores and policy modifiers
- [x] SandboxPolicy (seccomp, Landlock, network, resource limits, presets)
- [x] CredentialProxy (register, resolve, env_vars generation)
- [x] SecretRef with InjectionMethod (EnvVar, File, Stdin)
- [x] Sandbox lifecycle FSM (Created → Running → Paused → Stopped → Destroyed)
- [x] SandboxConfig builder pattern
- [x] ExecResult (exit code, stdout, stderr, duration, timeout flag)
- [x] KavachError with structured error types
- [x] Tests, CI/CD, benchmarks scaffold

---

## v0.22.3 — Process Backend

### Process isolation (the default backend)
- [x] Spawn child process with `tokio::process::Command`
- [x] Seccomp-bpf filter application (denylist basic + allowlist strict profiles)
- [x] Landlock filesystem restriction enforcement
- [x] Linux namespace isolation (PID, mount, network, user)
- [x] Timeout enforcement with kill-on-timeout
- [x] stdout/stderr capture with 1MB size limits
- [x] Resource limits via cgroups v2 (memory, CPU, PIDs) with setrlimit fallback
- [x] Capability dropping (CAP_SYS_ADMIN, CAP_SYS_PTRACE, etc.)
- [x] Best-effort isolation — degrades gracefully without privileges

### Platform detection
- [x] Seccomp mode detection from /proc/self/status
- [x] Landlock ABI version probing with kernel version fallback
- [x] cgroup v2 detection from /proc/mounts
- [x] Namespace availability check

### Externalization gate
- [x] Content policy check on sandbox output before release
- [x] 17 secret detection patterns (AWS, GitHub, Stripe, JWTs, private keys, PII)
- [x] Verdict system (pass/warn/quarantine/block)
- [x] Secret redaction in output
- [x] File size limits on externalized data

### Backend dispatch
- [x] Sandbox holds Box<dyn SandboxBackend>, delegates exec/destroy
- [x] NoopBackend for testing
- [x] create_backend() factory with feature-gated dispatch

---

## v0.23.3 — gVisor & OCI Backends

### gVisor (runsc)
- [x] OCI bundle creation for gVisor runtime
- [x] runsc run with config-file startup and timeout
- [x] Network isolation (--network=none when disabled)
- [x] Container cleanup (kill + delete --force)

### OCI (runc/crun)
- [x] OCI spec generation from SandboxConfig
- [x] Runtime auto-detection (prefers crun over runc)
- [x] Container lifecycle (run, kill, delete)
- [ ] Image pull integration (for pre-built sandbox images)

### Shared
- [x] Shared OCI spec generation module (oci_spec.rs)
- [x] Backend health monitoring (HealthStatus, check_health)
- [x] Sandbox metrics (SandboxMetrics: CPU, memory, PIDs from cgroup)

---

## v0.24.3 — Firecracker & WASM Backends

### Firecracker
- [x] microVM configuration from SandboxConfig (VmConfig JSON)
- [x] Boot drive + rootfs setup
- [x] Jailer integration for hardened execution (cgroups, seccomp, chroot)
- [x] Task script injection via workdir
- [ ] vsock communication for host ↔ VM IPC (framework present, not active)
- [ ] Snapshot + restore (checkpoint/migrate)
- [ ] Network tap device setup with iptables isolation

### WASM (wasmtime)
- [x] WASI module loading and execution via wasmtime v42
- [x] Filesystem preopen mapping from Landlock rules
- [x] Memory limit enforcement via wasmtime config
- [x] Fuel-based CPU metering
- [x] Async execution with timeout

---

## v0.25.3 — Hardware Enclaves & SyAgnos

### Intel SGX
- [x] Enclave creation via Gramine-SGX
- [x] Manifest generation from SandboxConfig (enclave_size, threads, fs mounts)
- [x] Environment variable and trusted file configuration
- [ ] Remote attestation integration
- [ ] Sealed data API (encrypt/decrypt to enclave identity)

### AMD SEV
- [x] SEV-SNP VM launch via QEMU with encrypted memory
- [x] QEMU args generation (EPYC-v4, memfd-private, SNP policy 0x30000)
- [x] Virtfs sharing for task scripts
- [ ] Attestation report verification
- [ ] Guest policy enforcement beyond default

### SyAgnos (hardened AGNOS OS sandbox)
- [x] SyAgnos backend variant (9th backend, strength 80–88)
- [x] Container runtime detection (docker/podman)
- [x] Three hardening tiers: minimal (80), dm-verity (85), TPM measured (88)
- [x] Tier detection from /etc/sy-agnos-release (JSON or key=value)
- [x] Container execution with memory/CPU/PID/network limits
- [x] Read-only rootfs enforcement at container level
- [x] Attestation report verification (PCR 8/9/10 + HMAC signature)
- [ ] Phylax output scanning integration
- [ ] Image pull and build integration (Dockerfile.sy-agnos)

---

## v0.26.3 — Consumer Integration

### Adoption
- [ ] SecureYeoman replaces internal sandbox framework with kavach
- [ ] daimon replaces 7 backend implementations with kavach
- [ ] AgnosAI adds sandboxed crew execution
- [ ] aethersafta uses kavach for plugin isolation

### Validation
- [ ] Cross-crate integration tests
- [ ] Strength scoring matches SY's existing scores
- [ ] Performance: kavach overhead < 1ms vs direct process spawn

---

## v1.0.0 Criteria

- [x] All 9 backends implemented and tested (Process, gVisor, Firecracker, WASM, OCI, SGX, SEV, SyAgnos, Noop)
- [ ] Strength scoring validated against SY reference scores
- [ ] CredentialProxy handles all injection methods
- [ ] Externalization gate tested with adversarial inputs
- [ ] Adversarial test suite passing (~300 tests across all layers) — see [tests/adversarial.rs](../../tests/adversarial.rs)
- [ ] Lifecycle FSM formally verified (no invalid transitions)
- [ ] 3+ downstream consumers in production
- [ ] 90%+ test coverage
- [ ] docs.rs complete
- [ ] No `unsafe` without `// SAFETY:` comments
- [ ] cargo-semver-checks in CI

---

## Post-v1

### Advanced isolation
- [ ] Nested sandboxes (sandbox within sandbox)
- [ ] Sandbox migration (checkpoint on node A, restore on node B)
- [ ] Live sandbox inspection (debug attach without breaking isolation)
- [ ] Deterministic execution (same input → same output, bit-for-bit)

### Integration
- [ ] majra integration (sandbox events as pub/sub topics via TypedPubSub)
- [ ] ai-hwaccel integration (GPU passthrough for ML sandboxes)
- [ ] nein integration (per-sandbox firewall rules)
- [ ] stiva integration (attested Rust-native container runtime, replaces docker/podman)
- [ ] Audit chain integration (cryptographic hash of all sandbox events)

### Composable isolation stacks — [stiva spec](stiva.md)
- [ ] Backend composition — stack multiple isolation layers (Firecracker + jailer + stiva + sy-agnos + TPM → 98)
- [ ] Composite strength scoring — sum of layered isolation with quantified degradation
- [ ] Runtime attestation — verify stiva binary hash before launching containers
- [ ] Image signature verification — reject unsigned/tampered images via ark signing
- [ ] Veraison EAR integration — standardized attestation result encoding (IETF RATS)

### Cross-platform porting

- [ ] **macOS: App Sandbox / sandbox-exec for process isolation** —
  `sandbox-exec` with custom Scheme profiles for filesystem and network
  restrictions. Map `SandboxPolicy` Landlock rules to sandbox profile
  `(allow file-read* (subpath ...))` directives. App Sandbox entitlements
  for distributed builds.
- [ ] **Windows: AppContainer for process isolation** — `CreateAppContainerProfile`
  + `UpdateProcThreadAttribute` via `windows-rs` for process-level
  isolation. Map `SandboxPolicy` seccomp rules to Windows restricted
  tokens and integrity levels.
- [ ] **Windows: Hyper-V for VM isolation** — Hyper-V lightweight utility
  VM as alternative to Firecracker. Similar strength score (85-90).
  Requires Windows Pro/Enterprise with Hyper-V enabled.
- [ ] **Cross-platform: platform-specific policy enforcement behind
  SandboxBackend trait** — Process backend dispatches to
  Linux (namespaces + seccomp + Landlock), macOS (sandbox-exec + App
  Sandbox), or Windows (AppContainer + restricted tokens) at runtime.
  `SandboxPolicy` remains the single API; platform mapping is internal.
  Feature-gated: `linux` (default), `macos`, `windows`.
- [ ] FreeBSD jails

---

## Non-goals

- **Container orchestration** — kavach is a sandbox primitive, not Kubernetes. daimon/AgnosAI handle orchestration.
- **Image registry** — kavach doesn't store or distribute images. ark/nous handle packages.
- **Network proxy** — kavach sets network policy, doesn't route traffic. nein handles firewall rules.
- **Secret storage** — kavach injects secrets, doesn't store them. The source of truth is the host's secret manager.
