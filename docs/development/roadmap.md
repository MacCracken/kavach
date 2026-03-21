# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## v0.21.3 — Foundation (current)

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
- [ ] Spawn child process with `tokio::process::Command`
- [ ] Seccomp-bpf filter application (basic + custom profiles)
- [ ] Landlock filesystem restriction enforcement
- [ ] Linux namespace isolation (PID, mount, network, user)
- [ ] Timeout enforcement with kill-on-timeout
- [ ] stdout/stderr capture with size limits
- [ ] Resource limits via cgroups v2 (memory, CPU, PIDs)

### Externalization gate
- [ ] Content policy check on sandbox output before release
- [ ] File size limits on externalized data
- [ ] Allowlist/blocklist for output patterns

---

## v0.23.3 — gVisor & OCI Backends

### gVisor (runsc)
- [ ] OCI bundle creation for gVisor runtime
- [ ] runsc exec with config-file startup
- [ ] Network namespace setup (host-gateway or isolated)
- [ ] Rootfs overlay (read-only base + writable layer)

### OCI (runc/crun)
- [ ] OCI spec generation from SandboxConfig
- [ ] Container lifecycle (create, start, exec, kill, delete)
- [ ] Image pull integration (for pre-built sandbox images)

### Shared
- [ ] Backend health monitoring (periodic liveness probes)
- [ ] Sandbox metrics (CPU/memory usage during execution)

---

## v0.24.3 — Firecracker & WASM Backends

### Firecracker
- [ ] microVM configuration from SandboxConfig
- [ ] Boot drive + rootfs setup
- [ ] vsock communication for host ↔ VM IPC
- [ ] Snapshot + restore (checkpoint/migrate)
- [ ] Network tap device for isolated networking

### WASM (wasmtime)
- [ ] WASI module loading and execution
- [ ] Filesystem preopen mapping from Landlock rules
- [ ] Memory limit enforcement via wasmtime config
- [ ] Fuel-based CPU metering

---

## v0.25.3 — Hardware Enclaves

### Intel SGX
- [ ] Enclave creation and attestation
- [ ] Sealed data (encrypt to enclave identity)
- [ ] Remote attestation integration

### AMD SEV
- [ ] SEV-SNP VM launch with attestation
- [ ] Encrypted memory verification
- [ ] Guest policy enforcement

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

- [ ] All 8 backends implemented and tested
- [ ] Strength scoring validated against SY reference scores
- [ ] CredentialProxy handles all injection methods
- [ ] Externalization gate tested with adversarial inputs
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
- [ ] majra integration (sandbox events as pub/sub topics)
- [ ] ai-hwaccel integration (GPU passthrough for ML sandboxes)
- [ ] nein integration (per-sandbox firewall rules)
- [ ] Audit chain integration (cryptographic hash of all sandbox events)

### Platform
- [ ] macOS sandbox (sandbox-exec / App Sandbox)
- [ ] Windows sandboxing (AppContainer / Hyper-V isolation)
- [ ] FreeBSD jails

---

## Non-goals

- **Container orchestration** — kavach is a sandbox primitive, not Kubernetes. daimon/AgnosAI handle orchestration.
- **Image registry** — kavach doesn't store or distribute images. ark/nous handle packages.
- **Network proxy** — kavach sets network policy, doesn't route traffic. nein handles firewall rules.
- **Secret storage** — kavach injects secrets, doesn't store them. The source of truth is the host's secret manager.
