# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## Completed

| Version | Milestone | Summary |
|---------|-----------|---------|
| v0.21.3 | Foundation | 9-variant Backend enum, SandboxBackend trait, StrengthScore (0–100), SandboxPolicy, CredentialProxy, lifecycle FSM, SandboxConfig builder, KavachError |
| v0.22.3 | Process Backend | Seccomp-bpf, Landlock, namespaces, cgroups v2, capability dropping, externalization gate (17 patterns), backend dispatch |
| v0.23.3 | gVisor & OCI | runsc/runc/crun integration, OCI spec generation, health monitoring, metrics, OciImageManager |
| v0.24.3 | Firecracker & WASM | Firecracker microVM (jailer, vsock, snapshot/restore, TAP networking), wasmtime WASI (fuel metering, memory limits) |
| v0.25.3 | Hardware Enclaves & SyAgnos | SGX (Gramine, attestation, sealed data), SEV-SNP (QEMU, attestation, guest policy), SyAgnos (3 tiers, Phylax scanning, image management) |

---

## v0.26.3 — Consumer Integration

### Adoption

| Consumer | Status | Roadmap location |
|----------|--------|------------------|
| **Stiva** | Active dependency (`kavach = ">=0.25"`) | [stiva/CLAUDE.md](../../../stiva/CLAUDE.md) |
| **Kiran** | Active dependency (`kavach = "0.25"`, `wasm` feature) | [kiran/CLAUDE.md](../../../kiran/CLAUDE.md) |
| **SecureYeoman** | Active (sy-sandbox + kavach) | [SY migration roadmap](../../../secureyeoman/docs/development/migration/roadmap.md) Phase 5 |
| **AgnosAI** | Planned — sandboxed crew execution | [agnosai roadmap](../../../agnosai/docs/development/roadmap.md) Kavach Integration section |
| **Hoosh** | Planned — tool sandboxing + externalization gate | [hoosh roadmap](../../../hoosh/docs/development/roadmap.md) Post-v1; [ADR-006](../../../hoosh/docs/decisions/006-kavach-tool-sandbox.md) |
| **Bote** | Planned — tool handler sandboxing | [bote roadmap](../../../bote/docs/development/roadmap.md) Post-v1 |
| **Aethersafta** | Planned — plugin isolation | [aethersafta roadmap](../../../aethersafta/docs/development/roadmap.md) Post-v1 ecosystem |

### Validation
- [ ] Cross-crate integration tests (stiva + kiran + kavach)
- [x] Strength scoring validated against SY reference scores
- [~] Performance: framework dispatch < 50µs; namespace isolation adds ~2.8ms (inherent OS cost)

---

## v1.0.0 Criteria

- [x] All 9 backends implemented and tested
- [x] Strength scoring validated against SY reference scores
- [x] CredentialProxy handles all injection methods (EnvVar, File, Stdin)
- [x] Externalization gate tested with adversarial inputs (30+ pattern tests)
- [x] Adversarial test suite passing (438 tests) — see [tests/adversarial.rs](../../tests/adversarial.rs)
- [x] Lifecycle FSM formally verified (exhaustive 5×5 transition matrix + state invariants)
- [~] 3+ downstream consumers in production (stiva, kiran active; SY integrating)
- [~] 90%+ test coverage (438 tests; line coverage limited by untestable external backends)
- [x] docs.rs complete (0 `missing_docs` warnings)
- [x] No `unsafe` without `// SAFETY:` comments
- [x] cargo-semver-checks in CI (`make semver`)

---

## Engineering Backlog (P1)

### Performance
- [ ] `redact()` returns `Cow` to avoid copy when no secrets found (`secrets.rs:209`)
- [ ] Policy clone optimization — extract only landlock/rlimit fields for pre_exec closure (`process/mod.rs:86`)
- [ ] `ScanFinding` fields use `Cow<'static, str>` for scanner/category (`secrets.rs:176`)
- [ ] Gate benchmark excludes `ExecResult::clone` from measurement (`benches/sandbox.rs`)
- [ ] `ExternalizationGate` cached on `Sandbox` struct instead of created per-exec (`lifecycle/mod.rs:265`)
- [ ] `eprintln!` in pre_exec replaced with `libc::write(2, ...)` for true async-signal-safety

### Scanning pipeline (SY parity)
- [x] Code scanner — command injection, data exfiltration, privilege escalation, supply chain, obfuscation (25 pattern groups)
- [x] Data/compliance scanner — PII (credit card, phone, IBAN, IPv4), HIPAA/GDPR/PCI-DSS/SOC2 keywords
- [ ] Threat classification — intent scoring (0.0–1.0), kill-chain stage tracking, MITRE ATT&CK mapping
- [ ] Repeat offender tracking — rolling window + time decay + escalation threshold
- [ ] Quarantine storage — file-based with metadata sidecar, approval workflow
- [ ] Cryptographic audit chain — HMAC-SHA256 signed append-only log with chain verification

### Runtime security
- [ ] Runtime guards — fork bomb detection, sensitive path blocklist, network allowlist per-sandbox
- [ ] Sandbox integrity monitoring — verify namespace/filesystem/process isolation holds at runtime
- [ ] Command allowlist/blocklist — block shells, interpreters, compilers in sandboxed execution
- [ ] Escalation management — 4-tier response (log/alert/suspend/revoke)

### Platform advances
- [ ] Landlock ABI v6 — IPC scoping (abstract UNIX socket + signal isolation)
- [ ] Landlock ABI v4 — TCP bind/connect port restrictions
- [ ] io_uring explicit blocking in seccomp profiles
- [ ] TDX backend — Intel Trust Domain Extensions (GA on Azure)
- [ ] `SandboxPool` — pre-warmed sandboxes with snapshot-based cloning for fast startup
- [ ] `CompositeBackend` — stack multiple isolation layers (WASM+Firecracker, Process+gVisor)
- [ ] Unified attestation via EAR tokens (veraison/rust-ear crate)
- [ ] OCI image signature verification (sigstore crate)
- [ ] Entropy-based secret detection (Shannon entropy > 4.5 on unrecognized high-entropy strings)

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
- [ ] macOS: App Sandbox / sandbox-exec for process isolation
- [ ] Windows: AppContainer for process isolation
- [ ] Windows: Hyper-V for VM isolation
- [ ] Cross-platform: platform-specific policy enforcement behind SandboxBackend trait
- [ ] FreeBSD jails

---

## Non-goals

- **Container orchestration** — kavach is a sandbox primitive, not Kubernetes. daimon/AgnosAI handle orchestration.
- **Image registry** — kavach doesn't store or distribute images. ark/nous handle packages.
- **Network proxy** — kavach sets network policy, doesn't route traffic. nein handles firewall rules.
- **Secret storage** — kavach injects secrets, doesn't store them. The source of truth is the host's secret manager.
