# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## v1.0.0 — Released 2026-03-25

| Milestone | Summary |
|-----------|---------|
| Foundation | 10-variant Backend enum, SandboxBackend trait, StrengthScore (0–100), SandboxPolicy, CredentialProxy, lifecycle FSM |
| Process Backend | Seccomp-bpf (87 allowed + 17 blocked + io_uring), Landlock v5, namespaces, cgroups v2, capability dropping |
| gVisor & OCI | runsc/runc/crun, OCI spec generation, health monitoring, metrics, OciImageManager |
| Firecracker & WASM | microVM (jailer, vsock, snapshot/restore, TAP networking), wasmtime WASI (fuel metering) |
| Hardware Enclaves | SGX (Gramine, attestation, sealed data), SEV-SNP (attestation, guest policy), TDX (10th backend) |
| SyAgnos | 3 hardening tiers, Phylax scanning, image management |
| Scanning Pipeline | Secrets (17 patterns + entropy), code (25 groups), data/compliance (10 patterns), threat classifier, quarantine, audit chain |
| Runtime Security | Guards (fork bomb, path blocklist, command blocklist), integrity monitoring, 4-tier escalation |
| Credential Proxy | Direct injection (env/file/stdin) + HTTP proxy (header injection, CONNECT tunnel, host allowlist) |
| Infrastructure | SandboxPool, backend auto-selection, 541 tests, cargo-semver-checks |

### Consumers

| Consumer | Version | Status |
|----------|---------|--------|
| **Stiva** | `kavach >= 1.0` | Active — container isolation |
| **Kiran** | `kavach = 1.0` | Active — WASM scripting sandbox |
| **SecureYeoman** | sy-sandbox + kavach | Active — agent sandboxing |
| **AgnosAI** | Planned | Sandboxed crew execution |
| **Hoosh** | Planned | Tool sandboxing + externalization gate ([ADR-006](../../../hoosh/docs/decisions/006-kavach-tool-sandbox.md)) |
| **Bote** | Planned | Tool handler sandboxing |
| **Aethersafta** | Planned | Plugin isolation |

---

## Remaining (blocked on external deps or design)

### Requires crate dependency additions
- [ ] Landlock ABI v6 — IPC scoping (`landlock` crate v0.5+)
- [ ] Landlock ABI v4 — TCP bind/connect (`landlock` crate v0.5+ `AccessNet`)
- [ ] Unified attestation via EAR tokens (`veraison/rust-ear` crate)
- [ ] OCI image signature verification (`sigstore` crate)
- [ ] Cryptographic HMAC upgrade for audit chain (`hmac` + `sha2` crates)

### Requires architectural design
- [ ] `CompositeBackend` — stack multiple isolation layers (WASM+Firecracker, Process+gVisor)
- [ ] Cross-crate integration tests (stiva + kiran + kavach)

### Minor optimizations
- [ ] Policy clone optimization — extract only landlock/rlimit fields for pre_exec closure
- [ ] `ScanFinding` fields use `Cow<'static, str>` for scanner/category

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
- [ ] stiva integration (attested Rust-native container runtime)

### Composable isolation stacks
- [ ] Backend composition — stack multiple isolation layers
- [ ] Composite strength scoring
- [ ] Runtime attestation — verify stiva binary hash before launching containers
- [ ] Image signature verification — reject unsigned/tampered images via ark signing
- [ ] Veraison EAR integration — standardized attestation result encoding (IETF RATS)

### Cross-platform porting
- [ ] macOS: App Sandbox / sandbox-exec
- [ ] Windows: AppContainer + Hyper-V
- [ ] Cross-platform: platform-specific policy enforcement behind SandboxBackend trait
- [ ] FreeBSD jails

---

## Non-goals

- **Container orchestration** — kavach is a sandbox primitive, not Kubernetes
- **Image registry** — kavach doesn't store or distribute images
- **Network proxy** — kavach sets network policy, doesn't route traffic
- **Secret storage** — kavach injects secrets, doesn't store them
