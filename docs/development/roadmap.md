# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## Ready to implement

- [x] Landlock ABI v4 — TCP bind/connect via `AccessNet` + `NetPort`
- [ ] Landlock ABI v5 — IOCTL scoping via `AccessFs::IoctlDev` (available since `landlock` 0.4.1)
- [ ] Landlock ABI v6 — IPC scoping via `Scope` + signal scoping (available since `landlock` 0.4.2)

## Requires architectural design

- [ ] Cross-crate integration tests (stiva + kiran + kavach)

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
