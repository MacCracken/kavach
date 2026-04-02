# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## Ready to implement

- [x] Landlock ABI v4 — TCP bind/connect via `AccessNet` + `NetPort`
- [x] Landlock ABI v5 — IOCTL scoping via `AccessFs::IoctlDev` (included in `AccessFs::from_all(V5+)`, active since ABI bump to V6)
- [x] Landlock ABI v6 — IPC scoping via `Scope::AbstractUnixSocket` + `Scope::Signal` (`LandlockScope` policy type)

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
- [x] majra integration (`SandboxEventBus` with MQTT-style wildcard pub/sub for lifecycle, policy, attestation, and scan events)
- [x] ai-hwaccel integration (`GpuPassthrough` detection, `GpuPolicy` filtering, device path → Landlock rule generation)
- [x] nein integration (per-sandbox firewall rules via `NamespaceFirewall` builder)
- [x] stiva integration (runtime binary attestation via `RuntimeManifest`)

### Composable isolation stacks
- [x] Backend composition — N-layer stacking via `stack_layers()` + `score_layers()`
- [x] Composite strength scoring — defense-in-depth bonus, Landlock TCP/scope modifiers
- [x] Runtime attestation — verify binary hashes via `RuntimeManifest` + `SandboxConfig::runtime_manifest`
- [x] Image signature verification — `ImageVerification` + `ImageVerificationPolicy` with signer trust and pattern matching
- [x] Veraison EAR integration — `sign_ear_jwt()`, `sign_ear_cose()`, `from_ear_jwt()`, `from_ear_cose()` for IETF RATS interop

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
