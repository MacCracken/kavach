# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## Advanced isolation

- [ ] Nested sandboxes (sandbox within sandbox)
- [ ] Sandbox migration (checkpoint on node A, restore on node B)
- [ ] Live sandbox inspection (debug attach without breaking isolation)
- [ ] Deterministic execution (same input → same output, bit-for-bit)

## Cross-platform porting

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
