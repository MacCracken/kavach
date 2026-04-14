# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## v3.0 Cyrius port — shipped

All of these landed in v3.0.0 (see CHANGELOG for full detail).

- [x] 33 Cyrius modules ported (util, error, backend, policy, scoring,
      lifecycle, 7× scanning_*, audit, credential, quarantine, oci_spec,
      composite, observability, attestation, backend_dispatch + 10
      per-backend modules, sandbox_exec, main)
- [x] Dispatch table + extension pattern ([ADR-002](../adr/002-backend-dispatch-fnptr-table.md))
- [x] All 10 backends registered (Noop, Process, gVisor, OCI, WASM,
      SyAgnos, SGX, SEV, TDX, Firecracker)
- [x] HMAC-SHA256 audit chain via sigil
- [x] 3-scanner externalization gate (secrets + code + data)
- [x] Runtime guards (fork bomb, command blocklist, sensitive paths, shell
      metacharacters, time anomaly)
- [x] Threat classification (intent scoring, kill-chain, escalation)
- [x] OffenderTracker with integer half-life decay
- [x] Sandbox integrity monitoring (/proc readers)
- [x] UUID-v4-equivalent IDs from /dev/urandom
- [x] WARN-verdict secret redaction
- [x] Composite backend with policy merging + +5 layered scoring bonus
- [x] Observability types (HealthStatus, SandboxMetrics, SpawnedProcess)
- [x] Attestation types (AttestationResult, SgxAttestationReport)
- [x] P(-1) hardening pass — 9 CWE-class findings fixed ([ADR-005](../adr/005-v3-hardening-pass.md))
- [x] Architecture overview + 5 ADRs + 3 guides + 4 examples
- [x] Benchmark comparison Rust v2.0 ↔ Cyrius v3.0

## v3.1 — unblocking queue

Items deferred from v3.0 ([ADR-004](../adr/004-deferred-features.md),
[ADR-005](../adr/005-v2-hardening-pass.md)), plus operational cleanups.

#### Ready — no external blockers

| Feature | Source | Notes |
|---------|--------|-------|
| `FileInjection.mode` honoring helper | ADR-005 §M2 | `credential_inject_files(injections)` that writes via `file_write_secure` then `sys_fchmod`. |
| `cyrius audit` clean | v3.0 backlog | fmt / lint / vet / deny. |
| Delete `rust-old/` | v3.0 backlog | Fully captured per `rust-old-removal.md`. |
| Report cyrius `deps` symlink bug upstream | v3.0 backlog | Workaround: absolute path for sigil in cyrius.toml. |

#### Blocked — awaiting upstream

| Feature | Blocking | Notes |
|---------|----------|-------|
| Seccomp hooks | Cyrius `sys_prctl`, `sys_seccomp` wrappers | Post-fork async-signal-safe only. |
| Landlock hooks | Cyrius `sys_landlock_*` wrappers | ABI v4 TCP port + v6 scoping. |
| cgroups v2 | Cyrius `/sys/fs/cgroup` writer | resource limits wired via cgroupfs. |
| SGX attestation + sealing | sigil EAR helpers + IAS cert chain | Enriches `backend_sgx.cyr`. |
| SEV/TDX attestation | sigil EAR helpers | Quote fetch + verify. |
| Firecracker jailer/vsock/snapshot | Cyrius `sys_setresuid` + unix-socket robustness | Enriches `backend_firecracker.cyr`. |
| HTTP credential proxy | `lib/http.cyr` CONNECT tunnel + TLS | Direct env/file/stdin already ships. |
| H4 binary-path TOCTOU | Cyrius `sys_execveat` + `O_PATH\|O_NOFOLLOW` fd-cache | ADR-005 §H4 residual. |
| Stiva OCI backend | stiva Cyrius port | `_oci_runtime_path` prepends stiva when available. |

#### Meta

- [ ] Report cyrius `deps` relative-path symlink bug upstream (workaround in cyrius.toml uses absolute path for sigil).
- [ ] Delete `rust-old/` once parity is reached in v3.0.

---

## Foreign Platform Containers

**Goal**: Run Windows, macOS, and Linux applications inside AGNOS without surrendering sovereignty. The foreign OS runs as a fully sandboxed guest — kavach controls every boundary.

### Architecture

```
AGNOS (sovereign host — 184KB foundation)
  └── kavach (sandbox boundary — nothing escapes)
       └── stiva (container/VM runtime)
            ├── Windows guest (their apps, their rules, your sandbox)
            ├── macOS guest (their apps, their rules, your sandbox)
            └── Linux guest (Debian, Ubuntu, etc. — contained)
```

### Sandbox Tiers

| Tier | Isolation | Use Case |
|------|-----------|----------|
| **basic** | seccomp + Landlock | Native AGNOS apps (trusted) |
| **standard** | + network isolation + credential proxy | Marketplace apps |
| **strict** | + Firecracker microVM | Untrusted code, agent sandboxes |
| **foreign** | + full VM (guest OS) | Windows/macOS/Linux applications |

### Foreign Container Capabilities

| Capability | Implementation | Notes |
|------------|---------------|-------|
| **Network** | nein firewall rules per container | Guest gets explicit allowlist, not blanket access |
| **Filesystem** | kavach mount policy | Guest sees only what you share — explicit directory passthrough |
| **Clipboard** | Explicit copy bridge | Data transfer audited by libro, opt-in per session |
| **USB/devices** | Selective passthrough | Per-device, per-session, revocable |
| **Display** | Wayland passthrough via aethersafha | Guest windows appear as native AGNOS windows |
| **Audio** | PipeWire passthrough via dhvani | Guest audio routed through AGNOS audio stack |
| **GPU** | GPU passthrough or virtio-gpu | For graphics-heavy apps (Photoshop, games) |
| **Scanning** | phylax on all boundary crossings | Files entering/leaving the container are scanned |
| **Audit** | libro logs all container events | Every file transfer, network request, device access logged |
| **Identity** | sigil — guest never sees host keys | Container has its own identity scope |
| **Economy** | vinimaya — container can transact if permitted | Licensed apps can phone home, metered |

### What the Guest CANNOT Access

- AGNOS host filesystem (only explicit mounts)
- sigil keys or trust chain
- mudra tokens or vinimaya accounts
- Other containers (isolation between guests)
- Host process list or system state
- Hardware directly (unless explicitly passed through)
- Any information about the host beyond what is shared

### Use Cases

| Scenario | Container Type | Why |
|----------|---------------|-----|
| Need Photoshop | macOS foreign container | Run it without macOS owning your machine |
| Need Visual Studio | Windows foreign container | Development tools without Windows |
| Need a specific Linux tool | Linux foreign container | Use Debian/Ubuntu packages without switching distros |
| Gaming (Windows-only) | Windows foreign + GPU passthrough | Play without dual-booting |
| Legacy enterprise app | Windows foreign | Corporate software doesn't dictate your OS |
| Testing | Any foreign | Test AGNOS apps against other platforms |

### Roadmap

| # | Item | Priority | Notes |
|---|------|----------|-------|
| 1 | VM backend in kavach (QEMU/KVM) | High | SandboxBackend trait implementation for full VM isolation |
| 2 | Windows guest support | High | QEMU + virtio drivers, SPICE/RDP display |
| 3 | macOS guest support | Medium | Requires Apple hardware for legal compliance, or Hackintosh-style (grey area) |
| 4 | Linux guest support | High | Simplest — same kernel family, virtio native |
| 5 | Display integration (aethersafha) | High | Guest windows composited as native AGNOS surfaces |
| 6 | Audio integration (dhvani/PipeWire) | Medium | Guest audio routed through host audio stack |
| 7 | Filesystem sharing policy | High | Explicit mount points, read-only default, write requires kavach approval |
| 8 | Clipboard bridge | Medium | Opt-in, audited, directional (guest→host requires confirmation) |
| 9 | USB passthrough | Medium | Per-device, per-session, revocable via kavach policy |
| 10 | GPU passthrough | Medium | VFIO for dedicated GPU, virtio-gpu for shared |
| 11 | phylax boundary scanning | High | All files crossing container boundary scanned for threats |
| 12 | libro container audit | High | Complete audit trail of all container activity |
| 13 | agnoshi intents | Low | "open photoshop" → launches macOS container + app |
| 14 | Container snapshots | Medium | Save/restore container state (kavach checkpoint) |
| 15 | Container templates | Low | Pre-configured Windows/macOS/Linux templates in mela |

### The Embassy Model

Foreign containers are digital embassies. The guest OS operates under its own rules inside its allocated space. But the space is on AGNOS sovereign land, surrounded by AGNOS walls (kavach), monitored by AGNOS guards (phylax), logged by AGNOS records (libro), and subject to AGNOS law (nein firewall policy).

The guest has autonomy within its borders. It has no authority beyond them.

---

## Advanced Isolation

- [ ] Nested sandboxes (sandbox within sandbox)
- [ ] Sandbox migration (checkpoint on node A, restore on node B)
- [ ] Live sandbox inspection (debug attach without breaking isolation)
- [ ] Deterministic execution (same input → same output, bit-for-bit)

## Cross-Platform Backend Porting

- [ ] macOS: App Sandbox / sandbox-exec (for AGNOS apps on macOS — reverse direction)
- [ ] Windows: AppContainer + Hyper-V (for AGNOS apps on Windows — reverse direction)
- [ ] FreeBSD jails
- [ ] Cross-platform: platform-specific policy enforcement behind SandboxBackend trait

## Polymorphic Defense Integration

- [ ] kavach sandbox policy includes deployment seed (from Cyrius `--poly-seed`)
- [ ] Each sandboxed deployment runs a structurally unique binary
- [ ] Sandbox attestation includes (binary hash + poly-seed) signed by sigil
- [ ] See Cyrius roadmap Phase 13 for full polymorphic codegen plan

---

## Non-Goals

- **Container orchestration** — kavach is a sandbox primitive, not Kubernetes. Use daimon for orchestration
- **Image registry** — kavach doesn't store or distribute images. Use mela/ark
- **Network proxy** — kavach sets network policy, doesn't route traffic. Use nein
- **Secret storage** — kavach injects secrets, doesn't store them. Use sigil
- **Replacing the guest OS** — the foreign container runs their OS unmodified. kavach controls the boundary, not the interior
