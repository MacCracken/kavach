# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

Completed items are in [CHANGELOG.md](../../CHANGELOG.md).

---

## Cyrius port completion (v2.0 → v2.1)

v2.0 ships the architectural skeleton: core types, scanning pipeline, threat
classification, audit chain, credential proxy, and 2 backends. v2.1 closes
the remaining feature gaps. See
[ADR-004](../adr/004-deferred-features.md) for the unblocking conditions.

### v2.0.x — skeleton + docs

- [x] 20 modules ported (util, error, backend, policy, scoring, lifecycle,
      7× scanning_*, audit, credential, quarantine, backend_dispatch,
      backend_noop, backend_process, sandbox_exec)
- [x] Dispatch table + extension pattern ([ADR-002](../adr/002-backend-dispatch-fnptr-table.md))
- [x] HMAC-SHA256 audit chain via sigil
- [x] End-to-end integration demo
- [x] Architecture overview + 4 ADRs + README rewrite
- [x] `path_exists` + `which_exists` via access(2) syscall
- [x] gVisor backend (OCI bundle generation + `runsc run` + auto-cleanup)
- [x] Shared `oci_spec.cyr` module (bundle mkdir/spec/cleanup)
- [x] OCI backend (runc/crun shell-out via shared oci_spec)
- [x] WASM backend (wasmtime CLI shell-out with --fuel / --max-memory-size / --dir)
- [x] SyAgnos backend (docker/podman + hardened AGNOS image + Phylax scanner)
- [x] SGX backend (gramine-sgx + auto-generated manifest)
- [x] SEV backend (qemu-system-x86_64 with SEV-SNP confidential-guest)
- [x] TDX backend (qemu-system-x86_64 with tdx-guest object)
- [x] Firecracker backend (microVM config.json + firecracker --no-api)
- [x] **All 10 backends registered** — v2.0 core complete
- [ ] `cyrius audit` clean (fmt/lint/vet/deny)
- [ ] Enrich SGX backend with attestation + sealing (sigil EAR)
- [ ] Enrich Firecracker backend with vsock + snapshot + jailer
- [ ] Switch OCI backend to stiva once stiva's Cyrius port lands
- [ ] Delete `rust-old/` once enrichments land
- [ ] Report cyrius `deps` relative-path symlink bug upstream (workaround
      in cyrius.toml uses absolute path for sigil)

### v2.1 — feature parity unblocks (deferred from v2.0)

Consolidated internal tracker. Covers items deferred from the v2.0 port
([ADR-004](../adr/004-deferred-features.md)) and hardening pass
([ADR-005](../adr/005-v2-hardening-pass.md)).

#### Ready — no external blockers (scheduled next)

| Feature | Source | Status |
|---------|--------|--------|
| UUID v4 | ADR-004 §8 | **done v2.1** — `rand_u64` in util.cyr; Sandbox/ScanFinding/Quarantine ids are now 64-bit random. |
| Secret redaction on WARN verdict | ADR-004 §7 | **done v2.1** — `secrets_redact(text)` rewrites matched spans to `[REDACTED:CATEGORY]`; called from `gate_apply` on WARN when policy opts in. |
| OffenderTracker | ADR-004 §5 | **done v2.1** — `offender_tracker_new` + `record` + `agent_score` (exponential half-life decay) + `should_escalate`. |
| Sandbox integrity monitoring | ADR-004 §6 | **done v2.1** — `check_integrity()` reads `/proc/1/cmdline`, `/proc/mounts`, `/proc/self/uid_map`; returns `IntegrityReport{intact, checks[3], checked_at}`. |
| M1 remaining overflow sites | ADR-005 §M1 | **done v2.1** — `checked_sum4` + `alloc_checked` wired into audit `_sign_input`, `_entry_to_jsonl`, quarantine `_qpath`, `_meta_jsonl`, and `oci_generate_spec`. |
| `FileInjection.mode` honoring helper | ADR-005 §M2 | `credential_inject_files(injections)` that writes via `file_write_secure` then `sys_fchmod`. |
| `cyrius audit` clean | v2.0.x backlog | fmt / lint / vet / deny. |

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
- [ ] Delete `rust-old/` once parity is reached in v2.1.

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
