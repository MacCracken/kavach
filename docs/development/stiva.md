# Stiva — Rust-Native Container Runtime for Kavach

> **Status**: Planned (post-v1.0) | **Upstream Spec**: [agnosticos/docs/development/applications/roadmap.md](https://github.com/MacCracken/agnosticos) (Stiva section)

## State of the Art (2025–2026)

No existing system combines composable multi-layer isolation with quantitative security scoring. The industry either does VM isolation (Firecracker, Kata) OR OS-level hardening (gVisor, seccomp) — not both, and never with an attested purpose-built runtime in between.

| Solution | Layers | Composable? | Quantitative Score? | Notes |
|----------|--------|------------|--------------------|----|
| Docker/Podman | 1 | No | No | General-purpose, 5 CVEs in 14 months |
| gVisor | 1 | No | No | User-space kernel, ~20% overhead |
| Kata Containers | 2 | Partial | No | VM + container |
| Firecracker | 2 | Partial | No | KVM microVM + jailer |
| AWS Nitro Enclaves | 2 | Partial | No | Proprietary, AWS-only |
| CoCo (CNCF) | 3 | Yes | Partial (EAR) | Closest — but no single score, Kubernetes-native |
| **Kavach + Stiva** | **5** | **Yes** | **Yes (0-100)** | **Only system with quantitative composite scoring** |

Key academic references: LATTE (EuroS&P 2025) on layered attestation, RContainer (NDSS 2025) on eliminating shim chains, CVE-2024-21626 / CVE-2025-31133/52565/52881 on runc mount races, CVE-2025-54867 proving Rust ≠ logic-safe.

Full analysis: [agnosticos stiva spec](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/stiva.md)

---

## What is Stiva?

Stiva (Romanian: "stack") is a purpose-built, Rust-native container runtime that replaces Docker/Podman for launching kavach sandbox containers. It is not a general-purpose container runtime — it exists solely to maximize isolation strength by eliminating the trust boundaries, escape hatches, and attack surface inherent in general-purpose runtimes.

## Why Stiva Exists

Docker and Podman are designed for developer ergonomics. They ship with:
- `--privileged` flag (disables all isolation)
- `--cap-add` (re-enables dangerous capabilities)
- 50MB+ root daemon with REST API (attack surface)
- `runc` shim chain (containerd → runc → container = 3 processes, CVE history)
- Runtime-applied seccomp (overridable via container config)
- Registry trust model (MITM-able image manifests)

Stiva has none of these. It is a single, signed binary that enforces kavach policy with no override mechanism.

## Architecture

```
Docker/Podman model:
  dockerd (root daemon, REST API, 50MB+)
    → containerd (shim manager)
      → runc (OCI runtime, CVE-2024-21626 etc.)
        → container
    → CNI plugins (network, pluggable = attackable)
    → registry pull (trust manifest, MITM-able)

Stiva model:
  stiva run (daemonless, single signed binary, <5MB)
    → clone(NEWPID|NEWNS|NEWNET|NEWUSER) directly
    → kavach policy enforcement (seccomp + landlock + caps)
    → image = ark-signed squashfs (no layer unpacking)
    → network = nein (Rust-native nfnetlink, no CNI)
```

### Dependency Stack

```
stiva (container runtime)
  ├── kavach  (isolation: namespaces, cgroups, seccomp, landlock, caps)
  ├── nein    (networking: bridge, port mapping, DNS via nfnetlink)
  ├── ark     (images: signed squashfs layers, registry client)
  └── libro   (audit: container lifecycle events, cryptographic chain)
```

## Security Uplift

When stiva replaces docker/podman as the sy-agnos container runtime:

| Feature | Docker/Podman | Stiva | Strength Boost |
|---------|--------------|-------|---------------|
| Runtime attestation | None — trust the daemon | Signed binary hash verified at launch | +3 |
| Image verification | Registry trust (MITM-able) | ark-signed squashfs, reject unsigned | +2 |
| Seccomp enforcement | Runtime-applied, overridable | Baked into runtime, no override API | +2 |
| Escape hatches | `--privileged`, `--cap-add`, etc. | No privilege escalation flags exist | +2 |
| Daemon attack surface | 50MB+ Go daemon, root, REST API | Daemonless single binary, <5MB | +2 |
| Syscall surface | containerd → runc shim chain | Direct clone() → exec, no shims | +1 |

## Composable Isolation Stacks

Stiva enables layer composition — stacking multiple isolation boundaries where each layer catches what the one above misses:

```
Firecracker (KVM microVM)           — hardware isolation boundary
  └── jailer (cgroup, seccomp, chroot) — privilege reduction
      └── stiva (attested runtime)     — no daemon, signed binary, no overrides
          └── sy-agnos (OS sandbox)    — immutable rootfs, baked seccomp/nftables
              └── TPM measured boot    — hardware-attested integrity chain
```

### Strength Scores by Configuration

| Configuration | Score | Notes |
|--------------|-------|-------|
| Docker default | ~30 | No seccomp, shared kernel, root daemon |
| Docker + seccomp + rootless | ~45 | General-purpose, runc CVEs |
| gVisor (runsc) | ~70 | User-space kernel |
| Kata Containers (QEMU) | ~75 | VM but no attestation |
| Firecracker (AWS) | ~85 | KVM + jailer |
| AWS Nitro Enclaves | ~90 | Hardware-isolated, proprietary |
| sy-agnos minimal + docker | 80 | OS-level sandbox, general runtime |
| sy-agnos minimal + stiva | 92 | OS-level sandbox, attested runtime |
| sy-agnos dm-verity + stiva | 94 | + verified rootfs |
| sy-agnos TPM + stiva | 95 | + measured boot |
| Firecracker + jailer | 93 | Hardware VM + privilege reduction |
| **Firecracker + jailer + stiva + sy-agnos TPM** | **98** | **Full stack, every layer purpose-built** |

The remaining 2 points to 100 represent "attacks we haven't thought of yet" — addressed by bug bounties, red teams, and continuous adversarial testing.

## Kavach Integration

Kavach's `SyAgnosBackend` already supports runtime detection. When stiva is available:

```rust
// kavach detects stiva as a first-class runtime
fn detect_runtime() -> Option<(String, RuntimeKind)> {
    if which_exists("stiva") {
        return Some(("stiva".into(), RuntimeKind::Stiva));  // +12 strength
    }
    if which_exists("docker") {
        return Some(("docker".into(), RuntimeKind::Docker)); // +0 strength
    }
    if which_exists("podman") {
        return Some(("podman".into(), RuntimeKind::Podman)); // +0 strength
    }
    None
}
```

The strength scoring modifier for stiva is applied on top of the sy-agnos tier base score:

```
base_score(SyAgnos)           = 80  (tier: minimal)
+ tier_modifier(dmverity)     = +5
+ tier_modifier(tpm_measured) = +8
+ runtime_modifier(stiva)     = +12  (attestation + signing + no overrides + no daemon)
```

## Adversarial Test Plan

See [tests/adversarial/](../../tests/adversarial/) for the full test suite. Each layer has targeted tests that prove specific attacks fail:

### Stiva Runtime Tests (~50 tests)
- **Binary attestation**: tampered stiva binary → must refuse to launch containers
- **Image signing**: unsigned image → must reject before unpacking
- **No override API**: programmatic privilege escalation → API must not exist
- **No daemon**: verify single-process model, no persistent root process
- **Minimal syscall surface**: stiva itself uses only ~40 syscalls (verified via seccomp self-application)

### Sy-Agnos Container Tests (~60 tests)
- **Shell escape**: attempt `exec /bin/sh`, `/bin/bash`, `sh -c` → must fail (no shells in image)
- **Seccomp bypass**: call every blocked syscall → must EPERM
- **Network egress**: outbound to unlisted host → must drop (nftables default-deny)
- **Filesystem write**: write to rootfs → must fail (squashfs/dm-verity)
- **Process tree**: verify only 3 processes running (init → agent → health)
- **Rootfs verification**: dm-verity tamper detection (modify block → must detect)

### Firecracker VM Tests (~40 tests)
- **VM escape**: CVE reproductions for known Firecracker/QEMU escapes
- **Memory isolation**: guest write to host address space → must fault
- **Device fuzzing**: malformed virtio requests → must not crash host
- **Jailer containment**: chroot breakout, cgroup escape, capability escalation

### TPM Attestation Tests (~30 tests)
- **Tampered PCR**: modified PCR register value → attestation must fail
- **Replay attack**: old attestation report → timestamp must reject
- **Missing HMAC**: report without signature → must reject
- **Algorithm downgrade**: weak hash algorithm → must reject
- **PCR coverage**: all critical measurements (kernel, initrd, rootfs) covered

### Cross-Layer Composition Tests (~20 tests)
- **Layer bypass**: attack that passes one layer must be caught by the next
- **Strength scoring accuracy**: composed score matches expected value
- **Degradation**: if one layer is unavailable, score reflects reduced isolation
- **Boot chain**: TPM → stiva → sy-agnos → application — verify full chain integrity

## Implementation Timeline

| Phase | When | Delivers |
|-------|------|---------|
| kavach v0.25.3 | Now | SyAgnos backend with docker/podman runtime |
| kavach v1.0 | Pre-1.0 | Adversarial test suite, consumer integration |
| stiva v0.1 | Post-v1.0 | Daemonless container lifecycle, kavach isolation |
| stiva v0.2 | Post-v1.0 | ark image signing, runtime attestation |
| stiva v0.3 | Post-v1.0 | nein networking, full composition with Firecracker |
| kavach post-v1 | Post-v1.0 | Stiva runtime detection, composite strength scoring |

## Non-Goals

- **General-purpose container runtime** — stiva is not Docker. It runs kavach sandbox images, not arbitrary containers.
- **Docker CLI compatibility** — no `docker build`, `docker compose`, `docker swarm`. Different tool, different purpose.
- **Multi-tenant orchestration** — stiva runs one container at a time. Fleet orchestration is daimon/sutra's job.
