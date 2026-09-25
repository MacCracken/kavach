# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

This roadmap is **future-facing only** — shipped work lives in [CHANGELOG.md](../../CHANGELOG.md). Current release: **v3.12.7**. Toolchain pin: cc `6.6.6`; sigil `3.12.18` (the snapshot's — see CLAUDE.md hazard 4), samay `1.1.5`, ai-hwaccel `2.4.0` (agnosys dropped at v3.5.0 — its security backends are internalized).

**Every release below is pinned.** Each names what ships in it, in the order the principle sets. To
move an item, edit this file; do not let it drift. Every release runs the CLAUDE.md development
loop: tests and benchmarks for new code, a `bench-history.csv` row labeled with the version, a
CHANGELOG entry with measured numbers, and a `doc-health.md` refresh for every doc touched. Items
with no dependency (for example the scanner work in 3.20) can be pulled forward; items with one say
what it is.

---

## 3.12.8 — ABI repairs: seccomp, and the aarch64 x86-isms

These repairs come before any 3.13 feature work. 3.12.8 was to be the P(-1) closeout unless more
repairs were needed before 3.13; these are those repairs, so the closeout moves to 3.12.9. Each
was found at 3.12.7 by reading the code against the cyrius 6.6.6 syscall tables. The aarch64
effects are inferred from those tables and have not yet been run on hardware.

- [ ] **The seccomp filter checks the architecture.** `security_create_exec_seccomp_filter` loads
  only `seccomp_data.nr`, never `seccomp_data.arch`, and its deny list is x86-64 syscall numbers.
  On aarch64 those numbers name other calls: x86-64 `ptrace` (101) is aarch64 `nanosleep`. So the
  filter kills benign calls there and allows the real `ptrace`, `mount` and `unshare`. On x86-64,
  a number-only filter is the pitfall seccomp(2) warns about, because the i386 (`int 0x80`) and
  x32 syscall numbers differ; that has not been demonstrated here. Fix: load `arch`, KILL on
  anything but the build's `AUDIT_ARCH_*` (and on the x32 bit on x86-64), and build the deny list
  per architecture.
- [ ] **Rootfs entry calls `chroot` by the right number.** `SYS_CHROOT_NR = 161` is x86-64
  `chroot`, cyrius 6.6.6 has no translation row for it, and on aarch64 161 is `sethostname`.
  Unprivileged, the call most likely fails and the child exits closed. As root it can succeed,
  leaving the payload in the host's root filesystem. **The most severe item here.**
- [ ] **Namespaces call `unshare` by the right number.** `SYS_UNSHARE = 272` is x86-64, with no
  translation row; on aarch64, 272 is a different call. Namespace creation fails there — closed,
  not open.
- [ ] **`_oci_dir_is_ours` reads `st_mode` / `st_uid` at x86-64 `struct stat` offsets** (24 and
  28); aarch64 has them at 16 and 24. Use the stdlib's `STAT_MODE` and a per-arch uid offset.
- [ ] **Re-run the aarch64 suite.** Under qemu-user it fails 19 assertions in 9 fork/exec groups
  and then segfaults, identically on 3.12.5 and 3.12.7. At least two groups trace to the items
  above: exit 125 is `SPAWN_EXIT_SECCOMP`, and the OCI state-root check. Re-run after the fixes,
  then confirm on real aarch64 hardware before claiming aarch64 exec support.
- [ ] **Keep it from recurring.** Add an aarch64 cross-build and a qemu run of the confinement
  tests to CI, so the next x86-only value fails a build instead of a release. File upstream: the
  stdlib names neither `SYS_CHROOT` / `SYS_UNSHARE` nor `AUDIT_ARCH_*`, so kavach needs its own
  per-arch table until it does.

## 3.12.9 — P(-1) closeout

The scaffold-hardening pass (CLAUDE.md, P(-1) steps 0–9), run to completion before feature work
starts at 3.13.0.

- [ ] Test and benchmark sweep; cleanliness (fmt, lint, vet); baseline benchmarks.
- [ ] Audit (performance, memory, security, edge cases). Known items going in:
  - `SpawnedProcess_pid` / `_set_pid` are defined in both `spawn.cyr` and `observability.cyr`,
    a `duplicate fn` inside kavach itself;
  - the remaining sigil overlaps (`syserr_*`, the `agnosys_*` helpers, `attestation_result_new`)
    get the `<crate>_` prefix that ADR-006 describes;
  - `file_restrict_mode` has had no caller since 3.12.6;
  - `kv_sleep_ms` still passes the raw x86 number 35, correct only through cyrius's translation
    row; use `sys_nanosleep`;
  - agnos: sweep every `sys_*` call reachable there for the Linux argument order (3.12.6 fixed the
    opens).
- [ ] **Benchmark tooling.** `bench-history.sh` pins to one CPU: unpinned exec timings are bimodal
  on the development host (3.12.7). A checked-in interleaved A/B script replaces the ad-hoc ones
  used for 3.12.6 and 3.12.7.
- [ ] **Documentation audit.** ADR-004 (several of its deferred features have shipped); guides and
  examples against the current API; `doc-health.md`; the zugot recipe, still at 3.4.2.
- [ ] Post-audit benchmarks against the 3.12.9 baseline.

## 3.13.x — TEE attestation I: SGX and TDX quote verification (ADR-004 §6)

**Unblocked:** sigil 3.12.18 ships `sgx_quote_parse`, `sgx_quote_verify_full`, `tdx_quote_parse`
and `tdx_quote_verify_full`.

- [ ] Fetch the quote from the running guest: Gramine for SGX, the TD quote for TDX.
- [ ] Verify it with sigil against the vendor root, and report the result through
  `src/attestation.cyr`, which today only stores the report's shape.
- [ ] A measurement allowlist in `SandboxPolicy`; a mismatch fails the exec.
- [ ] Accept and reject tests from sigil's test vectors.

## 3.14.x — TEE attestation II: SEV-SNP, and SGX sealing

- [ ] SEV-SNP report verification with the `snp_report_*` family (AMD ARK → ASK → VCEK).
- [ ] SGX sealing against MRSIGNER + ISVSVN.

## 3.15.x — Firecracker jailer

**Unblocked:** the stdlib has `sys_setresuid` / `sys_setresgid`. Today `backend_firecracker.cyr`
writes `config.json` and runs `firecracker --no-api --config-file`, with no per-VM UID/GID drop,
chroot, or proc/sys mounts.

- [ ] Per-VM UID/GID drop, chroot into the VM root, and the proc/sys mounts.
- [ ] vsock control-socket robustness: reconnect on `EAGAIN`, partial-frame retries.
- [ ] Snapshot / restore over the API socket.

## 3.16.x — Agent Injection Defense L4, phase 1: schema and shadow mode

Design reference: [Agent Injection Defense](#agent-injection-defense--irreversible-action-gating-post-closed-beta)
below. **Depends on** t-ron (L3) supplying the external-input-origin tag.

- [ ] The `irreversible` capability flag, with its default set.
- [ ] The external-input-origin tag from t-ron as the gate input.
- [ ] Shadow mode: log what would be blocked, enforce nothing.
- [ ] **Decision:** the confirmation primitive (terminal-typed phrase, hardware key, or
  out-of-band). 3.17 needs it.

## 3.17.x — L4 phase 2: confirmation tokens and audit-only mode

- [ ] Token scope: single use, bound to the action signature, time-limited (default ≤ 30 s).
- [ ] A token the LLM cannot synthesize, per the 3.16 decision, with the agnoshi terminal flow.
- [ ] Audit-only mode: annotate decisions, allow.

## 3.18.x — L4 phase 3: enforce

- [ ] Enforce mode, with per-deployment mode selection.
- [ ] Hardware-key backend, optional, for higher-assurance deployments.

## 3.19.x — VM backend foundation (QEMU/KVM)

The first step of [Foreign Platform Containers](#foreign-platform-containers): a VM backend behind
the dispatch table, a Linux guest first, and an explicit filesystem-sharing policy (read-only by
default, writes only with kavach approval).

## 3.20.x — Scanner performance

- [ ] **Data + phylax scanners → single Aho-Corasick pass.** `src/aho_corasick.cyr` is
  scanner-agnostic, but only the code scanner uses it. `_data_scan_*` (`scanning_data.cyr`, 30
  `cstr_contains` calls) and the phylax checks in `backend_sy_agnos.cyr` (14) still scan once per
  pattern. Apply the code scanner's integration: a cached automaton over each scanner's literal set,
  one pass over the lowered text into a hit table, and group checks through a `_hit()` lookup with a
  `cstr_contains` fallback, so a drifted pattern list can only cost speed, never correctness. The
  existing scanner tests are the regression guard. Benchmark a large artifact before and after.
- [ ] Re-measure the `secrets_*` rows, which lost 8–12% to the cyrius 6.6.5 / 6.6.6 codegen
  (3.12.6), with the Aho-Corasick pass in, and profile the hot loops.

---

## Beyond 3.x — unpinned

- The rest of [Foreign Platform Containers](#foreign-platform-containers): Windows and macOS
  guests, display through aethersafta, audio through dhvani, clipboard, USB and GPU passthrough,
  phylax boundary scanning, libro audit, templates.
- [Advanced Isolation](#advanced-isolation), [Cross-Platform Backend Porting](#cross-platform-backend-porting),
  [Polymorphic Defense Integration](#polymorphic-defense-integration) (waits on Cyrius Phase 13).

### Blocked — awaiting upstream

Each entry carries **what it means**, **who owns the upstream work**, and **trigger condition**.

### Stiva OCI backend

- **What it means.** Today `backend_oci.cyr::_oci_runtime_path()` returns the first of `runc` / `crun` found in PATH. ADR-004 §7 plans to prepend stiva when available, so the kavach OCI backend transparently uses stiva's hardened OCI runtime instead of upstream runc.
- **Who owns it.** Upstream — the **stiva Cyrius port**, now live at **v3.0.0** (a synchronous single-node OCI runtime with a 19-verb `stiva` CLI: run/ps/stop/rm/inspect/images/…). What kavach's OCI backend needs, though, is stiva as a **runc-compatible OCI runtime** — the `stiva create/start/state/kill/delete` CLI over a bundle — which the port does **not** expose yet. The OCI state/bundle primitives (`parse_bundle` / `build_state` / `to_oci_status`) **are** ported (stiva `oci` module); the container lifecycle it drives (`start` = run the container) is the **stiva v3.0.x runtime-completion line** (blocking, over the ported sync core), with detached `run -d` specifically being stiva's v3.1 residue blocked on this issue's `sandbox_spawn`; a runc-compatible OCI-runtime CLI on top is not yet scoped in stiva's roadmap.
- **Trigger condition.** stiva ships a stable OCI-runtime CLI (`stiva create/start/state/kill/delete` over a bundle — the runc drop-in) wrapping its v3.0.x lifecycle. Single-line addition to `_oci_runtime_path()` once it does. No upstream filing needed — stiva is a sibling repo, tracked in its own roadmap.


### Recorded negatives (don't chase these)

- **No faster substring search in the stdlib** — `str_contains_cstr` is the same naive O(n·m) loop, so swapping `cstr_contains` for it buys clarity, not speed. The real fix (Aho-Corasick over the literal set) is already in for the code scanner and tracked above for data/phylax.
- **No stdlib SHA-256** — kavach correctly stays on sigil for HMAC-SHA256.
- **`overflow.cyr` operators panic** rather than returning the `-1` sentinel `alloc_checked` relies on — don't swap the existing size guards for them.
- **Typed-`slice` sweep** — subscripting is read-only in cc 6.0.43 (no `_slice_idx_set_W`), dot-syntax isn't wired, and kavach's loops are already correctly bounded; adopt `slice` reads only opportunistically on untrusted-input paths (as done for `is_safe_text`/`is_safe_argument`), not as a blanket rewrite.


---

# Design reference

The sections below are the long-horizon design the pinned releases draw from.

## Agent Injection Defense — Irreversible-Action Gating (post-closed-beta)

> **Spec**: [`agnosticos/docs/development/planning/agent-injection-defense.md`](https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/agent-injection-defense.md) — six-layer cross-cutting design. **kavach owns L4 (sandbox capability gating + confirmation tokens).** Triggered by 2026-05 incident (third-party AI agent drained $200K via Morse code in tweet). **Phasing**: post-public-beta — this is the structural-immunity layer that pairs with agnostik's `UntrustedInput<T>` (L6).

L4's job: even when an agent is "authorized" to call a capability, **irreversible actions get a runtime confirmation step that the LLM cannot synthesize.** This is the layer that gives AGNOS structural immunity — same absence-by-design pattern as the kernel being immune to CVE-2026-31431, applied at the agent-capability boundary. Even if every detection layer (L1–L3) misses an injection encoding, the wallet drain doesn't happen because the gate doesn't exist for unconfirmed external-input-origin calls.

### Schema additions

- [ ] **`irreversible` capability flag** — declarative per-capability in agent profile. Defaults set on:
  - Wallet / crypto / financial operations
  - File deletion outside agent's working directory
  - Network operations to external endpoints (per-deployment allowlist)
  - System operations (reboot, shutdown, package install)
  - Outbound communication (email, SMS, post-to-feed, Slack)
- [ ] **Confirmation-token requirement** for irreversible actions — token must be one the LLM cannot generate (terminal-typed phrase, hardware-key press, or out-of-band confirmation)
- [ ] **Token-scope schema** — single-use, scoped to specific action signature, time-limited (default ≤30s)
- [ ] **External-input-origin tag** — kavach receives provenance from t-ron (L3) and uses it as the gate input

### Confirmation mechanism

The token mechanism is an **open design question** (see spec § Open design questions #1):

- **Terminal-typed phrase** — agnoshi prompt for explicit confirmation
- **Hardware key (YubiKey, etc.)** — physical presence requirement
- **Out-of-band (Signal, Matrix)** — separate channel confirmation
- **Per-deployment configurable, with a default** — TBD

- [ ] **Decision: confirmation primitive** — pick default before implementation
- [ ] **agnoshi integration** — terminal-typed confirmation flow
- [ ] **Hardware-key backend** — optional, for higher-assurance deployments

### Migration path

- [ ] **Shadow mode** — log what would have been blocked, no enforcement
- [ ] **Audit-only mode** — annotate decisions but allow
- [ ] **Enforce mode** — block irreversible actions without confirmation token
- [ ] **Per-deployment configurability** — each AGNOS deployment picks its mode

### Companion repos

- L1 (input scanning): `phylax`
- L2 (gateway pre-flight): `hoosh`
- L3 (MCP boundary capability-source policy): `t-ron`
- L5 (audit chain): `libro` (already shipped)
- L6 (`UntrustedInput<T>` shared type): `agnostik`

This work pairs tightly with **shakti** for the privilege-escalation boundary: `shakti` is the inter-process equivalent of what kavach's L4 gating does at the intra-agent level.

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
| **Display** | Wayland passthrough via aethersafta | Guest windows appear as native AGNOS windows |
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
| 5 | Display integration (aethersafta) | High | Guest windows composited as native AGNOS surfaces |
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
