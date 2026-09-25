# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

This roadmap is **future-facing only** — shipped work lives in [CHANGELOG.md](../../CHANGELOG.md). Current release: **v3.12.9**. Toolchain pin: cc `6.6.6`; sigil `3.12.18` (the snapshot's — see CLAUDE.md hazard 4), samay `1.1.5`, ai-hwaccel `2.4.0` (agnosys dropped at v3.5.0 — its security backends are internalized).

**Every release below is pinned.** Each names what ships in it, in the order the principle sets. To
move an item, edit this file; do not let it drift. Every release runs the CLAUDE.md development
loop: tests and benchmarks for new code, a `bench-history.csv` row labeled with the version, a
CHANGELOG entry with measured numbers, and a `doc-health.md` refresh for every doc touched. Items
with no dependency (for example the scanner work in 3.20) can be pulled forward; items with one say
what it is.

---

## 3.13.x — TEE attestation I: SGX and TDX quote verification (ADR-004 §2)

**Unblocked:** sigil 3.12.18 ships `sgx_quote_parse`, `sgx_quote_verify_full`, `tdx_quote_parse`
and `tdx_quote_verify_full`.

- [ ] **Record aarch64 as supported**, apart from namespaces and rootfs entry (ADR-007), once
  the `aarch64 (native)` CI job's notice shows the full count with seccomp loaded. 3.12.9 made
  the job blocking and added that notice; before it, a green run said only that nothing failed.
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

- **Generic public names — a decision, then a breaking release.** Found by 3.12.9's
  `scripts/check-symbols.py --tree ..`. kavach's public API still has names that other
  first-party bundles also define: `policy_new` (shakti); `finding_new`, `scan_result_new` and
  `severity_name` (phylax); `which_exists` (nous); `audit_chain_len` (t-ron). Several enum members
  are also generic (`KavachBackend`'s `PROCESS`, `WASM`, `OCI`, `NOOP`, …; `SandboxState`'s).
  None of those repos is compiled next to kavach by any consumer today, and cyrius warns on a
  duplicate `fn`, but a shared enum member would be silent (the 3.12.9 `STDIN` bug). A prefix
  sweep breaks every consumer's call sites, so it needs a version decision before it is pinned.
- **Landlock network rules and scopes — apply them, or stop scoring them.** The policy fields
  (TCP bind/connect port allowlist, ABI v4; abstract-unix and signal scopes, ABI v6) are stored
  and add 3 + 2 + 2 to the strength score, but nothing applies them (`overview.md`'s modifier
  table, rechecked at 3.12.9).
- The rest of [Foreign Platform Containers](#foreign-platform-containers): Windows and macOS
  guests, display through aethersafta, audio through dhvani, clipboard, USB and GPU passthrough,
  phylax boundary scanning, libro audit, templates.
- [Advanced Isolation](#advanced-isolation), [Cross-Platform Backend Porting](#cross-platform-backend-porting),
  [Polymorphic Defense Integration](#polymorphic-defense-integration) (waits on Cyrius Phase 13).

### Blocked — awaiting upstream

Each entry carries **what it means**, **who owns the upstream work**, and **trigger condition**.

### aarch64 namespaces and rootfs entry

- **What it means.** Since 3.12.8, `security_create_namespace` returns not-supported on aarch64 and
  `_spawn_enter_rootfs` returns -1 there, so an aarch64 sandbox gets no namespaces and no rootfs.
  kavach's x86-64 numbers for `unshare` (272) and `chroot` (161) run `kcmp` and `sethostname` on
  aarch64. The native numbers are not an option: cyrius renumbers 51 to `getsockname`, and a
  native number under an aarch64 `#ifdef` is what ADR-007 and the cyrius guide rule out.
- **Who owns it.** Upstream: cyrius, filed as
  `cyrius/docs/development/issues/2026-09-25-kavach-unshare-chroot-unnamed-aarch64-chroot-unreachable.md`.
  It asks for `SYS_UNSHARE` and `SYS_CHROOT` in both Linux peers with `ESYSXLAT` rows `272→97` and
  `161→51`. The `161→51` row has to sit below the `51→204` getsockname row.
- **Trigger condition.** A cyrius release declaring both names. Then move the pin, call
  `sys_unshare` / `sys_chroot`, delete the two constants in `src/sys_security_syscalls.cyr` and the
  aarch64 refusals, and run the namespace and rootfs tests on the `aarch64-native` CI job.

### Stiva OCI backend

- **What it means.** Today `backend_oci.cyr::_oci_runtime_path()` returns the first of `runc` / `crun` found in PATH. `src/backend_oci.cyr`'s header plans to prepend stiva when available, so the kavach OCI backend transparently uses stiva's hardened OCI runtime instead of upstream runc.
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
