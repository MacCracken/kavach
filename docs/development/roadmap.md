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
- [x] P(-1) hardening pass — 9 CWE-class findings fixed ([ADR-005](../adr/005-v2-hardening-pass.md))
- [x] Architecture overview + 5 ADRs + 3 guides + 4 examples
- [x] Benchmark comparison Rust v2.0 ↔ Cyrius v3.0

## v3.1 — modernization arc — shipped

Behavior-preserving repo modernization. Sandbox runtime / scanner /
audit-chain surface from v3.0 is unchanged. The previously-queued
"v3.1 — unblocking queue" cascaded to **v3.2** (below).

- [x] Cyrius toolchain pin: 4.5.0 → 5.10.34 (same floor as majra / nein / agnosys post-M6).
- [x] Manifest format: `cyrius.toml` → `cyrius.cyml` (mirrors majra shape — `${file:VERSION}`, `[deps] stdlib = [...]`, `[deps.sigil]` via git+tag).
- [x] `lib/` deleted from working tree + gitignored (`cyrius deps` is the source of truth; mirrors majra / nein).
- [x] `.cyrius-toolchain` deleted (cyrius pin lives in `cyrius.cyml`).
- [x] sigil pin: 2.1.2 → 2.9.0 (matches the rest of the first-party tree's bisect gate).
- [x] CI rewrite (`.github/workflows/ci.yml`): version-pinned toolchain installer + source-archive lib fetch + `cyrius deps` + lockfile hash gate + fmt / lint / vet / build / smoke / test / bench / fuzz / security / docs jobs. Pattern lifted from majra / nein.
- [x] Release rewrite (`.github/workflows/release.yml`): same installer flow + version verify + binary + source-archive assets + SHA256SUMS + dated CHANGELOG body extraction.
- [x] `docs/doc-health.md` scaffolded — initial currency ledger modeled on majra's.
- [x] cyrius `deps` symlink-bug roadmap item **retired** — the new manifest uses git-based `[deps.sigil]`, no longer needs the absolute-path workaround.

#### 3.1.x post-cut doc sweep — shipped (Unreleased; ready to date when 3.1.1 cuts)

Drained in the 2026-05-10 post-cut sweep. See `CHANGELOG.md` `[Unreleased]` for the full per-file note.

- [x] `README.md` refresh — Cyrius floor → 5.10.34, `cyrius deps` step added, manifest reference swap, v3.0 status split into v3.1 arc + v3.0 port summary.
- [x] `CLAUDE.md` refresh — Rust-era `MSRV: 1.89` dropped; Version → 3.1.0; new pinned-Language line; cleanliness checks swapped to `cyrius *`; Key Principles translated to Cyrius idioms; DO-NOT list rewritten.
- [x] `docs/guides/getting-started.md` — § 1 rewritten with `cyrius deps`, toolchain pin, sigil 2.9.0.
- [x] `docs/development/rust-old-removal.md` — sed recipe `cyrius.toml` → `cyrius.cyml`; parity audit re-verified; checklist gains the migration-prereq row.

#### Open question — defer or open

- [ ] `[lib]` profile + `dist/kavach.cyr` bundle. Currently kavach is binary-only and no consumer (SY / stiva / kiran / AgnosAI / hoosh / bote / aethersafta) embeds it at source level. Open the profile when the first consumer asks; not before — adding a bundle pre-demand creates a maintenance commitment with no current consumer benefit.

---

## v3.2 — unblocking queue

Items deferred from v3.0 ([ADR-004](../adr/004-deferred-features.md),
[ADR-005](../adr/005-v2-hardening-pass.md)), plus operational cleanups.
Cascaded from the prior "v3.1 — unblocking queue" when v3.1.0 was
re-scoped to the modernization arc.

> **Reclassification — 2026-05-10**: a verify-against-cc-5.10.34 pass moved
> three items out of "Blocked — awaiting upstream" and into "Ready" / "Done":
> Landlock hooks (`sys_landlock_*` wrappers ship in stdlib at 5.10.34),
> HTTP credential proxy (sandhi + tls + net ship in stdlib), and cgroups
> v2 (never actually needed a stdlib wrapper — `/sys/fs/cgroup` writes
> work via plain `fs.cyr` file I/O). See the per-item rows below for
> detail.

#### Done — landed in 3.1.x

| Feature | Source | Notes |
|---------|--------|-------|
| `FileInjection.mode` honoring helper | ADR-005 §M2, **3.1.1** | `credential_inject_files(injections)` in [`src/credential.cyr`](../../src/credential.cyr) writes each FileInjection via new `file_write_secure_modal(path, buf, len, mode)` in [`src/util.cyr`](../../src/util.cyr). |
| `cyrius lint` clean | v3.0 backlog, **3.1.1** | 37 long-line warnings cleared. CI lint gate flipped to hard-fail. |
| Delete `rust-old/` | v3.0 backlog, **3.1.1** | 1.4 MB / ~26K lines removed; parity re-verified. |
| Upstream P1 filings | **3.1.2** | Sandbox-runtime syscall wrappers filed in cyrius; SGX/SEV/TDX attestation modules filed in sigil. |

#### Done — landed in 3.2.0

| Feature | What landed | Where |
|---------|-------------|-------|
| **cgroups v2 resource limits** | `memory.max`, `cpu.max` (quota/period at 100ms), `pids.max` wired from `SandboxPolicy`. Per-sandbox cgroup at `/sys/fs/cgroup/kavach-<rand>/`. Race-tolerant shell-prepend placement: `["sh", "-c", "echo $$ > <path>/cgroup.procs; exec \"$@\"", "--", <argv>...]` — `"$@"` passthrough prevents user-argv re-interpretation. Graceful no-op when /sys/fs/cgroup is unavailable. | [`src/cgroup.cyr`](../../src/cgroup.cyr); wired into [`src/backend_process.cyr`](../../src/backend_process.cyr). |
| **HTTP credential proxy** (ADR-004 §4) | Loopback-only HTTP server serving `GET /v1/secret/<name>` from in-memory `CredentialProxy`. Per-instance allowlist (allowlist-miss = 403 without proxy consult). Audit-chain integration on every served fetch + 403/404. | [`src/credential_http.cyr`](../../src/credential_http.cyr); uses stdlib `sandhi` + `net`. |

#### Ready — but deferred to v3.4.0

> **Note (v3.3.0):** v3.3.0 shipped as the Cyrius 6.0 toolchain + dependency jump (cc `5.10.44` → `6.0.40`, sigil `2.9.0` → `3.5.9`), *not* the feature cut originally planned here. The items below were pushed back one minor to **v3.4.0**.

The remaining items group around a single shared piece of infrastructure (a `sandbox_fork_exec(args, pre_exec_fn)` helper). v3.4.0 will land the helper + Landlock + OCI cgroup integration, closing out the work arc.

| Feature | What it adds | Where it lands |
|---------|--------------|----------------|
| **Landlock hooks** | Filesystem and network sandboxing via the Linux Landlock LSM — ABI v4 (TCP port restrictions) + v6 (scoping). Adds the second hardening layer to `policy_strict()` alongside the existing process-scope guards. | New `src/landlock.cyr` (struct LandlockRuleset, builder fns) + post-fork hook in `src/backend_process.cyr`. Uses `sys_landlock_create_ruleset` / `sys_landlock_add_rule` / `sys_landlock_restrict_self` from stdlib `syscalls_x86_64_linux.cyr` L614-630 (and the aarch64 peer at L665-675). Needs the fork-infra below to install the ruleset post-fork in the child. |
| **`sandbox_fork_exec(args, pre_exec_fn)`** | Custom fork+exec helper: `sys_fork()` → in child, run async-signal-safe `pre_exec_fn` callback (landlock install, cgroup re-join when exact accounting matters, future seccomp filter), then `sys_execve`. Replaces the shell-prepend trick with a tight, no-shell-dependency path for sandboxes that need it. | New helper in `src/util.cyr` or new `src/fork_exec.cyr`. The shared infra for landlock + future seccomp. |
| **OCI backend cgroup integration** | Populate the `resources.linux.{memory,cpu,pids}` section of the OCI runtime spec in `oci_spec.cyr` so `runc` / `crun` set up cgroups directly instead of relying on kavach-managed cgroupfs writes. | [`src/oci_spec.cyr`](../../src/oci_spec.cyr) — extend the JSON template. Independent of the fork-infra; bundled into v3.3.0 to keep the OCI-cgroup story coherent. |
| **`cyrius fmt` clean** | Drains the v3.0-inherited fmt drift across `src/{audit,backend_sy_agnos,composite,credential,quarantine,scanning_gate,scanning_secrets}.cyr` and `tests/kavach.{tcyr,bcyr}`. | In-tree edits across the listed files. **Local-toolchain caveat**: cc 5.10.34 must be the running fmt — running 5.10.44 fmt locally and committing the result would write minor-version-sensitive drift. CI runs fmt as `::warning::` informational until cleared. |

#### Blocked — actually awaiting upstream

Each row carries: **what it means** (the concrete kavach-side surface that gates on it), **who owns the upstream work**, and **trigger condition** (what has to ship for kavach to unblock).

##### Seccomp hooks

- **What it means.** kavach calls `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` + `seccomp(SECCOMP_SET_MODE_FILTER, 0, &bpf_prog)` post-fork in the child between `fork()` and `execve()`. The BPF program filters syscalls per `SandboxPolicy.seccomp_profile` ("strict" / "basic" / off). Today `policy_strict()` stores the profile but the backend can't install it — the runtime guards in `scanning_runtime.cyr` are a poor substitute that scan the command string rather than block syscalls.
- **Who owns it.** Upstream Cyrius — `sys_prctl(option, arg2, arg3, arg4, arg5)` and `sys_seccomp(op, flags, args)` wrappers in `syscalls_x86_64_linux.cyr` (and the aarch64 peer). Async-signal-safe semantics are critical because the call sites are post-fork. Filed upstream: [`cyrius/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md) (covers prctl + seccomp + setresuid + setresgid + execveat + fchmod as a single coordinated batch).
- **Trigger condition.** Either (a) upstream lands the two wrappers, or (b) kavach adds raw `syscall(157, ...)` (SYS_PRCTL) and `syscall(317, ...)` (SYS_SECCOMP) in a `src/seccomp.cyr` module — same pattern we already use for SYS_FCHMOD in `file_write_secure_modal()`. Option (b) is do-able now if appetite exists; the only reason not to is that the BPF-program builder is non-trivial (~700 lines in the rust-old port).

##### Firecracker jailer / vsock / snapshot

- **What it means.** Today `backend_firecracker.cyr` writes a `config.json` and spawns `firecracker --no-api --config-file`. The Firecracker jailer (drops to a per-VM UID/GID via `setresuid` / `setresgid`, chroots into the VM rootfs, mounts proc/sys) isn't wired; nor are vsock control-socket robustness (reconnect on EAGAIN, partial-frame retries) or snapshot/restore (`vmm.snapshot.create` / `vmm.snapshot.load` over the api socket).
- **Who owns it.** Upstream Cyrius — `sys_setresuid(ruid, euid, suid)` / `sys_setresgid(rgid, egid, sgid)` wrappers, plus more-robust unix-socket helpers in `net.cyr` (today's surface is fine for one-shot connect/send/recv but doesn't deal well with backpressure on the FC api socket). The setresuid/setresgid pair is part of the same coordinated cyrius filing as seccomp — see the link in the Seccomp row above.
- **Trigger condition.** Same pattern as seccomp — wait for upstream wrappers, or do raw syscall(117, ...) / syscall(119, ...) here. Lower priority than seccomp because Firecracker without the jailer is still useful (microVM boundary is the primary isolation).

##### H4 binary-path TOCTOU (ADR-005 §H4 residual)

- **What it means.** The hardening pass closed argument-smuggling via control chars in v3.0, but the residual H4 finding is: between `which()` resolving the binary path and `execve()` opening it, an attacker who can write to `/usr/bin/<name>` (or another searched path) could swap the binary. Closure requires `execveat(O_PATH | O_NOFOLLOW fd, ...)` with the path resolved into an fd once at `which()` time and held until exec.
- **Who owns it.** Upstream Cyrius — `sys_execveat(dirfd, pathname, argv, envp, flags)` wrapper. Maybe also a Cyrius-side fd-cache helper since the fd has to survive across the fork boundary into the child's pre_exec. Part of the same coordinated cyrius filing as the other sandbox-runtime syscall wrappers (see the link in the Seccomp row above).
- **Trigger condition.** `sys_execveat` wrapper ships, OR kavach raw-syscalls SYS_EXECVEAT = 322 directly in `backend_process.cyr`. Same pattern as the others. Note: this is an enhancement to a *closed* finding — the H1-H3 fixes already prevent the dominant attack class.

##### SGX / SEV / TDX attestation + sealing

- **What it means.** `backend_sgx.cyr` / `backend_sev.cyr` / `backend_tdx.cyr` build the runtime today (Gramine manifest for SGX; qemu + SEV-SNP or TDX guest object for the others), but **none of them fetch or verify the resulting guest's attestation quote.** ADR-004 §6 calls for: parsing the quote (SGX EAR / SEV-SNP VCEK chain / TDX TD-quote), validating the cert chain (Intel IAS or DCAP for SGX; AMD ARK→ASK→VCEK for SEV-SNP), checking measurements (MRENCLAVE/MRSIGNER for SGX; MRTD/RTMR0-3 for TDX; guest hash for SEV-SNP) against an allowlist, and (SGX-only) sealing keys against MRSIGNER + ISVSVN. Today `src/attestation.cyr` stores the report shape (`SgxAttestationReport`) but the verifier doesn't exist.
- **Who owns it.** Upstream sigil — needs `sgx.cyr` + `sev_snp.cyr` + `tdx.cyr` (quote parsers + verifiers composing against existing sha256/hmac/ct), plus ECDSA P-256 (P-384 for some TDX paths) and minimal X.509 cert-chain primitives. sigil 2.9.0 has the crypto kernel (`sha256`, `hmac`, `ed25519`, `aes_gcm`, `verify`, `policy`, `trust`, `tpm`, `secureboot`, `ima`, `integrity`) but no TEE-specific quote-format surface. Filed upstream: [`sigil/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md`](https://github.com/MacCracken/sigil/blob/main/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md).
- **Trigger condition.** sigil ships the TEE-attestation module set. The filing suggests v3.2-or-later in sigil — the current sigil 3.1 arc is alloc-free verify rewrite (own perf-win for every downstream) and shouldn't be displaced. Stiva, daimon, AgnosAI, shakti are all secondary consumers when this lands.

##### Stiva OCI backend

- **What it means.** Today `backend_oci.cyr::_oci_runtime_path()` returns the first of `runc` / `crun` found in PATH. The plan in ADR-004 §7 is: prepend stiva when available, so that the kavach OCI backend can transparently use stiva's hardened OCI runtime instead of upstream runc when a stiva install is present.
- **Who owns it.** Upstream — there's no stiva Cyrius port yet. The Rust-era stiva is at the genesis repo; the Cyrius port hasn't started. Not in `/home/macro/Repos` as of 2026-05-10.
- **Trigger condition.** stiva Cyrius port ships v1.0.0 with a stable `stiva` CLI entry point. Single-line addition to `_oci_runtime_path()` once it does. **No upstream filing today** — there's no upstream repo to file against. Will revisit when the stiva Cyrius port repo lands.

#### Meta

- **Toolchain patch available.** cc `6.0.41` shipped just after the v3.3.0 pin landed at `6.0.40`. Pin stays at `6.0.40` for this release; adopt `6.0.41` in a later patch (v3.3.1 / v3.4.0) once it's run through the `deps → build → lint → vet → test → bench` gate. Local `cycc` already sits at 6.0.41, so the manifest-vs-cycc drift warning is expected until the pin catches up.
- Three items reclassified out of Blocked at the cc 5.10.34 verify pass (Landlock / cgroups v2 / HTTP credential proxy). The Blocked table is now load-bearing — each row gates on a verified-absent upstream surface, not a stale assumption.
- Upstream filings landed in 3.1.2: one cyrius issue covering the six sandbox-runtime syscall wrappers (prctl / seccomp / setresuid / setresgid / execveat / fchmod) and one sigil issue covering the SGX/SEV/TDX quote-parser + cert-chain primitives. Both filings include a **severity rationale** section letting the upstream maintainer adjust the rating; both are filed at P1 per kavach's perspective, with honest counter-cases noted (kavach raw-syscall workaround precedent for cyrius; "kavach ships fine without this today" for sigil).
- Re-run the verify pass when the Cyrius pin moves or when sigil unblocks past 2.9.0. **(v3.3.0: pin moved to cc 6.0.40 and sigil unblocked to 3.5.9 — the 5.10.x SIGILL bisect is retired. Re-run the SGX/SEV/TDX verify pass against the cc 6.0 surface.)**

---

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
