# Kavach Roadmap

> **Principle**: Security correctness first, then backend breadth, then performance. Every sandbox gets a number.

This roadmap is **future-facing only** — shipped work lives in [CHANGELOG.md](../../CHANGELOG.md). Current release: v3.11.14 (toolchain refresh + the dropped-`chrono`-include fix). Toolchain pin: cc `6.5.27`; sigil `3.12.9`, samay `1.0.1`, ai-hwaccel `2.3.16` (agnosys dropped at v3.5.0 — its security backends are internalized).

---

## Next

### 3.4.1 — extend Aho-Corasick to the data + phylax scanners

- [ ] **Data + phylax scanners → single Aho-Corasick pass.** The `src/aho_corasick.cyr` engine shipped in 3.4.0 is scanner-agnostic, but only the code scanner uses it. The compliance keyword groups in `_data_scan_*` (`scanning_data.cyr`) and the phylax checks in `backend_sy_agnos.cyr` still do per-pattern `cstr_contains`. Apply the same integration the code scanner uses: a cached automaton over each scanner's literal set, one pass over the lowered text into a hit table, group checks via a `_hit()` lookup with a `cstr_contains` fallback (so a drifted pattern list can only cost speed, never correctness). Behavior-preserving; the existing scanner tests are the regression guard. Lower volume than the code scanner, so lower urgency — but it closes out the audit's P2 finding across all three scanners. Benchmark on a large artifact to confirm the win before/after.

### Tech debt

- [ ] **`cyrius fmt` clean.** Drain the v3.0-inherited fmt drift across `src/{audit,backend_sy_agnos,composite,credential,quarantine,scanning_gate,scanning_secrets}.cyr` and `tests/kavach.{tcyr,bcyr}`, then flip CI fmt from `::warning::` informational to hard-fail. **Local-toolchain caveat**: the pinned `6.0.43` fmt must be the running fmt — running a different patch locally and committing the result would write minor-version-sensitive drift.

### Recorded negatives (don't chase these)

- **No faster substring search in the stdlib** — `str_contains_cstr` is the same naive O(n·m) loop, so swapping `cstr_contains` for it buys clarity, not speed. The real fix (Aho-Corasick over the literal set) is already in for the code scanner and tracked above for data/phylax.
- **No stdlib SHA-256** — kavach correctly stays on sigil for HMAC-SHA256.
- **`overflow.cyr` operators panic** rather than returning the `-1` sentinel `alloc_checked` relies on — don't swap the existing size guards for them.
- **Typed-`slice` sweep** — subscripting is read-only in cc 6.0.43 (no `_slice_idx_set_W`), dot-syntax isn't wired, and kavach's loops are already correctly bounded; adopt `slice` reads only opportunistically on untrusted-input paths (as done for `is_safe_text`/`is_safe_argument`), not as a blanket rewrite.

---

## v3.5.0 — Landlock + fork-infra + OCI cgroups (feature cut)

The next *capability* cut (vs the 3.3.x/3.4.x hardening + perf work). These group around a single shared piece of infrastructure — a `sandbox_fork_exec(args, pre_exec_fn)` helper — and were deferred through 3.3.0 → 3.4.0 as those slots went to the toolchain jump and the AC scanner. Re-target as the next feature minor.

| Feature | What it adds | Where it lands |
|---------|--------------|----------------|
| **`sandbox_fork_exec(args, pre_exec_fn)`** | Custom fork+exec helper: `sys_fork()` → in child, run async-signal-safe `pre_exec_fn` callback (landlock install, cgroup re-join when exact accounting matters, future seccomp filter), then `sys_execve`. Replaces the shell-prepend trick with a tight, no-shell-dependency path. The shared infra for landlock + future seccomp. | New helper in `src/util.cyr` or new `src/fork_exec.cyr`. |
| **Landlock hooks** | Filesystem and network sandboxing via the Linux Landlock LSM — ABI v4 (TCP port restrictions) + v6 (scoping). Adds the second hardening layer to `policy_strict()` alongside the existing process-scope guards. | New `src/landlock.cyr` (struct LandlockRuleset, builder fns) + post-fork hook in `src/backend_process.cyr`. Uses `sys_landlock_create_ruleset` / `sys_landlock_add_rule` / `sys_landlock_restrict_self` from stdlib `syscalls_x86_64_linux.cyr` L614-630 (and the aarch64 peer L665-675). Needs the fork-infra above to install the ruleset post-fork in the child. |
| **OCI backend cgroup integration** | Populate `resources.linux.{memory,cpu,pids}` in the OCI runtime spec so `runc` / `crun` set up cgroups directly instead of relying on kavach-managed cgroupfs writes. Independent of the fork-infra; bundled here to keep the OCI-cgroup story coherent. | [`src/oci_spec.cyr`](../../src/oci_spec.cyr) — extend the JSON template. |

---

## v3.8.0 — detached policy-threaded spawn (`sandbox_spawn`)

**Requested by the stiva Cyrius port (its v3.1 blocked residue — detached `run -d`) — the one kavach-side blocker for a
properly-isolated `stiva run -d`.** stiva's synchronous `run` already gets full policy via
`sandbox_exec`; a detached `run -d` has no policy-applying spawn today, so it can't ship without
silently dropping isolation. `persistent_spawn` is raw fork+exec with **no** policy, and
`SpawnedProcess` is an inert `{pid, backend, started_at}` record with no wait/kill — so this cut
adds a **detached twin of `sandbox_exec`** plus the process handle's lifecycle ops. A full,
code-grounded draft (4 files + tests + 5 design decisions) exists in the stiva port planning;
summarized here.

**Shares the v3.5.0 fork-infra.** The spawn child body (dup2 stdio → log fd, `close(3..)`,
`PR_SET_NO_NEW_PRIVS`, and later landlock/seccomp) is exactly a `pre_exec_fn`, so build
`process_spawn`'s child on `sandbox_fork_exec(args, pre_exec_fn)` (v3.5.0 above) in a **detached**
flavor (no `waitpid`). Interim if the fork-infra isn't landed yet: hand-roll the fork/exec
(mirroring `persistent_spawn`) and refactor onto `sandbox_fork_exec` when it arrives. When the
Seccomp-hooks blocker (below) clears, the same shared `pre_exec_fn` hardens `exec` **and** `spawn`
identically — no drift.

| Item | What it adds | Where |
|------|--------------|-------|
| **spawn vtable slot** | `backend_register_spawn` + `backend_dispatch_spawn(sandbox, command, log_fd)` using the free `reserved` slot @24 of the 32-byte backend table; returns 0 for non-spawnable backends (noop/wasm) → caller falls back to `exec` (the existing `SpawnedProcess` doc contract). | [`src/backend_dispatch.cyr`](../../src/backend_dispatch.cyr) |
| **`process_spawn(sandbox, command, log_fd)`** | The heart: same policy as `process_exec` (control-char guard + runtime guard + cgroup limits) but fork+exec's **detached** — child `dup2`s `log_fd`→1/2, `/dev/null`→0, `close(3..)` [CVE-2024-21626], `PR_SET_NO_NEW_PRIVS`, `execve`; parent returns a `SpawnedProcess`. Cgroup is torn down at **reap**, not after fork (the daemon lives in it). Register via `backend_register_spawn(Backend.PROCESS, …)`; oci/gvisor/firecracker get their own `*_spawn` later. | [`src/backend_process.cyr`](../../src/backend_process.cyr) |
| **`sandbox_spawn(sandbox, command, log_fd)`** | Entry point / twin of `sandbox_exec`: verify `RUNNING` → `backend_dispatch_spawn` → live `SpawnedProcess` (0 → caller falls back to `exec`). No externalization gate at spawn time (a daemon's output is scanned as the log is read). | [`src/sandbox_exec.cyr`](../../src/sandbox_exec.cyr) |
| **`SpawnedProcess` lifecycle** | Add a `cgroup` field (24→32 bytes) for reap-time teardown; add `spawned_wait` (block → `ExecResult`), `spawned_try_wait` (`WNOHANG` → exit code \| still-running sentinel), `spawned_kill(grace_ms)` (SIGTERM → poll ≤ grace → SIGKILL → reap). | [`src/observability.cyr`](../../src/observability.cyr) |

**Design decisions (from the draft, open for sign-off):** (1) policy level = **parity with
`sandbox_exec` today** (guard + cgroups; seccomp/landlock arrive together with the fork-infra +
the Seccomp-hooks unblock, applied to both via the shared `pre_exec_fn`); (2) the spawn child adds
`close(3..)` + NO_NEW_PRIVS — slightly **more** than exec's current child, justified because a
daemon outlives the parent (candidate to backport to exec); (3) cgroup teardown at **reap** via
the new struct field (alternative: hang it on the `Sandbox` and free it in `sandbox_destroy`);
(4) stdio → a **caller-provided `log_fd`** (this is what lets stiva's `logs -f` work with no
streaming machinery — the daemon writes its log directly).

**Tests:** mostly no-priv/deterministic — `sandbox_spawn` on a not-RUNNING sandbox → 0; spawn
`/bin/echo` with a temp `log_fd` → pid > 0, `spawned_wait` exit 0, the log file holds the output
(proves dup2-to-log); guard-reject never forks; an fd-leak assertion for `close(3..)`. Gated
rootful test: a `pids.max=1` policy caps a fork bomb and the cgroup dir is gone after reap.

**Consumer payoff:** stiva `spawn_container` becomes ~10 lines (`build_sandbox` → `sandbox_spawn`
→ `DaemonHandle{sp, sandbox}`), `DaemonHandle.wait/try_wait/kill` wrap `spawned_*`, and `run -d`
stops printing "deferred to v3.1". **Do not ship a half-isolated interim over `persistent_spawn`**
— it threads no policy and would be strictly less isolated than the sync `run`.

---

## Open questions

- [ ] **`[lib]` profile + `dist/kavach.cyr` bundle.** kavach is binary-only today and no consumer (SY / stiva / kiran / AgnosAI / hoosh / bote / aethersafta) embeds it at source level. Open the profile when the first consumer asks — adding a bundle pre-demand creates a maintenance commitment with no current consumer benefit.

---

## Blocked — awaiting upstream

Each row carries **what it means** (the concrete kavach-side surface that gates on it), **who owns the upstream work**, and **trigger condition** (what has to ship for kavach to unblock).

> Upstream filings (P1, with severity-rationale sections inviting the maintainer to re-rate): one **cyrius** issue covers the six sandbox-runtime syscall wrappers (prctl / seccomp / setresuid / setresgid / execveat / fchmod) as a coordinated batch; one **sigil** issue covers the SGX/SEV/TDX quote-parser + cert-chain primitives. Re-run the unblock verify pass whenever the cyrius pin moves or sigil ships new surface — most recently the cc 6.0 / sigil 3.5.9 jump, against which the SGX/SEV/TDX verify should be re-checked.

### Seccomp hooks

- **What it means.** kavach calls `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` + `seccomp(SECCOMP_SET_MODE_FILTER, 0, &bpf_prog)` post-fork in the child between `fork()` and `execve()`. The BPF program filters syscalls per `SandboxPolicy.seccomp_profile` ("strict" / "basic" / off). Today `policy_strict()` stores the profile but the backend can't install it — the runtime guards in `scanning_runtime.cyr` are a poor substitute that scan the command string rather than block syscalls.
- **Who owns it.** Upstream Cyrius — `sys_prctl(option, arg2, arg3, arg4, arg5)` and `sys_seccomp(op, flags, args)` wrappers in `syscalls_x86_64_linux.cyr` (and the aarch64 peer). Async-signal-safe semantics are critical because the call sites are post-fork. Filed upstream: [`cyrius/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md).
- **Trigger condition.** Either (a) upstream lands the two wrappers, or (b) kavach adds raw `syscall(157, ...)` (SYS_PRCTL) and `syscall(317, ...)` (SYS_SECCOMP) in a `src/seccomp.cyr` module — same pattern we already use for SYS_FCHMOD in `file_write_secure_modal()`. Option (b) is do-able now if appetite exists; the only reason not to is that the BPF-program builder is non-trivial (~700 lines in the rust-old port).

### Firecracker jailer / vsock / snapshot

- **What it means.** Today `backend_firecracker.cyr` writes a `config.json` and spawns `firecracker --no-api --config-file`. The Firecracker jailer (drops to a per-VM UID/GID via `setresuid` / `setresgid`, chroots into the VM rootfs, mounts proc/sys) isn't wired; nor are vsock control-socket robustness (reconnect on EAGAIN, partial-frame retries) or snapshot/restore (`vmm.snapshot.create` / `vmm.snapshot.load` over the api socket).
- **Who owns it.** Upstream Cyrius — `sys_setresuid` / `sys_setresgid` wrappers, plus more-robust unix-socket helpers in `net.cyr` (today's surface is fine for one-shot connect/send/recv but doesn't deal well with backpressure on the FC api socket). The setresuid/setresgid pair is part of the same coordinated cyrius filing as seccomp.
- **Trigger condition.** Same pattern as seccomp — wait for upstream wrappers, or do raw `syscall(117, ...)` / `syscall(119, ...)` here. Lower priority than seccomp because Firecracker without the jailer is still useful (the microVM boundary is the primary isolation).

### H4 binary-path TOCTOU (ADR-005 §H4 residual)

- **What it means.** The hardening pass closed argument-smuggling via control chars in v3.0; the residual H4 finding is that between `which()` resolving the binary path and `execve()` opening it, an attacker who can write to a searched path could swap the binary. Closure requires `execveat(O_PATH | O_NOFOLLOW fd, ...)` with the path resolved into an fd once at `which()` time and held until exec.
- **Who owns it.** Upstream Cyrius — `sys_execveat(dirfd, pathname, argv, envp, flags)` wrapper, plus possibly an fd-cache helper since the fd has to survive the fork boundary into the child's pre_exec. Part of the same coordinated cyrius filing.
- **Trigger condition.** `sys_execveat` ships, OR kavach raw-syscalls SYS_EXECVEAT = 322 in `backend_process.cyr`. This is an enhancement to a *closed* finding — the H1-H3 fixes already prevent the dominant attack class.

### SGX / SEV / TDX attestation + sealing

- **What it means.** `backend_sgx.cyr` / `backend_sev.cyr` / `backend_tdx.cyr` build the runtime today (Gramine manifest for SGX; qemu + SEV-SNP or TDX guest object for the others), but **none fetch or verify the guest's attestation quote.** ADR-004 §6 calls for parsing the quote (SGX EAR / SEV-SNP VCEK chain / TDX TD-quote), validating the cert chain (Intel IAS or DCAP for SGX; AMD ARK→ASK→VCEK for SEV-SNP), checking measurements against an allowlist, and (SGX-only) sealing keys against MRSIGNER + ISVSVN. Today `src/attestation.cyr` stores the report shape (`SgxAttestationReport`) but the verifier doesn't exist.
- **Who owns it.** Upstream sigil — needs `sgx.cyr` + `sev_snp.cyr` + `tdx.cyr` (quote parsers + verifiers composing against existing sha256/hmac/ct), plus ECDSA P-256 (P-384 for some TDX paths) and minimal X.509 cert-chain primitives. sigil has the crypto kernel but no TEE-specific quote-format surface. Filed upstream: [`sigil/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md`](https://github.com/MacCracken/sigil/blob/main/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md).
- **Trigger condition.** sigil ships the TEE-attestation module set. Re-check against the current sigil 3.5.9 surface.

### Stiva OCI backend

- **What it means.** Today `backend_oci.cyr::_oci_runtime_path()` returns the first of `runc` / `crun` found in PATH. ADR-004 §7 plans to prepend stiva when available, so the kavach OCI backend transparently uses stiva's hardened OCI runtime instead of upstream runc.
- **Who owns it.** Upstream — the **stiva Cyrius port**, now live at **v3.0.0** (a synchronous single-node OCI runtime with a 19-verb `stiva` CLI: run/ps/stop/rm/inspect/images/…). What kavach's OCI backend needs, though, is stiva as a **runc-compatible OCI runtime** — the `stiva create/start/state/kill/delete` CLI over a bundle — which the port does **not** expose yet. The OCI state/bundle primitives (`parse_bundle` / `build_state` / `to_oci_status`) **are** ported (stiva `oci` module); the container lifecycle it drives (`start` = run the container) is the **stiva v3.0.x runtime-completion line** (blocking, over the ported sync core), with detached `run -d` specifically being stiva's v3.1 residue blocked on this issue's `sandbox_spawn`; a runc-compatible OCI-runtime CLI on top is not yet scoped in stiva's roadmap.
- **Trigger condition.** stiva ships a stable OCI-runtime CLI (`stiva create/start/state/kill/delete` over a bundle — the runc drop-in) wrapping its v3.0.x lifecycle. Single-line addition to `_oci_runtime_path()` once it does. No upstream filing needed — stiva is a sibling repo, tracked in its own roadmap.

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

---

## Moving the cyrius pin to 6.6.6

**Current pin: `cyrius = "6.6.2"`** — four releases behind. Nothing must change first; this
is a pin bump and a rebuild. But read the two ⛔ items below before treating it as routine.

### ⭐ The reason to bump: the HMAC audit chain could silently write a torn line

This is a **Linux-side** fix, not the Windows one, and it lands squarely on kavach's
tamper-evidence guarantee.

`audit_chain_record` (`src/audit.cyr`) writes each JSONL entry with the stdlib's
`file_append_locked` and tests the result with `< 0`:

```cyrius
if (file_append_locked(AuditChain_log_path(chain), line, strlen(line)) < 0) {
    kavach_err_print(KAVACH_ERR_IO_ERROR, "audit chain write failed");
    return 0;
}
```

Before 6.6.6, `file_append_locked` issued **one** `write` and returned its count. A short
write appended a **prefix of the record** and returned a positive number — so a `< 0` test
saw success, the torn line went into the log, and `AuditChain_set_last_hmac` advanced the
chain over a line that no longer parses. For an append-only, tamper-evident HMAC chain that
is the worst possible failure mode: the log is corrupt and the corruption is
indistinguishable from tampering. 6.6.6 makes `file_append_locked` loop until the whole
record lands, holding the lock across the loop so the record stays contiguous.
**kavach's caller shape is exactly the one the fix names.**

### ⛔ The open aarch64 syscall issue is NOT closed by this bump

`docs/development/issues/2026-09-12-raw-x86-syscall-numbers-on-aarch64.md` stays open. Be
explicit about this, because 6.6.6 *does* contain ESYSXLAT work and it is easy to assume it
covers this:

- 6.6.6 adds an ESYSXLAT row for **statfs only** (`137 → 43` on aarch64) and names
  `SYS_STATFS` / `SYS_FSTATFS` in both Linux syscall peers. kavach has no `statfs` call
  site — checked, zero matches in `src/`.
- kavach's defects are syscall **35** and **91** (`src/util.cyr:359`'s `syscall(91, fd,
  mode, 0)` runs `capset` on aarch64; the credential-injection mode is silently never
  applied). 6.6.6 adds **no** row for either.
- The third defect in that filing is an **open flag value**, not a number: `131072` is
  `O_NOFOLLOW` on x86_64 and `O_LARGEFILE` on aarch64. cyrius does **not** translate open
  flag values on any release, 6.6.6 included. The 6.6.6 PE flag decoder is a Windows
  CreateFileW mapping and does nothing for aarch64 Linux.

So the pin move is orthogonal to that issue. Do not let the bump's CHANGELOG close it.

### O_APPEND / O_TRUNC — used, and Windows-safe by construction

kavach opens with both flags outside the vendored `lib/`:

- `src/confine.cyr:19` — `SPAWN_LOG_FLAGS = 1089` (`O_WRONLY|O_CREAT|O_APPEND`), used at
  `src/confine.cyr:190` for the container's stderr log. The comment there is exactly the
  invariant the Windows defect broke: *"a restarted container should extend its log, not
  silently erase the evidence of why the previous attempt died."* On a pre-6.6.6 PE build it
  would have erased it, from offset 0, with no error.
- `src/util.cyr:321` / `:351` — `file_write_secure_r` / `file_write_secure_modal` open
  `1 + 64 + 512 + 128 + 131072` (`O_WRONLY|O_CREAT|O_TRUNC|O_EXCL|O_NOFOLLOW`).
- `src/backend_oci.cyr:212` — `131265`, deliberately *without* `O_APPEND` (the comment at
  205–206 records why the earlier `O_APPEND` shape was wrong for that path).

**Not exposed** — checked rather than assumed: CI is `ubuntu-latest` only, there is no
`CYRIUS_TARGET_WIN` / `_TARGET_PE` branch anywhere in `src/`, no PE entry in `cyrius.cyml`,
and the security model is Landlock / seccomp-BPF / namespaces, which are Linux mechanisms.
The only conditional target is `CYRIUS_TARGET_AGNOS`.

### What else was checked

- **No shape the new refusals catch.** kavach declares 38 structs (`AuditChain`,
  `SandboxPolicy`, `SpawnedProcess`, `bpf_insn`, …) and **not one** is a by-value fn
  parameter, a fn return type, or a `var x: T = …` declaration — all are heap-offset layouts
  behind raw pointers, so neither the struct-copy refusal nor the by-value deep-copy change
  touches a line. The one `: Result` fn, `file_write_secure_r` (`src/util.cyr:319`), was
  walked: every `return` is `Ok(…)` or `Err(…)`, so the new "a pair-return fn must return a
  same-shaped pair" refusal is satisfied. No `async fn`, no `operator` fn, no SIMD-returning
  fn, no fn mixing pair and scalar returns.
- **Also clean:** no `var` inside a top-level block (zero top-level `{` / `if (` / `while (`
  at column 0), no `lib/regression.cyr` consumer, no `vec_*` of kavach's own, no duplicate
  top-level global, no symlink in `lib/` (6.6.6 makes `cyrius deps` **fail** rather than skip
  when a `lib/*.cyr` cannot be hashed — nothing to clear here; `release.yml` already runs
  `cyrius deps --verify`).
- **A stale comment to fix while you are in there.** `src/audit.cyr` says *"A wider
  `file_append_locked_mode` wrapper is scheduled for Cyrius stdlib 4.4.0"*. There is no such
  wrapper in 6.6.6's `lib/io.cyr`, and "stdlib 4.4.0" is not a version the toolchain has used
  for a long time. The hand-rolled `file_restrict_mode` after each append is still the
  hardening path — the comment should say so rather than promise a wrapper that is not coming.

### Other 6.6.6 changes worth knowing, with their actual relevance

- `file_write_atomic` now **keeps an existing file's mode** (it used to reset to
  `0644 & ~umask`), and the new `file_replace_atomic` writes **through** a symlink. kavach
  uses neither today — every write goes through `file_write_secure*`, which is `O_EXCL` +
  `O_NOFOLLOW` by design. ⚠ `file_replace_atomic`'s follow-the-symlink semantics are the
  **opposite** of kavach's threat model (`src/quarantine.cyr:111` exists because
  attacker-staged symlinks at the target paths are the attack). Do not adopt it in a
  quarantine or credential path.
- `cyrius build` now **exits 1** instead of 0 when its output rename fails. If any kavach
  script treated a build as successful without checking for the artifact, it starts failing
  correctly.

### What it gains

The `file_append_locked` fix above; 6.6.3's `#inline`-disarms-`#derive` fix; 6.6.4's ≥64 KB
string-literal read-back fix (kavach's longest literal is 534 B in `src/oci_spec.cyr`, so not
reachable today); 6.6.5's aggregate-layout fix, silently wrong since 5.8.17, and three
corrected ENTRY stack bases; and 6.6.6's nine new refusals.

### Verify after bumping

`cyrius deps` → `cyrius deps --verify` → `cyrius build` → `cyrius build --agnos` →
`cyrius test` → **regenerate `dist/kavach.cyr` and `dist/kavach-confine.cyr`**. Then the one
targeted check this bump earns: append a burst of audit entries large enough to provoke a
short write and run the chain verifier over the resulting log. That is the behaviour 6.6.6
changed, and a passing suite that never writes a big record will not see it.

⚠ The refreshed `lib/` carries the 6.6.6 `sigil.cyr`, whose shipped dist does not pass
`cyrfmt --check`. Harmless here — kavach's format gate loops over
`src/*.cyr tests/*.tcyr tests/*.bcyr tests/*.fcyr` and never walks `lib/`. Do not fix it in
the fold; per the ecosystem rule the repair belongs in the sigil source repo.
