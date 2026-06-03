# Kavach Architecture (v3.x — Cyrius port)

> Sandbox execution framework with quantitative strength scoring, a three-scanner
> externalization gate, credential proxy, runtime guards, threat classification,
> and an HMAC-SHA256 audit chain.
>
> **Name**: Kavach (कवच, Sanskrit) — armor, shield.
> Protects both what's inside the sandbox and what flows out of it.

---

## Design principles

1. **Backend-agnostic** — the dispatch table means callers write against `sandbox_exec()`, not a per-backend API.
2. **Quantitative security** — every sandbox gets a `StrengthScore` (0–100), not a vague "secure/insecure".
3. **Nothing leaves without scanning** — the externalization gate runs secrets + code + data scanners on every exec result.
4. **Audit by default** — every exec is HMAC-SHA256 signed and chained to the previous entry. Tampering breaks the chain.
5. **Credentials never land on disk** — the proxy holds secrets in memory and injects via env/file/stdin; the sandbox process never sees the registry.
6. **Fail closed** — unknown backends, missing dispatch slots, state-machine violations, and any scanner error path default to blocking.

---

## System architecture

```
Consumers (SY, stiva, kiran, AgnosAI, hoosh, bote, aethersafta)
         │
         ▼
┌────────────────────────────────────────────────────────────────┐
│ sandbox_exec(sandbox, command)         [sandbox_exec.cyr]      │
│                                                                │
│  1. State guard     (sandbox must be RUNNING)                  │
│  2. Backend dispatch  ──►  fnptr table keyed by Backend enum   │
│  3. Externalization gate                                       │
│       ├─ secrets scanner     (7 pattern families)              │
│       ├─ code scanner        (26 pattern groups)               │
│       └─ data scanner        (PII + 4 compliance frameworks)   │
│  4. Threat classification  (intent 0..1000, 7 kill-chain stages)│
│  5. Audit record (HMAC-SHA256 chain, JSONL on disk)            │
│  6. Verdict routing:                                           │
│     PASS / WARN     ─► release                                 │
│     QUARANTINE       ─► hold, require approval                 │
│     BLOCK            ─► reject                                 │
└────────────────────────────────────────────────────────────────┘
```

---

## Module map (Cyrius)

```
src/
├── main.cyr               Entry point, orchestration, include manifest
├── util.cyr               Shared string helpers (strieq, ch_ascii_lower)
├── error.cyr              KavachError enum + kavach_err_print
├── backend.cyr            Backend enum, name/parse, availability probes
├── policy.cyr             SandboxPolicy struct + minimal/basic/strict presets
├── scoring.cyr            base_score, score_backend, resolve_best_backend
├── lifecycle.cyr          SandboxState FSM, SandboxConfig, Sandbox, SandboxPool
│
├── scanning_types.cyr     Severity, ScanVerdict, ScanFinding, ScanResult,
│                          ExternalizationPolicy
├── scanning_secrets.cyr   Secret-pattern matchers (AWS/GitHub/GCP/JWT/priv-key/
│                          conn-string/SSN)
├── scanning_code.cyr      26 code-violation pattern groups
├── scanning_data.cyr      Credit-card/phone/IPv4/IBAN + HIPAA/GDPR/PCI/SOC2
├── scanning_gate.cyr      3-scanner orchestration → verdict
├── scanning_runtime.cyr   Fork-bomb, sensitive-path, command blocklist, shell
│                          metacharacter, time anomaly guards
├── scanning_threat.cyr    Intent scoring, kill-chain stages, escalation tiers
│
├── audit.cyr              HMAC-SHA256 append-only chain (JSONL on disk)
├── credential.cyr         SecretRef + CredentialProxy (env/file/stdin inject)
├── credential_http.cyr    Loopback HTTP credential proxy (GET /v1/secret/<name>)
├── quarantine.cyr         File-based artifact quarantine + status lifecycle
├── cgroup.cyr             cgroups v2 (memory.max / cpu.max / pids.max +
│                          shell-prepend placement)
│
├── oci_spec.cyr           Shared OCI runtime spec v1.0.2 generator +
│                          bundle mkdir/cleanup (used by gVisor + OCI)
├── backend_dispatch.cyr   Function-pointer table keyed by Backend enum
├── backend_noop.cyr       Noop backend registration
├── backend_process.cyr    Process backend (fork+exec+capture + guard precheck)
├── backend_gvisor.cyr     gVisor backend (shared oci_spec + `runsc run`)
├── backend_oci.cyr        OCI backend (shared oci_spec + `runc`/`crun`)
├── backend_wasm.cyr       WASM backend (`wasmtime` CLI shell-out)
├── backend_sy_agnos.cyr   Hardened AGNOS image + Phylax scanner
├── backend_sgx.cyr        Intel SGX via `gramine-sgx` + generated manifest
├── backend_sev.cyr        AMD SEV-SNP via QEMU with confidential-guest
├── backend_tdx.cyr        Intel TDX via QEMU with tdx-guest object
├── backend_firecracker.cyr Firecracker microVM with config.json + `--no-api`
├── composite.cyr          Defense-in-depth policy merging + composite score
├── observability.cyr      HealthStatus, SandboxMetrics, SpawnedProcess types
├── attestation.cyr        AttestationResult + AttestationTrust + SGX report
└── sandbox_exec.cyr       End-to-end: dispatch → gate → threat → audit
```

---

## Data flow

### Policy construction

```
policy_strict() ─► SandboxPolicy{ seccomp_enabled=1, seccomp_profile="strict",
                                  read_only_rootfs=1, memory_limit_mb=512,
                                  cpu_limit_tenths=10 (1.0 cores),
                                  max_pids=64,
                                  landlock_abstract_unix=1, landlock_signal=1 }
```

The `memory_limit_mb` / `cpu_limit_tenths` / `max_pids` fields are honored by `src/cgroup.cyr` (v3.2.0+); the `seccomp_*` and `landlock_*` fields wait on v3.3.0 + future seccomp.

### Backend selection

```
resolve_best_backend(policy) walks Backend enum by index,
  filters by backend_is_available(),
  scores each via score_backend(backend, policy),
  returns the highest (default: Backend.NOOP if nothing else registers).
```

### Exec pipeline

```
sandbox_exec(sb, "echo hi")
  ├─ backend_dispatch_exec(sb, "echo hi")
  │     looks up fnptr at _backend_table + backend_id * 32
  │     fncall2(fp, sandbox, command)  →  ExecResult*
  ├─ gate_apply(result, policy)
  │     concatenates stdout + "\n" + stderr
  │     runs secrets_scan, code_scan, data_scan
  │     determines verdict from worst severity vs thresholds
  │     returns ScanResult{ verdict, findings, worst_severity }
  ├─ classify_threat(findings)
  │     fixed-point (×1000) intent score
  │     co-occurrence amplifier on multi-stage findings
  │     ThreatAssessment{ intent, classification, escalation, stages }
  └─ audit_chain_record(chain, "exec_complete", verdict_name)
        HMAC-SHA256 signs: serial:event_type:payload:ts:prev_hmac
        appends JSONL line with file_append_locked
```

---

## Strength scoring

| Backend | Base | Tier |
|---------|-----:|------|
| Noop | 0 | minimal |
| Process | 50 | standard |
| OCI | 55 | standard |
| WASM | 65 | standard |
| gVisor | 70 | hardened |
| SGX | 80 | hardened |
| SEV | 82 | hardened |
| TDX | 85 | fortress |
| SyAgnos | 80 | hardened |
| Firecracker | 90 | fortress |

Policy modifiers (additive, clamped to [0, 100]). The score reflects what the
sandbox *claims* to enforce; runtime enforcement is per-feature (cgroups v2
shipping in v3.2.0; seccomp + Landlock waiting on v3.3.0):

| Modifier | +Score | Enforced at runtime today? |
|----------|-------:|----------------------------|
| seccomp enabled | +5 | No — claim only; v3.3.0+ |
| landlock rules present | +3 | No — claim only; v3.3.0 |
| network disabled | +5 | Backend-dependent (microVM/OCI yes, Process no) |
| read-only rootfs | +3 | Backend-dependent (OCI/gVisor/microVM yes) |
| memory OR cpu limit set | +2 | **Yes** (v3.2.0 via cgroups v2 on process backend) |
| TCP bind/connect port allowlist | +3 | No — claim only; v3.3.0 (Landlock ABI v4) |
| landlock scope: abstract unix socket | +2 | No — claim only; v3.3.0 |
| landlock scope: signal | +2 | No — claim only; v3.3.0 |

---

## Trust boundary

**HMAC-SHA256 audit chain** (`src/audit.cyr`)
- Every exec records `exec_begin` + `exec_complete` entries.
- Each entry: `HMAC(key, "serial:event_type:payload:timestamp:prev_hmac")`.
- File format: JSONL, appended with `file_append_locked` (file-locked writes).
- Tamper detection: `audit_entry_verify(entry, key, key_len)` recomputes HMAC; chain verification walks serials + `prev_hmac` linkage.
- Crypto via [sigil](https://github.com/MacCracken/sigil) 3.5.9 (pinned). Constant-time compare is now the stdlib `ct` module (`ct_eq_bytes_lens`) — sigil retired its own `ct_eq` in the 3.x line.

**Credential proxy** (`src/credential.cyr` + `src/credential_http.cyr`)
- `CredentialProxy` keeps a `map_new()` of `name → value`.
- `SecretRef{ name, inject_via: ENV_VAR | FILE | STDIN, param1, param2 }`.
- Resolution returns raw cstr (in-memory); the sandbox process sees only the destination form (env var, mounted file, stdin byte stream, or HTTP fetch).
- **HTTP variant (v3.2.0+):** `CredentialHttpProxy` exposes `GET /v1/secret/<name>` on a 127.0.0.1 listener; per-instance allowlist gates which names this proxy serves; every fetch + every 403/404 hits the audit chain when wired. Secrets never land on disk in this path — the "no on-disk artifact" alternative to file injection.

**cgroups v2 resource limits** (v3.2.0+, `src/cgroup.cyr`)
- Honors `SandboxPolicy.{memory_limit_mb, cpu_limit_tenths, max_pids}` via per-sandbox cgroup at `/sys/fs/cgroup/kavach-<rand_u64>/`.
- Placement: shell-prepend pattern. `backend_process.cyr::process_exec` wraps the user argv as `["sh", "-c", "echo $$ > <path>/cgroup.procs; exec \"$@\"", "--", <argv>...]`. `"$@"` passthrough avoids re-interpreting user metachars (variables, glob, quotes pass through positionally).
- Graceful no-op when `/sys/fs/cgroup` is read-only / absent / unprivileged. v3.3.0 will add a no-shell-dependency path via `sandbox_fork_exec` for sandboxes that need exact accounting from the first instruction.

---

## Extension pattern: adding a backend

Each backend is a plug into the dispatch table. To add `<name>`:

1. Create `src/backend_<name>.cyr`:
   ```
   fn <name>_exec(sandbox, command)     { ... return ExecResult*; }
   fn <name>_health(sandbox)            { return 1; }
   fn <name>_destroy(sandbox)           { return 0; }

   fn backend_<name>_register() {
       backend_register_exec(Backend.<NAME>, &<name>_exec);
       backend_register_health(Backend.<NAME>, &<name>_health);
       backend_register_destroy(Backend.<NAME>, &<name>_destroy);
       return 0;
   }
   ```
2. Include it in `src/main.cyr` and add the `backend_<name>_register()` call inside `kavach_init()` (`src/sandbox_exec.cyr`).
3. Update `backend_is_available(Backend.<NAME>)` in `src/backend.cyr` if availability requires a probe.
4. Add tests to `tests/kavach.tcyr`.

`Backend` dispatch slot layout (per backend, 32 bytes):

| Offset | Field | Signature |
|-------:|-------|-----------|
| 0 | exec_fn | `(sandbox, command) → ExecResult*` |
| 8 | health_fn | `(sandbox) → 1\|0` |
| 16 | destroy_fn | `(sandbox) → 0 on success` |
| 24 | reserved | |

---

## External dependencies

| Dep | Version | Purpose |
|-----|---------|---------|
| Cyrius toolchain | 6.0.43 (pinned in `cyrius.cyml`) | First-party tree is on the cc 6.0 line; the old 5.10.x sigil-NI asm-offset bisect is retired. Pin matches the installed cycc. |
| Cyrius stdlib | resolved by `cyrius deps` into `lib/` (gitignored) | `alloc, args, assert, bench, bigint, chrono, ct, dynlib, fdlopen, fmt, fnptr, freelist, fs, hashmap, hashmap_fast, io, json, keccak, mmap, net, process, result, sandhi, slice, str, string, syscalls, tagged, thread, tls, vec` |
| [sigil](https://github.com/MacCracken/sigil) | 3.5.9 (pinned tag) | SHA-256, HMAC-SHA256. Constant-time compare moved to the stdlib `ct` module (`ct_eq_bytes_lens`) — sigil retired `ct_eq` in 3.x. The 5.10.x SIGILL bisect that capped sigil at 2.9.0 no longer applies under cc 6.0.43. |
| [agnosys](https://github.com/MacCracken/agnosys) | 1.3.0 (transitive override) | sigil 3.5.9 pins agnosys 1.2.7 (cc 6.0.1), which fails to build under cc 6.0.43; kavach overrides to 1.3.0 (cc 6.0.24). Drops when sigil bumps its own pin. |

---

## Consumers

| Project | Usage |
|---------|-------|
| **SY** | Agent sandboxing (279 MCP tools) |
| **stiva** | Container runtime isolation |
| **kiran** | WASM scripting sandbox |
| **AgnosAI** | Sandboxed crew execution |
| **hoosh** | LLM tool sandboxing |
| **bote** | MCP tool handler isolation |
| **aethersafta** | Plugin isolation |

---

## Related docs

- [Getting started](../guides/getting-started.md)
- [Composite backends](../guides/composite-backends.md) — defense-in-depth patterns
- [Threat tracking](../guides/threat-tracking.md) — intent scoring and OffenderTracker
- [Worked examples](../examples/) — 4 progressive walkthroughs
- [Rust v2.0 vs Cyrius v3.0 benchmarks](../../benchmarks-rust-v-cyrius.md) (frozen historical snapshot)
- [Doc Health ledger](../doc-health.md) — currency tracking for the prose docs
- [ADR-001 port architecture](../adr/001-cyrius-port-architecture.md)
- [ADR-002 dispatch table](../adr/002-backend-dispatch-fnptr-table.md)
- [ADR-003 fixed-point scoring](../adr/003-fixed-point-threat-scoring.md)
- [ADR-005 hardening pass](../adr/005-v2-hardening-pass.md)

## Deferred surface (intentional)

See [ADR-004](../adr/004-deferred-features.md) for rationale; [`development/roadmap.md`](../development/roadmap.md) carries the live v3.3 + Blocked queues with upstream-filing cross-links.

What's still deferred at v3.3.0:

| Feature | Blocking dep | Trigger condition |
|---------|--------------|-------------------|
| **Landlock hooks** | A `sandbox_fork_exec(args, pre_exec_fn)` helper in kavach | **v3.4.0** — `sys_landlock_*` already in stdlib; we just need the post-fork hook point |
| **Seccomp BPF filter install** | Upstream `sys_prctl` + `sys_seccomp` wrappers (filed: [cyrius issue](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md)) OR raw syscall in kavach | Either upstream wrappers ship OR kavach raw-syscalls them; needs the same fork-infra as Landlock |
| **H4 binary-path TOCTOU** (ADR-005 §H4 residual) | Upstream `sys_execveat` wrapper (same filing) | Enhancement to a *closed* finding — H1-H3 already block dominant attack class |
| **Firecracker jailer / vsock / snapshot** | Upstream `sys_setresuid` / `sys_setresgid` + robust unix-socket helpers (same filing) | Lower priority — microVM boundary already isolates without jailer |
| **SGX / SEV / TDX attestation + sealing** | Upstream sigil attestation modules (filed: [sigil issue](https://github.com/MacCracken/sigil/blob/main/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md)) | sigil ships SGX/SEV/TDX quote-parser + cert-chain primitives |
| **Stiva OCI backend** | stiva Cyrius port repo exists | Single-line addition to `_oci_runtime_path()` when stiva ships v1.0.0 |
| **OCI backend cgroup integration** | None — populate `resources.linux.{memory,cpu,pids}` in `oci_spec.cyr` | **v3.3.0** (bundled with the fork-infra cut) |
| **async exec** | Cyrius async story still maturing | Synchronous fork+wait remains correct for sandbox-runtime semantics |
| **Full regex in pattern matchers** | PCRE engine in Cyrius | hand-rolled literal-prefix + char-class matchers cover the v3.x surface |

What was deferred in v3.0 but has since shipped: UUID v4 IDs, WARN-verdict secret redaction, OffenderTracker, sandbox integrity monitoring (all v3.0 closeout); `FileInjection.mode` honoring (v3.1.1); cgroups v2 + HTTP credential proxy (v3.2.0).

Hook points stay pluggable: each remaining row has a clear landing site and doesn't disturb the dispatch / scanner / audit-chain spine.
