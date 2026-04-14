# Kavach Architecture (v2.0 — Cyrius port)

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
├── quarantine.cyr         File-based artifact quarantine + status lifecycle
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
└── sandbox_exec.cyr       End-to-end: dispatch → gate → threat → audit
```

---

## Data flow

### Policy construction

```
policy_strict() ─► SandboxPolicy{ seccomp, ro_rootfs, mem=512, cpu=1.0,
                                  scope.abstract_unix=1, scope.signal=1 }
```

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

Policy modifiers (additive, clamped to [0, 100]):

| Modifier | +Score |
|----------|-------:|
| seccomp enabled | +5 |
| landlock rules present | +3 |
| network disabled | +5 |
| read-only rootfs | +3 |
| memory OR cpu limit set | +2 |
| TCP bind/connect port allowlist | +3 |
| landlock scope: abstract unix socket | +2 |
| landlock scope: signal | +2 |

---

## Trust boundary

**HMAC-SHA256 audit chain** (`src/audit.cyr`)
- Every exec records `exec_begin` + `exec_complete` entries.
- Each entry: `HMAC(key, "serial:event_type:payload:timestamp:prev_hmac")`.
- File format: JSONL, appended with `file_append_locked` (file-locked writes).
- Tamper detection: `audit_entry_verify(entry, key, key_len)` recomputes HMAC; chain verification walks serials + `prev_hmac` linkage.
- Crypto via [sigil](https://github.com/MacCracken/sigil) ≥ 2.1.2.

**Credential proxy** (`src/credential.cyr`)
- `CredentialProxy` keeps a `map_new()` of `name → value`.
- `SecretRef{ name, inject_via: ENV_VAR | FILE | STDIN, param1, param2 }`.
- Resolution returns raw cstr (in-memory); the sandbox process sees only the destination form (env var, mounted file, stdin byte stream).

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
| Cyrius stdlib | 4.0.0+ | string, fmt, alloc, vec, str, syscalls, io, args, assert, bigint, chrono, hashmap, freelist, fnptr, process |
| [sigil](https://github.com/MacCracken/sigil) | 2.1.2+ | SHA-256, HMAC-SHA256 |

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

## Deferred surface (intentional)

See [ADR-004](../adr/004-deferred-features.md) for rationale.

| Feature | Blocking dep | Workaround |
|---------|--------------|------------|
| Enriched per-backend features (SGX attestation + sealing, SEV attestation, Firecracker vsock/snapshot/jailer, SyAgnos image manager) | per-feature: sigil EAR helpers, net.cyr Unix sockets, uid/gid syscalls | dispatch slots live — enrichment happens in-place |
| seccomp/Landlock/cgroups hooks | syscall wrappers in Cyrius stdlib | process backend runs without them today |
| async exec | Cyrius async story still maturing | synchronous fork+wait |
| HTTP credential proxy | TLS + HTTP server in stdlib | direct injection (env/file/stdin) |
| OffenderTracker | chrono + keyed hashmap | threat classification still scores each exec |
| Sandbox integrity monitoring | /proc file reads | runtime guard still blocks by pattern |
| Secret redaction (WARN verdict) | single-pass range merger | BLOCK on any secret, WARN never redacts |
| UUID v4 | random-bytes provider | monotonic counter for sandbox id + quarantine id |
| Full regex in pattern matchers | PCRE engine in Cyrius | hand-rolled literal-prefix + char-class matchers |

These are pluggable: each has a clear hook point and does not affect the architecture.
