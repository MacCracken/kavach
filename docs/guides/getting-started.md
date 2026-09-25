# Getting started with kavach

This guide walks through the three minimum steps to run code through kavach:
configure a policy, create a sandbox, execute through the full pipeline.

## 1. Build + install

```sh
cd kavach
cyrius deps                                # resolve lib/ from cyrius.cyml [deps]
cyrius build src/main.cyr build/kavach
./build/kavach                             # runs the end-to-end demo
```

Cyrius toolchain `6.6.6` required (pinned in `cyrius.cyml`). The pin matches
the installed `cycc`; if `cycc` later drifts ahead of the pin, skip local
`cyrius fmt` writes to avoid minor-version drift.
Dependencies are declared in [`cyrius.cyml`](../../cyrius.cyml):

- **Cyrius stdlib** modules (alloc, args, assert, async, atomic, bayan, bench,
  chrono, ct, dynlib, fdlopen, fmt, fnptr, freelist, fs, hashmap, hashmap_fast,
  io, keccak, math, mmap, net, process, random, result, sakshi, sandhi, slice,
  str, string, syscalls, tagged, thread, thread_local, tls, vec). `ct`, `keccak`,
  `thread` and `thread_local` are opt-in modules sigil needs; leave one out and
  the build is clean but the first crypto call SIGILLs. `chrono` is also
  hand-included at the top of `src/util.cyr` (and in `tests/kavach.fcyr` +
  `tests/samay_integration.tcyr`), a guard from a cc 6.5.26–6.5.27 resolver bug
  that upstream fixed in 6.5.28 — see v3.11.14 and v3.12.6 in the CHANGELOG.
- **[sigil](https://github.com/MacCracken/sigil) 3.12.18** for SHA-256 and
  HMAC-SHA256 (used by `src/audit.cyr`). Constant-time compare
  (`src/util.cyr::ct_streq`) uses the stdlib `ct` module's `ct_eq_bytes_lens`.
  sigil comes from the pinned toolchain's stdlib snapshot (`tls` pulls it in),
  and `cyrius deps` will not let the `[deps.sigil]` artifact replace a stdlib
  leaf, so the pin is kept equal to the snapshot's sigil; a newer sigil arrives
  with a newer cyrius pin. The agnosys dependency was dropped at v3.5.0 —
  kavach internalized the Linux security backends it used (Landlock/seccomp,
  MAC, Linux-audit) as `src/` modules (the `agnosys → agnodrm` decomposition);
  see v3.5.0 in the CHANGELOG.
- **[samay](https://github.com/MacCracken/samay) 1.1.5** and
  **[ai-hwaccel](https://github.com/MacCracken/ai-hwaccel) 2.4.0**, optional
  behind the default-on `scheduler` feature, for the test-only scheduler bridge.
  Consumers of kavach do not inherit them.

`cyrius deps` populates `lib/` (gitignored) — that directory is reproducible
from the manifest + lockfile, not committed.

## 2. Configure a sandbox

Three preset policies are available. Choose one or build your own.

```cyrius
include "src/main.cyr"

fn configure() {
    var cfg = config_new();
    config_backend(cfg, Backend.PROCESS);     # pick a backend
    config_policy(cfg, policy_strict());      # or policy_basic()/policy_minimal()
    config_timeout_ms(cfg, 30000);
    config_agent_id(cfg, "my-agent-42");
    return cfg;
}
```

The three presets map to common hardening tiers:

| Preset | Seccomp | Network | RO rootfs | Memory limit | Use case |
|--------|---------|---------|-----------|-------------:|----------|
| `policy_minimal()` | off | on | no | none | Native AGNOS apps (trusted) |
| `policy_basic()` | on (basic) | off | no | none | Marketplace apps |
| `policy_strict()` | on (strict) | off | yes | 512 MB | Untrusted code |

See [ADR-003](../adr/003-fixed-point-threat-scoring.md) for the fixed-point
convention used in the policy struct.

## 3. Wire the trust layer (optional but recommended)

If you care about audit trails or quarantine:

```cyrius
# Audit chain: HMAC-SHA256 signed, tamper-evident append-only log.
var chain = audit_chain_open("/var/log/kavach.audit", "my-hmac-key", 11);
sandbox_exec_set_audit_chain(chain);

# Quarantine storage for BLOCK/QUARANTINE verdicts.
var qstorage = quarantine_storage_new("/var/lib/kavach/quarantine");
```

Rotate the HMAC key periodically and keep it off-disk (see
[ADR-005 §H5](../adr/005-v2-hardening-pass.md) on key lifetime).

## 4. Execute

```cyrius
var sb = sandbox_create(cfg);
sandbox_transition(sb, SandboxState.RUNNING);

var result = sandbox_exec(sb, "/usr/bin/ls /tmp");
if (result == 0) {
    # BLOCK or QUARANTINE verdict — inspect the last scan result
    var sr = sandbox_exec_last_scan_result();
    println("blocked");
}
else {
    println(ExecResult_stdout(result));
}

sandbox_destroy(sb);
audit_chain_close(chain);     # zeroes the HMAC key in memory
```

The full pipeline runs automatically:

```
sandbox_exec(sb, cmd)
  ├─ state guard      (must be RUNNING)
  ├─ backend dispatch (fnptr table → backend.exec)
  ├─ gate_apply       (3 scanners → verdict)
  ├─ classify_threat  (intent score, kill chain, escalation)
  └─ audit_chain_record (HMAC-linked JSONL)
```

## 5. Pick a backend

All 10 backends are registered. Probe availability before depending on one:

```cyrius
if (backend_is_available(Backend.GVISOR) == 1) {
    config_backend(cfg, Backend.GVISOR);
}
else {
    config_backend(cfg, Backend.PROCESS);
}

# Or let kavach pick the strongest available:
config_backend(cfg, resolve_best_backend(policy_strict()));
```

## 6. Handle verdicts

The scanner pipeline emits one of four verdicts:

| Verdict | Meaning | Default action |
|---------|---------|----------------|
| `ScanVerdict.PASS` | No findings | Release output as-is |
| `ScanVerdict.WARN` | Low-severity findings | Release; stdout/stderr redacted if `policy.redact_secrets` |
| `ScanVerdict.QUARANTINE` | High-severity findings | Hold for operator review; `quarantine_store` it |
| `ScanVerdict.BLOCK` | Critical findings | Drop the output |

Example WARN handling with quarantine fallback:

```cyrius
var r = sandbox_exec(sb, command);
if (r == 0) {
    var sr = sandbox_exec_last_scan_result();
    var v = ScanResult_verdict(sr);
    if (v == ScanVerdict.QUARANTINE) {
        # Persist the raw artifact for later review
        var orig = exec_result_new();
        # ... populate orig from the failed exec
        quarantine_store(qstorage, orig_stdout, len, sr, "sandbox-1");
    }
}
```

## Next steps

- [Policy merging with composite backends](composite-backends.md)
- [Threat classification + offender tracking](threat-tracking.md)
- [Architecture overview](../architecture/overview.md)
- [Worked examples](../examples/)
