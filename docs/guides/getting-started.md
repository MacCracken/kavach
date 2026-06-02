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

Cyrius toolchain `6.0.40` required (pinned in `cyrius.cyml`). The first-party
tree is on the cc 6.0 line; the old 5.10.x sigil-NI asm-offset bisect is
retired. Local `cycc` may sit a patch ahead (6.0.41) — the manifest pins
6.0.40, so skip local `cyrius fmt` writes to avoid minor-version drift.
Dependencies are declared in [`cyrius.cyml`](../../cyrius.cyml):

- **Cyrius stdlib** modules (alloc, args, assert, bench, bigint, chrono, ct,
  dynlib, fdlopen, fmt, fnptr, freelist, fs, hashmap, hashmap_fast, io, json,
  keccak, mmap, net, process, result, sandhi, slice, str, string, syscalls,
  tagged, thread, tls, vec)
- **[sigil](https://github.com/MacCracken/sigil) 3.5.9** for SHA-256 and
  HMAC-SHA256 (used by `src/audit.cyr`). Constant-time compare
  (`src/util.cyr::ct_streq`) now uses the stdlib `ct` module's
  `ct_eq_bytes_lens` — sigil retired its own `ct_eq` in the 3.x line. Latest
  tag; the 5.10.x SIGILL bisect that capped sigil at 2.9.0 no longer applies
  under cc 6.0.40. kavach adds an agnosys `1.3.0` transitive override for
  cc 6.0.40 compatibility (sigil pins 1.2.7, which is cc 6.0.1-only).

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
