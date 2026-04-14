# Getting started with kavach

This guide walks through the three minimum steps to run code through kavach:
configure a policy, create a sandbox, execute through the full pipeline.

## 1. Build + install

```sh
cd kavach
cyrius build src/main.cyr build/kavach
./build/kavach         # runs the end-to-end demo
```

Cyrius toolchain ≥ 4.4.3 required. Build dependencies resolve automatically
from `cyrius.toml` (stdlib + sigil 2.1.2 for crypto).

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
