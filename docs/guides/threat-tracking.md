# Threat classification and offender tracking

kavach classifies each scanner-produced finding set into an intent score,
a kill-chain stage view, and an escalation tier. Over time, repeat violations
by the same agent accumulate into a decayed offender score that crosses a
threshold → automatic escalation.

## Intent score (per-exec)

`classify_threat(findings)` returns a `ThreatAssessment` with:

- `intent_score_x1000`: 0..1000 (fixed-point — see ADR-003)
- `classification`: `BENIGN | SUSPICIOUS | LIKELY_MALICIOUS | MALICIOUS`
- `escalation`: `TIER1_LOG | TIER2_ALERT | TIER3_SUSPEND | TIER4_REVOKE`
- `kill_chain_stages`: unique stages observed across findings
- `finding_count`: total

The score combines per-severity weights (Info=50, Low=150, Medium=350,
High=600, Critical=900) with a co-occurrence amplifier (1.0x / 1.3x / 1.5x
for 1 / 2 / 3+ kill-chain stages).

```cyrius
var sr = scan_result_new();
secrets_scan(output, sr);
code_scan(output, sr);
var assessment = classify_threat(ScanResult_findings(sr));

if (ThreatAssessment_classification(assessment) == ThreatTier.MALICIOUS) {
    # Tier 4 — revoke agent credentials
}
```

## Kill-chain mapping

Finding categories map to Lockheed Martin kill-chain stages:

| Category | Stage |
|----------|-------|
| `pii_network` | RECONNAISSANCE |
| `obfuscation`, `crypto_misuse` | WEAPONIZATION |
| `supply_chain` | DELIVERY |
| `command_injection`, `privilege_escalation` | EXPLOITATION |
| `filesystem_abuse` | INSTALLATION |
| `data_exfiltration` | COMMAND_AND_CONTROL |
| `cloud_credential`, `api_token`, `auth_token`, `private_key`, `connection_string`, `credential`, `pii`, `pii_financial` | EXFILTRATION |

Multi-stage activity in a single exec triggers the co-occurrence amplifier —
a coordinated attack pattern is classified harder than an isolated indicator.

## Offender tracking (cross-exec)

One exec classification isn't enough for production. `OffenderTracker`
accumulates scored violations per agent with half-life time decay, so
repeat offenders escalate automatically while one-off anomalies fade.

### Defaults

- `window_secs = 3600` — 1 hour rolling window
- `decay_factor_x1000 = 500` — score halves every half-window (30 min)
- `escalation_threshold_x1000 = 3000` — 3.0 total decayed score → escalate

### Usage

```cyrius
var tracker = offender_tracker_new();

# After each exec:
offender_tracker_record(tracker, agent_id, assessment);

# Periodically:
if (offender_tracker_should_escalate(tracker, agent_id) == 1) {
    # Revoke or suspend the agent
}
```

### Decay math

Score contribution for a record age `t` seconds is:

```
contribution = score × (decay ^ (t / half_window))
```

Integer-only in the implementation: each half-window multiplies by
`decay_factor_x1000 / 1000`. After 2 half-windows (= 1 window), a critical
finding's initial 900 becomes `900 × 0.5 × 0.5 = 225`.

The window prune (`offender_tracker_prune`) drops records older than
`window_secs`; called implicitly by `agent_score` so callers don't have to
schedule it, but can call explicitly after bursts.

### Tuning

| Workload | Window | Decay | Threshold | Rationale |
|----------|-------:|------:|----------:|-----------|
| Interactive agent | 1h | 0.5 | 3.0 | Default; catches sustained bad behavior |
| Batch workload | 6h | 0.7 | 5.0 | Longer memory; higher bar |
| Zero-trust | 15min | 0.3 | 1.5 | Short memory; fast escalation |

```cyrius
var strict = offender_tracker_with_config(900, 300, 1500);   # zero-trust
```

## Putting it together

```cyrius
var chain = audit_chain_open("/var/log/kavach.audit", key, key_len);
var tracker = offender_tracker_new();
sandbox_exec_set_audit_chain(chain);

fn exec_with_tracking(sb, cmd, agent_id) {
    var r = sandbox_exec(sb, cmd);
    var sr = sandbox_exec_last_scan_result();
    var assessment = classify_threat(ScanResult_findings(sr));
    offender_tracker_record(tracker, agent_id, assessment);

    if (offender_tracker_should_escalate(tracker, agent_id) == 1) {
        audit_chain_record(chain, "agent_escalated", agent_id);
        # Signal the policy engine to revoke
    }
    return r;
}
```

## See also

- [ADR-003](../adr/003-fixed-point-threat-scoring.md) — why intent is fixed-point
- [ADR-005](../adr/005-v2-hardening-pass.md) — what the scanner now redacts
