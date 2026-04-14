# Example 4: Offender tracking across many execs

Demonstrates the OffenderTracker — per-agent accumulated threat score with
half-life decay — driving automatic escalation.

## Setup

```cyrius
include "src/main.cyr"

fn main() {
    kavach_init();
    sha256_global_init();

    var chain = audit_chain_open("/tmp/example-04.audit", "key", 3);
    sandbox_exec_set_audit_chain(chain);
    var tracker = offender_tracker_new();

    # ... configure sandbox as in examples 1-3
}
```

## Accumulate violations

Suppose an agent named `agent-X` tries four high-risk operations in rapid
succession:

```cyrius
fn accumulate_agent_x(tracker) {
    # Four Critical findings across multiple kill-chain stages:
    var findings = vec_new();
    vec_push(findings, finding_new("secrets", Severity.CRITICAL, "private_key", "k", 0));
    vec_push(findings, finding_new("code", Severity.CRITICAL, "command_injection", "c", 0));
    vec_push(findings, finding_new("code", Severity.CRITICAL, "data_exfiltration", "d", 0));

    var assess = classify_threat(findings);
    # intent_score_x1000 = 900 * 3 * 1.5 (3-stage amplifier) = 4050, clamped to 1000
    # classification = MALICIOUS, escalation = TIER4_REVOKE

    var i = 0;
    while (i < 4) {
        offender_tracker_record(tracker, "agent-X", assess);
        i = i + 1;
    }

    # After 4 records at intent=1000 each, fresh (no decay), score = 4000.
    # Default threshold = 3000 → escalate.
    if (offender_tracker_should_escalate(tracker, "agent-X") == 1) {
        audit_chain_record(chain, "agent_escalated", "agent-X");
    }
    return 0;
}
```

## Watch the decay

If agent-X stops misbehaving and the window passes, its score decays:

```
t=0:   score = 4000 (fresh)
t=30m: score = 4000 × 0.5 = 2000 (one half-life)
t=60m: records older than window_secs = 3600 are pruned → 0
```

The default decay_factor_x1000=500 means each half-window halves the
contribution. Pruning drops records entirely once they exceed the window.

## Alternative: tighter-trust tuning

Zero-trust environments want faster escalation:

```cyrius
# 15-min window, 70% decay per half-window, escalate at 1.5
var strict_tracker = offender_tracker_with_config(900, 700, 1500);
```

## Multi-agent — different scores

```cyrius
var t = offender_tracker_new();

# agent-A: 2 critical exploits
offender_tracker_record(t, "agent-A", crit_assess);
offender_tracker_record(t, "agent-A", crit_assess);
# score_A = 2000 (below threshold)

# agent-B: 1 critical exploit
offender_tracker_record(t, "agent-B", crit_assess);
# score_B = 1000

print_num(offender_tracker_agent_score(t, "agent-A"));  # 2000
print_num(offender_tracker_agent_score(t, "agent-B"));  # 1000
print_num(offender_tracker_agent_score(t, "new-agent")); # 0
```

## Production checklist

- Call `audit_chain_close(chain)` before process exit to zero the HMAC key.
- Schedule `offender_tracker_prune(tracker)` periodically if your workload
  has many short-lived agents — the prune is O(n) in records so bursty
  traffic keeps memory bounded.
- Escalation is your responsibility — `should_escalate` returns 1/0; act on
  it by revoking credentials, pausing the agent, or paging an operator.
- Record the escalation event in the audit chain so downstream systems
  have a signed trail.

## See also

- [Threat classification guide](../guides/threat-tracking.md)
- [ADR-003 fixed-point rationale](../adr/003-fixed-point-threat-scoring.md)
