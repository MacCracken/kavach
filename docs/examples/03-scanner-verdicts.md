# Example 3: Scanner verdicts and redaction

Demonstrates the four possible gate verdicts (PASS / WARN / QUARANTINE /
BLOCK), how they flow from scanner findings, and how WARN activates
in-place secret redaction.

## PASS — clean output

```cyrius
var er = exec_result_new();
ExecResult_set_stdout(er, "hello world, nothing to see here");
var pol = ext_policy_default();

var sr = gate_apply(er, pol);
# ScanResult_verdict(sr) == ScanVerdict.PASS
```

No scanner fires; worst_severity stays Info; verdict = PASS.

## BLOCK — private key in output

```cyrius
ExecResult_set_stdout(er, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAA...");
var sr = gate_apply(er, pol);
# verdict = BLOCK (private_key → Critical; default block_threshold = Critical)
```

The stdout is dropped (gate_apply returns the ScanResult but the caller
treats BLOCK as a hard reject).

## QUARANTINE — high-severity finding

```cyrius
ExecResult_set_stdout(er, "call 555-123-4567 for details");
# US phone number = Medium severity (PII). Tune thresholds to trigger:
ExternalizationPolicy_set_quarantine_threshold(pol, Severity.MEDIUM);
var sr = gate_apply(er, pol);
# verdict = QUARANTINE
```

Caller should `quarantine_store` the artifact for operator review.

## WARN — low-severity, redacted

```cyrius
ExecResult_set_stdout(er, "prefix AKIAIOSFODNN7EXAMPLE tail");

# Tune thresholds so AWS key (Critical) routes to WARN instead of BLOCK:
ExternalizationPolicy_set_block_threshold(pol, Severity.CRITICAL + 1);
ExternalizationPolicy_set_quarantine_threshold(pol, Severity.CRITICAL + 1);
# Opt into in-place redaction (default: 1):
ExternalizationPolicy_set_redact_secrets(pol, 1);

var sr = gate_apply(er, pol);
# verdict = WARN
# ExecResult_stdout(er) has been rewritten to:
# "prefix [REDACTED:cloud_credential] tail"
```

The gate calls `secrets_redact(stdout)` and `secrets_redact(stderr)` in
place. The raw secret never leaves the gate; the caller gets a clean
artifact with a marker indicating what category was suppressed.

## Scanner-specific categories

| Scanner | Category examples |
|---------|-------------------|
| secrets | `cloud_credential`, `api_token`, `auth_token`, `private_key`, `connection_string`, `pii` |
| code | `command_injection`, `data_exfiltration`, `privilege_escalation`, `supply_chain`, `obfuscation`, `filesystem_abuse`, `crypto_misuse` |
| data | `pii_financial`, `pii_network`, `pii`, `compliance_hipaa`, `compliance_gdpr`, `compliance_pci`, `compliance_soc2` |

Each category maps to a kill-chain stage via `_category_to_stage` (see
[threat-tracking.md](../guides/threat-tracking.md)).

## Evidence redaction in findings

Even before the WARN-verdict redaction, every ScanFinding stores only a
redacted evidence snippet (`AKIA****MPLE`, not the raw key). So even if the
findings themselves reach an audit log or quarantine metadata, the secret
middle bytes don't travel with them. See ADR-005 §H1 for the rationale.

## Next

[Example 4: Threat classification + offender tracking](04-offender-tracking.md)
