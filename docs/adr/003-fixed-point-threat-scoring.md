# ADR-003 — Fixed-point (×1000) arithmetic for threat scoring

**Status**: Accepted
**Date**: 2026-04-13
**Version**: v2.0.0

## Context

Rust kavach's threat classifier used `f64` throughout:

```rust
fn severity_weight(severity: Severity) -> f64 { ... }
let raw_score: f64 = findings.iter().map(|f| severity_weight(f.severity)).sum();
let amplifier = if stages.len() >= 3 { 1.5 } else if stages.len() >= 2 { 1.3 } else { 1.0 };
let intent_score = (raw_score * amplifier).min(1.0);
```

Cyrius values are i64. The language has 20+ f64 builtins (SSE2/SSE4.1/x87)
for explicit float operations but no implicit int/float coercion — moving
floats through structs requires `store64` of bit patterns and explicit
`f64_*` helpers. Compliance/audit code reading the struct would need to
understand bit-pattern semantics. Reviewable maths in tests becomes
type-juggling.

## Decision

**Represent intent_score as an integer 0..1000 where each unit = 0.001**.
Severity weights and the co-occurrence amplifier are likewise scaled:

| Rust (f64) | Cyrius (i64 ×1000) |
|-----------:|-------------------:|
| 0.05 (Info weight) | 50 |
| 0.15 (Low) | 150 |
| 0.35 (Medium) | 350 |
| 0.60 (High) | 600 |
| 0.90 (Critical) | 900 |
| 1.3 (2-stage amp) | 1300 |
| 1.5 (3-stage amp) | 1500 |
| clamp(1.0) | clamp(1000) |
| threshold 0.2 | 200 |
| threshold 0.5 | 500 |
| threshold 0.8 | 800 |

Intent computation:

```
intent_x1000 = (raw_x1000 * amp_x1000) / 1000     # ×1000 × ×1000 / 1000
if (intent_x1000 > 1000) { intent_x1000 = 1000; }
```

The `ThreatAssessment` struct field is named `intent_score_x1000` to make
the scaling explicit at every call site. Display code (not yet ported)
should divide by 10 for a "0..100%" presentation.

## Consequences

**Positive**
- Pure integer maths. Every value through the threat pipeline is human-readable
  in a debugger.
- No risk of subtle FP precision bugs (NaN, ±Inf, `0.1 + 0.2 != 0.3`) leaking
  into classification tier cutoffs.
- The `_x1000` suffix is self-documenting — callers reading
  `intent_score_x1000(a) >= 500` immediately see "at least 0.5".
- Matches Cyrius stdlib convention: `RuntimeGuardConfig.time_anomaly_multiplier_x100`
  already ships this way.

**Negative**
- **Precision is 3 decimal places**, not the full f64 significand. For threat
  scoring this is irrelevant — the Rust impl already rounded into one of 4
  tiers. But if a future feature needs higher precision (e.g., Bayesian
  scoring), we'd re-scale to `_x1000000` or switch to f64.
- Formula integrity is the reviewer's job: `raw * amp / 1000` is correct
  only because both factors are `_x1000` and we divide by the scale once.
  Future contributors must understand the invariant or use a helper.

**Neutral**
- The API changes: `intent_score: f64` becomes `intent_score_x1000: i64`.
  Since v2.0 is a clean port, consumers re-write their call sites anyway.

## Alternatives considered

- **Use Cyrius f64 builtins**: possible but requires threading bit-pattern
  representation through struct fields. f64 in structs would need `store64`
  of reinterpreted bits and `f64_*` helpers at every load. Worse reviewability
  and debugging for no functional benefit.
- **×100 instead of ×1000**: 2 decimal places is enough for tier cutoffs, but
  `_x100` aliases with our existing `time_anomaly_multiplier_x100` so the
  factor in `raw * amp / 100` becomes ambiguous on the division scale. `_x1000`
  leaves room.
- **Percentage (0..100 integer)**: drops the ability to express amplifier
  (1.3, 1.5) without another scale. Rejected.

## Scope

This ADR applies to threat scoring only. Strength scoring
(`score_backend`) is already natively i64 (0..100 points) in both Rust and
Cyrius and needs no re-scaling.
