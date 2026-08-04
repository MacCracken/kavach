# `SandboxConfig` has no `externalization` field, so a per-sandbox gate policy cannot be attached — RESOLVED

**Discovered:** 2026-08-03, porting agnosai's `sandbox/kavach_bridge` (M7 bite 3).
**Severity:** Low — additive gap, with a working consumer-side workaround.
**Affects:** kavach 3.11.1 and earlier.
**Status:** ✅ **RESOLVED in kavach 3.11.2** (2026-08-03). `config_externalization(c, p)`
added; `SANDBOX_CONFIG_SIZE` grew 72 → 80. The default is **0**, not
`ext_policy_default()`, so a fresh config behaves exactly as it did in 3.11.1 —
see the 3.11.2 section of `CHANGELOG.md`. Guarded by three tests, including an
ABI-safety round-trip of all nine pre-existing fields.

## Summary

`struct SandboxConfig` (`src/lifecycle.cyr`, vendored at `lib/kavach.cyr:3300-3310`)
has nine fields:

```
backend  policy  timeout_ms  inner_backend  agent_id
hostname  domainname  workdir  rootfs
```

There is no `externalization`, and no `config_externalization(c, p)` setter
alongside the existing `config_rootfs` / `config_agent_id` / `config_network`.

So an `ExternalizationPolicy` cannot travel with a sandbox. A caller can build
one (`ext_policy_default()`, or a hand-rolled one) and can apply it directly
through `gate_apply(result, policy)`, but it cannot say *"this sandbox scans its
output with this policy"* and have the lifecycle honour it.

## Why it matters to a consumer

The Rust kavach exposes it, and agnosai's Rust code uses it unconditionally:

```rust
// rust-old/src/sandbox/kavach_bridge.rs:48-68
let mut builder = SandboxConfig::builder()
    .backend(backend)
    .network(policy.needs_network)
    .timeout_ms(policy.max_duration_secs * 1000);
// ...
builder = builder.externalization(ExternalizationPolicy::default());
```

Porting that line has no counterpart, so agnosai's `build_config` cannot
reproduce it, and the oracle's `build_config_enables_externalization` test has
nothing to assert against. That test is the only one of kavach_bridge's 16 that
could not be ported.

The practical consequence is per-*sandbox* policy: agnosai's
`policy_for_trust(trust)` maps a crew's trust level to one of three
externalization policies, and the intended design is that each sandbox carries
the policy for its own crew. Without a field on the config, the policy has to be
threaded separately by every caller and applied by hand at the gate — which
works, but means two sandboxes running under different trust levels look
identical to anything reading their configs.

## Reproduction

Not a runtime failure — a missing field. Verified by reading:

```sh
grep -A12 'struct SandboxConfig' lib/kavach.cyr    # nine fields, no externalization
grep -c 'config_externalization\|SandboxConfig_externalization' lib/kavach.cyr   # 0
```

## Proposed fix

Additive:

1. Add `externalization;` to `struct SandboxConfig` and bump
   `SANDBOX_CONFIG_SIZE` 72 → 80.
2. Add the setter beside the others:
   ```cyrius
   fn config_externalization(c, p) { SandboxConfig_set_externalization(c, p); return c; }
   ```
3. Default it in `config_new()` — either `0` (meaning "no gate", preserving
   today's behaviour exactly) or `ext_policy_default()`. **`0` is the safer
   default for a patch release**: defaulting to an active gate would start
   scanning output for every existing consumer that never asked for it, which is
   a behaviour change rather than a new capability.
4. If the lifecycle should apply it automatically after `sandbox_exec`, that is
   a second and larger decision — the field alone is enough to unblock the
   consumer, which can keep calling `gate_apply` itself.

ABI note: `config_new` looks like the only constructor, and the struct size is
not documented to callers, so growing it should be safe — the same reasoning
bote used when `dispatcher_new` grew 72 → 88 in 3.3.0.

## Consumer-side workaround

agnosai exposes `agnosai_kavach_default_ext_policy()` so the policy the oracle
would have attached is still constructible and testable, and applies it by
calling `gate_apply` at the point of use. Nothing is blocked; the config simply
does not carry it.
