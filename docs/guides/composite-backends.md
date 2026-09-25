# Composite backends — defense-in-depth

Composite backends stack two isolation layers. The outer backend is the
runtime boundary (VM or container); the inner provides a tighter policy that
gets merged on every exec.

## When to use

Single-layer isolation is usually enough. Reach for composites when:

- **Regulatory posture** requires two independent controls (e.g., gVisor for
  syscall interposition PLUS seccomp for per-syscall filtering).
- **Defense-in-depth** against kernel 0-days: gVisor as the user-space kernel
  boundary PLUS process-level seccomp/landlock as a second line.
- **Hybrid environments**: Firecracker microVM for network isolation PLUS the
  SyAgnos hardened image for application-level policy.

## Merge semantics

`merge_policies(base, overlay)` returns a new policy per these rules:

| Field | Rule | Why |
|-------|------|-----|
| `seccomp_enabled` | OR | Either side enabling = enabled |
| `seccomp_profile` | `"strict"` wins | Stricter profile always |
| `network_enabled` | AND | Both must allow (fail closed) |
| `read_only_rootfs` | OR | Either side requires = required |
| `landlock_rules` (with `landlock_rules_len`) | union, in a fresh list; the count is the list's length | Additive — both sets allowed. Landlock names allowed paths, and each layer may need its own |
| landlock deny-all (`policy_landlock_deny_all`) | deny-all if either side is | That side has said the payload needs no path; the other side's rules would hand it some |
| `memory_limit_mb` | min (non-zero) | Smaller = tighter |
| `cpu_limit_tenths` | min (non-zero) | Smaller = tighter |
| `max_pids` | min (non-zero) | Smaller = tighter |
| `landlock_abstract_unix` | OR | Either enables = enabled |
| `landlock_signal` | OR | Either enables = enabled |
| attestation (`attest_*`, v3.13.0) | required if either requires it; allowlists intersected; debug allowed only if both allow it | A guest must satisfy both. Two different roots, or allowlists with nothing in common, admit no guest: the merge keeps the requirement and every attestation fails |

The landlock rules are the one field merged toward the looser side. The merged
list holds both inputs' rules, so a path either side's rules allow stays
allowed. A side with no rules adds none: merging a policy that has no rules
with one that has some confines the payload to the second policy's rules. Each
input contributes the rules it applies, its first `landlock_rules_len`.
Neither input's list is shared, so adding a rule to the merged policy, or to
an input afterwards, changes only that policy.

A deny-all input is the exception. `policy_landlock_deny_all` asks for a
ruleset naming no path, written as a count above the rule list, and a merge
with such a policy is deny-all whatever the other side allows. Alone or
merged, a deny-all policy applies no rule: `policy_landlock_deny_all` drops
the rules the policy named, `policy_landlock_add` refuses one afterwards, and
the exec child reads any count above the list as deny-all, the test the merge
makes (`policy_landlock_is_deny_all`). Through v3.13.0 a policy that named
rules and was then made deny-all still applied them on its own, and denied
every path only once merged.

Every path includes the payload's own executable. The child applies landlock
before it execs the payload, so the exec is refused (EACCES) and a composite
exec with a deny-all side does not start its payload: it exits 127. A layer
that makes the merge deny-all stops the payload; it does not confine one that
has to run. To confine that, name its binary (and, if dynamically linked, its
loader and libraries) with `policy_landlock_add`; landlock denies every other
path already.

Through v3.13.0 the merge summed the two counts and carried no list, and a
count with no list is deny-all: a merge with a rule on either side denied the
payload every path, so that `/bin/cat` could not even start (exit 127).

## Example

```cyrius
var outer = policy_minimal();             # gVisor's default
var inner = policy_strict();              # seccomp + ro rootfs + limits
var merged = merge_policies(outer, inner);

# Now merged carries: seccomp strict, ro rootfs, 512 MB, 1 vCPU, 64 PIDs,
# both landlock scopes on — even though the outer policy was minimal.
```

## Scoring

`score_composite(outer_backend, inner_backend, policy)` returns a score
reflecting both layers, with a +5 bonus for the defense-in-depth stack:

```cyrius
# gVisor outer (base 70) + Process inner (base 50), strict policy
var s = score_composite(KavachBackend.GVISOR, KavachBackend.PROCESS, policy_strict());
# s ≈ 94 (clamped to 100)
```

The bonus recognizes that layered isolation is harder to defeat than either
layer alone — an attacker must bypass BOTH the runtime boundary AND the
policy-enforcement layer.

## Executing through a composite

```cyrius
var outer_backend = KavachBackend.GVISOR;
var inner_backend = KavachBackend.PROCESS;
var inner_policy = policy_strict();

var cfg = config_new();
config_backend(cfg, outer_backend);        # outer runs
config_policy(cfg, policy_basic());        # caller's base policy
var sb = sandbox_create(cfg);
sandbox_transition(sb, SandboxState.RUNNING);

# composite_exec merges caller_policy + inner_policy, then dispatches to outer:
var result = composite_exec(outer_backend, inner_backend, sb,
                            "echo hello", inner_policy);
```

`composite_exec` dispatches straight to the outer backend, past the
attestation gate in `sandbox_exec`, so it refuses (returns 0) when either
policy requires attestation (v3.13.0).

## Caveat: fail-closed on unavailable outer

If the outer backend (gVisor, Firecracker, etc.) isn't installed, the
composite exec returns an error ExecResult with exit code 1 and a descriptive
stderr — no silent fallback to the inner-only backend. Callers wanting
fallback should check availability and re-select before exec:

```cyrius
var chosen = outer_backend;
if (backend_is_available(chosen) == 0) {
    chosen = inner_backend;    # fall back
}
composite_exec(chosen, inner_backend, sb, command, inner_policy);
```

## See also

- [ADR-002](../adr/002-backend-dispatch-fnptr-table.md) — backend dispatch table
- [ADR-003](../adr/003-fixed-point-threat-scoring.md) — why fields are fixed-point
- [Architecture overview](../architecture/overview.md) — policy struct layout
