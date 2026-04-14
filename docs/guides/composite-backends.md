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
| `landlock_rules_len` | SUM | Additive — both sets allowed |
| `memory_limit_mb` | min (non-zero) | Smaller = tighter |
| `cpu_limit_tenths` | min (non-zero) | Smaller = tighter |
| `max_pids` | min (non-zero) | Smaller = tighter |
| `landlock_abstract_unix` | OR | Either enables = enabled |
| `landlock_signal` | OR | Either enables = enabled |

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
var s = score_composite(Backend.GVISOR, Backend.PROCESS, policy_strict());
# s ≈ 94 (clamped to 100)
```

The bonus recognizes that layered isolation is harder to defeat than either
layer alone — an attacker must bypass BOTH the runtime boundary AND the
policy-enforcement layer.

## Executing through a composite

```cyrius
var outer_backend = Backend.GVISOR;
var inner_backend = Backend.PROCESS;
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
