# Example 1: Hello, Noop

The simplest possible kavach program. Creates a sandbox with the testing-only
Noop backend, runs a "command" (Noop returns a clean ExecResult), and cleans up.

## Code

```cyrius
include "src/main.cyr"

fn main() {
    kavach_init();

    var cfg = config_new();
    config_backend(cfg, Backend.NOOP);

    var sb = sandbox_create(cfg);
    sandbox_transition(sb, SandboxState.RUNNING);

    var result = sandbox_exec(sb, "echo hello");
    if (result == 0) {
        println("blocked by gate");
        return 1;
    }
    syscall(1, 1, "stdout: ", 8);
    var out = ExecResult_stdout(result);
    syscall(1, 1, out, strlen(out));
    syscall(1, 1, "\n", 1);

    sandbox_destroy(sb);
    return 0;
}

var r = main();
syscall(60, r);
```

## What happens

1. `kavach_init()` registers all 10 backends into the dispatch table.
2. `config_new()` constructs a default config (backend=Process, policy=basic).
3. `config_backend(Backend.NOOP)` overrides to Noop.
4. `sandbox_create` allocates a Sandbox with a random UUID-v4-equivalent id.
5. `sandbox_transition(RUNNING)` moves the FSM.
6. `sandbox_exec("echo hello")` runs the full pipeline:
   - Dispatch → `noop_exec` returns an empty ExecResult.
   - Gate → zero findings, verdict=PASS.
   - Threat classifier → intent=0, BENIGN, TIER1_LOG.
   - Audit → skipped (no chain configured).
7. Result is released; we print its empty stdout.

## Exit state

- Sandbox lifetime: Created → Running → Destroyed.
- No audit chain, no quarantine store, no offender tracking.
- Noop's strength score is 0 (`minimal` tier) — this mode is for testing only.

## Next

[Example 2: Real process backend with audit chain](02-process-with-audit.md)
