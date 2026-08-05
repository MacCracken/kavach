# `SandboxConfig.timeout_ms` is ignored by every backend except WASM — RESOLVED

**Filed by**: agnosai (Rust → Cyrius port, M7 — `kavach_bridge`'s exec half)
**Date**: 2026-08-04
**Version**: kavach 3.11.2
**Severity**: High — a sandboxed payload that never exits hangs its caller
forever, and `ExecResult.timed_out` reports `0` while it does.

**Status:** ✅ **RESOLVED in kavach 3.11.4**. `backend_process.cyr:63` reads
`SandboxConfig_timeout_ms(cfg)` and threads it into `confine_capture`, which
enforces it in the drain loop. Verified against live code 2026-08-05 during the
3.11.7 cut; covered by `timeout_ms_is_enforced` (a 1000 ms deadline on
`/bin/sleep 8` must report `timed_out` and return in under 5 s) and
`timeout_does_not_truncate` for the negative case.

## What happens

`config_timeout_ms` is the documented way to bound a sandboxed execution, and
`config_new` sets a 30-second default, so every sandbox carries one whether or
not the caller asks. **Only `wasm_exec` ever reads it** — as a fuel budget
(`_wasm_fuel_from_timeout`, line ~9308). Every other registered backend takes
the field and drops it:

| backend exec | reads `timeout_ms`? |
|---|---|
| `wasm_exec` | **yes** (as fuel) |
| `process_exec` | no |
| `oci_exec` | no |
| `gvisor_exec` | no |
| `noop_exec` | no |
| `sy_agnos_exec` | no |
| `sgx_exec` / `sev_exec` / `tdx_exec` | no |
| `firecracker_exec` | no |
| `composite_exec` | no |

`process_exec` ends at `exec_capture(args, buf, PROCESS_MAX_OUTPUT)`, and
`exec_capture` in `lib/process.cyr` waits with `sys_waitpid(pid, &stbuf, 0)` —
a blocking wait with no deadline and nothing to interrupt it. The
rootfs branch reaches `confine_capture`, which is the same story.

## Reproduction

```cyrius
# kvt.cyr — build with `cyrius build kvt.cyr /tmp/kvt`
fn _run(cmd, ms) {
    var c = config_new();
    SandboxConfig_set_backend(c, Backend.PROCESS);
    config_timeout_ms(c, ms);                 # a one-second deadline
    var s = sandbox_create(c);
    sandbox_transition(s, SandboxState.RUNNING);
    var t0 = mono_now_ns();
    var r = sandbox_exec(s, cmd);
    var dt = (mono_now_ns() - t0) / 1000000;
    sandbox_destroy(s);
    print("wall_ms=", 9); print_num(dt);
    print(" exit=", 6); print_num(ExecResult_exit_code(r));
    print(" dur_ms=", 8); print_num(ExecResult_duration_ms(r));
    print(" timed_out=", 11); print_num(ExecResult_timed_out(r));
    print("\n", 1);
    return 0;
}
fn main(): i64 {
    alloc_init();
    kavach_init();
    _run("/bin/echo hi", 1000);
    _run("/bin/sleep 8", 1000);
    return 0;
}
var rc = main();
syscall(60, rc);
```

Observed on x86_64 Linux, kavach 3.11.2:

```
wall_ms=4    /bin/echo hi   exit=0 dur_ms=0    timed_out=0
wall_ms=8001 /bin/sleep 8   exit=0 dur_ms=8000 timed_out=0
```

The second line is the bug in full: a **1000 ms** deadline, an **8001 ms**
execution, and `timed_out = 0`.

## Why it matters

Two separate problems, and the second is the worse one.

1. **The bound is not enforced.** A payload that blocks — on a read, a socket,
   a `sleep`, an infinite loop — runs until it chooses to stop. For a sandbox,
   "the untrusted thing decides when it is done" is the property the deadline
   exists to remove. `PROCESS_MAX_OUTPUT` caps how much a payload can *say*;
   nothing caps how long it can *take*.

2. **`timed_out` is not merely absent, it is wrong.** The field exists on
   `ExecResult` and is set to 0 on the paths above, so a caller that checks it —
   the obvious thing to do — is told the execution completed within its
   deadline. Reporting an unenforced deadline as "not timed out" is worse than
   having no field, because it invites the caller to stop worrying about it.

agnosai reaches this through `kavach_bridge::build_config`, which sets
`timeout_ms(policy.max_duration_secs * 1000)` from a per-tool sandbox policy.
That policy is how an operator says "this tool gets 30 seconds"; today the
number is accepted, stored, and never consulted.

## Suggested fix

`process_exec` is the one that matters most — it is the default backend and the
one every consumer hits first.

The mechanism agnosai ended up building for its own subprocess sandbox may be
useful as a reference (`agnosai/src/sandbox/spawn.cyr`): non-blocking reads on
the output pipes, a short sleep on any iteration that moved no bytes, and a
deadline check on that same tick; on expiry, `kill(pid, 9)` followed by
`waitpid` — SIGKILL rather than SIGTERM, because a payload that installs a TERM
handler would otherwise outlive the deadline and the reap that follows would
block forever on a child that never dies. The reap must happen before the
function returns, or the zombie keeps the pipe ends open.

`exec_capture` is a stdlib function shared beyond kavach, so a deadline
probably belongs either in a kavach-local capture (as `confine_capture` already
is) or in a new `exec_capture_timeout(args, buf, buflen, timeout_ms)` alongside
it, leaving the existing signature untouched.

Whatever the mechanism, the two observable outcomes are:

- a payload exceeding `timeout_ms` is killed, and
- `ExecResult.timed_out` is 1 when that happened.

**If a backend cannot enforce it**, saying so explicitly would still be a large
improvement over silence — a documented "this backend does not honour
`timeout_ms`", or an error at `sandbox_create` when a non-default deadline is
set on a backend that will ignore it. Silent acceptance is the part that turns
a missing feature into a wrong answer.

## Note on prior art

agnosai's port plan has carried a line since M7 planning that
"`kavach_bridge::execute` cannot honour `max_duration_secs` because nothing on
the process path reads `timeout_ms`". That was recorded as an agnosai-side
limitation. Measuring it for this filing showed it is neither agnosai-side nor
limited to the process path.
