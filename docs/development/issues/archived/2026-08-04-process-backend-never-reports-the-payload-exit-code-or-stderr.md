# Process backend never reports the payload's exit code or stderr — RESOLVED

**Filed by**: agnosai (Rust → Cyrius port, M7 — `kavach_bridge`'s exec half)
**Date**: 2026-08-04
**Version**: kavach 3.11.2
**Severity**: High — a payload that fails is indistinguishable from one that
succeeded, and its diagnostics are discarded.

**Related**: `2026-07-26-oci-backend-never-reports-the-container-exit-code.md`
is the same defect on the OCI backend. This one is on `Backend.PROCESS`, which
is what `config_new` selects by default and therefore what most consumers hit
first.

**Status:** ✅ **RESOLVED in kavach 3.11.4** (stderr stream split in 3.11.5).
`backend_process.cyr:115-137` stores `confine_last_exit()` and
`confine_last_stderr()` on both the confined and unconfined paths. Verified
against live code 2026-08-05 during the 3.11.7 cut; covered by
`process_reports_real_exit_code` and `stderr_is_its_own_stream`.

## What happens

`backend_capture_finish` — the shared tail of `process_exec` — **hardcodes both
fields** on its success path:

```cyrius
else {
    if (n >= out_cap) { n = out_cap - 1; }
    store8(out_buf + n, 0);
    ExecResult_set_exit_code(r, 0);      # <-- always 0
    ExecResult_set_stdout(r, out_buf);
    ExecResult_set_stderr(r, "");        # <-- always empty
}
```

Nothing reads the child's wait status. `exec_capture` (`lib/process.cyr:201`)
returns the number of bytes captured; it calls `sys_waitpid(pid, &stbuf, 0)`
and discards `stbuf`, so the status never leaves that function. The `n < 0`
branch reports exit code 1, but that signals "capture failed", not "the payload
exited 1".

`process_exec`'s **rootfs** branch already fixes this for itself:

```cyrius
# Surface the payload's real exit code. Reporting 0 for a command that
# never ran is how the missing-rootfs bug looked healthy for so long.
if (rr != 0) { ExecResult_set_exit_code(rr, confine_last_exit()); }
```

The non-rootfs branch — the ordinary one — has no equivalent.

## Reproduction

```cyrius
fn _run(cmd, ms) {
    var c = config_new();
    SandboxConfig_set_backend(c, Backend.PROCESS);
    config_timeout_ms(c, ms);
    var s = sandbox_create(c);
    sandbox_transition(s, SandboxState.RUNNING);
    var r = sandbox_exec(s, cmd);
    sandbox_destroy(s);
    print(cmd, strlen(cmd));
    print(" exit=", 6); print_num(ExecResult_exit_code(r));
    print(" stderr=", 8);
    print(str_data(str_from(ExecResult_stderr(r))), str_len(str_from(ExecResult_stderr(r))));
    print("\n", 1);
    return 0;
}
fn main(): i64 {
    alloc_init();
    kavach_init();
    _run("/bin/true", 5000);
    _run("/bin/false", 5000);
    _run("/bin/ls /nonexistent-path-xyz", 5000);
    return 0;
}
var rc = main();
syscall(60, rc);
```

Observed on x86_64 Linux, kavach 3.11.2:

```
/bin/true                     exit=0 stderr=
/bin/false                    exit=0 stderr=          <-- real exit is 1
/bin/ls /nonexistent-path-xyz exit=0 stderr=          <-- real exit is 2,
                                                          and its "No such file
                                                          or directory" is gone
```

Ground truth from the same shell: `/bin/false` → 1, `/bin/ls` on a missing path
→ 2 with a message on stderr.

`/bin/true` reporting 0 is correct by coincidence — every command reports 0.

## Why it matters

A sandbox exists to run code that is not trusted to be correct. The two
questions a caller has afterwards are "did it work?" and "if not, why not", and
the process backend currently answers the first with an unconditional yes and
the second with an empty string.

Concretely, for agnosai: `kavach_bridge::execute` returns a `KavachToolResult`
whose `exit_code` feeds tool-failure handling and whose `stderr` is what an
operator reads when a tool misbehaves. Through this backend, a tool that
crashed, exited non-zero, or could not find its input reports success with no
output — and a crew that branches on tool failure never branches.

The stderr loss compounds it: even a caller that ignores exit codes and parses
output has nothing to parse, because the diagnostic went nowhere. Note that
these are the paths the runtime guard did **not** reject — a guard rejection
(`exit=126 stderr=blocked command: sh`) reports correctly, which makes the
silent-success case easy to miss when spot-checking.

## Suggested fix

The status is available at the point it is currently dropped. `exec_capture`
already calls `sys_waitpid(pid, &stbuf, 0)`; what is missing is a way for the
caller to see `stbuf`.

Options, roughly in order of least disruption:

1. **A capture variant that returns the status.** `exec_capture` is a stdlib
   function used beyond kavach, so its signature is best left alone. An
   `exec_capture_status(args, buf, buflen, out_status)` beside it — or a
   kavach-local capture, as `confine_capture` already is — would let
   `process_exec` do what its rootfs branch does:
   `ExecResult_set_exit_code(r, decoded_status)`.

2. **Decode as `waitpid` does.** `(raw >> 8) & 255` for a normal exit;
   `raw & 127` non-zero means a signal, which is conventionally reported as
   -1 or 128+signal. Worth settling deliberately, since the OCI filing will
   want the same convention.

3. **Capture stderr separately.** This is the larger half — it needs a second
   pipe and an interleaved drain, because draining one pipe to EOF and then the
   other deadlocks as soon as the undrained one fills (64 KiB). agnosai built
   exactly this for its own subprocess sandbox and the shape is in
   `agnosai/src/sandbox/spawn.cyr` if it is useful: both read ends
   `O_NONBLOCK`, drained round-robin, with a short sleep on any iteration that
   moved no bytes.

If capturing stderr separately is out of scope for now, **merging it into
stdout would still be better than dropping it**, and saying so in the field
documentation would be better again. The current state — a `stderr` field that
is always empty — reads as "the payload wrote nothing to stderr", which is a
different and false claim.
