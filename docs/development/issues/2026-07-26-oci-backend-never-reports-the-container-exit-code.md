# OCI backend never reports the container's exit code — every run looks like success

**Discovered:** 2026-07-26, while verifying stiva's `stiva build` end to end
**Severity:** High (silent wrong value on the default backend of any host with runc installed)
**Affects:** kavach 3.9.1 (`src/backend.cyr` `oci_exec`); the PROCESS backend was fixed in 3.9.1,
the OCI backend was not

## Summary

`oci_exec` returns an `ExecResult` whose `exit_code` is **always 0** for any container that ran,
regardless of what the payload actually did. A container whose command does not exist, exits 1, or
is killed by a signal is indistinguishable from one that succeeded.

This is the **same defect** 3.9.1 fixed for the process backend. That fix added
`ExecResult_set_exit_code(rr, confine_last_exit())` to `process_exec` and its CHANGELOG recorded
"a failed `execve` no longer reports exit 0" — but `oci_exec` has no equivalent, and `oci_exec` is
the backend that gets *selected* whenever `runc` or `crun` is on the host.

`stderr` is likewise always `""` on this path, for a related reason (below).

## Reproduction

With `runc` installed, so `backend_is_available(Backend.OCI)` is true:

```
$ stiva run local/demo:v1 /definitely-not-here
[INFO] executing one-shot container via kavach: /definitely-not-here
[INFO] container execution complete, exit_code=0
$ echo $?
0
```

The binary does not exist in the image or on the host. Nothing ran. Exit code 0.

The process backend, probed directly, is correct — so the divergence is backend-specific:

```
confine_capture(["/definitely-not-here"], 0, rootfs, 0, 0, buf, 65536)
  -> n = 0, confine_last_exit() = 127     # correct
```

## Root cause

Three links, all in `src/backend.cyr`:

1. `_oci_run` (`:8572` as vendored in cyrius 6.4.78's `lib/kavach.cyr`) calls the stdlib's
   `exec_capture(args, out_buf, out_cap)`, which returns a **byte count**. runc's wait status is
   never retrieved and is not recoverable from that return value.
2. `oci_exec` (`:8597`) passes that byte count straight to `backend_capture_finish`.
3. `backend_capture_finish` (`:2740`) sets `exit_code = 0` on every `n >= 0` path.

So the exit code reported is a property of *whether the capture read bytes*, not of the container.

The same `exec_capture` call is why stderr is always empty: `lib/process.cyr:225` `dup2`s
`/dev/null` onto the child's fd 2. `_oci_state_root`'s own comment (`:8549-8557`) documents having
been bitten by exactly this — an unprivileged runc failing with "mkdir /run/runc: permission
denied" on stderr, discarded, "so the whole container silently produced nothing and reported
success". The stderr half of that was worked around by passing `--root`; the **exit-code half was
never addressed**, so the general case still reports success.

## Impact on consumers

For stiva (`exec_container`, `src/runtime.cyr:944`, reads `ExecResult_exit_code` verbatim):

- `stiva run` reports exit 0 for every container on a runc host.
- `stiva wait` therefore always yields 0.
- `state.json`'s `exit_status` is wrong, so it is wrong after a restart too.
- Restart policies that branch on exit status (`on-failure`, `unless-stopped` — `src/health.cyr`)
  can never observe a failure.
- Any CI or orchestration that checks a container's exit status is blind.

## Proposed fix

`_oci_run` needs a capture primitive that reports the child's wait status alongside the byte count.
kavach already has one on the confined path — `confine_capture` + `confine_last_exit()`
(`src/confine.cyr:298-368`) — which decodes `waitpid` status properly, including the
`128 + signal` convention. The narrow fix is an `exec_capture`-shaped helper that does the same and
exposes the status, then:

```
n = _oci_run(runtime, bundle, container_id, out_buf, out_cap)
var r = backend_capture_finish(out_buf, n, out_cap, "OCI runtime run failed", start_ns, end_ns)
if (r != 0) { ExecResult_set_exit_code(r, <runc's exit status>) }
```

mirroring `process_exec:8016-8022` exactly.

Two things worth deciding while in there, flagged as design questions rather than prescriptions:

- **runc's own failures vs the payload's.** `runc run` exits with the container's exit code on
  success, but also uses non-zero for its own errors (bad bundle, permission denied). Conflating
  them means a broken bundle looks like a container that exited 1. runc writes its own diagnostics
  to stderr, which is currently discarded — capturing stderr separately would let the two be
  distinguished, and would also stop swallowing the diagnostic that explains the failure.
- **Signals.** `confine_capture` maps a signalled child to `128 + sig`. Whatever `oci_exec` does
  should match it, or one backend's exit codes will not mean the same thing as the other's.

## Related

- kavach 3.9.1 — fixed this for the PROCESS backend only (`process_exec`, the
  `confine_last_exit()` call).
- stiva `docs/development/roadmap.md` §K — the "container filesystem is never entered" work, which
  is where the process-backend half of this was found and fixed. This is its unfinished sibling:
  the same "looks healthy because it reports 0" failure mode, one backend over.
