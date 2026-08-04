# Neither exec path applies seccomp or landlock without a rootfs

**Filed by**: agnosai (Rust → Cyrius port, M7 — the cx tool-sandbox bites)
**Date**: 2026-08-04
**Version**: kavach 3.11.2
**Severity**: Critical — a policy with `seccomp_enabled = 1` runs its payload
with no confinement at all, and reports success.

## Summary

kavach has exactly one code path that applies seccomp or landlock: the
**rootfs** branch of `process_exec`, which calls `confine_capture` →
`confine_child`. Both of the APIs a consumer can actually reach —
`sandbox_exec` without a rootfs, and `persistent_spawn` — bypass it entirely
and `execve` the payload with the caller's full ambient authority.

`SandboxPolicy.seccomp_enabled` is accepted, stored, scored, and never applied.

## Measured

All on x86_64 Linux, kavach 3.11.2, 2026-08-04.

### 1. `sandbox_exec` without a rootfs does not confine

```cyrius
var c = config_new();
SandboxConfig_set_backend(c, Backend.PROCESS);
SandboxConfig_set_policy(c, policy_strict());   # seccomp_enabled = 1
var s = sandbox_create(c);
sandbox_transition(s, SandboxState.RUNNING);
var r = sandbox_exec(s, "/bin/cat /tmp/agnosai-cx-probe.txt");
```

```
policy_basic,  no rootfs   exit=0 bytes_read=33   <-- READ the file
policy_strict, no rootfs   exit=0 bytes_read=33   <-- READ the file
```

Both policies report `seccomp_enabled = 1`:

```
policy_basic   seccomp_enabled=1 landlock_rules_len=0 read_only_rootfs=0 network=0
policy_strict  seccomp_enabled=1 landlock_rules_len=0 read_only_rootfs=1 network=0
```

The cause is in `process_exec`: `confine_capture` is reached only under
`if (rootfs != 0)`. The fall-through is `exec_capture(args, buf, ...)`, a plain
fork/exec with no filter.

*(Aside: pointing the same test at `/etc/passwd` is misleading — the read
**succeeds** and the externalization gate then quarantines the output, so the
call returns null and looks confined. It is not; the file was opened and read.
A benign target shows the truth.)*

### 2. `persistent_spawn` does not confine, and takes no policy

```cyrius
fn persistent_spawn(command) { ... }
```

Its only parameter is the command. It is not associated with a `Sandbox`, so it
has no policy to apply even in principle: it runs the runtime guard, forks,
`dup2`s three fds, and `kv_execve`s. No seccomp, no landlock, no namespaces.

### 3. End-to-end: the ADR-006 gate test fails

agnosai's [ADR-006](https://github.com/MacCracken/agnosai) replaces WASM tool
sandboxing with cx bytecode (`cycc_cx` → `.cyx` → `cxvm`) run **inside a kavach
sandbox**, on the explicit premise that "kavach's seccomp + landlock *are* the
security boundary" — because `cxvm` dispatches guest syscalls straight to the
host kernel with no allowlist. The ADR names its own acceptance test: *a `.cyx`
attempting `open("/etc/passwd")` must be refused.*

Compiled `.cyx` (268 bytes), whose guest does `syscall(2, "/etc/passwd", 0, 0)`
and exits 1 if it got a descriptor:

```
bare cxvm, no sandbox at all         -> guest exit=1   (expected: it is not a sandbox)
via kavach persistent_spawn(cxvm)    -> guest exit=1   <-- NOT confined
```

`persistent_spawn` is the only kavach API with a stdin channel, and `cxvm` takes
its bytecode on stdin, so it is the path this design requires.

## Why this is Critical rather than a gap

The three ordinary readings of the current API are all wrong:

- **"I set `policy_strict`, so the payload is confined."** It is not, and
  nothing says so — `sandbox_exec` returns a normal successful result.
- **"`strength_for_policy` scores this sandbox highly, so it is strong."**
  `score_backend` adds points for `seccomp_enabled` and for
  `landlock_rules_len > 0`. The score describes the configuration, not what was
  applied, so a consumer's audit trail records confinement that never happened.
- **"Confinement is best-effort and degrades."** A degraded sandbox that says so
  is a design choice. This one is silent.

For a library whose entire purpose is confinement, "the isolation flags are
advisory unless you also set an unrelated field" is a security-relevant
surprise.

## Also blocking: landlock rules cannot be expressed

`SandboxPolicy.landlock_rules_len` is a bare **counter**. There is no
`policy_landlock_add(path, access)` or equivalent — grep finds no setter beyond
the derived `SandboxPolicy_set_landlock_rules_len` and a merge in the policy
overlay that sums two counts. The one consumer of it is:

```cyrius
if (SandboxPolicy_landlock_rules_len(policy) > 0) {
    if (is_ok(security_apply_landlock(0, 0)) == 0) { sys_exit(SPAWN_EXIT_LANDLOCK); }
}
```

— called with `(0, 0)`, i.e. no path lists. So even on the rootfs path, a
consumer cannot say "this tool may read `/opt/tool-data` and nothing else".
Since both built-in policies ship `landlock_rules_len = 0`, landlock is
currently applied by nothing.

(A total-deny landlock would actually suit the cx case well — `cxvm` receives
its bytecode on an already-open stdin, and landlock does not affect open
descriptors — but there is no way to ask for one.)

## Suggested fix, in dependency order

1. **Apply seccomp on the non-rootfs `process_exec` path.** The filter is
   already built for the rootfs branch (`security_create_exec_seccomp_filter`);
   what is missing is a child-side seam in the non-rootfs capture to install it
   between `fork` and `execve`. This is the single highest-value change: it
   makes `seccomp_enabled` mean something on the default backend.

2. **Decide what `persistent_spawn` is.** It either (a) grows a `sandbox`
   parameter and confines like `process_exec`, or (b) is documented as an
   explicitly unconfined channel and given a name that says so. Silently
   unconfined is the one option that should not survive — it is currently the
   only API offering stdin, so it is what a consumer needing one will reach for.

3. **A landlock path API.** `policy_landlock_add(policy, path, access)`
   accumulating a real rule list, with `security_apply_landlock` receiving it
   instead of `(0, 0)`. kavach 3.11.1 already fixed the rights mask; the rules
   themselves are the remaining half.

4. **Fail loudly where confinement is impossible.** If a backend cannot honour
   `seccomp_enabled`, `sandbox_create` returning an error beats running
   unconfined. Same argument as the `timeout_ms` filing.

## Related filings

- `2026-08-04-sandbox-config-timeout-ms-is-ignored-by-every-backend-except-wasm.md`
  — for cx tools this is not a minor gap: ADR-006 accepts losing wasmtime's fuel
  metering *because* a wall-clock timeout remains, and there is no wall-clock
  timeout either.
- `2026-08-04-process-backend-never-reports-the-payload-exit-code-or-stderr.md`
  — cx's result channel is "process stdout + exit code" per the same ADR.

Together these three are the blocker set for agnosai's M7 cx bites. None is
worked around agnosai-side: each would mask an upstream defect that every kavach
consumer shares.
