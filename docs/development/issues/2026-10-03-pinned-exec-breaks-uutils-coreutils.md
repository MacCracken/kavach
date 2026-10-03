# 2026-10-03 — a pinned exec cannot run uutils coreutils: Ubuntu 25.10+ payloads such as `/bin/echo` exit 1

**Status:** 🟡 **OPEN** — found while certifying 3.13.2 natively on aarch64.
**Checked against:** kavach **3.13.1** (built with cyrius 6.6.6) and the 3.13.2 candidate (cyrius 6.6.14), both
the same. `src/util.cyr` `kv_exec_pin` (:228) and `kv_exec_pinned` (:260), in place since 3.12.7 (ADR-005 §H4).
**Severity:** every payload that is a uutils coreutils binary exits 1 without running: `echo`, `cat`, `printf`,
`env` and the rest. Ubuntu ships uutils as its default coreutils from 25.10, including 26.04 LTS. A consumer
on such a host (agnosai sandboxes its tools through kavach) cannot run them.

## What happens

`kv_exec_pin` opens the payload's binary `O_PATH` in the parent, and the child runs it with
`execveat(fd, "", argv, envp, AT_EMPTY_PATH)`. For that exec the kernel records the program's name as
`/dev/fd/<fd>`. uutils' multicall binary compares the utility it is asked for with the executable's own name,
and refuses when they differ:

```
Security violation: Requested utility `9` does not match executable name:
/usr/lib/cargo/bin/coreutils/echo
```

`9` is the pinned fd. GNU coreutils do not check, and run normally through the same path.

## Reproduction (run 2026-10-03)

Host: Raspberry Pi, Ubuntu 26.04.1 LTS, kernel `7.0.0-1020-raspi`, aarch64. Packages: `rust-coreutils`
0.10.0-1ubuntu2~26.04.1 (`/usr/bin/echo` → `/usr/lib/cargo/bin/coreutils/echo`) and `gnu-coreutils` 9.7
(`/usr/bin/gnuecho`).

A probe built as a `.tcyr` with `tests/kavach.tcyr`'s `include` lines, cross-built with
`cyrius build --aarch64` and run on that host:

```cyrius
fn _probe(cmd) {
    kavach_init();
    var cfg = config_new();
    config_backend(cfg, KavachBackend.NOOP);
    var sb = sandbox_create(cfg);
    var r = process_exec(sb, cmd);
    println(cmd);
    if (r == 0) { println("  no result"); return 0; }
    print("  exit ", 7); fmt_int(ExecResult_exit_code(r)); println("");
    var out = ExecResult_stdout(r);
    print("  stdout: ", 10); if (out != 0) { println(out); } else { println("(null)"); }
    var err = ExecResult_stderr(r);
    print("  stderr: ", 10); if (err != 0) { println(err); } else { println("(null)"); }
    return 0;
}

fn main() {
    _probe("/bin/echo hello_uutils");
    _probe("/usr/bin/gnuecho hello_gnu");
    _probe("/usr/lib/cargo/bin/coreutils/echo hello_direct");
    _probe("/usr/bin/printf hello_printf");
    return 0;
}
var _rc = main();
syscall(60, _rc);
```

| payload | exit | stdout |
|---|---:|---|
| `/bin/echo` (uutils) | 1 | empty; stderr is the refusal above |
| `/usr/bin/gnuecho` (GNU) | 0 | `hello_gnu` |
| `/usr/lib/cargo/bin/coreutils/echo` (uutils, by its real path) | 1 | empty; the same refusal |
| `/usr/bin/printf` (uutils) | 1 | empty; the same refusal, naming `printf` |

The suite itself, cross-built and run natively there, fails 44 of 1152 assertions. 3.13.1 (cyrius 6.6.6) and
the 3.13.2 candidate (cyrius 6.6.14) fail the same 44. They fall in 15 groups:
`process_exec_honours_config_io` (12), `payload_stdin_is_empty_unless_asked` (6),
`results_keep_their_own_stderr` (4), `confine_capture_input` (4), `persistent guest (live stdin/stdout)` (3),
`timeout_does_not_truncate`, `sandbox_spawn_log_appends`, `process_real_exec`,
`exec_capture_pinned_captures_stdout`, `capture_ends_a_full_stream` (2 each), `timeout_ms_is_enforced`,
`stderr_is_its_own_stream`, `sandbox_spawn_logging`, `persistent_namespaces` and
`persistent_guest_closes_inherited_fds` (1 each). Unconfined runs fail too, so neither seccomp nor landlock is
involved. CI's `aarch64 (native)` job passes on `ubuntu-24.04-arm` because that image ships GNU coreutils.

## The decision (kavach's)

What H4 pins is the file. The ways to keep that while giving the payload a name uutils accepts are not free:

- **Exec through a pinned directory:** open the binary's directory `O_PATH`, check the binary's identity
  (`fstatat`, device and inode against the pinned file), then `execveat(dirfd, basename, …, AT_SYMLINK_NOFOLLOW)`.
  The kernel records `/dev/fd/<dirfd>/<basename>`, whose last component is the utility's name. This narrows
  the window to a swap inside a directory kavach checked rather than closing it.
- **Leave the pin and document the limit:** uutils payloads need a host whose coreutils are GNU (on Ubuntu,
  `coreutils-from-gnu`) or GNU binaries named explicitly (`/usr/bin/gnuecho`).
- The suite's assertions that assume `/bin/cat` and `/bin/echo` behave like GNU's would then need a host
  check, as the seccomp and landlock ones already have.

## Acceptance

- A probe on a uutils host (Ubuntu 25.10 or later): `process_exec(sb, "/bin/echo x")` either prints `x`, or
  kavach refuses up front with an error that names the cause.
- The native aarch64 suite passes on that host, or skips with a reason the way the qemu run does for
  seccomp.
