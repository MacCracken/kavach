# 2026-10-03 — a pinned exec cannot run uutils coreutils: Ubuntu 25.10+ payloads such as `/bin/echo` exit 1 — RESOLVED

**Status:** ✅ **RESOLVED in kavach 3.14.0** (cyrius pin 6.7.9): the pinned exec goes through `/proc/self/fd/N`, and CI runs on `ubuntu-26.04` / `ubuntu-26.04-arm`. Neither option below was taken; see the resolution at the end.
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

## Update 2026-11-02 — `ubuntu-latest` is Ubuntu 26.04, and CI failed on it

GitHub moves the `ubuntu-latest` label to Ubuntu 26.04 from 2026-10-19. The first pushes after that ran on image
`ubuntu-26.04` 20261025.179.1 (Ubuntu 26.04.1 LTS). Both runs failed the same way:
- `237098d`, still at cyrius 6.6.14 with a docs-only change;
- 3.13.3's first commit, at cyrius 6.6.20.

| job | 3.13.2, Ubuntu 24.04 (2026-10-03) | Ubuntu 26.04 (2026-11-02, both commits) |
|---|---|---|
| Build & Test (x86-64) | 1183 of 1183 | 1115 of 1159, **44 failed** |
| aarch64 under qemu | 1116 of 1116 | 1073 of 1108, **35 failed** |

The x86-64 failures are the groups listed above. One line of the job log shows a second uutils refusal, distinct from
the `/dev/fd` name check: `coreutils: unknown program 'kavach-h4-bin-814af573099ba4f1'`. The H4 test copies a
coreutils binary under a temporary name, and uutils' multicall dispatches on that name. A host-aware suite has to
skip or rewrite that test as well.

3.13.3 pins every `ubuntu-latest` job (`ci.yml`'s four, `release.yml`'s release job) to `ubuntu-24.04`, which ships GNU
coreutils. That keeps CI testing what it tested; it does not change what a 26.04 host gets. The decision above is
still open, and the roadmap pins it in 3.13.x.

## Resolution — 3.14.0: exec through `/proc/self/fd/N`

Neither option above. Exec through a pinned directory would only narrow the H4 window. Documenting the limit would
leave kavach unable to run the current Ubuntu LTS's coreutils. What uutils reads decides the fix. `binary_path` in
`src/common/validation.rs` (0.8.0 and 0.10.0, Linux) takes the utility from the kernel's `AT_EXECFN`, and uses argv[0]
instead in three cases: the basenames match, `AT_EXECFN` starts with `/proc/`, or the file is a `#!` script. Ubuntu's
0.10.0 build adds `require-utility-to-be-invoked-at-matching-path.patch`: that name must also be
`readlink /proc/self/exe`'s basename. `execveat(fd, "", AT_EMPTY_PATH)` records `/dev/fd/N`, which is none of those.

`kv_exec_pinned` now runs `execve("/proc/self/fd/N")` first. The procfs entry is a magic link to the open file, so
the pinned inode runs. The recorded name starts with `/proc/`, so uutils takes argv[0] (`/bin/echo` → `echo`, which is
also the exe's basename). The child uses it only when `/proc/self/fd` is a real procfs (`statfs` magic `0x9fa0`) and
the link opens to the pinned `st_dev`/`st_ino`. `#!` scripts keep the fd exec and its dup retry. Anything else falls
back to `execveat`.

Measured in an Ubuntu 26.04.1 base rootfs (non-root uid, user namespace and chroot), with 3.13.3's exec against
3.14.0's:

| run | 3.13.3 | 3.14.0 |
|---|---|---|
| x86-64, uutils 0.8.0 (the image's) | 44 failed of 1161 | 1197 of 1197 |
| x86-64, uutils 0.10.0-1ubuntu2~26.04.1 (Ubuntu's patch) | 44 failed of 1161 | 1197 of 1197 |
| aarch64 under 26.04's qemu 10.2.1 | 35 failed of 1110 | 1130 of 1130 |

The H4 test's `kavach-h4-bin-…` refusal noted on 2026-11-02 was a false pass: its control expected exit 1 from `false`
and got exit 1 from uutils refusing the copy's random name. In 3.14.0 the test copies `/bin/true` under its own name
and swaps in a `#!` script. The native aarch64 run that found this issue (Raspberry Pi, Ubuntu 26.04) has not been
repeated; CI's `ubuntu-26.04-arm` job is the next native run.
