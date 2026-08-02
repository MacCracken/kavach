# The Firecracker and OCI backends call the LINUX syscall wrappers unguarded — every `--agnos` consumer fails to compile

**Discovered:** 2026-08-01, building aethersafha `--agnos` during the desktop-arc GPU work
**Severity:** High — it is a hard compile error, and it blocks the whole consumer, not just the backend
**Affects:** kavach 3.9.3 (`src/backend_firecracker.cyr`, `src/backend_oci.cyr`)

## Summary

`sys_unlink` and `sys_rmdir` have **different arities on Linux and agnos**:

| target | signature |
|---|---|
| Linux (`lib/syscalls_x86_64_linux.cyr`) | `fn sys_unlink(path)` · `fn sys_rmdir(path)` |
| agnos (`lib/syscalls_x86_64_agnos.cyr`) | `fn sys_unlink(path, pathlen)` · `fn sys_rmdir(path, pathlen)` |

kavach's Firecracker and OCI backends call the **one-argument Linux form**, with no
`#ifdef CYRIUS_TARGET_AGNOS` anywhere in either file:

- `src/backend_firecracker.cyr:115` — `sys_unlink(cfg_path);`
- `src/backend_firecracker.cyr:116` — `sys_rmdir(workdir);`
- `src/backend_oci.cyr:178` — `sys_unlink(err_path);`
- `src/backend_oci.cyr:180` — `sys_unlink(log_path_pre);`
- `src/backend_oci.cyr:264` — `sys_unlink(path);`

plus `sys_mount` (agnos takes **0** arguments, the call passes 5) and a bare `SYS_CHDIR`, which
does not exist in the agnos enum at all.

Because `cyrius build` auto-prepends every `[deps.*]` module into the compilation unit, this is
**not** contained to consumers that use the OCI or Firecracker backends. Any project that declares
`[deps.kavach]` and builds `--agnos` fails, even if it only ever touches `sandbox_*`.

## Why it is newly fatal

Cyrius used to **warn** on an arity mismatch and compile anyway — which is its own hazard (the
agnos kernel has a documented case where a warned-through arity mismatch made a function's first
statement a wild kernel store). Arity is now a hard **error**, so what was silently-wrong code is
now a build stop. That is the correct direction; this issue is the backlog it exposes.

## Reproduction

```bash
cd /home/macro/Repos/aethersafha
cyrius build --agnos src/main.cyr build/aethersafha_agnos
```

```
error:lib/kavach.cyr:7429: 'sys_rmdir' expects 2 arguments, got 1
error:lib/kavach.cyr:7808: 'sys_unlink' expects 2 arguments, got 1
error:lib/kavach.cyr:7930: 'sys_mount' expects 0 arguments, got 5
error:lib/kavach.cyr:7934:26: undefined variable 'SYS_CHDIR' (missing include or enum?)
FAIL
```

Reproduces identically under the pinned 6.4.78 toolchain and under 6.5.5, so it is not toolchain
drift on the consumer's side.

## ⭐ THE REGRESSION HAS A DATE, AND IT IS NOT A GRADUAL DRIFT

`src/confine.cyr` is **new in kavach 3.9.1, released 2026-07-25** (its own CHANGELOG entry: *"the
child-side confinement sequence, shared by every backend that forks… extracted from `spawn.cyr`"*).
aethersafha's last successfully-built `--agnos` binary is dated **2026-07-25 11:24**.

So the sequence is: aethersafha built clean against a local kavach at ≤ 3.9.0; 3.9.1 landed
`confine.cyr` later that day; aethersafha's `path = "../kavach"` override picked it up with no
manifest change; and its `--agnos` build has been broken ever since **with nobody noticing, because
nothing in CI or the smokes rebuilds that target.**

⭐ **The important nuance: agnos did not newly LOSE anything.** `sys_fork`/`sys_execve` were always
absent there. What 3.9.1 changed is that the fork path became **REACHABLE** from the compilation
unit — cyrius only refuses to emit on *reachable* undefined functions. This is why the fix is
guarding entry points rather than porting a process model.

## What has been done (2026-08-01) and what remains

**Done — the arity/model half, host build and 554 tests still green:**

- `src/util.cyr` gained `kv_unlink` / `kv_rmdir` / `kv_waitpid`, the one place the target difference
  lives; 25 call sites across 8 files now route through them.
- ⚠ **`kv_waitpid` is not an arity adapter, it is a MODEL adapter.** Linux writes a packed
  wait-status word; agnos `sys_waitpid(pid)` returns the exit code **directly** (cyrius's own
  `syscalls_x86_64_agnos.cyr` says so). Every caller here decodes `(status >> 8) & 255`, so handing
  them a bare code would put it in the **signal** field — a child exiting 11 would read as
  "killed by SIGSEGV". The agnos arm synthesises the packed word.
- Guarded, each **failing closed** rather than fabricating success: `_spawn_enter_rootfs`,
  `confine_child`, `spawn_namespaces_available`, `spawn_seccomp_available`, `confine_capture`,
  `_oci_run`. ⛔ None returns 0 on agnos — a sandbox that reports success without confining anything
  is the worst failure this file could have.

**Remaining — three reachable undefined symbols, and this needs the owner, not another sweep pass:**

- `sys_fork` at `src/persistent.cyr:69` and `src/spawn.cyr:139`
- `sys_dup2` in `_spawn_redirect_stdio` (`src/confine.cyr:157,168,169`) and the fork children
- `json_v_parse_str` — **not kavach's**; a bayan JSON symbol, and a separate matter

⛔ **Do NOT reach for `--allow-undef`.** It emits a binary containing undefined functions, which is
exactly the class of silent wrongness this ecosystem keeps paying for in hardware burns.

## Suggested fix

These backends are **inherently Linux-only** — agnos has no Firecracker VMM, no OCI runtime, and
no `fork`. So the fix is a guard, not a port:

1. Wrap the Linux-only bodies in `#ifdef CYRIUS_TARGET_AGNOS` / `#ifndef` so the agnos build gets
   a clean "backend unavailable" stub, exactly as `backend_is_available` already models at runtime.
2. Or, if any of these paths must survive on agnos, use the two-argument form there with an
   explicit length.

⚠ **Please do not fix this in a consumer's `lib/`.** That directory is materialized output; an edit
there is erased by the next `cyrius deps` and hides the defect from every other consumer.

## A second, separable problem this surfaced — in the consumer

aethersafha's manifest declares:

```toml
[deps.kavach]
tag = "3.7.0"
path = "../kavach"
```

The `path` override wins, so `cyrius deps` materialized the **local working tree at 3.9.3**, not the
3.7.0 the manifest names. `lib/kavach.cyr` is byte-identical to `/home/macro/Repos/kavach/dist/kavach.cyr`.

That means a consumer's vendored dependency silently tracks whatever a sibling checkout happens to
contain, and the declared tag documents an intention that is not enforced. The consumer's build was
working on 2026-07-25 and stopped working with no change to the consumer — which is the failure mode
worth naming: **the pin did not hold, and nothing said so.** Filed here because it is the same
incident; it belongs to the consumer to decide (drop the path override for releases, or bump the tag
to match reality).
