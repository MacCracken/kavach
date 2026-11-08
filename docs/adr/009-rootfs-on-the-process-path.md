# ADR-009 — A rootfs on the process path: pivot_root and the default set

**Status**: Accepted. Extended by [ADR-011](011-dev-pids-and-network-on-the-process-path.md) (v3.14.8): its open items (no rootfs as root, `sandbox_spawn` on an OCI sandbox) are decided there.
**Date**: 2026-11-06
**Version**: v3.14.6

## Context

[ADR-008](008-oci-capability-default.md) bounded what an OCI container holds. The process path had no bound at all,
and `sandbox_spawn` takes that path whatever backend the sandbox names, so a detached payload never met ADR-008's set
on any backend. Measured as root under `policy_basic()`, the policy stiva starts from:

| Payload in a rootfs with no `/proc` | Through 3.14.5 |
|---|---|
| `CapEff`, `CapBnd` | `000001ffffffffff` |
| leave the rootfs by `chroot`, then open `core_pattern` to write | **allowed** |
| `mknod` a character device in the rootfs and open it | **allowed** |
| `open_by_handle_at` a file outside the rootfs | **allowed** |

The rootfs was entered with `chroot`, which moves a process's root and leaves the old tree in its mount namespace.
The payload held CAP_SYS_CHROOT and the filter has no `chroot` row, so three calls took it out, as root and rootless:
`chroot("sub")`, `chdir("..")` to the top, `chroot(".")`. It needed no fd from outside, as the code's comment had said
it did. The full record is in
[the issue](../development/issues/archived/2026-11-06-process-backend-keeps-every-capability.md).

ADR-008's set could not simply be copied. It keeps CAP_SYS_CHROOT for images that call `chroot`, which is safe under
runc's `pivot_root` and was the escape under kavach's `chroot`. Measured with the twelve applied to the payload, the
walk still left the rootfs. So the decision was about the entry as much as the set, and it is the maintainer's: it
changes what a payload may do.

## Decision

**A rootfs is entered with `pivot_root`**, runc's sequence and the one pivot_root(2) gives: make `/` private, bind the
rootfs onto itself, `pivot_root(".", ".")`, detach the old root. Nothing is left in the mount namespace to walk up to.
With no fall back to `chroot`, which is the escape: where this cannot run, the payload does not.

**A payload with a rootfs holds ADR-008's twelve**, in the bounding, permitted and effective sets, with inheritable and
ambient empty, on `sandbox_exec`, `sandbox_spawn` and any caller of `confine_child`. One default on every path, read as
`CapEff: 00000000a00405fb`.

**`config_capabilities` is read here too**, so the same list means the same thing on the process path. The mask is
built in the parent, because the child cannot allocate after fork. A name kavach does not know is refused before
anything runs.

**CAP_SYS_ADMIN under a filter is not refused here**, unlike the OCI backend. That rule answers a runtime resolving a
filter by name and skipping a name it does not know, so `open_tree_attr` got past it. This filter compares numbers.

**The set applies only with a rootfs.** With none the payload is on the host's files, where no set helps: see
Consequences. That path holds what kavach holds, as it always has. The maintainer's approval covered the rootfs path,
and what a payload with no rootfs should hold is still open in the issue.

`rootfs == "/"` skips the pivot, which would read EBUSY: nothing is above it to leave. It keeps the private mount and
the set.

## Alternatives

Measured as root, from inside the payload:

| | leave the rootfs | `mknod` | handle | nested user namespace |
|---|---|---|---|---|
| `chroot`, every capability (through 3.14.5) | **escapes** | opens | reads | not run |
| `chroot`, the twelve | **escapes** | EPERM | EPERM | EPERM |
| `chroot`, the twelve less CAP_SYS_CHROOT | EPERM | EPERM | EPERM | EPERM |
| `pivot_root`, the twelve (this) | stays in | EPERM | EPERM | holds every capability, and stays in |

- **Keep `chroot`, drop CAP_SYS_CHROOT here.** Smaller, and it holds. It leaves two defaults, breaks a payload that calls
  `chroot`, and `config_capabilities` naming the capability would reopen the escape, so that name would have to be
  refused on one backend and allowed on another.
- **Add `chroot`, `mknod` and `open_by_handle_at` to the deny list.** The table is shared, so the rows reach the OCI filter
  too, and would take from images the capability ADR-008 kept. `policy_new()` has no filter to hold them either.
- **A 15th positional on `confine_capture_input_env_wd`.** The parameter list carried a note saying the next one should
  be a struct. It is: `ConfineCapture`, with `confine_capture_new` and `confine_capture_run`. The positional functions
  stay, so every caller still compiles.

The capability table moved from `oci_spec.cyr` to `security.cyr`. `[lib.confine]` carries `confine.cyr` and `spawn.cyr` and
not `oci_spec.cyr`, so leaving it there would have compiled in-tree and broken thoth's build.

## What consumers run

ADR-008's table was measured under runc. Here an image also has no `/proc` and no `/dev` unless its caller adds them, so
it was measured again: the image's own filesystem as a rootfs, as root, under `policy_basic()`, through `sandbox_spawn` and
`sandbox_exec`, before and after, with a client from outside where there is a server.

| | 3.14.5, as kavach leaves a rootfs | 3.14.6, the same | 3.14.5, caller adds `/dev` and `/proc` | 3.14.6, the same |
|---|---|---|---|---|
| `su` | runs | runs | runs | runs |
| `chown` | runs | runs | runs | runs |
| nginx, workers at uid 101, serves a page | runs | runs | runs | runs |
| postgres entry point, answers `pg_isready` | fails | fails | runs | runs |

The one failure is the same on both sides: the entry point's `gosu` stats `/proc/self/exe`, and there is none. Nothing
that ran before stopped. nginx's master reads `CapEff: 00000000a00405fb` where it read every capability, and its workers
read 0 on both.

## Consequences

- A payload with a rootfs that used a raw socket, set the clock, or held any capability outside the twelve reads EPERM
  until it asks with `config_capabilities`. A caller of `confine_child` passing a rootfs gets the bound unasked.
- The same tests fail on `chroot`: `test_process_rootfs_payload` walks out from inside a payload, on both paths, and a
  mutation pass reverting each part of the change failed the suite each time.
- A new exit code, SPAWN_EXIT_CAPS (116), for a bound that could not be applied.
- `SANDBOX_CONFIG_SIZE` is unchanged. `ConfineCapture` is new.
- ⚠ **A `/proc` the caller mounted is not read-only here**, as it is under runc. uid 0 with the twelve still opens
  `core_pattern` and `sysrq-trigger` to write in such a rootfs, because that access is uid 0's and not a capability's.
  `/proc/kcore` is closed, by the set. Measured and open in the issue: a read-only mount over them, with the bound,
  held in a standalone prototype, and neither works alone.
- ⚠ **With no rootfs nothing here applies.** `core_pattern` and `/etc/passwd` open to write with `CapEff` zero, so no set
  would bound that payload. Measured with every capability, a landlock rule naming only its directory reads EACCES on all
  of them. That is what bounds such a payload today, and no preset names a rule.
- ⚠ **`sandbox_spawn` still reads no backend.** An OCI sandbox gets the set and the pivot this way, but no PID namespace, no
  `/proc` and no masks, and `score_backend` scores it as OCI.
- A chrooted caller is unchanged: on a plain directory it was refused at the private mount before and after, and onto a mount
  point it works. pivot_root(2) says a root on the initial ramfs cannot pivot, so such a host now refuses a rootfs. That
  is read and not run.
- ⚠ A nested user namespace holds every capability only where the host lets it. On CI's `ubuntu-26.04` root job `unshare` read
  0 and `chroot` then failed there, likely AppArmor's restriction on unprivileged user namespaces, so the walk does not run
  on that host. That is tighter, not looser, and the test asserts what must hold on both.
- Not run: nginx and postgres rootless, an image under crun, any kernel with AppArmor, since every container here shares
  one Arch kernel, and the rootfs group on aarch64. Under qemu the namespaces are refused and the calls were traced instead.
  CI's native job gained a root step for it, which had not run when this was written.
