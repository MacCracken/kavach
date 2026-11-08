# ADR-010 — A caller's `/proc` and `/sys` in a process-path rootfs: runc's lists

**Status**: Accepted
**Date**: 2026-11-07
**Version**: v3.14.7

## Context

[ADR-009](009-rootfs-on-the-process-path.md) entered a rootfs with `pivot_root` and bounded the payload to ADR-008's
twelve capabilities. kavach mounts no `/proc` there, but a caller may, and the postgres entry point needs one: its
`gosu` stats `/proc/self/exe`. In such a rootfs, uid 0 with the twelve still opened `core_pattern` and
`sysrq-trigger` to write. That access is uid 0's and not a capability's: `sysctl_perm` compares the euid with the
global root, so no set reaches it. Under runc the read-only mounts from `runc spec`'s lists stop it, and the set keeps
the mounts on. The full record is in
[the issue](../development/issues/2026-11-06-process-backend-keeps-every-capability.md).

Measured as root through `sandbox_exec`, from inside the payload, opening and never writing, with the caller's
`/proc` and `/sys` mounted in the rootfs, on 3.14.6:

| | fresh `/proc` and `/sys` | `/proc` an rbind of one holding binfmt_misc |
|---|---|---|
| open `core_pattern`, `sysrq-trigger`, `/proc/irq/default_smp_affinity` to write | **opened**, each | **opened**, each |
| open `/sys/kernel/mm/transparent_hugepage/enabled` to write | **opened** | no `/sys` |
| open `/proc/sys/fs/binfmt_misc/register` to write | not mounted | **opened** |
| read `/proc/kcore`, `/proc/timer_list` | EPERM, a byte | EPERM, a byte |

A handler registered in binfmt_misc runs for the host's own execs, so the last row is an escape on its own.

The roadmap left four decisions to the maintainer: which paths, what masks a file after the pivot, and what a list
naming CAP_SYS_ADMIN gets. Each is below as decided.

## Decision

**runc's two lists, from one table.** `runc spec` 1.5.2's ten masked and five read-only paths moved from
`oci_spec.cyr` to `security.cyr` (`security_masked_path`, `security_readonly_path`), as the capability table did in
3.14.6, because `[lib.confine]` carries `security.cyr` and not `oci_spec.cyr`. The OCI spec writes the same JSON from
them, and a test holds it to 3.14.6's literal. They are string literals by index, so a forked child reads them
without allocating. A sysfs at `/sys` is made read-only too, as runc's spec mounts one; `/sys/firmware` is in the
masked list.

**Where a `/proc` or `/sys` is there, and only there.** After the rootfs is bound onto itself and before the pivot,
`_spawn_guard_proc_sys` looks for a directory `proc` on a procfs and `sys` on a sysfs. Neither is the common case, and
then nothing is mounted. Where one is, the read-only paths come first and then the masks, as runc orders them. A path
the kernel does not have is skipped, as runc skips it.

**The host's `/dev/null` masks a file.** A rootfs as kavach leaves it has no `/dev`, and runc's own check on a rootfs's
`/dev/null` exists because an image can make that one a symlink (CVE-2025-31133). The decision was the host's, opened
before the pivot and bound after it through `/proc/self/fd/N`. Built that way, the bind would read EINVAL: its source
is on the old root, and a bind's source must be on a mount still in the caller's namespace, which the detach has just
removed. So the guard runs before the pivot instead, with the cwd at the top of the rootfs's own bind. It binds the
host's `/dev/null` by path, after checking that it is a character device, onto the relative path. The masks are
mounts inside that bind, so the pivot carries them along. A directory is masked with an empty read-only tmpfs, as runc
does.

**Not recursive first.** A read-only remount is not recursive. A recursive bind of `/proc/sys` would carry a
binfmt_misc mounted below it into the bind with its own flags, writable, and a recursive bind of `/sys` would carry
cgroup, debugfs and tracefs the same way. A bind that is not recursive hides them. In a user namespace the kernel
refuses that bind (EINVAL) when a locked mount is below. There the bind falls back to recursive, because such a mount
is owned by a uid the payload is not, and writes to it read EACCES. The remount carries the mount's own nosuid, nodev,
noexec and atime flags, read with `statfs`, because in a user namespace the kernel locks them and a remount that drops
one reads EPERM.

**CAP_SYS_ADMIN with no filter is refused.** With every capability, `umount` worked and `core_pattern` opened again,
and as root CAP_SYS_ADMIN also mounts a `/proc` of the payload's own. The filter denies `mount`, `umount2`,
`move_mount` and the rest of the mount API, so under one the masks hold, and the payload's `umount2` is killed
(measured: exit 159). `confine_capabilities_refusal` refuses such a list in the parent with a message, and
`confine_child_caps` refuses the bit itself with SPAWN_EXIT_CAPS, for a caller that passes the mask directly.

**After the pivot, the guard is verified.** Before the pivot an absolute symlink in the rootfs resolves against the
host, so the guard takes a `proc` or `sys` that is a directory and nothing else. After the pivot a symlink resolves
inside the rootfs, and could lead to a procfs nothing guarded. `_spawn_proc_sys_held` follows `/proc` and `/sys` as
the payload will. A procfs there must have a read-only `/proc/sys`, and a sysfs there must be read-only, or the
payload does not run. Measured: a `/proc` symlinked to a procfs at `/realproc` exits SPAWN_EXIT_PROC.

**`read_only_rootfs` applies on this path.** `score_backend` gave it 3 and nothing here applied it. After the pivot `/`
is the rootfs's own bind, so a remount makes that mount alone read-only, and a guarded `/proc` below keeps what it has.

Two new exit codes: SPAWN_EXIT_PROC (115), "cannot make /proc or /sys in the rootfs read-only", and
SPAWN_EXIT_READONLY (114), "cannot make the rootfs read-only".

## Alternatives

- **The three paths the prototype measured** (`/proc/sys` and `sysrq-trigger` read-only, `/proc/kcore` masked). The
  two backends' `/proc` would differ, and `/proc/irq` stays writable to uid 0: measured, an IRQ affinity opened to
  write.
- **The rootfs's own `/dev/null`**, runc's choice with its CVE-2025-31133 check. A rootfs with a `/proc` and no `/dev`
  would refuse the exec.
- **`open_tree` and `move_mount`**, which need no `/dev/null` path at all. The stdlib names neither, so by ADR-007 they
  would be x86-64 only, and aarch64 would refuse every rootfs with a `/proc`.
- **CAP_SYS_ADMIN refused always, or allowed and documented.** Refused always takes from a filtered payload something
  the filter already bounds. Allowed, the masks mean nothing to a payload holding it with no filter.

## What consumers run

The postgres entry point, as ADR-009 ran it: its image's filesystem as the rootfs, with the caller's `/dev` (an rbind)
and `/proc`, through `sandbox_spawn` under `policy_basic()`, as root. `pg_isready` over the socket in the rootfs read
"accepting connections" on 3.14.6 and on 3.14.7.

## Consequences

Measured as above, on 3.14.7, under `policy_basic()` and `policy_new()`, on `sandbox_exec` and `sandbox_spawn`:

| | 3.14.6 | 3.14.7 |
|---|---|---|
| open `core_pattern`, `sysrq-trigger`, an IRQ affinity, a sysfs file to write | **opened** | EROFS |
| open binfmt_misc's `register` to write, `/proc` an rbind carrying it | **opened** | ENOENT: hidden |
| read `/proc/kcore`, `/proc/timer_list` | EPERM, a byte | 0 bytes: masked |
| with no filter, `umount2("/proc/sys")` | EPERM | EPERM |
| from a nested user namespace, `umount2("/proc/sys")` | nothing mounted there to lift | EINVAL: locked |

- Rootless the same mounts are made, and the writes read EACCES before and after, so the tests read them from
  `mountinfo`. `test_process_rootfs_guards_proc` does that with rootfs `/`, which carries the host's `/proc` and `/sys`.
  `test_process_rootfs_caller_proc` runs as root, mounting a `/proc` and `/sys` in a child's own mount namespace, so
  the host's table is never touched.
- rootfs `/` is guarded too: its `/proc` and `/sys` are the host's, in the payload's own mount namespace. A payload
  there no longer sees mounts below `/proc/sys` or `/sys` (binfmt_misc, cgroup, debugfs) as root, because the bind
  is not recursive.
- A rootfs with no `/proc` and no `/sys`, as kavach leaves one, is unchanged: two `lstat` calls, and nothing mounted.
- ⚠ **Only `/proc` and `/sys`.** A procfs the caller mounted elsewhere in the rootfs (`/host/proc`) is neither found nor
  guarded. runc's lists name the same paths; what differs is that runc mounts its own `/proc`, so a caller reaches
  another only by naming it in the spec.
- ⚠ **`/proc/<pid>/root` reaches a sibling sandbox.** A payload here has no PID namespace, so a caller's `/proc` lists the
  host's processes. Measured as root on 3.14.6 and 3.14.7 alike: `/proc/<pid>/root/<file>` of another sandbox's
  payload, which holds the same twelve, read its file, under both policies. The host's PID 1 and kavach's own process
  read EACCES, because they hold capabilities the payload does not, and the ptrace check refuses. This ADR does not close it. A PID
  namespace with a `/proc` of kavach's own, as runc mounts one, or a landlock domain on every payload, which refuses ptrace
  access outside its domain, would. It is open on the roadmap.
- ⚠ **A `/dev` the caller mounted is not narrowed.** Under runc a device cgroup refuses a node the spec does not list,
  and the process path has none. Measured as root, under both policies, with the caller's `/dev` an rbind of the host's:
  the payload opened the host's disk (`/dev/nvme0n1`) read-only. It was opened and closed, and nothing was read. On the roadmap.
