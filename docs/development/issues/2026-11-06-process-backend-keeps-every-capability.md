# 2026-11-06 — a process-backend payload keeps every capability, and a rootfs does not hold it — OPEN IN PART

**Discovered:** 2026-11-06, measuring the process backend as root after kavach 3.14.5 closed the same hole on the
OCI backend.
**Severity:** High when kavach runs as root. Rootless the capabilities are confined to the user namespace and the
rootfs still does not hold, so a payload reads whatever the rootless uid can.
**Affects:** every kavach release with a process backend: `confine_child_wd` and `_spawn_enter_rootfs`
(`src/confine.cyr`), `_seccomp_deny_list` (`src/security.cyr`), `sandbox_spawn` (`src/spawn.cyr`) and persistent
guests. Consumers that reach them, stiva's `run -d` among them, whatever backend the sandbox names.
**Status:** 🟡 OPEN IN PART. A rootfs is ✅ **resolved in kavach 3.14.6**, by the maintainer's choice of `pivot_root`
([ADR-009](../../adr/009-rootfs-on-the-process-path.md)), and a `/proc` the caller mounted there is ✅ **resolved in
3.14.7** ([ADR-010](../../adr/010-proc-and-sys-in-a-process-path-rootfs.md)), with the two scoring items under "Also
seen" and Ask 4's scoring. See the resolutions at the end. Still open: no rootfs as root (Ask 3), a detached OCI payload
that never meets runc (Ask 4's other half), and `/proc/<pid>/root`, measured in 3.14.7. What follows is as filed, measured against 3.14.5 on x86-64, Linux 7.2.14 and runc 1.5.2.

## What happens

**Nothing on the process path drops a capability.** `src/` holds no `capset`, no `PR_CAPBSET_DROP` and no call that
changes a uid or a gid. Its `prctl`s are NO_NEW_PRIVS, PDEATHSIG and seccomp, and NO_NEW_PRIVS stops a gain and
takes nothing away. As root:

| Payload, `policy_basic()` or `policy_new()`, `sandbox_exec` or `sandbox_spawn` | `CapEff`, `CapBnd` | open `core_pattern` to write | open `sysrq-trigger` to write | read `/proc/kcore` |
|---|---|---|---|---|
| no rootfs | `000001ffffffffff` | **allowed** | **allowed** | a byte |
| a rootfs, as kavach leaves it | `000001ffffffffff` ¹ | ENOENT | ENOENT | ENOENT |
| a rootfs whose caller mounted `/proc` in it | `000001ffffffffff` | **allowed** | **allowed** | a byte |
| control: OCI backend, `sandbox_exec` | `00000000a00405fb` | EROFS | EROFS | none |

¹ From `capget` and `PR_CAPBSET_READ`, because `/proc/self/status` is not there to read. Where it is, they agree.

The two policies differ only in the filter, and `policy_new()` with no rootfs under `sandbox_exec` also has no
NO_NEW_PRIVS, because that path runs no `confine_child` at all (`do_confine = 0`, `src/backend_process.cyr:158`). A
persistent guest reads the same `CapEff` under both policies. The control is the same binary under runc, so the
probe can tell the two apart.

### The ENOENT is not protection

It means kavach mounted no `/proc`. It does not stop a payload getting to one. `_spawn_enter_rootfs` uses `chroot`,
the payload keeps CAP_SYS_CHROOT, and **`chroot` is not in `_seccomp_deny_list`**, so under `policy_basic()`, the
policy stiva starts from, a payload walks out:

```
chroot("/sub");  chdir("..") to the top;  chroot(".");
```

From a rootfs with no `/proc`, as root:

| | `policy_basic()` | `policy_new()` | OCI backend, `sandbox_exec` |
|---|---|---|---|
| leave the rootfs by `chroot`, then read a file outside it | **escapes** | **escapes** | stays: ENOENT |
| …then open `core_pattern` to write, read `/proc/kcore` | **allowed**, a byte | **allowed**, a byte | EROFS, none |
| `mount` a `/proc` of its own, then the same | killed by the filter | **mounts, allowed** | not run |
| `mknod` a character device in the rootfs and open it (`/dev/kmsg`) | **opens** | **opens** | EPERM |
| `open_by_handle_at` a file outside the rootfs ² | **reads it** | **reads it** | EPERM |

² On tmpfs, with a real handle handed in, so the row shows that a chroot does not bound a handle and that the filter
does not deny the call. overlayfs issues none (EOPNOTSUPP). Every other row reads the same on both.

`sandbox_exec` and `sandbox_spawn` read the same in every cell. The payload stays in its own mount namespace, but
that is a copy of the caller's, so it reaches every filesystem kavach can. It has no PID namespace: `ns/pid` equals
kavach's on every process row.

**Rootless**, the chroot escapes on both paths under both policies, and the payload reads anything the rootless uid
can. `mount`, `mknod` and the handle read EPERM, `core_pattern` and `/proc/kcore` read EACCES, and the OCI backend
holds. With no rootfs and no namespace a rootless payload has `CapEff` 0.

### `sandbox_spawn` never reaches the OCI backend

`sandbox_spawn` reads no backend. It always forks and calls `confine_child_wd` (`src/spawn.cyr:201`), with
`want_ns = 1`, so it is the process path with a network namespace that `sandbox_exec` without a rootfs does not
get. With runc installed and `KavachBackend.OCI` in the config, as root:

| OCI sandbox, rootfs | `sandbox_exec` | `sandbox_spawn` |
|---|---|---|
| `CapEff`, `CapBnd` | `00000000a00405fb` | `000001ffffffffff` |
| PID namespace | its own | kavach's |
| leave the rootfs by `chroot` | stays | **escapes** |
| `mknod` | EPERM | **opens** |

So ADR-008's set and masks reach no detached payload on any backend, `config_capabilities` is read only by
`src/oci_spec.cyr`, and `score_backend` scores that sandbox as OCI (65, against 60 for process) for a payload runc
never saw. stiva's `spawn_container` calls `sandbox_spawn` (`src/runtime.cyr:1088` there), and `build_sandbox` picks OCI
wherever it is available, so **every detached stiva container appears to be on this path, on a host with runc too**.
That is read and not run.

### Comments this disproves

- `src/confine.cyr:101` says a chroot is escapable by a process holding CAP_SYS_CHROOT "*and* a directory fd outside
  the new root", and that the payload is left "with no capability to re-chroot". No outside fd is needed, and the
  payload keeps the capability.
- `src/confine.cyr:301` and `src/spawn.cyr:39` say the filter denies `chroot`. The table has no such row.

## A bound set alone does not close it

Measured by a payload that drops its own set and re-execs, which is what `confine_child` would do, so kavach is
unchanged. Each row is `policy_basic()` and `policy_new()` alike, and `/etc/passwd` is the rig's own, standing in
for any file root owns.

| Set, as root | leave the rootfs by `chroot` | `mknod` | handle | no rootfs: open `core_pattern` to write | no rootfs: read `/proc/kcore` | no rootfs: open `/etc/passwd` to write |
|---|---|---|---|---|---|---|
| every capability | **escapes** | opens | reads | **allowed** | a byte | **allowed** |
| ADR-008's twelve | **escapes** | EPERM | EPERM | **allowed** | EPERM | **allowed** |
| the twelve less CAP_SYS_CHROOT | EPERM | EPERM | EPERM | **allowed** | EPERM | **allowed** |
| none | EPERM | EPERM | EPERM | **allowed** | EPERM | **allowed** |

- **ADR-008's set cannot be copied here as it stands.** It keeps CAP_SYS_CHROOT for images that call `chroot`, which
  is safe under runc's `pivot_root` and is the escape under kavach's `chroot`.
- **`core_pattern` is not a capability question.** `sysctl_perm` compares the euid with the global root, so uid 0
  opens it to write with `CapEff` zero. On the OCI backend the read-only mount stops that, and the set only keeps
  the mount on. With no rootfs there is no such mount, and no set bounds a uid 0 payload from files root owns.

A nested user namespace does not get past a bound under `chroot`: the filter kills `unshare`, and with no filter the
kernel refuses a chrooted caller (EPERM).

## Candidates

The first three ran on their own, with no filter and no kavach, as a payload standing where `confine_child`'s `chroot`
does (`pv` and `rosys` in the repro). None is on a kavach path.

| Candidate | Measured |
|---|---|
| `pivot_root`, runc's sequence, and the twelve | Stays in the rootfs. `mknod` and `mount` read EPERM. A nested user namespace holds every capability, and still stays in, with `mount` EPERM. The handle row was not repeated here; the twelve read EPERM above. |
| No rootfs: read-only `/proc/sys` and `sysrq-trigger`, `/dev/null` over `/proc/kcore`, in a mount namespace of its own, and the twelve | `core_pattern` and `sysrq-trigger` read EROFS, `/proc/kcore` none. `umount` reads EPERM, and EINVAL from a nested user namespace. **`/etc/passwd` still opens.** |
| The same mounts with every capability | `umount` works, and `core_pattern` opens again. The set and the mounts need each other. |
| No rootfs: a landlock rule naming only the payload's directory, with every capability, through kavach on both paths | `core_pattern`, `sysrq-trigger`, `/proc/kcore` and `/etc/passwd` all read EACCES. |

Landlock is the only thing measured that bounds a root payload with no rootfs, and kavach already has it
(`policy_landlock_add`). No preset names a rule.

## Ask

A decision for the maintainer. Proposed:

1. **A rootfs: `pivot_root` and ADR-008's twelve.** `_spawn_enter_rootfs` takes runc's sequence, and `confine_child_wd`
   applies the set after the rootfs and before seccomp, reading `config_capabilities`. One default and one list on
   every path with a rootfs, and `sandbox_spawn` gets it by sharing that function.
   The alternative keeps `chroot` and drops CAP_SYS_CHROOT here. It is smaller and measured, but leaves two defaults,
   breaks a payload that calls `chroot`, and `config_capabilities` naming it would reopen the escape, so it would have
   to be refused.
2. **Leave the deny list.** Rows for `chroot`, `mknod` and `open_by_handle_at` would also reach the OCI filter, which
   shares the table, and would take from images the capability ADR-008 kept. `policy_new()` has no filter to hold them.
3. **No rootfs, as root: say what it is.** A bound set is worth having, and stops `/proc/kcore`, but `SECURITY.md`
   should say that a root payload with no rootfs and no landlock rule is on the host's files. Decide too whether the
   `do_confine = 0` path takes the set: it runs nothing today, because the policy asked for nothing. The read-only
   mounts work and leave `/etc/passwd` open, so they are not proposed as a default.
4. **`sandbox_spawn` on an OCI sandbox.** After 1 it holds the twelve, with no `/proc` and no PID namespace, and is still
   scored as OCI. Either detach through runc, or score the path taken. Refusing would break `stiva run -d`. This one
   can follow 1.
5. **Assert it from inside a payload**, as `test_oci_payload_observes_the_filter` does: the chroot, `mknod` and handle
   rows on both paths, as root in CI's root job and rootless.

⚠ This changes what a payload may do, so it needs the look ADR-008 took first. Its table measured nginx and postgres
under runc, and here an image also has no `/proc`. That has not been run.

⚠ Three things a fix or its test will meet, all met here:

- A rootless payload with no namespace holds nothing to drop with. Its `CapBnd` stayed full and `capset` to the twelve
  read EPERM, so failing closed there would stop every rootless exec. Skip when nothing is held.
- A Cyrius binary reads its argv from `/proc/self/cmdline`, so inside a rootfs with no `/proc` it has none. The repro's
  payload is C for that reason.
- As root a seccomp kill is a core dump, and a core dump runs the host's `core_pattern`. The payload sets
  PR_SET_DUMPABLE 0 first.

## Repro

`docs/development/issues/repros/2026-11-06-process-backend-capabilities.{cyr,c,sh}`: the driver through kavach's public
paths, the payload, and the script for a throwaway privileged container. The payload opens and never writes, and
reads `/proc/kcore` for one byte.

## Not measured

- **The write.** `core_pattern` was opened and never written, so the last step of the chain was not run, as in 3.14.5.
  That a write would be accepted with `CapEff` zero is reasoning from the open, not a test.
- **`stiva run -d`.** Its path to `sandbox_spawn` is read from stiva's source, which pins 3.14.4, so it gets none of
  3.14.6 until it bumps.
- **A guessed handle.** The row hands the payload a real one. Whether a handle can be forged depends on the
  filesystem, and tmpfs and overlayfs were the only two run. ext4 and btrfs were not.
- **A real aarch64 kernel, crun, and any kernel but 7.2.14**, which also means any kernel with AppArmor. `pivot_root` under a filter was not run either: the filter denies it, so
  it has to come before seccomp, as `chroot` does.

## Also seen

`score_backend` adds 5 for `network_enabled = 0`, but `sandbox_exec` with no rootfs leaves the payload in kavach's
network namespace unless `require_ns` is set. `ns/net` equals the driver's. `confine_child`'s header calls that path
one that claims no isolation it did not get, and the score does claim it.

`score_backend` adds 3 for `read_only_rootfs`, which `policy_strict()` sets, and nothing on the process path applies it.
`docs/architecture/overview.md` says as much. Since 3.14.6 the rootfs is a bind mount of its own, so a remount is a line.

## Resolution in part (3.14.6)

**Ask 1, 2 and 5, as proposed.** The maintainer chose `pivot_root` and the twelve over keeping `chroot`, and
`config_capabilities` is read. `sandbox_spawn` has it by sharing `confine_child_caps`. As root, under either policy, on
`sandbox_exec` and `sandbox_spawn`, and on `sandbox_spawn` with an OCI sandbox:

| From a rootfs with no `/proc` | 3.14.5 | 3.14.6 |
|---|---|---|
| `CapEff`, `CapBnd` | `000001ffffffffff` | `00000000a00405fb` |
| leave the rootfs by `chroot`, then read a file outside it | **escapes** | stays in |
| `mknod` a character device and open it | **opens** | EPERM |
| `open_by_handle_at` a file outside the rootfs | **reads it** | EPERM |
| with no filter, `mount` a `/proc` of its own | **mounts** | EPERM |

`chroot` itself still works, for an image that calls it. Rootless the walk stays in too, and a nested user namespace,
which hands back every capability, stays in and mounts nothing. nginx and the postgres entry point behave as they did on
3.14.5, on a rootfs as kavach leaves it and with `/dev` and `/proc` added: the table is in ADR-009.

**Still open.**

- **A `/proc` the caller mounted**, pinned to 3.14.7 on the [roadmap](../roadmap.md). This is the third row of the first
  table, and Ask 1 does not reach it:

  | A rootfs whose caller mounted `/proc`, as root | 3.14.5 | 3.14.6 |
  |---|---|---|
  | open `core_pattern` to write | allowed | **allowed** |
  | open `sysrq-trigger` to write | allowed | **allowed** |
  | read `/proc/kcore` | a byte | EPERM |

  A rootfs needs this to run the postgres entry point, so a caller has a reason to do it. The candidate is the second row
  of the Candidates table, done after the pivot: read-only `/proc/sys` and `sysrq-trigger`, and `/dev/null` over
  `/proc/kcore`, where a `/proc` is there. It held as a prototype, and it is on no kavach path. A payload here has no PID
  namespace either, so `/proc/<pid>/root` names the host's root for any process that ptrace access lets it read. That
  was not measured.
- **No rootfs, as root (Ask 3).** Unchanged, and now in `SECURITY.md`. `config_capabilities` is not read there, so a caller
  narrowing a list on that path gets no narrowing. Whether the path takes a set is still the decision in Ask 3.
- **`sandbox_spawn` on an OCI sandbox (Ask 4).** Bounded, with no PID namespace, no `/proc` and no masks, and scored as OCI.

**Found on the way.**

- `rootfs == "/"` read EBUSY from `pivot_root`, which `test_rootfs_always_gets_a_mount_namespace` caught. Nothing is above it
  to leave, so it skips the pivot and keeps the private mount.
- A mutation pass reverted each part of the change, and one survived: with the `capset` deleted the suite stayed green.
  Inheritable capabilities pass `execve` for a uid 0 payload whatever the bounding set says, and no test held any.
  `test_bound_clears_inheritable_and_ambient` does now.
- The capability table had to leave `oci_spec.cyr`, which `[lib.confine]` does not carry. In-tree that would have compiled.
- A chrooted caller is not a regression. On a plain directory it was refused at the private mount before and after, and
  onto a mount point it works in both.
- CI's `ubuntu-26.04` root job failed the first draft of the test. In a nested user namespace `unshare` read 0 and `chroot`
  then failed, where the test took that namespace for one holding every capability. Nothing mounted and nothing was reached,
  so the payload was held tighter and the test was wrong. Every run here shared one Arch kernel with no AppArmor, whatever
  the container's distribution, so none could show this. AppArmor's restriction on unprivileged user namespaces is the
  likely cause. It is not measured: the skip now prints the payload's numbers, and CI raises it as a warning.

## Resolution in part (3.14.7)

**A `/proc` the caller mounted.** As the maintainer decided ([ADR-010](../../adr/010-proc-and-sys-in-a-process-path-rootfs.md)):
`runc spec`'s two full lists from one table in `security.cyr`, which the OCI spec writes from too; the host's
`/dev/null` over a masked file; CAP_SYS_ADMIN refused with no filter. Where a rootfs holds a procfs at `/proc` or a
sysfs at `/sys`, they are made what runc makes them, between the bind and the pivot, and checked again after it. Measured
as root through kavach's public paths, from inside the payload, opening and never writing, the caller's `/proc` and `/sys`
in the rootfs, `policy_basic()` and `policy_new()` alike:

| | 3.14.6 | 3.14.7 |
|---|---|---|
| open `core_pattern`, `sysrq-trigger`, `/proc/irq/default_smp_affinity` to write | **allowed** | EROFS |
| open `/sys/kernel/mm/transparent_hugepage/enabled` to write | **allowed** | EROFS |
| `/proc` an rbind carrying binfmt_misc: open its `register` to write | **allowed** | ENOENT: the bind hides it |
| read `/proc/kcore`, `/proc/timer_list` | EPERM, a byte | 0 bytes: masked |
| with no filter, `umount2` of `/proc/sys`, `/proc/kcore`, `/sys` | nothing to lift | EPERM |
| from a nested user namespace, the same | nothing to lift | EINVAL: locked |
| a `/proc` symlinked to a procfs elsewhere in the rootfs | not reached | refused, SPAWN_EXIT_PROC |
| CAP_SYS_ADMIN in the list, no filter | ran | refused |

The postgres entry point, its image as the rootfs with the caller's `/dev` and `/proc`, answers `pg_isready` on both, as
ADR-009 ran it. Rootless the writes read EACCES before and after, so the tests read `mountinfo` for that half.

**`read_only_rootfs`**, from "Also seen", applies on this path with a rootfs: a remount of the pivoted root. A create at
`/` reads EROFS, on `sandbox_exec` and `sandbox_spawn`.

**Scoring, from "Also seen" and Ask 4.** `score_backend` no longer gives the process backend 5 for `network_enabled = 0`
or 3 for `read_only_rootfs`, which that path applies only with a rootfs or `config_require_namespaces`. `score_config`
adds them back where the config makes the path apply them, and `score_spawn` scores `sandbox_spawn`, which reads no
backend: an OCI sandbox's spawn scores 60 under `policy_basic()`, as the process path, where `score_backend` gave it 65.

**Found on the way: `config_require_namespaces` was ignored with a policy asking for no seccomp and no landlock.** That
policy took the unconfined capture, which reads no namespaces, so `policy_new()` with the flag set ran in kavach's
network namespace. Measured: the payload's `readlink /proc/self/ns/net` read kavach's own. The flag now takes the
confined path, which creates the namespaces or refuses closed.

**Measured, and open: `/proc/<pid>/root` reaches a sibling sandbox.** A payload here has no PID namespace, so a caller's
`/proc` lists the host's processes, and a ptrace access check is all that stands at `/proc/<pid>/root`. As root, on 3.14.6
and 3.14.7 alike, under both policies:

| From a payload whose caller mounted `/proc`, reading `/proc/<pid>/root/<file>` | Result |
|---|---|
| another sandbox's payload, spawned with the same twelve, its own rootfs | **reads the file** |
| the host's PID 1 | EACCES |
| kavach's own process | EACCES |

The two that hold, hold because their capabilities are not a subset of the payload's. Any uid 0 process holding no more
than the twelve is reachable, every sibling sandbox among them. Rootless a payload's user namespace is not its target's, and
the check needs CAP_SYS_PTRACE in the target's: that is reasoning, not a measurement. Neither 3.14.6's `pivot_root` nor 3.14.7's masks
reach this. A PID namespace with a `/proc` of kavach's own, which is runc's answer, or a landlock domain on every payload,
which refuses ptrace access outside its domain, would. It is on the roadmap.

**Repro**: `repros/2026-11-07-process-rootfs-caller-proc.{cyr,sh}`, the driver and payload in one binary and the script for a
throwaway privileged container: the before and after above, `/proc/<pid>/root`, the caller's `/dev`, and postgres.

**Still open.**

- **No rootfs, as root (Ask 3).** Unchanged.
- **`sandbox_spawn` on an OCI sandbox (Ask 4).** Scored as what it is since 3.14.7, and still detached on the process path:
  no runc, no PID namespace, no `/proc` of its own.
- **`/proc/<pid>/root`**, above.
- **A `/dev` the caller mounted reaches the host's disks.** Under runc a device cgroup refuses a node the spec does not
  list, and the process path has none. Measured as root in 3.14.7, under both policies, with the caller's `/dev` an
  rbind of the host's as ADR-009 ran postgres: the payload opened `/dev/nvme0n1`, the host's disk, read-only (it was
  opened and closed, and nothing was read). uid 0 owns the node, so no capability is needed for that. It reads the same
  on 3.14.6, which has the same path. A caller adding `/dev` this way hands the payload the host's block devices.

