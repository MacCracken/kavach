# ADR-011 — `/dev`, other processes, capabilities and the network on the process path, and an OCI spawn through runc

**Status**: Accepted
**Date**: 2026-11-07
**Version**: v3.14.8

## Context

[ADR-009](009-rootfs-on-the-process-path.md) entered a rootfs with `pivot_root` and bounded the payload to ADR-008's
twelve capabilities. [ADR-010](010-proc-and-sys-in-a-process-path-rootfs.md) made a caller's `/proc` and `/sys` there
what runc makes them. Four things measured on the way were still not runc's, and each reached past a sandbox. The full
record is in [the process-backend issue](../development/issues/archived/2026-11-06-process-backend-keeps-every-capability.md).
Measured as root on 3.14.7, under `policy_basic()` and `policy_new()`:

| | 3.14.7 |
|---|---|
| the caller's `/dev` an rbind of the host's, as ADR-009 ran postgres: open `/dev/nvme0n1` read-only | **opened** |
| with a caller's `/proc`, read a file in a sibling sandbox's root through `/proc/<pid>/root` | **read it** |
| no rootfs: `CapEff` | **every capability kavach holds** |
| `sandbox_spawn` on an OCI sandbox: PID namespace, `/proc` of its own | **none**, kavach's |

agnosai filed a fifth, on the same path
([archived issue](../development/issues/archived/2026-11-07-agnosai-a-policy-denying-network-needs-a-namespace.md)): a
policy denying network was enforced by a network namespace and nothing else, and an unprivileged process cannot have one
on Ubuntu 24.04 and later, under docker's default seccomp profile, or on GitHub's runners.

The roadmap left four decisions to the maintainer, for the first four rows. Each is below as decided. The fifth followed
the issue's own proposal.

## Decision

**A landlock domain on every confined payload** (the second row). `_spawn_apply_landlock` installs one whatever the policy
names (`security_apply_landlock_domain`). A process inside a landlock domain may ptrace, and so open another's
`/proc/<pid>/root` or `environ`, only for a process in its own domain or one below it, so each payload is shut out of every
other's and of kavach's (measured for `root` and `environ`; for `environ`, see the ⚠ below). On ABI v6 the domain also scopes its signals (LANDLOCK_SCOPE_SIGNAL), so a root payload
holding CAP_KILL signals neither a sibling nor kavach. A domain needs something handled. With no rule and no scope from the
policy, and below ABI v6, it is a ruleset handling one right, making a block device, and allowing it beneath `/`, which
allows every path. It needs no namespace, so it holds rootless and on a host that refuses user namespaces. Chosen over a PID
namespace with a `/proc` of kavach's own, which is runc's answer: that needs a second fork per exec, makes the payload PID 1
with PID 1's signal semantics, and needs a user namespace rootless, which those same hosts refuse.

**A `/dev` of kavach's own wherever the rootfs has a `dev` directory** (the first row). Between the `/proc` guard and the
pivot, `_spawn_own_dev` mounts a tmpfs over `dev`, binds runc's default devices onto it from the host's (`null`, `zero`,
`full`, `random`, `urandom`, `tty`, each only where the host has it as a character device), mounts a devpts with
`newinstance` (and `gid=5` outside a user namespace, where gid 5 is not mapped), a tmpfs `/dev/shm`, and runc's links:
`fd`, `stdin`, `stdout`, `stderr` and `ptmx`. After the pivot `_spawn_dev_held` checks that `/dev` is that tmpfs. A rootfs of
`/` gets it too, the host's devices bound through a descriptor to its `/dev` taken before the tmpfs covers it, since the stdlib
names no `open_tree`. A rootfs with no `dev` keeps having none, since kavach makes no directory in the caller's tree, and one
whose `dev` is a symlink is refused (SPAWN_EXIT_DEV, 113): before the pivot it would resolve against the host. Chosen over
covering only a `dev` something is mounted on, which leaves an image's own device nodes visible, and over a cgroup v2 device
program over the caller's `/dev`, which needs bpf(2), a cgroup and root and does nothing rootless.

**The bound on every confined payload, rootfs or not** (the third row, the issue's Ask 3). `confine_child_caps` applies
`config_capabilities`, the twelve by default, with no rootfs as with one, and so does a confined persistent guest. A caller
that is not uid 0 and holds no CAP_SETPCAP, as a rootless kavach outside a user namespace does, cannot drop the bounding set
and need not: under NO_NEW_PRIVS an exec grants nothing from a file's capabilities or a set-id bit, and only uid 0 takes the
bounding set at `execve`. Its other sets are lowered all the same. The unconfined path `policy_new()` takes is unchanged,
as decided: the choice of bounding every payload, which would confine that path minimally, was not taken. uid 0 with no rootfs
is still on the host's files, which no set bounds; `SECURITY.md` says so.

**`sandbox_spawn` on an OCI sandbox runs `runc run` in the foreground** (the fourth row, the issue's Ask 4). The dispatch
table's reserved slot is a backend's spawn (`backend_register_spawn`), the OCI backend registers `oci_spawn`, and
`sandbox_spawn` hands over to it after the checks every detached payload passes. runc is the handle's pid: it stays the
container's parent, forwards a signal it is sent, exits with the container's status and deletes the container when that ends.
A SIGKILL, which runc cannot be asked to forward, goes through `runc kill` (`kill_fn`), and once runc is reaped
`runc delete --force` and the bundle's removal run (`reap_fn`), so a runc that was itself killed leaves nothing. The payload
gets what `oci_exec`'s gets: a PID namespace, runc's `/proc` and masks, its device rules, ADR-008's set and the policy's
filter. `[lib.confine]` carries no OCI backend, so its consumers' OCI sandboxes still detach on the process path, and
`score_spawn` scores what each takes. Chosen over keeping the process path for that spawn.

**A policy denying network, denied with no namespace** (agnosai's issue, as it proposed). A confined payload with
`network_enabled = 0`, no network namespace of its own and landlock ABI v4 gets landlock's TCP rights in its domain, so every
TCP bind and connect reads EACCES but to a port the policy names (`policy_network_allow_tcp`, as NET_PORT rules), and a
network filter of its own (`security_net_seccomp_filter`), loaded beside any other. Measured with landlock alone, an MPTCP
socket connected to a refused port and an SCTP connect went out: landlock's network rights are plain TCP's. So the filter
allows `socket(2)` for AF_UNIX and AF_NETLINK, and for AF_INET and AF_INET6 only as a TCP stream, refuses everything else with
EACCES, and refuses `io_uring_setup` with ENOSYS, as a ring opens sockets with no call to test. Both apply or neither. Below
ABI v4 nothing changes. A policy naming ports gets no network namespace, which would leave nothing to reach.

## What consumers run

As root, in a throwaway privileged container, through kavach's public paths, both builds from this tree. The images'
filesystems as rootfs, `docker export`ed:

| | 3.14.7 | 3.14.8 |
|---|---|---|
| postgres entry point, the caller's `/dev` and `/proc`: answers `pg_isready`, stops on SIGTERM | yes, exit 0 | yes, exit 0 |
| postgres entry point, the caller's `/proc` only | fails: `/dev/null: Permission denied` | answers, exit 0: kavach's `/dev` |
| the caller's `/dev` an rbind of the host's: a payload opens the host's disk read-only | **opened** | ENOENT |
| nginx, network allowed: serves a page | yes, exit 0 | yes, exit 0 |
| nginx, network denied, port 80 to bind (`policy_network_allow_tcp`) | no such list: no page, in a namespace of its own | **serves**, exit 0 |
| nginx, network denied | no page | no page |
| nginx detached from an OCI sandbox (`sandbox_spawn`), network allowed | serves; nginx is the handle, in kavach's PID namespace | serves; runc is the handle, nginx PID 1; SIGTERM forwarded, exit 0 |

The OCI row ran in a chroot of this machine's root, read-only, for its runc 1.5.2; the rest in `ubuntu:24.04`. The rig,
[`repros/2026-11-07-consumer-images-on-3.14.8.{cyr,sh}`](../development/issues/repros/), found one regression on the way,
fixed before this was written: kavach's `/dev` first carried runc's `stdin`, `stdout`, `stderr` and `fd` links into `/proc`
whatever the rootfs held, and nginx:alpine's error log is a link to `/dev/stderr`. With no `/proc` the open of that dangling
link read ENOENT and nginx exited 1, where 3.14.7's open made a file. The links are now made only where the rootfs has a
procfs at `/proc`.

## Consequences

- **A confined payload denied network has no network** where the kernel has landlock ABI v4, which `policy_basic()` and
  `policy_strict()` ask for: through 3.14.7 such a payload with no rootfs kept the host's. It is listed under the CHANGELOG's
  behaviour changes, with how to keep it: `network_enabled = 1`, or a port list.
- **A confined payload signals nothing outside its domain** on ABI v6, kavach included: a program sending its parent a signal
  reads EPERM. Its own children are in its domain.
- ⚠ **The domain does not hold `/proc/<pid>/environ` against CAP_SYS_ADMIN or CAP_PERFMON.** Measured as root, the twelve plus
  one capability at a time: with either of those two, a confined payload opened kavach's `environ`, while `/proc/<pid>/root`
  and a signal stayed refused; with CAP_SYS_PTRACE, or any of the other 26, it read EACCES. Neither is in the default set, so
  this takes a `config_capabilities` list naming one. Not traced to the kernel's code.
- **A confined root payload with no rootfs holds the twelve.** A program needing more names it in `config_capabilities`.
- **A rootfs's `dev` is kavach's.** An image's own device nodes, and a caller's `/dev`, are no longer seen. A payload needing
  another device has no way to ask on this path, as under runc without a spec entry. Building it costs a rootfs exec 0.53 ms
  (6.42 to 6.95 ms, as root, one CPU); a rootfs with no `dev` pays nothing.
- **Denying the network costs an exec nothing measurable**: `process_exec_confined` against the same policy with the network
  allowed, 2.678 and 2.671 ms.
- **An OCI sandbox's spawned payload is PID 1** in a namespace of its own. A SIGTERM it has no handler for does nothing, as
  under `docker stop`, so `spawned_terminate` ends it with its SIGKILL after the grace period.
- New exit code SPAWN_EXIT_DEV (113). `SANDBOX_POLICY_SIZE` 176, `SANDBOX_SIZE` 112, `EXEC_RESULT_SIZE` 64,
  `CONFINE_CAPTURE_SIZE` 160 and `SPAWNED_PROCESS_SIZE` 64, each appended so no field moves.
- Not run here: a kernel below landlock ABI v6, where the allow-all ruleset makes the domain (CI's runners may be one), any
  kernel with AppArmor, crun, gVisor's spawn, and the OCI spawn on aarch64.
