# 2026-11-06 — an OCI container keeps nearly every capability, and `/proc` is neither masked nor read-only — RESOLVED

**Discovered:** 2026-11-06, probing the OCI backend under runc 1.5.2 for kavach 3.14.4.
**Severity:** High when kavach runs as root; lower rootless, where the capabilities are confined to the user
namespace kavach creates.
**Affects:** every kavach release with an OCI backend: `oci_generate_spec` (`src/oci_spec.cyr`), and consumers
that run containers through it, stiva among them.
**Status:** ✅ **RESOLVED in kavach 3.14.5**; see the resolution at the end. As filed, the spec and the rootless run
were measured and a run as root was not. It has been made since, and the chain below holds as far as the open.

## What happens

Through 3.14.3 `oci_generate_spec` wrote no `process.capabilities`, and runc drops nothing when the key is
absent. A rootless payload read this from `/proc/self/status`:

```
CapEff:	000001ffffffffff
```

3.14.4 lists capabilities only under a filter, and drops only CAP_SYS_ADMIN, because the filter needs that:
`_oci_capabilities_json` says why. Under `policy_basic()` the same line now reads `0000003fffdfffff`. A policy
with no filter still gets the full set. That list is a fix for one bypass, not a policy: it keeps CAP_SYS_MODULE,
CAP_SYS_RAWIO, CAP_NET_ADMIN and the rest.

The spec also has no `linux.maskedPaths` or `linux.readonlyPaths`, so `/proc/sys`, `/proc/sysrq-trigger` and
`/proc/kcore` are as the mount gives them.

Rootless, those capabilities are held in a user namespace that owns nothing on the host, and 3.14.4's filter and
`noNewPrivileges` narrow them further. **As root the same spec should give the payload real capabilities on the
host.** The filter stops `mount`, `ptrace`, `init_module` and the rest, but it filters
syscalls, not files: writing `/proc/sys/kernel/core_pattern` is an `open` and a `write`, which it allows, and a
core pattern naming a program runs that program on the host. That chain is the reasoning, not a test.

## Ask

- Write a bounded `process.capabilities` set, in bounding, effective and permitted, with no filter too. Docker's
  default set is the usual starting point; the choice is a policy decision, and a payload that needs more needs a
  way to ask.
- Name no capability newer than the oldest kernel kavach supports: runc logs an unknown one at `level=warning`,
  and `_oci_exec_with` reads any log as a runtime failure.
- Write `linux.maskedPaths` and `linux.readonlyPaths`, as `runc spec` does by default.
- Test both from inside the container, as `test_oci_payload_observes_the_filter` does, and as root where a CI
  job can.

⚠ This changes what a container may do, so it needs a look at what consumers run first: an image whose entry
point calls `chown` or binds a low port needs the capability for it.

## Resolution (3.14.5)

**The set.** Every OCI and gVisor spec writes twelve capabilities, under any policy: Docker's default set less
CAP_NET_RAW and CAP_MKNOD. A payload reads `CapEff: 00000000a00405fb`, with or without a filter. The maintainer
chose it, from the measurements in [ADR-008](../../../adr/008-oci-capability-default.md):

| Under `no-new-privileges` | nginx | postgres entry point | `su` | `chown` |
|---|---|---|---|---|
| `runc spec`'s 3 | fails | fails | fails | fails |
| Docker's 14 | runs | runs | runs | runs |
| This, 12 | runs | runs | runs | runs |

**Asking for more.** `config_capabilities(c, v)` replaces the list, as `config_env` replaces its own, and
`oci_default_capabilities()` returns the default to extend. A name kavach does not know is refused, and so is
CAP_SYS_ADMIN under a filter, which is what the filter's `open_tree_attr` gap needs. The exec reports which.

**`/proc`.** `linux.maskedPaths` and `linux.readonlyPaths` are what `runc spec` 1.5.2 writes.

**As root**, the run this issue did not have. A privileged throwaway container, under runc 1.5.2, with the spec
as filed and with the fix:

| | as filed | 3.14.5 |
|---|---|---|
| `CapEff` | `000001ffffffffff` | bounded |
| open `/proc/sys/kernel/core_pattern` to write | **allowed** | EROFS |
| open `/proc/sysrq-trigger` to write | **allowed** | EROFS |
| read `/proc/kcore` | a byte | none |

The probe opened those files and wrote nothing, so the chain's last step, a core pattern running a program, was
not run. It stopped being reachable at the open. `test_oci_payload_observes_the_filter` now asserts all of this
from inside a container, passing rootless and as root under runc 1.5.2 (Arch), 1.4.0 (Ubuntu 26.04) and 1.3.4
(Ubuntu 24.04), and CI runs the group as root with `--kv-oci-only`.

**Three things found on the way.**

- ⚠ A rootless `/proc/sys` cannot be tested by opening a sysctl to write. `sysctl_perm` compares against the
  global root, and `net_ctl_permissions` gives root's bits only to a holder of CAP_NET_ADMIN, so the open reads
  EACCES with or without the mount. The first draft of the test asserted EROFS there and failed. Accepting
  EACCES would have passed with the mount gone, so the test reads `mountinfo` instead, and has a payload that
  holds CAP_NET_ADMIN read EROFS, which only the mount can answer.
- ⚠ `CapEff` is not the whole bound. With no filter, `unshare` hands a payload every capability in a nested user
  namespace, and a spec cannot stop that. Run as root and rootless, they do not reach what the spec set up:
  `umount` of `/proc/sys` and of a mask reads EINVAL, and a fresh `/proc` mount is refused. With no masks the same
  payload mounts one, so the masks are what refuses it.
- The group's skip used to be silent, so a spec that stopped runc from starting would have read as a host that
  cannot run a container, and passed. A skip now prints `SKIP:` with the runtime's message.

**Not measured:** gVisor, read from runsc's source only, with no runsc on hand. A list adds capabilities there,
from none, inside the sentry. crun, which writes its own device rules: the claim about CAP_MKNOD is runc's
default, and only matters to a caller who asks for that capability. A kernel older than this host's: the newest
default name is CAP_SETFCAP (2.6.24), so the `level=warning` hazard cannot arise from the default.

⚠ **Consumers.** stiva takes this at its next kavach bump, and its containers run as uid 0 with the twelve. An image
needing more has no way to ask until stiva exposes `config_capabilities`.
