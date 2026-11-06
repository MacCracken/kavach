# ADR-008 — The OCI capability default, and how a payload asks for more

**Status**: Accepted. Since v3.14.6 the process path holds this set and reads this list too, with a rootfs:
[ADR-009](009-rootfs-on-the-process-path.md). "No other backend reads the list" below is true of 3.14.5.
**Date**: 2026-11-06
**Version**: v3.14.5

## Context

`oci_generate_spec` is the path every container takes where runc or crun is installed. Through 3.14.4 it
named capabilities only under a seccomp filter, and that list dropped only CAP_SYS_ADMIN, to close a hole in
the filter. A spec with no filter named none, and runc drops nothing when the key is absent. Nothing was
masked either.

Rootless, those capabilities sit in a user namespace that owns nothing on the host. Run as root they are real.
The first run as root, made for this decision under runc 1.5.2 with the 3.14.4 no-filter spec, read:

| | |
|---|---|
| `CapEff` | `000001ffffffffff` |
| open `/proc/sys/kernel/core_pattern` to write | allowed |
| open `/proc/sysrq-trigger` to write | allowed |
| read `/proc/kcore` | a byte |

A core pattern naming a program runs that program on the host. A seccomp filter cannot stand in for the
fix: writing a sysctl is an `open` and a `write`.

The set is a policy decision, because it changes what a container may do. So it was measured against what
consumers run before it was chosen, and the maintainer chose it.

- **stiva** picks the OCI backend wherever one is available, with `policy_basic()`, and every container runs as
  uid 0 inside, because nothing drops privileges before exec (stiva roadmap v3.2.2). Its documentation names
  nginx, postgres and alpine images.
- **agnosai**'s OCI tier runs `docker run`, not `oci_generate_spec`, so its payloads already hold Docker's
  default set. `agnosai_kavach_execute` would reach this spec, and has no live caller.

## Decision

**Every OCI and gVisor spec writes twelve capabilities, under any policy**: Docker's default set less
CAP_NET_RAW and CAP_MKNOD. In bounding, effective and permitted, with inheritable and ambient empty. A payload
reads `CapEff: 00000000a00405fb`. Docker's own default reads `00000000a80425fb`.

CAP_AUDIT_WRITE, CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_NET_BIND_SERVICE,
CAP_SETFCAP, CAP_SETGID, CAP_SETPCAP, CAP_SETUID, CAP_SYS_CHROOT.

**Every spec also writes `linux.maskedPaths` and `linux.readonlyPaths`**, as `runc spec` 1.5.2 does.

**A payload asks for more with `config_capabilities(c, v)`**, a list that replaces the default, as `config_env`
replaces its own. `oci_default_capabilities()` returns the default as a fresh vec to extend, so "one more" is a
line, and the same call narrows. An empty list is no capabilities. It is one field and one setter.

**Two requests are refused, and the exec says which and why**, rather than dropping the name:

- a name not in kavach's table, because a runtime only warns about one, which `_oci_exec_with` reports as a
  runtime failure, and because a name is written unescaped once it has matched;
- CAP_SYS_ADMIN under a seccomp filter, because `open_tree_attr` gets past the filter by name and that
  capability is what lets it clone a tree writable, past a read-only rootfs. A caller who needs it turns the
  filter off, which says plainly what is being given up.

## Alternatives

Measured under `no-new-privileges`, which every kavach spec sets:

| Set | nginx | postgres entry point | `su` | `chown` |
|---|---|---|---|---|
| `runc spec`'s 3 | fails | fails | fails | fails |
| Docker's 14 | runs | runs | runs | runs |
| This, 12 | runs | runs | runs | runs |

- **`runc spec`'s three.** The tightest, and it breaks the images consumers run, so every caller would have to
  ask for more, and the default would protect nothing in practice.
- **Docker's fourteen, exactly.** The most compatible, and the same set agnosai's tier holds. It keeps two
  capabilities that earn nothing here:
  - CAP_NET_RAW reaches nothing in the empty network namespace of a policy with no network, and
    `network_enabled` shares the host's namespace, where a payload running as root could read and forge host
    traffic. It is either useless or too much.
  - CAP_MKNOD cannot make a device node in a user namespace. As root under runc 1.5.2 it can, and opening one
    past runc's default rules still read EPERM. That is runc's default, measured, and not a rule this spec
    writes, so crun is not covered by it.
- **`config_cap_add` and `config_cap_drop`.** Docker's shape, and compose's. Two fields, de-duplication, and an
  ordering rule for a name in both, to save one `vec_push`.
- **A `SandboxPolicy` field.** It would let `score_backend` see the list, but a policy is a shared preset, and
  the set a payload needs belongs to that payload. `score_backend` does not see it, as it does not see
  `config_env`.

## Consequences

- A payload that used a raw socket, set a sysctl or called `mount` with the filter off now reads EPERM or EROFS
  until it asks. 3.14.4 told a caller who needed `mount` to turn the filter off. That now also takes
  CAP_SYS_ADMIN from `config_capabilities`.
- gVisor gains capabilities, from none. runsc gives a spec with no list no capabilities at all
  (`specutils.Capabilities`, read and not run), so `chown` and `setuid` failed there. They are the sentry's own,
  held against its emulated kernel and not the host. The two path lists are ignored there.
- ⚠ `CapEff` is not the whole bound. With no filter, `unshare` hands a payload every capability in a nested user
  namespace, whatever the bounding set says, and a spec cannot stop that. Measured as root and rootless, they do
  not reach what the spec set up: `umount` of `/proc/sys` and of a mask reads EINVAL, the kernel having locked
  them, and a fresh `/proc` mount is refused. With no masks the same payload mounts one, so the masks are what
  refuses it. The filter denies `unshare` outright.
- No other backend reads the list. A caller narrowing it on a host that falls back to the process backend gets no
  narrowing.
- Rootless, a test cannot tell a read-only `/proc/sys` from an open to write: `sysctl_perm` compares against the
  global root, so without CAP_NET_ADMIN that open reads EACCES with or without the mount. The suite asserts on
  `mountinfo`, and on a payload holding CAP_NET_ADMIN, and CI runs the group as root as well.
