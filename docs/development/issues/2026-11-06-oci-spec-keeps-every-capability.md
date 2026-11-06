# 2026-11-06 — an OCI container keeps nearly every capability, and `/proc` is neither masked nor read-only — OPEN

**Discovered:** 2026-11-06, probing the OCI backend under runc 1.5.2 for kavach 3.14.4.
**Severity:** High when kavach runs as root; lower rootless, where the capabilities are confined to the user
namespace kavach creates.
**Affects:** every kavach release with an OCI backend: `oci_generate_spec` (`src/oci_spec.cyr`), and consumers
that run containers through it, stiva among them.
**Status:** 🔴 OPEN. The spec and the rootless run are measured. A run as root is not: it is read from the spec.

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
