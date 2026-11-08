# 2026-11-06 — a gVisor sandbox's `seccomp_enabled` is stored and scored, and kavach applies no filter — RESOLVED (scoring); the filter waits for runsc

**Discovered:** 2026-11-06, adding the filter to the OCI spec in kavach 3.14.4. **Severity:** Low.
**Affects:** every kavach release with a gVisor backend: `_gvisor_run` (`src/backend_gvisor.cyr`).
**Status:** ✅ **RESOLVED in kavach 3.14.7** by the second ask: `score_backend` no longer scores `seccomp_enabled` on
this backend. The first ask, a filter runsc applies, waits for a machine with runsc; see the resolution at the end.
Read from runsc's source, not run: this machine has no runsc.

## What happens

The gVisor backend shares `oci_generate_spec` with the OCI backend, but runsc is not runc about seccomp:

- It applies a spec's `linux.seccomp` only under `--oci-seccomp` (`runsc/config/flags.go`: "Enables loading OCI
  seccomp filters inside the sandbox"; `buildOCISeccompProgram` in `runsc/boot/loader.go`). kavach does not pass
  the flag.
- With the flag, `convertAction` (`runsc/specutils/seccomp/seccomp.go`) has no case for
  `SCMP_ACT_KILL_PROCESS`, which is what the OCI backend's filter uses, so that filter would fail as "invalid
  action". `SCMP_ACT_KILL` is accepted, and it kills the thread.

So 3.14.4's `_oci_seccomp_json` emits nothing for `KavachBackend.GVISOR`, and `noNewPrivileges` is the only
change a gVisor spec gets. `score_backend` still adds 5 for `seccomp_enabled`, as it did for the OCI backend
until 3.14.4 and the WASM backend until 3.13.2.

The severity is low because the sentry already stands between a gVisor payload and the host: a `mount` from the
payload is served by the sentry's own kernel, and no filter is what keeps it from the host's.

## Ask

Run this on a machine that has runsc, before changing the argv:

1. Emit the filter for gVisor with `SCMP_ACT_KILL` in place of `SCMP_ACT_KILL_PROCESS`, and pass `--oci-seccomp`
   when the spec carries one.
2. Or stop scoring `seccomp_enabled` on this backend, and say so in `docs/architecture/overview.md`.

A wrong flag fails every gVisor sandbox on the default policy, which is why this was not shipped unrun.

## Resolution (3.14.7)

**Ask 2.** `score_backend(KavachBackend.GVISOR, policy)` adds nothing for `seccomp_enabled`, so a gVisor sandbox scores
what its spec carries: under `policy_basic()` 75 where it read 80. The OCI backend, which applies the filter, still
takes the 5. `test_score_what_is_applied` holds both, and failed against 3.14.6. `docs/architecture/overview.md`'s
scoring row says so.

**Ask 1 is not done.** This machine still has no runsc, and at 3.14.2 downloading one to run here was refused as
external code. A wrong flag fails every gVisor sandbox on the default policy, so `--oci-seccomp` and `SCMP_ACT_KILL`
stay unshipped until they can be run. It is on the roadmap's Blocked list, with the SGX and TDX launchers, for the
same reason: a backend built against a tool never run would be a claim, not a fix. When it lands, the 5 comes back
with it.

