# Security Policy

## Reporting Vulnerabilities

Report security issues to: **security@agnosticos.org**

Do **not** open public issues for security vulnerabilities. Include in your
report:

- Affected component (backend name, scanner, audit chain, etc.)
- Reproduction steps
- Impact assessment (isolation escape, information disclosure, tampering, DoS)
- Your disclosure timeline preference

## Scope

Kavach is a sandbox execution framework — the trust boundary is the whole
point. Security-relevant areas:

- **Isolation integrity** — any path that lets sandboxed code escape its
  backend boundary (process, gVisor, Firecracker, SGX, SEV, TDX, etc.).
- **Attestation** — a quote that passes `kavach_attest_quote` without a valid
  chain to the policy's root, the policy's measurement, or the exec's nonce; a
  path that runs a payload under a policy requiring attestation without
  checking a quote.
- **Audit chain** — HMAC-SHA256 linked log tampering, verification bypass,
  key-extraction side channels.
- **Credential proxy** — secrets leaking from `CredentialProxy` to sandboxed
  processes, audit logs, or quarantine storage.
- **Scanner pipeline** — false negatives on the secrets/code/data scanners
  that lets a harmful artifact pass the gate with a PASS or WARN verdict.
- **Threat classification** — intent-score or offender-tracker logic that
  fails to escalate a malicious actor.
- **Backend dispatch** — function-pointer table tampering, TOCTOU between
  registration and invocation.
- **On-disk artifacts** — audit log, quarantine files, OCI/FC/SGX bundle
  configs: permission bits, symlink attacks, race conditions.

For the v3.0 hardening pass (P(-1)) findings already fixed + deferred items
with residual risk, see [ADR-005](docs/adr/005-v2-hardening-pass.md).

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.14.x (Cyrius) | **Yes — active.** Fixes land in the next 3.14.x release; nothing is backported. |
| < 3.14 (Cyrius) | No — upgrade to the latest 3.14.x. |
| 1.x, 2.x (Rust) | End-of-life; archived in git history. |

## Response

We aim to respond to security reports within **48 hours** and provide fixes
within **7 days** for CRITICAL issues, **30 days** for HIGH, and next minor
release for MEDIUM/LOW.

## Known deferred security items

Items tracked in [ADR-004](docs/adr/004-deferred-features.md) and
[ADR-005](docs/adr/005-v2-hardening-pass.md) with documented residual risk
and unblocking conditions:

- **A payload with no rootfs, as root, is on the host's files.** It holds what kavach holds. No capability set would
  bound it: `/proc/sys/kernel/core_pattern` and files root owns open to write with `CapEff` zero, because that access
  is uid 0's. A landlock rule is what bounds it (`policy_landlock_add`), and no preset names one.
- **A `/dev` a caller mounted in a process-path rootfs is the host's.** The process path has no device cgroup, so where
  a caller binds the host's `/dev` into a rootfs, a payload running as uid 0 opens the host's disks (measured:
  `/dev/nvme0n1`, read-only). Under runc the device rules refuse a node the spec does not list.
- **`/proc/<pid>/root` reaches a sibling sandbox.** A process-path payload has no PID namespace, so where a caller
  mounted a `/proc` in its rootfs, it reads files in the root of another sandbox's payload that holds no more than
  the same twelve capabilities (measured as root). The host's init and kavach's own process read EACCES.
- **`sandbox_spawn` reads no backend.** A sandbox configured for OCI forks without a runtime: it holds the default set,
  `pivot_root` and the `/proc` and `/sys` guard, with no PID namespace and no `/proc` of its own. Since v3.14.7
  `score_spawn` scores it as the process path it takes.
  All four are in `docs/development/issues/2026-11-06-process-backend-keeps-every-capability.md`, and pinned for 3.14.8.
- **HTTP credential proxy** — direct env/file/stdin injection and the
  loopback HTTP proxy (`GET /v1/secret/<name>`) ship; HTTPS `CONNECT`
  tunnelling is not implemented
- **Attestation limits** — kavach's own SGX and TDX launchers cannot fetch a
  quote and refuse a policy that requires attestation. The collateral is the
  caller's to fetch and keep current: kavach makes no network call, and refuses
  collateral past its `nextUpdate`. TDX quote format v5 is not parsed (sigil
  3.13.15 refuses it). Quote verification itself evaluates Intel's collateral
  and the TDX RTMRs since v3.14.2.

Resolved since earlier releases:

- **v3.14.7:**
  - where a caller had mounted a `/proc` or `/sys` in a process-path rootfs, a payload running as uid 0 opened
    `core_pattern`, `sysrq-trigger`, an IRQ affinity and a sysfs file to write, and through a `/proc` that was an rbind
    of the host's, binfmt_misc's `register`, whose handlers run for the host's execs. Both are now made what runc makes
    them, from the same lists the OCI spec writes, and CAP_SYS_ADMIN, which would lift them, is refused with no filter
    ([ADR-010](docs/adr/010-proc-and-sys-in-a-process-path-rootfs.md)). CHANGELOG 3.14.7.
  - `config_require_namespaces` was ignored under a policy asking for no seccomp and no landlock, so a payload promised
    a network namespace ran in kavach's. CHANGELOG 3.14.7.
- **v3.14.6:**
  - a payload with a rootfs on the process path, and every `sandbox_spawn` whatever the backend, held every capability
    and left its rootfs by `chroot`, as root and rootless, under `policy_basic()`. From there, as root, it could open
    `core_pattern` to write. A rootfs is now entered with `pivot_root` and the payload holds the OCI default set
    ([ADR-009](docs/adr/009-rootfs-on-the-process-path.md)). CHANGELOG 3.14.6.
- **v3.14.5:**
  - an OCI container kept every capability with no filter, and all but CAP_SYS_ADMIN with one, and `/proc` was
    neither masked nor read-only. Measured as root, a payload could open
    `/proc/sys/kernel/core_pattern` to write. Every spec now writes twelve capabilities and `runc spec`'s two
    path lists ([ADR-008](docs/adr/008-oci-capability-default.md)). CHANGELOG 3.14.5.
- **v3.14.4:**
  - the OCI backend ran every container with no seccomp filter and without `no_new_privs`, on the
    path taken wherever runc or crun is installed, while `score_backend` scored the filter;
  - a payload exiting with `config_stdin` input unread killed the host process with SIGPIPE, unless
    the host had ignored it;
  - a payload could outlive `timeout_ms` for good, by writing while it read a large stdin, or by
    closing stdout and stderr and carrying on.

  Two gaps were found and not closed at the time: the capabilities and `/proc`, closed in v3.14.5; and
  gVisor applies no filter, still open. See `docs/development/issues/` and CHANGELOG 3.14.4.
- **v3.14.2:**
  - a quote passed on its signatures alone: Intel's TCB level, the QE identity and
    the PCK/root CRLs were not evaluated, so a genuine platform with an out-of-date
    or revoked TCB passed. For TDX only MRTD (the firmware) was checked, not the
    RTMRs that measure the kernel and command line. Both now fail closed;
  - TDX verification could not parse a real Intel quote (sigil reads no type-6
    certification data), so it accepted only synthesized ones;
  - runsc's and docker's own error messages reached the externalization gate as
    the payload's stderr.

  See CHANGELOG 3.14.2.
- **v3.13.1:**
  - `policy_landlock_deny_all` on a policy that named paths left those rules in force, so the
    payload could open the paths deny-all was meant to deny;
  - the WASM backend read no landlock rule: a deny-all guest got its workdir, read-write, and a
    read-only rule was not held read-only;
  - a process payload given `config_stdin` read kavach's own stdin instead, and could consume
    whatever the host process had there.

  See CHANGELOG 3.13.1.
- **v3.13.0:** `kavach_attestation_result_new` allocated 48 bytes for a
  56-byte struct, so setting `details` overwrote the first word of the next
  allocation. See CHANGELOG 3.13.0.
- **v3.12.9:**
  - a stdin credential could be routed as an env var in a consumer
    (`InjectionMethod.STDIN` taken over by the stdlib's `STDIN`);
  - the exec filter's mount-API and `clone`/`clone3` bypasses;
  - a heap overflow in OCI spec generation;
  - host fds, the credential proxy's listener among them, inherited by persistent guests;
  - netlink audit controls reported as applied when the kernel refused them;
  - two symlink-following quarantine writes;
  - a stale flag that let `sandbox_exec` skip the externalization gate.

  See CHANGELOG 3.12.9.
- **Seccomp architecture check** (v3.12.8). The filter checks
  `seccomp_data.arch` and uses a table per architecture, so a denied call can
  no longer be made through another ABI: the i386 gate (`int 0x80`) or an x32
  call on x86-64. On aarch64 it now denies the right calls. See
  [ADR-007](docs/adr/007-syscall-numbers-across-architectures.md).
- The **H4** binary-path TOCTOU: exec by pinned fd (v3.12.7).
- Seccomp, Landlock and cgroups are enforced in the exec child (v3.9.0 onward).
