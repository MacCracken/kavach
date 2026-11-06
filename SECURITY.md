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
| 3.13.x (Cyrius) | **Yes — active.** Fixes land in the next 3.13.x release; nothing is backported. |
| < 3.13 (Cyrius) | No — upgrade to the latest 3.13.x. |
| 1.x, 2.x (Rust) | End-of-life; archived in git history. |

## Response

We aim to respond to security reports within **48 hours** and provide fixes
within **7 days** for CRITICAL issues, **30 days** for HIGH, and next minor
release for MEDIUM/LOW.

## Known deferred security items

Items tracked in [ADR-004](docs/adr/004-deferred-features.md) and
[ADR-005](docs/adr/005-v2-hardening-pass.md) with documented residual risk
and unblocking conditions:

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

- **v3.14.4:**
  - the OCI backend ran every container with no seccomp filter and without `no_new_privs`, on the
    path taken wherever runc or crun is installed, while `score_backend` scored the filter;
  - a payload exiting with `config_stdin` input unread killed the host process with SIGPIPE, unless
    the host had ignored it;
  - a payload could outlive `timeout_ms` for good, by writing while it read a large stdin, or by
    closing stdout and stderr and carrying on.

  Two gaps were found and not closed: a container keeps every capability but CAP_SYS_ADMIN, and
  `/proc` is neither masked nor read-only, which matters most when kavach runs as root; and gVisor
  applies no filter. See `docs/development/issues/` and CHANGELOG 3.14.4.
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
