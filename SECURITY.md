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
| 2.1.x (Cyrius) | **Yes — active** |
| 2.0.x (Cyrius) | Security fixes only |
| 1.x (Rust) | End-of-life; archived in git history |

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

Resolved since earlier releases:

- **Seccomp architecture check** (v3.12.8). The filter checks
  `seccomp_data.arch` and uses a table per architecture, so a denied call can
  no longer be made through another ABI: the i386 gate (`int 0x80`) or an x32
  call on x86-64. On aarch64 it now denies the right calls. See
  [ADR-007](docs/adr/007-syscall-numbers-across-architectures.md).
- The **H4** binary-path TOCTOU: exec by pinned fd (v3.12.7).
- Seccomp, Landlock and cgroups are enforced in the exec child (v3.9.0 onward).
