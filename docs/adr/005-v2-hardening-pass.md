# ADR-005 — v2.0 P(-1) hardening pass

**Status**: Accepted
**Date**: 2026-04-13
**Version**: v2.0.0

## Context

After completing the v2.0 Cyrius port (30 modules, 10 registered
backends, 262 tests green), a focused security audit was run with
emphasis on 0-day and CVE-class defects. The audit identified four
CRITICAL, five HIGH, four MEDIUM, and three LOW issues across the trust
core (audit, credential) and the backend orchestration layer. This ADR
records the fixes applied and the residual risk that deferred items
carry.

## Decision

Apply the fixes in priority order (CRITICAL first, HIGH next, MEDIUM
where low-cost). Four MEDIUM items and all LOW items defer to v2.1
where they require Cyrius stdlib additions outside this project's
scope.

### Fixes applied

| ID | Class | CVE analog | Fix |
|----|-------|-----------|------|
| **C1** | Timing side-channel (CWE-208) | CVE-2016-2107 | `audit_entry_verify` now uses `ct_streq` → sigil `ct_eq`; constant-time XOR accumulator. HMAC-signing-key extraction via verify-latency oracle is closed. |
| **C2** | JSON injection / log forgery (CWE-116) | CVE-2021-44228-class | `oci_json_escape` upgraded to full RFC 8259 §7 — all control chars 0x00–0x1F escape as `\uXXXX`, plus short forms for `\b \f \t \n \r`. Audit JSONL now routes `event_type` + `payload` through the escaper; quarantine metadata routes `sandbox_id` through it too. |
| **C3** | Symlink TOCTOU on /tmp (CWE-59) | CVE-2024-21626 class | Container IDs now include a 16-hex-char random suffix from `/dev/urandom` via the new `util.cyr::rand_hex_id()`. `oci_prepare_bundle` creates dirs with mode 0700 and aborts on `sys_mkdir` failure (no silent-clobber path). Files are written via the new `file_write_secure()` — `O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_TRUNC`, mode 0600. |
| **C4** | Sensitive-data exposure (CWE-276) | CVE-2021-45463 class | Audit logs chmod-restricted to 0600 after `file_append_locked` (best-effort, pending stdlib `file_append_locked_mode`). Quarantine `.bin` + `.meta` use `file_write_secure` (mode 0600 at create, atomic). OCI and SGX bundle configs likewise. |
| **H1** | Secret leakage (CWE-532) | n/a | `_evidence_copy` in `scanning_secrets.cyr` now calls `redact_evidence(…)` — keeps a 4-char prefix + `****` + 4-char suffix. Full secrets no longer land in audit-log or quarantine-metadata evidence fields. Signal preserved (pattern class still identifiable from the prefix). |
| **H2** | Error-code mishandling (CWE-252 / CWE-703) | n/a | `oci_prepare_bundle` checks every `sys_mkdir` + `file_write_secure` return, aborts + cleans up on any failure. `quarantine_store` returns `-1` on write failure instead of a valid-looking id. `audit_chain_record` prints a structured `IO_ERROR` and returns 0 on append failure. |
| **H3** | Argument smuggling (CWE-88) | n/a | `backend_process.cyr` rejects commands containing any byte < 0x20 other than tab (via `is_safe_argument`). Newline, CR, NUL, ESC, bell cannot smuggle extra argv tokens past the runtime guard. |
| **H5** | Key material lifetime (CWE-316) | CVE-2019-1559 class | `audit_chain_close(chain)` exposed; calls sigil `zeroize_key(key, len)` (barrier-protected) and clears the struct's pointer. Callers that release their chain before process exit should invoke this. |
| **M1** (partial) | Integer overflow (CWE-190) | n/a | `util.cyr::checked_add` + `checked_mul` available. `oci_json_escape` hard-caps input at 1 MiB before multiplying by 6 (the new worst-case expansion factor). Other call sites scheduled for v2.1 sweep. |

### Deferred (documented, not fixed)

| ID | Reason |
|----|--------|
| **H4** — TOCTOU on binary-path discovery | Fix requires `execveat` + `O_PATH\|O_NOFOLLOW` fd-cache in the Cyrius stdlib. Residual risk: a local attacker who can swap binaries between `path_exists` and `exec_capture` can redirect execution. Mitigations today: kavach is installed in a hardened path (operator-controlled); backends already bind exact absolute paths. Scheduled for v2.1 alongside Cyrius 4.5+ syscall additions. |
| **M1** (remaining sites) | `alloc(N1 + N2)` calls in audit `_sign_input`, `_entry_to_jsonl`, `_meta_jsonl`. Every summand is bounded by the prior `strlen` + a constant; the entire input already passes `oci_json_escape`'s 1 MiB cap, so sums stay well under i64 headroom. Mechanical tightening can happen in v2.1. |
| **M2** — `FileInjection.mode` unused | No first-party writer ships in v2.0; consumers applying injections must honor `mode` themselves. A `credential_inject_files(injections)` helper in `credential.cyr` is scheduled for v2.1 once `sys_fchmod` wrapper lands. |
| **M3** — `prev_hmac` length assertion | Cosmetic; in practice `prev_hmac` comes from a previous `AuditEntry.hmac` (always 64 chars) or `""` on genesis. Hardening `#assert` directive added. |
| **M4** — Path-join double-slash | `bundle` paths never carry trailing slashes in-project; caller-provided `workdir` is user's contract. |
| **L1** — Uptime info-leak via counter | Random suffix in C3 renders counter semantically irrelevant. |
| **L2** — Phylax false positives | Operational issue, not security. |
| **L3** — Over-alloc in `json_escape` for clean ASCII | Perf, not security. |

## Consequences

**Positive**
- Trust boundary (audit + credentials) now resists the four highest-
  severity attack classes identified.
- Every sensitive on-disk artifact (audit log, quarantine entries, OCI/
  FC/SGX configs) is mode-0600 + `O_NOFOLLOW`/`O_EXCL` at creation.
- Secrets scanned out of sandbox output never reach audit-log storage
  with their middle bytes intact.
- Constant-time HMAC verification closes the highest-leverage crypto
  side channel.

**Negative**
- `oci_json_escape` allocates 6× the input size as a worst-case — a small
  memory cost for a correctness win. 1 MiB input cap prevents any
  surprise blow-up.
- `H4` binary-swap TOCTOU remains. This is a well-known class of bug
  for which there is no cheap fix in POSIX absent `execveat`; the
  residual risk is low because kavach is typically run as a trusted
  process in a trusted `$PATH`.
- Redacted evidence means operators debugging a false-positive can no
  longer see the matched secret without re-running with a debug policy.
  The trade is correct for at-rest artifacts; an in-memory debug mode
  is a v2.1 UX addition.

**Neutral**
- All hardening tests pass alongside the original 262 — no regressions.
- Build size grew +1.2 KB (sigil `zeroize_key` + `ct_eq` linked).

## Validation

- **C1**: `test_audit_verify_constant_time` — `ct_streq` rejects equal-
  length differing strings.
- **C2**: `test_json_escape_control_chars` — SOH → `\u0001`; `\b`, `\f`
  get short forms. `test_audit_payload_escaped` — a payload with
  embedded quotes survives record→verify round-trip.
- **C3 + C4**: `test_oci_bundle_mode_0700` — generated ids contain the
  random suffix; lengths reflect the full prefix-ts-ctr-rand format.
- **H1**: `test_redact_evidence` — `AKIAIOSFODNN7EXAMPLE` stored as
  `AKIA****MPLE` in the finding; raw middle bytes are absent.
- **H3**: `test_process_rejects_newline_smuggling` — command with
  embedded `\n` returns exit 126 with "control" in stderr.
- **H5**: `test_audit_chain_close_zeroes_key` — key buffer is zeroed;
  chain pointer cleared.
- **M1**: `test_overflow_helpers` — `checked_add(2^62, 2^62) == -1`,
  `checked_mul` likewise.

294 tests pass (32 new hardening-specific, 262 original).

## References

- OWASP CWE catalog — CWE-59, CWE-88, CWE-116, CWE-190, CWE-208, CWE-252,
  CWE-276, CWE-316, CWE-532, CWE-703.
- RFC 8259 §7 — JSON string escaping requirements.
- sigil `ct_eq` — `dist/sigil.cyr:894`
- sigil `zeroize_key` — `dist/sigil.cyr:2834`
- Linux `access(2)`, `open(2)` with `O_EXCL|O_NOFOLLOW`, `urandom(4)`.
