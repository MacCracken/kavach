# ADR-004 — Deferred features and their unblocking conditions

**Status**: Accepted
**Date**: 2026-04-13
**Version**: v2.0.0

## Context

The Cyrius port could not land every v1.x Rust feature in one pass. Some
features depend on Cyrius language capabilities or stdlib modules that are
on the Cyrius roadmap but not yet shipped as of toolchain v4.0.0. Shipping
without a recorded deferred list would make it easy for future contributors
to either (a) think the gaps were oversights and fill them poorly, or (b)
not realise a feature was intentional and re-implement something already in
flight.

This ADR is the single source of truth for what's missing in v2.0 and what
unblocks each item.

## Deferred features

### 1. Async exec

**Rust shape**: `async fn exec(&self, ...) -> Result<ExecResult>`.
**Cyrius v2.0**: synchronous `fn <backend>_exec(sandbox, command) → ExecResult*`.

**Unblocking**: Cyrius async primitives are maturing (`lib/async.cyr`
exists). When the ecosystem converges on a stable async convention and
`sigil`/`patra`/`sakshi` go async, kavach follows.

**Mitigation today**: fork+exec+wait is synchronous from the caller's
perspective anyway — the Rust async was driven by tokio integration for
parallel sandbox pools, not by per-exec overlap. Throughput of a single
sandbox is not impacted.

### 2. 8 remaining backends (gVisor, Firecracker, OCI, WASM, SGX, SEV, TDX, SyAgnos)

**Rust shape**: 10 backends, each ~500-2000 LOC of IPC/config/attestation.

**Cyrius v2.0**: NOOP + PROCESS. Extension pattern (ADR-002) in place; each
backend is a self-contained file that calls `backend_register_exec/health/
destroy`. Dispatch table has slots for all 10.

**Unblocking**: per-backend; independent. Most gVisor/OCI logic is
shell-outs to `runsc`/`runc` and translates straightforwardly via
`exec_capture`. Firecracker needs vsock (needs `lib/net.cyr` unix-socket
support, present but under-tested). SGX/SEV/TDX need attestation report
parsing (needs `sigil` EAR helpers).

**Mitigation today**: `backend_is_available(b)` returns 0 for
unregistered backends; `resolve_best_backend()` skips them. Consumers
targeting Process get a working path; consumers targeting others get an
explicit `BACKEND_UNAVAILABLE` error.

### 3. Seccomp / Landlock / cgroups hooks

**Rust shape**: pre_exec callbacks that install seccomp BPF, apply
Landlock ruleset v4, set cgroup v2 limits — all async-signal-safe after
fork.

**Cyrius v2.0**: `process_exec` runs without these hooks. The runtime
guard precheck (`check_command`) provides a string-level blocklist, but
the kernel-level isolation is not yet applied.

**Unblocking**: Cyrius needs thin syscall wrappers for `prctl`,
`seccomp`, `landlock_*`, `setresuid`, `setrlimit`. These are thin — each
is a `syscall(N, ...)` wrapper — but they need to be async-signal-safe
(no `alloc`, no `tracing`) after fork.

**Mitigation today**: consumers requiring real isolation should run
kavach inside a pre-isolated environment (container/VM) until hooks land.
Strength score still reflects the policy, so scoring-based decisions are
correct; the kernel enforcement just isn't there yet.

### 4. HTTP credential proxy

**Rust shape**: listens on 127.0.0.1, intercepts sandbox HTTP/HTTPS,
injects `Authorization: Bearer ...` for allowlisted hosts, blocks others.

**Cyrius v2.0**: direct injection only (env, file, stdin). The
`credential.cyr` module handles the three direct methods.

**Unblocking**: Cyrius `lib/http.cyr` + `lib/tls.cyr` + `lib/net.cyr` are
all present but need CONNECT tunnelling support (HTTPS proxy requires
connecting to the origin on the sandbox's behalf). TLS termination for
inspection is explicitly out of scope.

**Mitigation today**: the direct-injection path covers the most common
agent patterns (OpenAI, Anthropic, Stripe, etc. — all support env-var
credentials). Host allowlisting via Landlock TCP port rules (ABI v4) is
available at the policy level.

### 5. OffenderTracker (repeat offender + time decay)

**Rust shape**: rolling 1h window, 0.5 decay factor, per-agent HashMap,
threshold triggers escalation.

**Cyrius v2.0**: `classify_threat(findings)` runs per-exec; assessment is
not persisted across execs. There's no per-agent history.

**Unblocking**: needs agent-keyed hashmap persistence + chrono + a prune
policy. `lib/hashmap.cyr` + `lib/chrono.cyr` are both present. Work is
mechanical; deferred to keep v2.0 scope focused.

**Mitigation today**: each exec is independently classified; audit chain
records every exec so external tooling can compute rolling scores from the
log.

### 6. Sandbox integrity monitoring

**Rust shape**: reads `/proc/1/cmdline`, `/proc/mounts`, `/proc/self/uid_map`
to verify namespace isolation.

**Cyrius v2.0**: not ported. `scanning_runtime.cyr` covers command + path
+ shell-metacharacter checks; the `/proc` readers are missing.

**Unblocking**: needs `file_read_to_string`-style helper in `lib/io.cyr`.
Present via `file_read_all` but the check logic needs porting.

**Mitigation today**: runtime guards still reject dangerous patterns
before fork; policy-level isolation still applies.

### 7. Full secret redaction on WARN verdict

**Rust shape**: `SecretsScanner::redact()` does a single-pass range merger
on all regex matches, replacing with `[REDACTED:CATEGORY]`.

**Cyrius v2.0**: gate treats WARN as pass-through. No in-place redaction.

**Unblocking**: needs a single-pass range-merge helper + cstr rebuild. No
external dependencies — just mechanical porting.

**Mitigation today**: WARN-severity findings (Low-severity patterns, email
address detection) pass through un-redacted. Anything High or Critical is
BLOCKed or QUARANTINEd, so true secrets don't leak.

### 8. UUID v4 for sandbox ID + audit entry ID + quarantine ID

**Rust shape**: `uuid::Uuid::new_v4()` everywhere.

**Cyrius v2.0**: monotonic counters (`_sandbox_next_id`,
`_finding_id_counter`, `QuarantineStorage.next_id`).

**Unblocking**: needs a random-bytes provider in Cyrius
(`/dev/urandom` reader or `getrandom` syscall). The syscall is trivial; the
port has not yet pulled it in.

**Mitigation today**: within a single process, counters are collision-free
and monotonic. Across processes, the audit chain's HMAC linkage prevents
forgery even if IDs collide — the trust boundary does not depend on UUIDs.

### 9. Full regex in secret/data matchers

**Rust shape**: PCRE-style patterns with character classes, lookahead,
case-insensitive flags.

**Cyrius v2.0**: hand-rolled literal-prefix + char-class matchers. Patterns
that rely on case-insensitive substring OR anchored word boundaries are
approximated; the most specific patterns (AWS key prefix, GitHub token
prefix, private-key PEM headers, SSN, connection-string schemes) match
identically.

**Unblocking**: Cyrius stdlib `lib/regex.cyr` is glob-only today. A PCRE
engine port is not on the immediate roadmap. Ad-hoc matchers will cover
most real-world needs.

**Mitigation today**: see `scanning_secrets.cyr` and `scanning_data.cyr`
inline comments — each lists which Rust patterns were ported verbatim and
which are TODO.

## Meta-rules

1. **Deferred ≠ silently missing**. Every gap has a code comment and is
   listed here.
2. **API surface stays clean**. No field should be shipped if its value is
   "always zero because not implemented yet."
3. **Test coverage stays honest**. Tests assert what the port does, not
   what the Rust version did. If a test would check for behavior that was
   deferred, it doesn't ship either.
4. **Rollouts are per-feature**, not per-module. Adding real seccomp support
   is a v2.1 unblock, not a v3.0 rewrite.
