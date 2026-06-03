# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.3.1] — 2026-06-02

Memory-safety + hardening patch from the post-3.3.0 source audit, plus the
first cc 6.0 stdlib adoptions. 394 tests pass (+10 regression cases); lint 0
warnings; vet 34 deps, 0 untrusted/missing. Benchmarks vs 3.3.0 are flat
within measurement noise (e.g. `ct_streq_64` 227→217ns, `audit_chain_record`
13→12µs) — the added bounds checks and clamps carry no measurable cost.

### Security
- **Heap overflow in every exec-capture backend (M1).** `exec_capture`
  (`lib/process.cyr`) fills until `total >= buflen` and can return exactly
  `out_cap`; the per-backend `store8(out_buf + n, 0)` then wrote a NUL one
  byte past `alloc(out_cap)` on attacker-influenced subprocess output. Fixed
  once in the new shared `backend_capture_finish` (see R1) by clamping `n`
  into `[0, out_cap - 1]` before the terminator. Affected all nine capture
  backends (process / gvisor / oci / wasm / sgx / sev / tdx / sy-agnos /
  firecracker).
- **Off-by-one in the three `/proc` integrity readers (M2).** `_integrity_check_{pid,mount,user}_ns`
  in `scanning_runtime.cyr` read the full buffer length then NUL-terminated at
  `buf + n` — OOB when the read filled the buffer. Now read `size - 1`,
  matching `cgroup_supported`.
- **Predictable `/tmp` workdir + symlink TOCTOU in SGX & Firecracker (SEC1).**
  `/tmp/kavach-{sgx,fc}-<epoch_secs>` was a guessable path written via plain
  `file_write_all`. Now uses an unpredictable `rand_hex_id()` name, mode-0700
  `mkdir` with abort-on-`EEXIST`, and `file_write_secure` (`O_EXCL|O_NOFOLLOW`)
  — matching the hardening already on the OCI/quarantine paths (ADR-005 §C3/§C4).
- **Out-of-range backend id → wild fn-pointer (SEC3).** `backend_dispatch_*`
  now route through a bounds-checked `_backend_fp(bid, offset)`; an id outside
  `[0, BACKEND_COUNT)` reads as unregistered instead of indexing
  `_backend_table[320]` out of bounds.
- **cgroup controller false-positive (SEC2).** `cgroup_supported` matched
  `"cpu"` as a substring of `cpuset`. New `_cgroup_has_controller` does a
  whole-token match over `cgroup.subtree_control`.
- **Overflow-checked stdin credential payload (M3).** `credential_proxy_stdin_payload`
  now accumulates lengths via `checked_add` and allocates via `alloc_checked`.

### Fixed
- **Data-scanner evidence pointed at the wrong bytes (P1).** The structural PII
  matchers emitted a single stand-in char (`"4"`/`"0"`/…) as the match pattern,
  so evidence extraction re-scanned the whole (up to 50 MiB) artifact and
  snipped around the first stray digit. New `code_emit_at` /
  `code_extract_evidence_at` take the known `(start, len)` directly — correct
  snippet, no per-finding re-scan.
- **OCI `pids` limit buffer under-allocation (C1).** `oci_generate_spec` sized
  the resources buffer as `alloc(64 + mem_len)`, ignoring `pids_len`; a large
  `max_pids` overflowed it. Now sized with `checked_sum4`/`alloc_checked` over
  both rendered ints.
- **`quarantine_store` / `quarantine_update_status` now null-check `_qpath`**
  before writing (C2).

### Changed
- **R1 — shared exec-backend epilogue.** Extracted `backend_error_result`,
  `backend_guard_result`, and `backend_capture_finish` into `backend.cyr`; all
  nine capture backends route through them. The ~40-line-per-backend duplication
  (which is why M1 lived in nine places at once) is gone, so the overflow fix
  and future changes land in one place.
- **Raw syscalls replaced with stdlib wrappers (S2/S3).** `path_exists` now uses
  `sys_access`; `kavach_err_print` and the `main.cyr` banner use `sys_write` —
  dropping bare `syscall(21,…)` / `syscall(1,…)` and their magic numbers.
- **`mono_now_ns` is now a thin alias over `chrono.clock_now_ns`** (S1) — it was
  a byte-for-byte duplicate of the stdlib monotonic clock; chrono was already a
  dep.

### Added
- **wasm backend resolves `$HOME/.cargo/bin/wasmtime` via stdlib `getenv`** —
  closes the long-standing `# no getenv yet` placeholder now that `getenv`
  ships in `lib/io.cyr`. Probed at config time only (getenv allocates and is
  not async-signal-safe).
- **10 regression assertions** (`tests/kavach.tcyr`): `backend_capture_finish`
  clamp on a full buffer, cgroup controller whole-token match, dispatch-id
  bounds, and position-based evidence extraction.
- **`benches/bench-history.csv`** row for `3.3.1`.

## [3.3.0] — 2026-06-02

Major toolchain + dependency jump to the Cyrius 6.0 line, plus the
release-benchmark discipline now baked into the dev loop. The first-party
tree has moved off the 5.10.x sigil-NI asm-offset bisect gate; validation
is now a clean `deps → build → lint → vet → test → bench` run on the
pinned toolchain. All 384 tests pass; lint is 0 warnings; vet reports 34
deps, 0 untrusted, 0 missing.

### Changed
- **Cyrius pin** — `cyrius.cyml` bumped `5.10.44` → `6.0.40`. `README.md`,
  `CLAUDE.md`, and the `docs/` set updated to match. The DO-NOT rule
  against bumping the pin now references the build/test/bench validation
  path instead of the retired 5.10.x asm-offset bisect. (Local `cycc` may
  sit a patch ahead at 6.0.41 — the manifest pins 6.0.40 and fmt writes
  are skipped locally to avoid minor-version drift against CI.)
- **sigil pin** — `2.9.0` → `3.5.9` (latest). The cc 5.10.x bisect that
  capped sigil at 2.9.0 (2.9.1 → 3.0.1 SIGILL on the ed25519-NI path,
  3.1.0 on aes-gcm-NI) no longer applies under cc 6.0.40 — the NI-path
  offsets are stable across the sigil 3.x line, validated by a clean
  build/test/bench at this pin.
- **`scripts/bench-history.sh`** — ported off the Rust-era
  `cargo bench --manifest-path Cargo.toml` (the stale `Cargo.toml` is
  long gone) to `cyrius bench tests/kavach.bcyr`. Parser rewritten for the
  `name: <avg><unit> avg (...)` format; unit→ns normalization moved from
  `bc` (not installed here) to `awk` so the `time_ns` column is correctly
  comparable across ns/us/ms rows. Seeds `benches/bench-history.csv` (new).

### Added
- **`[deps.agnosys]` transitive override (`1.3.0`)** — sigil 3.5.9 pins
  agnosys `1.2.7` (authored for cc 6.0.1), which fails to compile under
  cc 6.0.40 (the 6.0 line tightened slice-subscript codegen to require the
  `lib/slice.cyr` helpers). agnosys `1.3.0` (cc 6.0.24) is the latest and
  builds clean; override drops once sigil bumps its own agnosys pin
  upstream.
- **Stdlib modules `ct`, `json`, `keccak`, `slice`, `thread`** added to
  `[deps] stdlib`. The cc 6.0 stdlib absorbed constant-time compare into
  `ct.cyr` (which is why sigil retired its own `ct.cyr`), and the sigil
  3.5.9 dist transitively references `json`/`keccak`/`thread`; `slice`
  satisfies the new slice-subscript helper requirement.
- **`benches/bench-history.csv`** — first per-release benchmark baseline,
  labeled `3.3.0` (20 benchmarks). Selected medians at this cut:
  `state_valid_transition_check` 7ns, `cgroup_policy_has_limits` 10ns,
  `score_backend_process_strict` 37ns, `http_allowlist_hit` 74ns,
  `policy_strict_create` 100ns, `ct_streq_64` 227ns,
  `score_all_backends_strict` 365ns, `cgroup_wrap_argv` 545ns,
  `sandbox_full_lifecycle` 9µs, `audit_chain_record_to_tmpfs` 13µs,
  `credential_env_vars_100` 18µs. This is the reference row future
  releases diff against.

### Migration
- **sigil `ct_eq` retired → stdlib `ct_eq_bytes_lens`.** sigil removed
  `src/ct.cyr` and the public `ct_eq` / `ct_eq_32` symbols from
  `dist/sigil.cyr` in the 3.x line in favor of the cyrius stdlib
  `ct_eq_bytes_lens` (identical semantics, one identifier rename).
  `src/util.cyr::ct_streq` migrated accordingly — the audit-chain
  constant-time HMAC compare (ADR-005 §C1) is unchanged in behavior.
- **Renamed kavach helpers that newly collided with cc 6.0 stdlib / sigil
  symbols** (the cc 6.0 stdlib grew `str_contains`/`str_index_of`/`now_ns`
  and sigil's dist now exports `integrity_report_new`, all with
  signatures incompatible with kavach's same-named helpers):
  - `now_ns` → `mono_now_ns` (kavach's CLOCK_MONOTONIC timer; the stdlib
    `bench.cyr` now ships a CLOCK_MONOTONIC_RAW `now_ns`).
  - `str_contains` → `cstr_contains`, `str_index_of` → `cstr_index_of`
    (kavach's cstr-pointer substring helpers; the stdlib's are `Str`-typed
    and char-based — passing a cstr to the stdlib version SIGSEGVs).
  - `integrity_report_new` → `runtime_integrity_report_new` (kavach's
    runtime-scanner report, distinct from sigil's integrity type).
  These were applied across `src/` **and** `tests/kavach.tcyr`.
- **`backend_wasm.cyr`** — removed a dead `syscall(0 - 1, 0)` placeholder
  (unused `home`, flagged by cc 6.0's stricter syscall-arity check); the
  `$HOME/.cargo/bin` probe lands when stdlib `getenv` is available.

## [3.2.1] — 2026-05-11

Toolchain pin refresh — Cyrius 5.10.34 → 5.10.44 across the first-party
tree (majra / nein / agnosys / kavach), re-validated against the
sigil-NI asm-offset bisect. No source changes; CI fmt baseline now
runs at 5.10.44.

### Changed
- **Cyrius pin** — `cyrius.cyml` bumped from `5.10.34` to `5.10.44`.
  `README.md`, `CLAUDE.md`, and `docs/architecture/overview.md` updated
  to match. The DO-NOT rule against running `cyrius fmt` with a
  non-pinned local toolchain now references 5.10.44 as the in-tree
  baseline.

## [3.2.0] — 2026-05-10

Two new feature modules from the v3.2 Ready queue. Both are unblocked
at cc 5.10.34 + sigil 2.9.0 — no upstream wait. The third Ready
feature (Landlock hooks) deferred to v3.3.0 because it requires a
`sandbox_fork_exec(args, pre_exec_fn)` helper that's better built
jointly with future seccomp support; v3.3.0 will be the final cut of
this work arc.

### Added
- **`src/cgroup.cyr`** — cgroups v2 resource limits. Wires
  `SandboxPolicy.{memory_limit_mb, cpu_limit_tenths, max_pids}` into a
  per-sandbox cgroup at `/sys/fs/cgroup/kavach-<random_u64>/`. Writes
  `memory.max` (bytes), `cpu.max` (quota/period with 100ms period), and
  `pids.max` from the policy. Placement uses the shell-prepend pattern:
  user argv gets wrapped in `["sh", "-c", "echo $$ > <path>/cgroup.procs;
  exec \"$@\"", "--", <user argv>...]` so the shell writes its own PID
  into `cgroup.procs` and `exec "$@"` replaces the shell with the user
  command — same PID, same cgroup placement, **no shell re-interpretation
  of the user's argv** (variables and metachars in user args don't
  expand because they pass through `"$@"` positionally, not through
  `<command>` substitution). Graceful no-op when /sys/fs/cgroup isn't
  writable. Public surface: `cgroup_supported()`,
  `cgroup_policy_has_limits(policy)`, `cgroup_setup(policy) → path`,
  `cgroup_wrap_argv(path, user_argv) → wrapped_argv`,
  `cgroup_teardown(path)`. Wired into `backend_process.cyr::process_exec`;
  the OCI backend handles cgroup limits via the OCI runtime spec
  (future enhancement; current `oci_spec.cyr` minimal spec is unchanged
  in this cut).
- **`src/credential_http.cyr`** — closes ADR-004 §4. Sandhi-backed
  HTTP server on `127.0.0.1:<port>` (loopback only — never binds
  `INADDR_ANY`) that serves `GET /v1/secret/<name>` from the existing
  in-memory `CredentialProxy`. Per-instance allowlist gates which names
  this proxy serves; allowlist-miss returns 403 without consulting the
  proxy (no oracle for "does this name exist?"). Every served fetch +
  every 403/404 hits the audit chain when one is wired. Pairs with the
  v3.0 env/file/stdin injection methods — HTTP is the "no secret on
  disk" alternative. Public surface:
  `credential_http_proxy_new(proxy, allowed_vec, audit) → handle`,
  `credential_http_proxy_listen(http, port) → 0|-1`,
  `credential_http_proxy_serve_one(http)`,
  `credential_http_proxy_serve(http, max_requests)`,
  `credential_http_proxy_close(http)`.
- **`file_write_secure_modal` precedent reuse** — the cgroup module's
  `_cgroup_write_int` / `_cgroup_write_str` use plain `file_write_all`
  rather than the secure variant; cgroup files are owned by root and
  the kernel manages their attributes — the precautions
  `file_write_secure` adds (O_EXCL, O_NOFOLLOW, mode 0600) don't
  apply to /sys/fs/cgroup writes.
- **stdlib surface added** to `cyrius.cyml [deps] stdlib`:
  `dynlib`, `fdlopen`, `fs`, `hashmap_fast`, `mmap`, `net`, `result`,
  `sandhi`, `tls` — most are transitive pulls from sandhi's TLS / HTTP
  surface. `net` + `sandhi` are the direct dependencies of the HTTP
  credential proxy.
- **28 new tests** (358 → 386). Coverage:
  - cgroup: `policy_has_limits` shape, `wrap_argv` shape (argv layout +
    body content), `supported()` graceful return, `setup()` no-op when
    unsupported (the common CI environment).
  - credential_http: handle shape, allowlist hit/miss/empty, path
    extraction (valid / wrong-prefix / empty-suffix / nested-path
    rejected), listen+close lifecycle.
- **5 new benches** (15 → 20):
  - `cgroup_wrap_argv` — 498ns (alloc + vec_push of 4 strings)
  - `cgroup_policy_has_limits` — 9ns (3 field reads + compares)
  - `http_path_extract` — 111ns (prefix check + traversal check + alloc)
  - `http_allowlist_hit` — 69ns (linear scan + streq)
  - `http_allowlist_miss` — 81ns (linear scan, no early termination)

### Changed
- **`src/backend_process.cyr::process_exec`** — when the sandbox's
  policy has any cgroup-controlled limit set, the user argv is wrapped
  via `cgroup_wrap_argv()` before being passed to `exec_capture()`.
  The wrap is conditional — sandboxes with no resource limits avoid
  the `sh` dependency entirely. Cgroup teardown via `cgroup_teardown()`
  runs unconditionally after exec (no-op when no setup happened).
  Runtime guard check runs against the *original* command (not the
  wrapped one), so the sh-prepend doesn't bypass argument-smuggling
  detection.
- **`src/main.cyr`** banner string `v3.0.0` → `v3.2.0` (the v3.1.x
  patches didn't touch the banner; this cut brings it current).
- **CI **lint gate** stays hard-fail** (set in v3.1.1); the two new
  modules + bench-file edits ship lint-clean against cc 5.10.34.

### Internal — known upstream gap
- **sandhi 1.3.3 hashmap_ vs map_ naming inconsistency.** sandhi's
  TLS session cache references `hashmap_new_a` / `hashmap_get` /
  `hashmap_set_a` / `hashmap_len` while the stdlib `hashmap` module
  exports the same shape under `map_*` names. The HTTP credential
  proxy is loopback-only and never reaches sandhi's TLS code, but the
  linker still resolves the symbols. Worked around with 4-line shim
  wrappers in `credential_http.cyr` that route `hashmap_*` → `map_*`.
  Tracked: needs an upstream sandhi filing — fold the shims back to
  bare imports when sandhi resolves the naming.

### Race-tolerance note for cgroups v2
Per the 3.1.2 scoping discussion: cgroups v2 placement is done via
the shell-prepend pattern, which introduces a small bounded window
between `fork()` and the shell writing its own PID to `cgroup.procs`
in the new process. During that window the process is NOT in the
target cgroup; its scheduling / accounting falls under whatever
cgroup `kavach` itself sits in (typically the agnos service slice,
fine). Functional impact: resource accounting from the first ~few
syscalls of `sh` startup is attributed to kavach's parent cgroup,
not the sandbox's. This is the standard race-tolerant model used by
container runtimes that don't have a custom fork+pre_exec helper
available. v3.3.0 + the `sandbox_fork_exec` helper will close this
window for the configurations that need exact accounting from the
first instruction; today's pattern is correct for the 99% case
where cgroup limits exist to constrain steady-state, not to bound
microsecond-scale startup costs.

### Deferred to v3.3.0 (final cut of this work arc)
- **Landlock hooks** — needs the `sandbox_fork_exec(args, pre_exec_fn)`
  helper to install the ruleset post-fork in the child.
- **`sandbox_fork_exec` helper itself** — same infrastructure that
  future seccomp (waiting on the upstream cyrius `sys_prctl` /
  `sys_seccomp` wrappers) will slot into.
- **OCI backend cgroup integration** — populate the `resources` section
  of the OCI runtime spec so `runc` / `crun` set up cgroups directly.
  Independent of the fork-infra; deferred only to keep this cut tight.

### Still deferred (unchanged)
- **`cyrius fmt` drift** across 7 src/ files + 2 tests/ files. Local
  cyrius is 5.10.44; pin is 5.10.34. Awaiting 5.10.34 toolchain to
  clear safely. CI fmt step remains `::warning::` informational.

## [3.1.2] — 2026-05-10

Closes out the 3.1.x arc by filing the v3.2 Blocked-queue items
upstream as P1 issues in the projects that own them. No source /
behavior changes in kavach; this is documentation work that
externalises kavach's wait-list so upstream maintainers can plan.

The three v3.2 "Ready" feature items that the cc-5.10.34 verify pass
unblocked (Landlock hooks, cgroups v2, HTTP credential proxy) are
**deliberately deferred to 3.2.0** — each is a new module plus
post-fork wiring, which is minor-sized work, not patch-sized.

### Added (upstream filings)
- **[`cyrius/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md)**
  — single coordinated filing covering the six sandbox-runtime
  syscall wrappers kavach v3.2 features will use: `sys_prctl`
  (157), `sys_seccomp` (317), `sys_setresuid` (117),
  `sys_setresgid` (119), `sys_execveat` (322), `sys_fchmod`
  (91). Per-wrapper detail: numbers (x86_64 + aarch64), the
  kavach feature it gates, the async-signal-safe post-fork
  context, the workaround-via-raw-syscall pattern (kavach 3.1.1
  ships `SYS_FCHMOD` this way as the precedent), and a
  suggested landing order. Filed P1 with explicit "severity
  rationale" letting an upstream maintainer re-rate to P2 if
  scheduling pressure is elsewhere (workaround exists in-tree).
- **[`sigil/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md`](https://github.com/MacCracken/sigil/blob/main/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md)**
  — single coordinated filing covering the TEE attestation +
  sealing surface for kavach's SGX / SEV-SNP / TDX backends.
  Calls out: SGX quote parser + IAS/DCAP cert chain; SEV-SNP
  guest attestation parser (VCEK chain); TDX TD-quote parser;
  SGX sealing (key derivation against MRSIGNER + ISVSVN).
  Notes which crypto primitives sigil 2.9.0 already ships
  (sha256 / hmac / ct / hkdf / ed25519 / verify) and what's
  missing (ECDSA P-256, minimal X.509 cert-chain primitives,
  quote-format parsers). Suggested placement: sigil 3.2-or-later
  (sigil 3.1 alloc-free verify rewrite shouldn't be displaced).
  Filed P1 with explicit "severity rationale" letting an upstream
  maintainer re-rate to P3 (enhancement; kavach ships fine
  today without quote verify — the backends start the runtime
  but don't attest its identity).
- **Stiva OCI backend** — no upstream filing. There's no stiva
  Cyrius port repo today; the blocker resolves when one ships,
  and will be revisited then.

### Changed
- **`docs/development/roadmap.md` § v3.2 Blocked rows** — each
  blocker row now cross-links to its upstream filing under the
  "Who owns it" line. SGX / SEV / TDX rows merged into a single
  unified row (they share the upstream filing). Meta block updated
  with a summary of the upstream-filing work landed in this patch.

### Deferred to 3.2.0 (deliberately)
The three v3.2-Ready feature items unblocked at cc 5.10.34 are
**not** in this patch — each is new-module work that belongs in a
minor cut, not a patch:
- **Landlock hooks** — new `src/landlock.cyr` + post-fork hooks in
  `backend_process` / `backend_oci`.
- **cgroups v2 resource limits** — new `src/cgroup.cyr` + pre-exec
  hook in `sandbox_exec.cyr`.
- **HTTP credential proxy** — new `src/credential_http.cyr` using
  sandhi + tls from stdlib.

### Still deferred (unchanged from 3.1.1)
- **`cyrius fmt` drift** across `src/{audit,backend_sy_agnos,composite,credential,quarantine,scanning_gate,scanning_secrets}.cyr`
  + `tests/kavach.{tcyr,bcyr}`. Local toolchain is 5.10.44; pin is
  5.10.34. Awaiting a 5.10.34-toolchain install to clear safely.

## [3.1.1] — 2026-05-10

Post-3.1.0 patch cut. Drains the doc-sweep queue the v3.1.0
`doc-health.md` left open, plus three concrete v3.2-Ready items:
lint clean, `FileInjection.mode` honoring helper, and the
`rust-old/` removal. Also a verify-pass against cc 5.10.34
that reclassifies three "Blocked" items as Ready and rewrites
the v3.2 Blocked table with full per-item context. No
behavior changes to the sandbox runtime, scanners, audit
chain, or threat classifier.

### Added
- **`credential_inject_files(injections)`** in
  [`src/credential.cyr`](src/credential.cyr) — closes
  [ADR-005](docs/adr/005-v2-hardening-pass.md) §M2. Iterates the
  FileInjection vec, writes each via the new
  `file_write_secure_modal(path, buf, len, mode)` helper, returns
  the count of successful writes (or `-(n+1)` on first failure).
- **`file_write_secure_modal(path, buf, len, mode)`** in
  [`src/util.cyr`](src/util.cyr) — variant of `file_write_secure`
  that holds the fd across an fchmod-to-caller-mode before close.
  Closes the TOCTOU window between write and chmod that
  `file_write_secure` + post-close `sys_chmod` would re-open.
  Raw `syscall(91, fd, mode, 0)` since stdlib has no
  `sys_fchmod` wrapper at cc 5.10.34 — folded back to a wrapper
  when upstream ships one. SAFETY-commented per the raw-syscall
  convention.
- **5 new tests** in `tests/kavach.tcyr` covering
  `credential_inject_files`: empty vec, single file with mode
  honoring, two-file batch, O_EXCL refuses preexisting target,
  failure return-code shape (`-(written + 1)`). Test count:
  349 → 358.

### Changed
- **`cyrius lint` clean across `src/`** — 37 long-line warnings
  (inherited from the v3.0 cut, chiefly in the scanner pattern
  lists) cleared by rewrapping call sites. Affected files:
  `scanning_code.cyr` (16 `code_emit` call sites rewrapped to
  two-line form, plus all sibling sites in the same module for
  style consistency); `scanning_data.cyr` (16 `_dg_emit` sites,
  same treatment); `backend_sgx.cyr` (3 long string literals
  split into `p1a`/`p1b`, `p2a`/`p2b`, `p3a`-`p3f` with adjacent
  `memcpy` calls — same bytes emitted, smaller per-line
  surface); `oci_spec.cyr` (1 string-literal split via `mid1a` /
  `mid1b`); `scanning_runtime.cyr` (1 multi-arg `vec_push` call
  rewrapped). No semantic change. CI lint gate flipped from
  `::warning::` informational to hard-fail.
- **CHANGELOG `[Unreleased]` block from 3.1.0 → `[3.1.1]`** —
  the post-cut doc sweep (README, CLAUDE.md, getting-started,
  rust-old-removal) is now dated. See the rolled-in detail below.
- **`docs/development/roadmap.md` § v3.2** — rewritten. Three
  items reclassified out of "Blocked — awaiting upstream" after
  a cc-5.10.34 verify pass:
  - **Landlock hooks** — `sys_landlock_create_ruleset`,
    `sys_landlock_add_rule`, `sys_landlock_restrict_self` ship
    in stdlib (`syscalls_x86_64_linux.cyr` L614-630 + aarch64
    peer). Moved to Ready.
  - **HTTP credential proxy** — `sandhi` (HTTP server/client),
    `tls`, `net` all ship in stdlib at 5.10.34. Moved to Ready.
  - **cgroups v2** — never actually needed a stdlib wrapper;
    `/sys/fs/cgroup/<scope>/{memory.max,cpu.max,pids.max}`
    writes work via plain `fs.cyr`. Mis-classified in v3.0;
    moved to Ready.

  Remaining "Blocked — actually awaiting upstream" rows each
  carry **what it means** (concrete kavach-side surface that
  gates on the missing piece), **who owns the upstream work**,
  and **trigger condition** (what has to ship): seccomp hooks,
  Firecracker jailer/vsock/snapshot, H4 binary-path TOCTOU
  (residual from ADR-005 §H4), SGX attestation + sealing,
  SEV/TDX attestation, Stiva OCI backend.

### Removed
- **`rust-old/` tree** (1.4 MB, 25,935 lines of Rust). Parity
  audit re-verified 2026-05-10 — every public Rust API has a
  Cyrius equivalent per
  [`docs/development/rust-old-removal.md`](docs/development/rust-old-removal.md).
  Heritage `# Ported from rust-old/src/...` header comments
  in `src/` preserved as breadcrumbs to git history; the source
  tree itself is reachable via git history pre-3.1.1. Suggest
  tagging `kavach-pre-rust-removal` at the parent commit for
  easy rollback / archaeology. `.gitignore` `rust-old/target/`
  line dropped (parent directory no longer exists).

### Doc sweep (rolled in from the pre-3.1.1 [Unreleased] block)
- **`README.md`** — Cyrius floor bumped to 5.10.34 with the
  pin-lock rationale (sigil-NI asm-offset bisect); `cyrius
  deps` step added to the build instructions; `cyrius.toml`
  → `cyrius.cyml`; v3.0 status block split into v3.1
  modernization arc + v3.0 port summary; dep list updated
  against `[deps] stdlib` + sigil 2.9.0; `doc-health.md`
  cross-link added.
- **`CLAUDE.md`** — Rust-era `MSRV: 1.89` line dropped;
  Version bumped to v3.1.0 (now → v3.1.1); new `Language:
  Cyrius (pinned at 5.10.34 …)` line carrying the pin-lock
  rationale. Cleanliness Check lines swapped from `cargo *`
  → `cyrius *`. Key Principles translated from Rust-attribute
  idioms to Cyrius-shaped equivalents. DO-NOT list rewritten
  with the pin-bump prohibition + `cyrius fmt` on
  non-pinned-toolchain prohibition + `lib/`/`build/`
  gitignore reminders. `Cargo.lock` reference dropped.
- **`docs/guides/getting-started.md`** — § 1 "Build +
  install" rewritten: `cyrius deps` step added; toolchain
  line bumped to 5.10.34; dep list aligned to `[deps]
  stdlib`; sigil pin updated 2.1.2 → 2.9.0; `lib/`
  gitignored model documented.
- **`docs/development/rust-old-removal.md`** — sed recipe
  `cyrius.toml` → `cyrius.cyml`; commit message bumped v3.0
  → v3.x; pre-removal checklist gains the
  cyrius.cyml-migration-prereq row.
- **`docs/doc-health.md`** — bucket counts walked after the
  sweep: Fresh 5 → 9, Stale 3 → 1, Read-through 2 → 0.
  Per-row Last touched / Status / Notes refreshed.

### Still queued (carried into v3.2 backlog)
- **`cyrius fmt` drift** across `src/{audit,backend_sy_agnos,composite,credential,quarantine,scanning_gate,scanning_secrets}.cyr`
  + `tests/kavach.{tcyr,bcyr}`. (Shorter list than v3.1.0
  documented — the lint-cleanup pass incidentally restyled
  `scanning_code.cyr` and `scanning_data.cyr`.) Needs a clean
  run against the cc 5.10.34 toolchain; CI fmt step remains
  `::warning::` informational until cleared.

## [3.1.0] — 2026-05-10

**Modernization arc.** Brings the kavach build / dependency / CI / release
surface into line with majra and nein. No behavior changes to the sandbox
runtime; the v3.0.0 surface (10 backends, 3-scanner pipeline, HMAC audit
chain, threat classifier, hardening pass) is unchanged. The previously
queued "v3.1 — unblocking queue" backlog has cascaded to v3.2 — see
[`docs/development/roadmap.md`](docs/development/roadmap.md) for the
new shape.

### Changed
- **Cyrius toolchain pin: 4.5.0 → 5.10.34.** Same floor as majra / nein /
  agnosys post-M6. Picks up the cc5 type-check default-on surface
  (cstring / Str annotations) and the arch-peer include resolution
  under `~/.cyrius/versions/<V>/lib`.
- **Manifest format: `cyrius.toml` → `cyrius.cyml`.** Mirrors the majra
  shape: `version = "${file:VERSION}"` so the `VERSION` file is the
  single source of truth; `[deps] stdlib = [...]` lists the union of
  stdlib modules included across src/, tests/, and fuzz/;
  `[deps.sigil]` switched from path/absolute-path workaround to
  `git = "https://github.com/MacCracken/sigil.git"` + `tag = "2.9.0"`.
- **`lib/` is no longer committed.** Added `/lib/` to `.gitignore`.
  `cyrius deps` is now the source of truth — it populates `lib/` from
  the cc 5.10.34 stdlib snapshot plus the `[deps.sigil]` git tag.
  Mirrors majra / nein post-M6.
- **`.cyrius-toolchain` removed.** The cyrius pin lives in
  `cyrius.cyml`'s `cyrius = "5.10.34"` field — single source of truth.
  CI installers read the pin via a grep on `cyrius.cyml` (same
  pattern as majra / nein).
- **sigil pin: 2.1.2 → 2.9.0.** Same gate the rest of the first-party
  tree is on. 2.9.1 through 3.0.1 SIGILL on the ed25519-NI path under
  cc5 5.10.x; 3.1.0 also breaks aes-gcm-NI. Bump only when sigil
  ships an asm-offset-stable release (tracked upstream).
- **VERSION: 3.0.0 → 3.1.0.**

### Added
- **CI rewrite** (`.github/workflows/ci.yml`). Version-pinned toolchain
  installer (`~/.cyrius/versions/<V>/{bin,lib}` + `~/.cyrius/{bin,lib}`
  symlinks), source-archive fetch for the stdlib snapshot (release
  tarball ships `bin/` + `deps/` only under 5.10.x), `cyrius deps` +
  lockfile hash verification, `cyrius fmt / lint / vet` gates,
  build / smoke / test / bench / fuzz pipeline, security scan
  (raw-execve allowlist + `/etc` writes guard), docs presence +
  version-consistency + CHANGELOG-date currency gates. Pattern lifted
  from majra / nein / agnosys.
- **Release rewrite** (`.github/workflows/release.yml`). Same installer
  + deps flow, version verify (semver shape + VERSION-vs-tag match +
  `${file:VERSION}` literal check on `cyrius.cyml`), binary +
  source-archive assets, SHA256SUMS, dated CHANGELOG body
  extraction for the release notes. Accepts both `v3.1.0` and
  `3.1.0` tag styles.
- **`docs/doc-health.md`** — initial doc-currency ledger, modeled on
  majra's. Buckets the ~22-file surface into fresh / stale /
  read-through / evergreen / frozen, queues the 3 stale rows
  (`README.md`, `CLAUDE.md`, `benchmarks-rust-v-cyrius.md`) and 2
  read-through rows (`docs/guides/getting-started.md`,
  `docs/development/rust-old-removal.md`) for the 3.1.x follow-up.

### Removed
- **`cyrius.toml`** — replaced by `cyrius.cyml`.
- **`.cyrius-toolchain`** — cyrius pin moved into `cyrius.cyml`.
- **`cyrius.lock`** — will be regenerated by the first `cyrius deps`
  run under the new manifest; stale lockfile from the v3.0 toolchain
  deleted.
- **`lib/` (working tree, 27 vendored stdlib + sigil modules)** —
  resolved by `cyrius deps` from now on. Gitignored.

### Notes for consumers
- SY / stiva / kiran / AgnosAI / hoosh / bote / aethersafta: kavach is
  binary-only at the moment, so consumers don't pull a manifest
  reference. If a consumer starts embedding kavach modules at the
  source level (similar to how majra is consumed), a `[lib]` profile
  and `dist/kavach.cyr` bundle will land in a 3.1.x patch.

## [3.0.0] — 2026-04-13

Complete language migration — **Rust → Cyrius**. First release of kavach in
Cyrius; supersedes the Rust v2.0.0 line. Major version bump reflects the
language/ABI change and the intentional API refinements (async → sync,
monotonic IDs → UUID-v4-equivalent random, field consolidations). 25,935
lines of Rust → 33 Cyrius modules, ~7K lines. See
[ADR-001](docs/adr/001-cyrius-port-architecture.md) for the port rationale.

The v3.0.0 release bundles three internal waves of work:

1. **Port skeleton** — all 10 backends, scanner pipeline, threat classifier,
   lifecycle FSM, credential proxy, audit chain, quarantine storage.
2. **P(-1) hardening pass** — see [ADR-005](docs/adr/005-v2-hardening-pass.md).
   9 CWE-class findings fixed in-tree (CWE-208, CWE-116, CWE-59, CWE-276,
   CWE-532, CWE-88, CWE-316, CWE-190, CWE-252).
3. **Feature closeout** — UUID v4 IDs, WARN-verdict redaction, OffenderTracker,
   integrity monitoring, composite backend, observability + attestation types.

### Added (gap-close wave)
- **CompositeBackend port** (`src/composite.cyr`) — `merge_policies(base, overlay)` with stricter-wins semantics, `score_composite(outer, inner, policy)` returning the layered score with +5 defense-in-depth bonus, and `composite_exec(...)` for executing through an outer backend with a merged inner policy.
- **Observability types** (`src/observability.cyr`) — `HealthStatus`, `HealthState` enum, `health_probe(sandbox)`, `SandboxMetrics` struct (CPU/memory/PID/IO/wall fields; cgroup-backed populator pending), `sandbox_metrics_from_result`, `SpawnedProcess` handle for fire-and-forget execs.
- **Attestation types** (`src/attestation.cyr`) — `AttestationResult` + `AttestationTrust` enum (Contraindicated < Warning < None < Affirming), `attestation_is_acceptable(result, min_trust)`, `SgxAttestationReport` with `sgx_report_verify_structure` (MRENCLAVE/MRSIGNER hex + IAS signature length check; full cryptographic verify deferred to v3.0 sigil EAR helpers).
- **33 Cyrius modules total** — added composite.cyr + observability.cyr + attestation.cyr.

### Documentation
- **Benchmarks — Rust v2.0 vs Cyrius v3.0** (`benchmarks-rust-v-cyrius.md`) — apples-to-apples per-op comparison with honest commentary on where Cyrius is slower (unoptimized codegen tax) and where it's faster (no tokio startup on sandbox lifecycle).
- **Guides** (`docs/guides/`): getting-started (build → configure → execute), composite-backends (defense-in-depth merge rules), threat-tracking (intent scoring + OffenderTracker + decay tuning).
- **Worked examples** (`docs/examples/`): 4 progressive walkthroughs covering Noop, Process+audit, scanner verdicts with WARN redaction, offender tracking across execs.
- **rust-old removal readiness** (`docs/development/rust-old-removal.md`) — per-symbol audit confirming Cyrius coverage, pre-removal checklist, removal command.
- **Benchmark harness** (`tests/kavach.bcyr`) — 15 benches via `lib/bench.cyr` covering scoring, policy build, credentials, scanners, gate, lifecycle, audit.
- **349 tests** (was 326) — 23 new tests for composite merge + score, health probe, metrics, attestation trust ordering, SGX report structure.

### Feature closeout wave

Drains 5 of the 7 "ready" items from the internal roadmap; leaves
`FileInjection.mode` helper and `cyrius audit` for a future release.

- **UUID v4 IDs** — Sandbox, ScanFinding, and Quarantine entry ids are now 64-bit random values from `/dev/urandom` via new `util.cyr::rand_u64`. Monotonic counters removed. Collision probability across 2^32 entries is ~2^-32.
- **Secret redaction on WARN verdict** — `secrets_redact(text)` walks the text once, rewrites every secret-pattern span to `[REDACTED:CATEGORY]`, returns the cleaned cstr. `gate_apply` now invokes it on `stdout`/`stderr` when the verdict is WARN and `policy.redact_secrets == 1`.
- **OffenderTracker** — `offender_tracker_new/with_config/record/prune/agent_score/should_escalate/count`. Per-agent violation score accumulates with integer-only half-life decay (score × decay_factor^(age / half_window)). Defaults match the Rust original: 1h window, decay 0.5 per half-window, escalation threshold 3.0.
- **Sandbox integrity monitoring** — `check_integrity()` returns an `IntegrityReport{intact, checks[3], checked_at}` verifying PID namespace (`/proc/1/cmdline` not systemd/init), mount namespace (`/proc/mounts` no host `/home` without overlay), and user namespace (`/proc/self/uid_map` populated).
- **Integer-overflow guards completed (M1 closeout)** — new `checked_sum4` + `alloc_checked` wired through audit `_sign_input`/`_entry_to_jsonl`, quarantine `_qpath`/`_meta_jsonl`, and `oci_generate_spec`. Every multi-term allocation refuses negative sizes or anything over 64 MiB per single allocation.

### Changed
- **`QuarantineStorage.next_id` field retained for ABI** but no longer incremented. Entry IDs come from `rand_u64()` per `quarantine_store()` call.
- **349 tests passing, 0 failing**.
- **33 Cyrius modules**.

### Security
- **P(-1) hardening pass completed** — see [ADR-005](docs/adr/005-v2-hardening-pass.md). Fixes applied, with CWE/CVE analogs:
  - **Constant-time HMAC verification** (CWE-208, CVE-2016-2107 class) — `audit_entry_verify` now uses sigil `ct_eq` via new `util.cyr::ct_streq`. HMAC-signing-key extraction via verify-latency oracle is closed.
  - **Full RFC 8259 JSON escape** (CWE-116, CVE-2021-44228 class) — `oci_json_escape` now escapes all control chars 0x00–0x1F as `\uXXXX` with short forms for `\b\f\t\n\r`. Audit JSONL routes `event_type` + `payload` through it; quarantine metadata escapes `sandbox_id`. Log forgery via control chars in user-controlled strings is closed.
  - **Symlink TOCTOU on /tmp** (CWE-59, CVE-2024-21626 class) — container IDs include 16 random hex chars from `/dev/urandom`. `oci_prepare_bundle` uses mode 0700 + checks `sys_mkdir` returns; files via new `file_write_secure()` with `O_CREAT|O_EXCL|O_NOFOLLOW`. Symlink-preseed redirection of config writes is closed.
  - **Sensitive artifacts mode 0600** (CWE-276) — audit log + quarantine `.bin`/`.meta` + OCI/FC/SGX configs now created with mode 0600 (not stdlib default 0644). Audit log additionally `sys_chmod`-tightened after `file_append_locked`.
  - **Secret evidence redaction** (CWE-532) — `_evidence_copy` in scanner now keeps first 4 + `****` + last 4; full secrets never land in findings, audit logs, or quarantine files. Prefix preserves signal (`AKIA****…`) without leaking the secret.
  - **Argument smuggling via control chars** (CWE-88) — `backend_process.cyr::process_exec` rejects commands with any byte < 0x20 except tab. Newline-smuggled second tokens past the runtime guard are closed.
  - **HMAC key lifetime** (CWE-316, CVE-2019-1559 class) — new `audit_chain_close(chain)` calls sigil `zeroize_key` on the key buffer and clears the chain's pointer.
  - **Integer overflow guards** (CWE-190, partial) — new `util.cyr::checked_add` + `checked_mul`. `oci_json_escape` caps input at 1 MiB before the ×6 expansion.
- **32 new hardening-specific tests** added to `tests/kavach.tcyr` (constant-time comparator, JSON control-char escape, argument-smuggling rejection, overflow guards, redacted evidence, key zeroing).

### Added
- **All 10 backends registered** — Noop, Process, gVisor, OCI, WASM, SyAgnos, SGX, SEV, TDX, Firecracker. Dispatch table fully populated; ADR-002's extension pattern is fully demonstrated.
- **SyAgnos backend** (`src/backend_sy_agnos.cyr`) — docker/podman shell-out against the hardened AGNOS container image (`ghcr.io/maccracken/agnos:latest`), with Phylax scanner extending the secrets scanner to detect verity violations, nftables bypass, namespace escape, and mount-escape attempts.
- **SGX backend** (`src/backend_sgx.cyr`) — `gramine-sgx` with an auto-generated Gramine manifest. Requires `/dev/sgx_enclave`.
- **SEV backend** (`src/backend_sev.cyr`) — `qemu-system-x86_64` with SEV-SNP confidential-guest object. Requires `/dev/sev`.
- **TDX backend** (`src/backend_tdx.cyr`) — `qemu-system-x86_64` with tdx-guest object. Requires `/dev/tdx_guest`.
- **Firecracker backend** (`src/backend_firecracker.cyr`) — minimal microVM config.json + `firecracker --no-api --config-file`. Jailer/vsock/snapshot deferred.
- **WASM backend** (`src/backend_wasm.cyr`) — `wasmtime run` shell-out with fuel-based CPU metering (`--fuel`), memory limit (`--max-memory-size`), and directory preopens (`--dir`). Takes a `.wasm` file path as the command. Registers into the dispatch table.
- **OCI backend** (`src/backend_oci.cyr`) — `runc`/`crun` shell-out against the shared OCI bundle. Picks first available runtime from PATH. Same dispatch registration pattern as gVisor.
- **Shared OCI spec module** (`src/oci_spec.cyr`) — extracted from the gVisor backend: container-id generation, JSON escape, minimal runtime spec v1.0.2, bundle mkdir, and cleanup (unlink config.json, rmdir rootfs/, rmdir bundle/). Both gVisor and OCI backends call into this.
- **Bundle cleanup on exit** — `oci_cleanup_bundle(bundle)` called after every exec regardless of outcome. Prevents `/tmp/kavach-gvisor-*` and `/tmp/kavach-oci-*` accumulation.
- **gVisor backend** (`src/backend_gvisor.cyr`) — OCI bundle generation + `runsc run` + auto-cleanup. Registers into the dispatch table via `backend_gvisor_register()`. Proves ADR-002's "3-line extension" pattern: same dispatch slot layout, different `exec_fn`.
- **`path_exists` + `which_exists`** — real implementations via `access(2)` syscall. Enables meaningful `backend_is_available()` probes and `resolve_best_backend()` ranking.

### Fixed
- **`cyrius.toml` sigil path** — switched from `path = "../sigil"` to
  absolute path to work around a `cyrius deps` bug where relative `path`
  entries produce broken symlinks in `lib/`. Symptom was
  `undefined function 'hmac_sha256'` despite successful dep resolution.
  Fix is temporary; file upstream for cyrius 4.4.0.: `error`, `util`, `backend`, `policy`, `scoring`,
  `lifecycle`, `scanning_types/_secrets/_code/_data/_gate/_runtime/_threat`,
  `audit`, `credential`, `quarantine`, `backend_dispatch/_noop/_process`,
  `sandbox_exec`
- **Function-pointer dispatch table** for backends — O(1) lookup, O(3-line)
  extension cost. See [ADR-002](docs/adr/002-backend-dispatch-fnptr-table.md).
- **Fixed-point threat scoring** — intent_score is `_x1000` (0..1000). See
  [ADR-003](docs/adr/003-fixed-point-threat-scoring.md).
- **HMAC-SHA256 audit chain** via [sigil](https://github.com/MacCracken/sigil) ≥ 2.1.2
- **End-to-end demo** (`./build/kavach`): backend dispatch → gate → threat →
  audit, writes `/tmp/kavach-demo.audit` with linked HMAC chain.
- **Architecture docs**: [overview](docs/architecture/overview.md) +
  4 ADRs + README rewrite for the Cyrius edition.
- **Integration tests**: real `/bin/echo` fork+exec via PROCESS backend;
  full scanner pipeline validated with synthetic inputs.

### Changed
- **Language**: Rust 2021 → Cyrius 4.0.0+
- **Async → sync**: all exec paths are synchronous in v3.0. See
  [ADR-004 §1](docs/adr/004-deferred-features.md).
- **Build tool**: `cargo` → `cyrius build`
- **Dependency model**: `Cargo.toml` → `cyrius.toml`; binary deps via sigil
- **Test runner**: `cargo test` → `cyrius test tests/kavach.tcyr`
- **Module layout**: nested `src/<module>/mod.rs` → flat `src/<module>.cyr`

### Deferred — see [ADR-004](docs/adr/004-deferred-features.md)
- 8 of 10 backends (Noop + Process shipped; slots reserved for the other 8)
- Seccomp / Landlock / cgroups kernel-level enforcement hooks
- HTTP credential proxy (direct env/file/stdin injection shipped)
- OffenderTracker (per-exec threat classification shipped)
- Sandbox integrity monitoring (`/proc` readers)
- Secret redaction on WARN verdict
- UUID v4 (monotonic counters shipped — audit HMAC covers trust boundary)
- Full PCRE regex (literal-prefix + char-class matchers shipped for all
  distinctive secret/data patterns)

### Removed
- `rust-old/` contains the entire v1.x Rust source (25,935 lines) preserved
  for reference. Will be deleted in v3.0 once port reaches feature parity.
- Cargo workspace, Makefile, `deny.toml`, `rust-toolchain.toml` —
  replaced by `cyrius.toml`.

---

## [2.0.0] — 2026-04-02 (Rust, superseded by 3.0.0 Cyrius port)

### Added
- **Firewall types in agnosys** — `TrafficDirection`, `Protocol`, `FirewallAction` enums, `FirewallRule` and `FirewallPolicy` structs with constructors, `apply_firewall_rules()` function, nftables ruleset rendering
- **`sandbox_core` module enabled** — unblocked by agnosys firewall API; `#[cfg(feature = "agnostik")]` now compiles and links
- **Delegation depth limit** — capability token delegation chains capped at 5 levels to prevent unbounded chains
- **Process substitution detection** — `<(` and `>(` patterns added to code scanner shell metacharacter group
- **`shell_words()` validation** — now returns `Result` and rejects unclosed quotes instead of silently accepting malformed input
- **Namespace check fail-safe** — `is_in_separate_namespace()` returns `true` (assume isolated) when namespace inodes are unreadable, preventing false-negative escape verdicts
- **Exec timeout enforcement** — `child.wait()` now bounded by remaining timeout budget; prevents zombie processes hanging indefinitely after I/O completes
- 5 new tests: unclosed quote rejection, process substitution detection, delegation depth, cascade revocation, namespace fail-safe

### Changed
- **Dependencies updated** — hmac 0.12→0.13, sha2 0.10→0.11, nix 0.29→0.31, seccompiler 0.4→0.5, oci-spec 0.7→0.9, wasmtime 42→43, criterion 0.5→0.8, libc 0.2.183→0.2.184
- **HMAC `KeyInit` import** — adapted `scanning::audit` for hmac 0.13 API change
- **`deny.toml`** — added `GPL-3.0-only` and `CDLA-Permissive-2.0` to license allowlist
- **agnos-common workspace license** — corrected from deprecated `GPL-3.0` to `GPL-3.0-only`
- Dependency count reduced from 513 to 448 crates

### Fixed
- 6 collapsible-if clippy warnings in `v2.rs` and `credential_proxy.rs`
- 2 collapsible-if clippy warnings in `sandbox_core.rs` teardown

### Security
- P(-1) scaffold hardening audit completed — 13 findings across security, correctness, and performance
- 872 tests passing (up from 561 at v1.0.0)

## [1.0.0] — 2026-03-25

### Added
- **TDX backend** (`Backend::Tdx`) — Intel Trust Domain Extensions, 10th backend variant (strength 85)
- **Backend auto-selection** — `Backend::resolve_best()` ranks by strength; `resolve_min_strength()` filters by minimum
- **`SandboxPool`** — pre-warmed sandbox pool with `claim()`/`replenish()` for fast startup
- **`CompositeBackend`** — stack isolation layers with policy merging (stricter-wins, intersected allowlists, +5 scoring bonus)
- **`Backend::FromStr`** — parse backend names case-insensitively, returns `KavachError`
- **`SandboxPolicy::from_preset()`** — parse policy preset by name
- **Code scanner** (`scanning::code`) — 25 pattern groups: command injection, exfiltration, privilege escalation, supply chain, obfuscation, filesystem abuse, crypto misuse
- **Data scanner** (`scanning::data`) — PII (Visa/MC/Amex/IBAN, phone, IPv4) and compliance (HIPAA, GDPR, PCI-DSS, SOC2)
- **Threat classifier** (`scanning::threat`) — intent scoring (0.0-1.0), 7 kill-chain stages, co-occurrence amplification, 4-tier escalation
- **Repeat offender tracker** — rolling window + time decay + per-agent scoring
- **Quarantine storage** (`scanning::quarantine`) — file-based with metadata sidecar, approval/reject workflow
- **Audit chain** (`scanning::audit`) — HMAC-SHA256 append-only log with chain verification and tamper detection
- **Runtime guards** (`scanning::runtime`) — fork bomb detection, 15-path sensitive blocklist, 26-command blocklist, shell metacharacter detection, time anomaly checks
- **Sandbox integrity monitoring** — PID/mount/user namespace isolation verification
- **Entropy-based secret detection** — Shannon entropy > 4.5 on unrecognized high-entropy strings
- **Multi-scanner gate** — ExternalizationGate runs secrets + code + data scanners on every exec
- **HTTP credential proxy** (`credential::http_proxy`) — transparent proxy on 127.0.0.1, Authorization header injection, CONNECT tunneling, host allowlist
- **SEV attestation** — `SevAttestationReport`, `SevAttestationPolicy`, `SevGuestPolicy` with composable bit flags
- **SGX attestation** — `SgxAttestationReport`, `SgxAttestationPolicy`, sealed data API (`SealedData`, `SealKeyPolicy`)
- **Unified attestation** (`backend::attestation`) — `Attestable` trait, `AttestationResult`, EAR conversion for Veraison/IETF RATS
- **Phylax scanner** (SyAgnos) — verity violation + nftables bypass + namespace/mount escape detection
- **Image managers** — `SyAgnosImageManager` and `OciImageManager` for pull/build/list
- **Firecracker** — vsock communication, snapshot/restore, network TAP with iptables isolation
- **Dependencies** — `hmac` v0.12, `sha2` v0.10, `ear` v0.5 (optional), `sigstore` v0.13 (optional)
- **Infrastructure** — `scripts/bench-history.sh`, `make semver`, overhead benchmark, `.cargo/audit.toml`

### Changed
- **Seccomp blocklist** expanded from 14 to 17 entries (added `io_uring_setup`, `io_uring_enter`, `io_uring_register`)
- **Audit chain** upgraded from SipHash to cryptographic HMAC-SHA256
- **`AttestationTrust` ordering** — now `Contraindicated < Warning < None < Affirming` (higher = more trusted)

### Fixed
- Zombie process leak on I/O error path in `execute_with_timeout`
- `eprintln!` in pre_exec replaced with `libc::write(2)` for async-signal-safety
- All `tracing::*` calls removed from post-fork path (namespaces, landlock, capabilities)
- iptables rule ordering — ACCEPT ESTABLISHED before DROP in TAP config
- IP overflow in `TapConfig::for_vm()` for > 60 VMs
- Gate stdout/stderr boundary — newline separator prevents false positives
- SGX seal/unseal — direct tool invocation instead of shell command
- Vsock CONNECT response validation
- Audit chain — `sorted_json` propagates errors instead of swallowing
- HTTP proxy — CRLF sanitization, 8 KiB request line cap, exact/suffix host matching
- Composite network allowlists intersected (not unioned)
- `cgroups.rs` — `.unwrap()` replaced with `.unwrap_or()`

### Performance
- Seccomp BPF cache — 61-71x faster filter retrieval via `LazyLock`
- Capabilities cache — `OnceLock` eliminates 5 `/proc` reads per exec
- UTF-8 zero-copy — `lossy_utf8()` avoids 1 MiB copy for valid output
- Cow redact — `SecretsScanner::redact()` returns `Cow<str>`, zero-copy when clean
- Gate caching — `ExternalizationGate` created once per sandbox
- Policy clone optimization — `LandlockParams` extracts only needed fields; rlimits use raw scalars
- Code scanner patterns pre-lowercased, no per-match allocation
- `resolve_min_strength` scores each backend once via `filter_map`

### Security
- `#[non_exhaustive]` on all 18 public enums and key structs
- `#[must_use]` on ~35 pure functions
- `#[inline]` on ~12 hot-path functions
- `// SAFETY:` comments on all 4 unsafe blocks
- All public items documented (0 `missing_docs` warnings)
- 561 tests across 35 source files

## [0.22.3] — 2026-03-22

### Changed
- Version bump for stiva 0.22.3 ecosystem release

## [0.21.4] — 2026-03-21

### Fixed
- aarch64 Linux build — legacy syscalls mapped to modern equivalents via `#[cfg(target_arch)]`
- cargo-deny license failure — added `MPL-2.0` for `sized-chunks` (wasmtime)
- Release workflow packages platform binaries as `kavach-{version}-{arch}.tar.gz`

## [0.21.3] — 2026-03-21

### Added
- `#[derive(Debug)]` on all backend structs
- `#[must_use]` on `Backend::is_available()` and `Backend::available()`
- 39 tests (error.rs, gVisor, OCI, exec_util)
- Benchmark history log

### Changed
- Extracted `execute_with_timeout()` — eliminated ~250 lines of duplication across 7 backends
- `which_first()` returns `&str` instead of allocating

### Fixed
- OCI backend missing `#[derive(Debug)]` with `--features full`

### Performance
- `secrets_redact` 2.4x faster (single-pass replacement)
- LazyLock regex caching
- `shell_words()` pre-allocates capacity

## [0.21.2] — 2026-03-21

### Added
- Benchmark suite — 23 benchmarks
- Adversarial integration tests — 30 tests

## [0.21.1] — 2026-03-21

### Added
- gVisor and OCI backends
- Health monitoring, sandbox metrics, OCI spec generation, Firecracker config

## [0.21.0] — 2026-03-21

### Added
- Initial release — Backend trait, 7 backends, strength scoring, policy engine, credential proxy, secrets scanner, externalization gate, lifecycle FSM
