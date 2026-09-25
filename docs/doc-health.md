---
name: Kavach Documentation Health
description: Living ledger of doc currency in the kavach repo — fresh / stale / read-through / evergreen / frozen, refreshed as docs are touched
type: state
---

# Documentation Health — kavach

> **Last refresh**: 2026-09-25 — current through **v3.13.1** (a fix release: `merge_policies` carries the union of both policies' landlock rules; `policy_landlock_deny_all` denies every path in either call order, with `policy_landlock_is_deny_all`; a rule naming a file allows that file; the WASM backend preopens the policy's directories and confines wasmtime with landlock; the process backend hands its payload `config_stdin`, and its unconfined capture `config_env` and `config_workdir`; 1104 tests (1046 on aarch64 under qemu) + 12 samay, 29 benches). The README gains a v3.13.1 status block; `SECURITY.md` lists three resolved items; the roadmap names v3.13.1 and gains three unpinned items (seccomp on WASM, `IOCTL_DEV`, `config_stdin` on the shell-out backends); the overview says a rule may name a file and the WASM backend enforces the rules; the composite guide gives the deny-all semantics; new `tests/wasm_fs_probe.wat`.
>
> **Prior refresh**: 2026-09-25 — current through **v3.13.0** (SGX and TDX quote verification: `kavach_attest_quote` on sigil's verifiers, the `SandboxPolicy` measurement allowlist and root, the attestation gate in `sandbox_exec`, the refusals on paths that cannot check a quote, the `kavach_attestation_result_new` overflow fix, `scripts/check-bundles.py`, the aarch64 support record; 971 tests (942 on aarch64 under qemu) + 12 samay, 27 benches). New example 05; the composite guide gains the attestation merge rule; the overview gains a Platforms table and the attestation step in the exec pipeline; the roadmap's 3.13.x keeps the quote fetch, the RTMRs and Intel's collateral as open items with what blocks each.
>
> **Earlier**: 2026-09-25 — current through **v3.12.9** (the P(-1) closeout: the `InjectionMethod` STDIN routing fix and the `scripts/check-symbols.py` CI gate, the deny list's mount-API and `clone`/`clone3` doors closed, a rootfs always inside a mount namespace, `kv_mkdir` for agnos, the native aarch64 CI job blocking, pinned benchmarks and `scripts/bench-ab.py`; 879 tests (850 on aarch64 under qemu) + 12 samay, 25 benches; plus the fixes from a twelve-module security review). Documentation audit: ADR-004 got a status table (7 of its 9 items shipped), ADR-006 an amendment (the §4 overlaps closed and gated), the guides and examples moved from the old `Backend.X` qualifier to `KavachBackend.X`, `overview.md`'s scoring rows were rechecked, `SECURITY.md`'s Supported Versions table (it read 2.1.x) now matches the 3.12.x line, and the STDIN issue is archived.
>
> **Earlier**: 2026-09-25 — current through **v3.12.8** (the ABI repairs: the seccomp architecture check, per-architecture tables, aarch64 `unshare`/`chroot` refused, `struct stat` through the stdlib's offsets, CI's aarch64 jobs and the fixed security scan; 812 tests (791 on aarch64 under qemu) + 12 samay, 25 benches). New ADR-007. `overview.md`'s seccomp and Landlock rows said "claim only" since before 3.9.0 and were corrected; `SECURITY.md` lists the architecture check as resolved; the roadmap drops 3.12.8 and adds three 3.12.9 items and a blocked entry.
>
> **Earlier**: 2026-09-24 — current through **v3.12.7** (H4 exec by pinned fd; the audit fresh-line guard; 753 tests + 12 samay, 25 benches). The roadmap became a sequence of pinned releases (3.12.8–3.20.x), each item checked against the source; `overview.md`'s v3.4.0 deferred table and `SECURITY.md`'s known items were brought up to date; ADR-005 records H4 as resolved.
>
> **Earlier**: 2026-09-24 — current through **v3.12.6** (pin cc `6.6.2 → 6.6.6`; sigil `3.12.16 → 3.12.18`, ai-hwaccel `2.3.22 → 2.4.0`, samay `1.1.2 → 1.1.5`; 730 tests + 12 samay, 25 benches). Merged the torn-tail task's all-or-nothing audit append (ADR-005 §C4 note, overview), routed every agnos-reachable open through `file_open`, and fixed kavach's raw x86 syscall values on aarch64 (fchmod ran as `capset`; `O_NOFOLLOW` read as `O_LARGEFILE` at four sites), verified under `qemu-aarch64 -strace`, and archived that issue. `cyrius.cyml` was trimmed to configuration only and every doc that pointed into its comment blocks now points at CHANGELOG / ADR-006 / `overview.md` / CLAUDE.md. Pins swept across `CLAUDE.md`, `README.md`, `overview.md`, `roadmap.md` and `getting-started.md`; the chrono / 4095-byte hazards are recorded as fixed upstream in cc 6.5.28, and the new sigil-snapshot hazard is documented. The README's consumer stdlib set was found broken (missing `sakshi`) and corrected.
>
> **Earlier**: 2026-08-17 — current through **v3.11.14** (toolchain refresh + the dropped-`chrono`-include fix; pin cc `6.5.21 → 6.5.27`, deps unmoved at sigil `3.12.9` / samay `1.0.1` / ai-hwaccel `2.3.16`; 684 tests + 12 samay, 25 benches). This refresh swept the cc pin across `CLAUDE.md`, `README.md`, `overview.md`, `roadmap.md`, `getting-started.md` and `cyrius.cyml`, and added a **new standing hazard** to each: since cc 6.5.26 a `[deps].stdlib` declaration is *not sufficient* to get a module into the compilation unit — one first reached transitively is copied to `lib/` with no `include` emitted — so the explicit `include "lib/chrono.cyr"` in `src/util.cyr`, `tests/kavach.fcyr` and `tests/samay_integration.tcyr` is load-bearing and every doc that lists the stdlib set now says so. Two stale claims were also corrected: `scripts/version-bump.sh` asserted kavach had **no embedded version literal** (`src/main.cyr` had printed `kavach v3.2.0` for nine releases), and this ledger's own `VERSION` row still read `3.7.1`.
>
> **Earlier**: 2026-08-14 — current through **v3.11.13** (error-constructor namespacing + toolchain/dependency refresh; pin cc `6.5.20 → 6.5.21`, sigil `3.12.7 → 3.12.9`; 684 tests, 25 benches). This refresh swept the version claims that had gone stale across the 3.8–3.11 arc — `CLAUDE.md` still read pin `6.4.62` / sigil `3.11.1` / `v3.7.1`, `overview.md`'s dependency table and `roadmap.md`'s header the same — and corrected `README.md` + [ADR-006](adr/006-library-surface-and-bundle-generation.md), whose "the constructor/accessor API … is unchanged" claim the `err_* → kavach_err_*` rename invalidated (ADR-006 got a **superseding note**, not a rewrite — the record of its v3.6.0 enum decision stands).
>
> **Earlier**: 2026-07-13 — current through **v3.7.1** (toolchain + dependency refresh; pin cc `6.3.40 → 6.4.62`, sigil `3.9.8 → 3.11.1`; 422 tests, 22 benches). This refresh swept the toolchain/dependency pins that had gone stale since the v3.4.2 sweep — README, `overview.md`, `getting-started.md`, `roadmap.md`, `CLAUDE.md`, and the `cyrius.cyml` comment blocks still read cc `6.2.11` / sigil `3.7.14` / agnosys `1.4.3` — and corrected the overview + getting-started dependency tables that still listed agnosys as a live dep (dropped at v3.5.0; the security backends are internalized — the `agnosys → agnodrm` decomposition). **Per-version history lives in [CHANGELOG.md](../../CHANGELOG.md)** — this ledger tracks doc *currency*, not release notes. | **Refresh cadence**: when docs are touched, update the affected row. Pair with the release dance, but no hard release attachment.
> **Scope**: This repo only (`kavach`) — root-level files (README, CHANGELOG, CLAUDE.md, etc.) plus the entire `docs/` tree, plus `benchmarks-rust-v-cyrius.md` at the root. The `rust-old/` tree is **deliberately excluded** — it's the pre-v3.0 Rust archive (slated for removal, see roadmap) and its inline docs are not maintained.

This is a **ledger**, not a one-time audit. Rewrite-in-place as docs change. Kavach is the sandbox-execution primitive for SY, stiva, kiran, AgnosAI, hoosh, bote, and aethersafta; stale backend / policy / scanner docs propagate downstream as consumer-side mis-integrations, so doc currency carries weight even though the doc surface is small (~22 files).

Pattern lifted from the majra ledger ([`majra/docs/doc-health.md`](https://github.com/MacCracken/majra/blob/main/docs/doc-health.md)) and the agnosys ledger upstream of it — same buckets, kavach-shaped tiers (ADRs are a real surface here; no audit/review cadence yet; one frozen benchmarks artifact at the root).

---

## At a glance — 2026-05-10 inventory

**~22 markdown files** total (8 root + 13 under `docs/` + 1 benchmarks artifact at root). Buckets after the v3.1.0 modernization cut + the post-cut doc sweep:

| Bucket | Count | What it means |
|---|---|---|
| ✅ **Fresh — touched in the v3.1.0 arc or the post-cut sweep** | 9 | `CHANGELOG.md`, `VERSION`, `cyrius.cyml` (new), `.github/workflows/{ci,release}.yml` (ci.yml's 4095-byte `[deps]`-window gate, added at v3.11.14, was retired at v3.12.6 — fixed upstream in cc 6.5.28; its dist gate now covers every `[lib.X]` profile; v3.12.8 added the `aarch64` cross-build + qemu job and an informational native `aarch64-native` job, and repaired the security scan, whose `syscall 59` pattern had never compiled under GNU grep), `docs/development/roadmap.md`, `docs/doc-health.md` (this file) — all from the modernization arc. Plus `README.md`, `CLAUDE.md`, `docs/guides/getting-started.md`, `docs/development/rust-old-removal.md` — refreshed in the post-cut sweep. As of v3.12.6 these carry the cyrius-`6.6.6` / sigil-`3.12.18` reality with agnosys dropped at v3.5.0 (was cyrius-`6.5.27` / sigil-`3.12.9` through v3.11.14; cyrius-`6.5.21` through v3.11.13; cyrius-`6.4.62` / sigil-`3.11.1` through v3.7.1; cyrius-`6.2.11` / sigil-`3.7.14` / agnosys-`1.4.3` through v3.4.2; cyrius-`6.0.43` / sigil-`3.5.9` through v3.4.0); all still lib-via-`cyrius deps`. |
| 🟡 **Stale — refresh in place** | 1 | `benchmarks-rust-v-cyrius.md` root file (snapshot at v3.0.0; see Tier-1 frozen note — refresh only if a new comparison snapshot is captured, otherwise treat as `📦 Frozen — snapshot`). |
| 🟠 **Read-through outstanding** | 0 | Both queued read-through items (`docs/guides/getting-started.md`, `docs/development/rust-old-removal.md`) closed in the post-cut sweep. |
| 🔵 **Probably evergreen** | 4 | `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE`, `CONTRIBUTING.md`. No version-tied claims that drift between minor releases. Re-read pass annually. |
| 📦 **Archive / frozen by design** | 6 | `docs/adr/001..005` (5 ADRs — decisions are dated at write-time and don't decay; superseding ADRs reference originals) + `docs/adr/README.md` (index, refresh only when ADRs are added). |
| 📁 **Worked examples + supplementary** | 5 | `docs/examples/01..04` + `docs/examples/README.md`, `docs/guides/{composite-backends,threat-tracking}.md`, `docs/guides/README.md`, `docs/architecture/overview.md`, `docs/development/stiva.md`. Mostly untouched in this cut — flag for refresh during next feature work that lands new public API surface. |
| ❓ **Open strategic question** | 0 | See [Open questions](#open-strategic-questions) for what would re-open. |

**v3.1.0 modernization cut completed 2026-05-10:**
- ✅ `cyrius.toml` deleted; `cyrius.cyml` written in the majra shape — `${file:VERSION}`, `cyrius = "5.10.34"`, `[deps] stdlib = [...]`, `[deps.sigil]` git+tag at 2.9.0 (same gate as majra/nein for the asm-offset NI bisect).
- ✅ `.cyrius-toolchain` deleted — cyrius pin lives in `cyrius.cyml` (single source of truth).
- ✅ `lib/` deleted from working tree; `/lib/` added to `.gitignore` — `cyrius deps` is now the source of truth, mirroring majra/nein.
- ✅ `VERSION` bumped 3.0.0 → 3.1.0.
- ✅ CI (`.github/workflows/ci.yml`) rewritten against the majra/nein installer pattern — version-pinned toolchain layout (`~/.cyrius/versions/<V>/{bin,lib}` + symlinks), source-archive fetch for `lib/`, `cyrius deps` + lockfile gate, fmt / lint / vet / build / test / bench / fuzz / security / docs jobs.
- ✅ Release (`.github/workflows/release.yml`) rewritten in the same shape — version verify, source archive + binary asset, SHA256SUMS, dated CHANGELOG body extraction.
- ✅ `docs/development/roadmap.md` — previous "v3.1 — unblocking queue" cascaded to v3.2 per the modernization arc convention; new "v3.1 — modernization arc" section records what shipped.
- ✅ `docs/doc-health.md` (this file) scaffolded — initial audit + bucket assignment + 3 stale rows queued for follow-up.

**Post-cut doc sweep completed 2026-05-10:**
- ✅ `README.md` — "Requires Cyrius ≥ 4.0.0" replaced with "Cyrius 5.10.34 (pinned in `cyrius.cyml`)"; `cyrius.toml` → `cyrius.cyml`; explicit `cyrius deps` step added to the build instructions; v3.0 status block expanded to a v3.1 / v3.0 split (modernization arc on top, port summary below); dep list updated against the actual `[deps] stdlib` set + sigil 2.9.0; consumer reference to `doc-health.md` added.
- ✅ `CLAUDE.md` — Rust-era `MSRV: 1.89` line dropped; Version bumped 3.0.0 → 3.1.0; new `Language: Cyrius (pinned at 5.10.34 ...)` line carrying the pin-lock rationale; `Type` line rewritten to acknowledge the consumer-embedding future; Cleanliness Check lines in P(-1) + Development Loop swapped from `cargo fmt / clippy / audit / deny` → `cyrius fmt / lint / vet / audit`; `Cargo.toml` → `cyrius.cyml` in the Version-check step; Key Principles section translated from Rust-attribute idioms (`#[non_exhaustive]`, `#[must_use]`, `#[inline]`, `Cow over clone`, `// SAFETY:`) to Cyrius-shaped equivalents (Str-borrows, `# SAFETY:` comment on raw syscalls, etc.); DO-NOT list rewritten — pin-bump prohibition added, `cyrius fmt`-on-wrong-toolchain prohibition added, `lib/`/`build/` gitignore reminder added; `Cargo.lock` reference dropped.
- ✅ `docs/guides/getting-started.md` — § 1 "Build + install" rewritten: `cyrius deps` step added; toolchain line bumped to 5.10.34 with the pin-lock rationale; dep list updated against `cyrius.cyml`; sigil pin updated 2.1.2 → 2.9.0 with the SIGILL gate context; `lib/` gitignored model documented.
- ✅ `docs/development/rust-old-removal.md` — sed recipe in § "Removal command" updated: `cyrius.toml` → `cyrius.cyml`; commit message bumped from `v3.0` → `v3.x`; new checked-off line in the Pre-removal checklist records the cyrius.cyml-migration prereq; parity checklist re-verified against the v3.0 surface — no drift caught.

**Queued for follow-up (carried from v3.1.0; now sits in roadmap v3.2 under the `cyrius audit` clean item):**
- ✅ **`cyrius fmt` drift — resolved at v3.4.2.** The 6.1 → 6.2 pin move reflowed multi-line call-continuation arguments (paren-aligned → flat 4-space); 13 src/ + tests/ files were re-formatted under the pinned `6.2.11` toolchain and the tree is now fmt-clean. Don't run `cyrius fmt` locally with a non-`6.5.27` toolchain — fmt output is minor-version-sensitive and would commit new drift. ⭐ Re-verified fmt-clean end to end at v3.11.14 under the matching `6.5.27`; the one residual drift (a wrapped-call continuation indent in `tests/samay_integration.tcyr`) was closed there — it had been drifting under **both** 6.5.21 and 6.5.27, so it was not a pin-move artifact.
- ⚠️ **`cyrius lint` long-line warnings (37 total)** — pre-existing v3.0 content, chiefly in the scanner pattern lists: `src/scanning_code.cyr` (16) + `src/scanning_data.cyr` (16), plus stragglers in `src/backend_sgx.cyr` (3), `src/oci_spec.cyr` (1), `src/scanning_runtime.cyr` (1). CI runs lint as `::warning::` informational at v3.1.0; tracked alongside fmt in the v3.2 `cyrius audit` clean item. The lint step also handles cc's "exit code = warning count" convention via `|| true` so the loop doesn't trip `set -eo pipefail`.

---

## Tier 1 — Root files

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-09-25 | ✅ Fresh | v3.13.1: status block on top (the five fixes, with what each payload got before); 1104 assertions and 29 benches in §Build. Before that: v3.13.0: status block on top (quote verification, the gate, what is not evaluated, the launchers that cannot fetch); 971 assertions and 27 benches in §Build, which also runs `scripts/check-bundles.py`; the SGX and TDX scoreboard rows say what their launchers lack. Before that: Status block for **v3.12.9** on top; the symbol-overlap caveat rewritten for the closed §4 overlaps and the gate; accessors now `kavach_syserr_*`; `KavachBackend.X` in the examples; 879 assertions. Before that: Status block for **v3.12.8** on top (the ABI repairs; 32-bit payloads now killed under a filter; aarch64 refusals); §Build → cc `6.6.6`, 812 assertions, `fmt --check`, `cyrius distlib --all`. Deps list → sigil `3.12.18` (from the toolchain snapshot) plus samay / ai-hwaccel; stdlib list complete. §Consume: the example's tag → `3.12.8`, and its 33-leaf stdlib set re-verified by a `[deps.kavach]` build at 3.12.8. Older per-version status blocks are history. |
| `CHANGELOG.md` | 2026-09-25 | ✅ Fresh | **[Unreleased] (3.13.2 work)**: an intro and eight entries, each measured before its change: the gVisor, OCI and SY-agnos backends report their runtime's run (exit status, stderr, the config's deadline and stdin; SY-agnos `-i`, `--name`, `rm --force`; OCI's stderr file gone); an unset `config_stdin` is empty, `config_stdin_inherit` opts in; landlock scopes applied; `IOCTL_DEV` handled; wasmtime under the policy's seccomp and scopes; TCP port counts unscored; the capture's full-buffer hang; a result's stderr aliasing; a capture's payload outliving kavach (the parent-death guard); a payload inheriting kavach's SIGPIPE ignore (found by CI, where the runner starts steps with SIGPIPE ignored). Every behaviour change marked ⚠. Tests (ten new, fourteen changed, the two quarantine tests now removing their stores; 66 assertions fail against 3.13.1) and 39 mutants, Verified. Then the roadmap-after-3.13.1 docs entry. Before that: **v3.13.1**: an intro and five fixes: four landlock, and the process backend's stdin (with `config_env` and `config_workdir` on its unconfined capture), each measured before and after. `merge_policies` carries the union of both rule lists, deny-all if either side is. `policy_landlock_deny_all` drops the policy's rules, a later `policy_landlock_add` is refused, and the exec child reads a count above the list as deny-all, as the merge does (`policy_landlock_is_deny_all`). The WASM backend preopens exactly the policy's rule directories (none for deny-all, not the workdir) and confines wasmtime with landlock so read-only rules hold. The measured before/after of each, why deny-all means no path, the finding that a deny-all payload cannot start on the exec'd backends (its exec is refused, exit 127), and a landlock rule naming a file, which failed every exec (EINVAL on directory rights), now allows that file alone with the kernel's file rights, measured one right at a time; wasmtime's ruleset names its binary and module files, and a file rule gets no WASM preopen. Tests and mutants, Verified, Performance. Before that: **v3.13.0**: Added (verification, policy fields, the gate, the backend hand-off, the bundle check), Changed (refusals, merge), Fixed (the result overflow; the confine bundle break caught before release), Not done (quote fetch, with blockers), Platforms, CI, tests and mutants, Verified, Performance. Before that: **v3.12.9**: Breaking (the prefixed names and removed functions), the STDIN routing fix, the symbol gate, the deny-list doors, rootfs namespaces, `kv_mkdir`, CI and bench tooling, the docs audit, Verified, Performance. Before that: **v3.12.8**: Breaking (32-bit payloads under a filter; five removed syscall constants), the seccomp architecture check with the measured 3.12.7 bypass, the name map, the aarch64 refusals with the `-strace` evidence, the `struct stat` fix, CI, tests and mutants, Verified, Performance (pinned A/B against the 3.12.7 tag). **v3.12.7**: H4 exec-by-fd (design, coverage, tests and mutants, aarch64 trace), the audit fresh-line guard, the pinned-roadmap reorganization, Verified, and Performance (pinned A/B against the 3.12.6 tag; the unpinned bimodality note). **v3.12.6** as before. |
| `CLAUDE.md` | 2026-09-25 | ✅ Fresh | v3.13.1: version. Before that: v3.13.0: version; the dist DO-NOT adds `scripts/check-bundles.py`. Before that: v3.12.9: version; DO-NOTs for kavach names another module can own (with the gate) and for `sys_*` calls whose agnos form differs (`kv_*` shims); the loop names `scripts/bench-ab.py` and no longer mentions an external recipe repo. Before that: Version → **v3.12.8**; pin cc `6.6.6`. Hazards: four live (opt-in stdlib, 6.2 consolidation, sigil symbol collisions, the toolchain snapshot's sigil overriding `[deps.sigil]`); two recorded as fixed upstream in cc 6.5.28. DO-NOTs added in 3.12.6–3.12.7: no commentary in `cyrius.cyml`; no plain `cyrius distlib`; no hardcoded x86-64 syscall numbers or open flags; no exec by path in a child (pin with `kv_exec_pin`). 3.12.8: no aarch64-native syscall numbers either (ADR-007), with the one exception of seccomp tables. |
| `CONTRIBUTING.md` | 2026-04-13 | 🔵 Evergreen | Generic contributor workflow. Re-read annually. |
| `SECURITY.md` | 2026-09-25 | ✅ Fresh | v3.13.1: three resolved items (deny-all keeping a policy's rules, the WASM backend ignoring them, a process payload reading kavach's stdin); Supported Versions unchanged at 3.13.x. Before that: v3.13.0: Supported Versions → 3.13.x; attestation in scope; its limits under known deferred items; the result overflow resolved. Before that: v3.12.9: the Supported Versions table read 2.1.x as active (1.x/2.x were the Rust line); it now names 3.12.x, forward-only fixes. Before that: Resolved list: the seccomp architecture check (v3.12.8, now fixed and so listed), H4 (v3.12.7), seccomp / Landlock / cgroups enforced since 3.9.0; HTTPS `CONNECT` tunnelling still not implemented. ⚠ Its **Supported Versions** table still reads 2.1.x as active: a support-policy call for the maintainer, not edited here. |
| `CODE_OF_CONDUCT.md` | 2026-04-13 | 🔵 Evergreen | Standard. |
| `VERSION` | 2026-09-25 | ✅ Fresh | **`3.13.1`**. Before that: **`3.13.0`**. Before that: **`3.12.9`**. Before that: **`3.12.8`** — single source of truth, read into `cyrius.cyml` via `${file:VERSION}`. |
| `LICENSE` | (initial commit) | 🔵 Evergreen | GPL-3.0-only. |
| `cyrius.cyml` | 2026-09-24 | ✅ Fresh | **Configuration only since v3.12.6** — 12,819 → 3,135 bytes, 143 comment lines → 0. History lives in CHANGELOG, rationale in ADR-006 and `overview.md`, hazards in CLAUDE.md. cc pin `6.6.6`; `[deps.sigil]` `3.12.18`, kept equal to the toolchain snapshot's sigil, which wins (CLAUDE.md hazard 4); ai-hwaccel `2.4.0` + samay `1.1.5` optional behind the default-on `scheduler` feature; `[lib]` + `[lib.confine]` module lists. |
| `benchmarks-rust-v-cyrius.md` | 2026-04-13 | 📦 Frozen — snapshot | v2.0.0-Rust ↔ v3.0.0-Cyrius release comparison. Don't refresh in place; the next cross-language comparison (if any) gets a new dated file. Today the numbers stand as the cutover headliner. |

---

## Tier 2 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `overview.md` | 2026-09-25 | ✅ Fresh | 3.13.2 work: the policy paragraph gains `IOCTL_DEV` (read-write rules only), the scopes on every confining path where the kernel has ABI v6, wasmtime under seccomp and the scopes, and the port counts applied nowhere and unscored; the scoring prose rechecked at 3.13.2; the seccomp row adds the wasmtime process, the scope rows say "Yes" with their paths and ABI, and the port row scores 0. Before that: v3.13.1: a landlock rule names a directory or a file (a file rule allows that file alone; through v3.13.0 it failed every exec, exit 124). Also v3.13.1: the WASM backend's filesystem rules — the policy paragraph and the scoring prose say WASM enforces them (the rules are the guest's preopens, none for deny-all, not the workdir; landlock on wasmtime holds read-only rules), and the "landlock rules present" row says so, with the pre-fix behaviour (workdir preopened read-write, rules ignored, still scored). Before that: v3.13.0: Platforms table (aarch64 supported apart from namespaces and rootfs entry, with the CI evidence); the attestation fields after policy construction; the attestation step in the exec pipeline; `attestation.cyr` in the module map; deferred table re-dated, its TEE row split into quote fetch (with what blocks it) and SEV-SNP / sealing. Before that: v3.12.9: `SecretRef` shows `KAVACH_INJECT_*`; the network row says when the process backend really isolates (a rootfs, or `config_require_namespaces`); the three Landlock network/scope rows stay "claim only" without their stale v3.5.0 target; `KavachBackend.NOOP`. Before that: v3.12.8: the policy-construction note and the scoring table said seccomp and Landlock were "claim only"; corrected to where each is applied (process backend and `sandbox_spawn` through `confine_child`, persistent guests through their own sequence) and since when. The Landlock network and scope rows are still claim-only and left to the 3.12.9 doc audit. Deferred table re-dated with an aarch64 namespaces + rootfs row. The deferred-features table was still dated v3.4.0 and listed shipped work as pending; rewritten at v3.12.7 to what is still deferred (TEE attestation and the jailer, now kavach-side work; stiva OCI; async exec; regex), with a line for what shipped since. Audit append: `_audit_append`, all or nothing, fresh line after a torn fragment. Dependencies table: cc `6.6.6`, sigil `3.12.18` with the snapshot mechanism, samay / ai-hwaccel rows. |

---

## Tier 3 — Decisions (`docs/adr/`)

ADRs are point-in-time records — they don't decay the way prose docs do. Each ADR is dated at write-time; superseding ADRs reference the originals.

| ADR | Status | Notes |
|---|---|---|
| `001-cyrius-port-architecture.md` | 📦 Frozen — accepted | Port philosophy. References `cyrius.toml` in commentary (L58); informational only — not a recipe. No refresh owed. |
| `002-backend-dispatch-fnptr-table.md` | 📦 Frozen — accepted | The dispatch-table pattern. Reinforced by every backend_* module shipping the same slot layout. |
| `003-fixed-point-threat-scoring.md` | 📦 Frozen — accepted | ×1000 fixed-point for threat intent scoring. |
| `004-deferred-features.md` | 📦 Frozen — accepted, status-updated | The deliberate-deferral list. v3.12.9 appended a status table checked against the source: seven of nine items shipped (async exec and full regex remain). v3.13.0 re-dated it: §2's SGX / TDX quote verification shipped; quote fetch and SEV-SNP remain, with what the launchers lack. The 3.13.2 work updated row 3: `IOCTL_DEV` and the scopes are enforced; the network rules are not, and the port counts are unscored. |
| `005-v2-hardening-pass.md` | 📦 Frozen — accepted, amended | P(-1) hardening pass — 9 CWE-class fixes. Two dated notes: C4's audit-log clause superseded in part (v3.12.6: 0600 at create, `fchmod` on the fd), and **H4 resolved** (v3.12.7: exec by pinned fd; why no `O_NOFOLLOW`). |
| `007-syscall-numbers-across-architectures.md` | ✅ Accepted | v3.13.0: aarch64 recorded as supported apart from namespaces and rootfs entry, with the native CI job's count as evidence. v3.12.8: filters admit only the build's ABI (arch check, x32 bit), filter tables are native two-column data, and a `syscall()` site takes a stdlib name, an x86-only declaration or a refusal — never an aarch64-native number. |
| `006-library-surface-and-bundle-generation.md` | ✅ Accepted — amended | `[lib]` + `cyrius distlib`. Amended in place at v3.11.13 (the `err_*` superseded note) and v3.12.6 (profiles: `[lib.confine]`, `distlib --all`, the re-verified consumer stdlib set, sigil from the consumer's snapshot). v3.12.9: a third amendment closes §4's remaining overlaps (`syserr_*`, `agnosys_*`, `attestation_result_new`) and records the CI gate. |
| `README.md` | 2026-09-25 | 📦 Frozen — index | ADR index; refresh only when a new ADR is added (ADR-007 at v3.12.8). |

Decision velocity is low. Open a new ADR only when a load-bearing decision is reversible and would benefit from a referenceable "we decided X because Y" artifact. The v3.1.0 modernization arc didn't earn one — the CHANGELOG entry carries the rationale.

---

## Tier 4 — Development (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-09-25 | ✅ Fresh | 3.13.2's items checked off as done in the tree (the section goes when 3.13.2 is cut), with the four defects found on the way; "Later in 3.13.x" gains the runtime diagnostics on gVisor and SY-agnos, which reach the gate with the payload's stderr; "Beyond 3.x" gains Landlock TCP port rules (a list and a setter). Before that: after v3.13.1: shipped narrative removed; the open fixes pinned. 3.13.2 (next): the shell-out backends' capture (gVisor, OCI, SY-agnos: exit status, stderr, deadline, stdin), the inherit-stdin decision, `IOCTL_DEV`, seccomp on WASM, and the landlock network rules and scopes; SGX/TDX, SEV and Firecracker take their capture fixes in the arcs that rebuild their launchers (3.13.x, 3.14, 3.15), and 3.19's VM backend starts on it; the generic-names sweep pinned as 4.0.0 with its decision. Claims rechecked against the source and the 6.6.6 stdlib (aarch64 still blocked; the slice negative still holds). Before that: v3.13.1: current release, and a line on what it fixed under 3.13.x; "Beyond 3.x" gains seccomp on the WASM backend (apply or stop scoring), `IOCTL_DEV`, and `config_stdin` on the shell-out backends with the inherit-by-default question. Before that: v3.13.0: current release; 3.13.x's shipped items moved to the CHANGELOG, leaving the quote fetch (with what each launcher lacks), the TDX RTMRs and Intel's collateral. Before that: 3.12.9 shipped and removed; the next release is 3.13.x, which gains the aarch64-support record; "Beyond 3.x" gains the generic-public-names decision and "apply or stop scoring" the Landlock network rules; ADR-004 references corrected (§2, not §6; the stiva plan is in `backend_oci.cyr`). Before that: **Pinned releases** since v3.12.7; 3.12.8 shipped and removed. 3.12.9 P(-1) closeout gained three items (deny-list doors: the new mount API and `clone`/`clone3`; `confine_child`'s rootfs without `NS_MOUNT`; the native aarch64 CI job) and lost `kv_sleep_ms` (shipped in 3.12.8); a blocked entry for the aarch64 refusals. 3.13–3.15 attestation and the jailer, 3.16–3.18 the L4 gate, 3.19 the VM backend foundation, 3.20 scanner performance; then Beyond 3.x (unpinned, with the one blocked item) and the design reference. Every item was checked against the source before it was pinned. |
| `rust-old-removal.md` | 2026-05-10 | 📦 Frozen — historical | Doc fulfilled its purpose at v3.1.1: rust-old/ tree deleted (1.4 MB / 25,935 lines), parity audit re-verified, sed recipe applied to `src/main.cyr` header. Keep as historical reference (per-symbol Rust→Cyrius mapping is still useful archaeology). No refresh owed; if rust-old/ is restored from git history for any reason, re-open. |
| `stiva.md` | 2026-04-13 | 📁 Supplementary | Integration note for the stiva consumer. Refresh when stiva's Cyrius port lands (tracked in roadmap v3.2 blocked queue). |

---

## Tier 5 — Guides (`docs/guides/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-04-13 | 📁 Supplementary | Index. |
| `getting-started.md` | 2026-09-25 | ✅ Fresh | Toolchain → cc `6.6.6`; stdlib list completed; the chrono hand-include described as a harmless guard (fixed upstream in 6.5.28); sigil `3.12.18` with the snapshot note; samay / ai-hwaccel bullet added; agnosys pointer → CHANGELOG 3.5.0. Build → configure → execute walkthrough still tracks src/. v3.12.9: code checked against the current API; `Backend.X` → `KavachBackend.X` (the enum was renamed at 3.11.15; the old qualifier still compiled because qualifiers are cosmetic). |
| `composite-backends.md` | 2026-09-25 | 📁 Supplementary | Defense-in-depth merge rules. No manifest references; content tracks `src/composite.cyr`. v3.12.9: code checked against the current API; `Backend.X` → `KavachBackend.X`. v3.13.0: the attestation merge rule, and `composite_exec`'s refusal of a policy that requires attestation. v3.13.1: the `landlock_rules_len` SUM row, which the code never met (it summed the counts, carried no list, and so denied every path), became two rows checked against the fixed merge: the rule lists' union in a fresh list, and deny-all if either side is. A paragraph under the table gives the reasons and the pre-fix behaviour. Then, with the `policy_landlock_deny_all` fix: the deny-all paragraph no longer says a deny-all policy that names rules applies them alone (the call now drops them, a later add is refused, and the exec child makes the merge's test), and a new paragraph says a deny-all side stops the payload, because its exec is refused (exit 127, measured), and how to confine a payload that has to run. |
| `threat-tracking.md` | 2026-04-13 | 📁 Supplementary | Intent scoring + OffenderTracker + decay tuning. No manifest references; content tracks `src/scanning_threat.cyr`. |

---

## Tier 6 — Examples (`docs/examples/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-09-25 | 📁 Supplementary | Index. v3.13.0: example 05 added. |
| `01-hello-noop.md` | 2026-09-25 | 📁 Supplementary | Noop backend walkthrough. v3.12.9: `KavachBackend.NOOP`. |
| `02-process-with-audit.md` | 2026-09-25 | 📁 Supplementary | Process backend + audit chain. v3.12.9: `KavachBackend.PROCESS`. |
| `03-scanner-verdicts.md` | 2026-04-13 | 📁 Supplementary | Scanner verdict surface + WARN redaction. |
| `04-offender-tracking.md` | 2026-04-13 | 📁 Supplementary | OffenderTracker across execs. |
| `05-tee-attestation.md` | 2026-09-25 | ✅ Fresh | v3.13.0: verifying sigil's SGX test quote, and the `sandbox_exec` gate through a stand-in backend (fresh nonce passes, replay is withheld). The code was built against `dist/kavach.cyr` and its output copied from the run. |

Examples track the v3.0 surface — re-read in tandem with any guide that gets refreshed, but no per-cut churn owed unless API breaks.

---

## What this repo does NOT have yet (and doesn't need to invent)

The majra ledger has tiers for **state.md** (live volatile state) and **cyrius-quirks.md** (toolchain gotchas). Kavach has neither, by design — for now:

- **No `docs/development/state.md`.** Kavach's volatile state (cyrius pin, sigil pin, test count, backend count) is small enough to live in CHANGELOG entries + the roadmap header. Open a state.md if CLAUDE.md drifts to inline-volatile content again (the post-3.1.0 refresh is the natural trigger to evaluate).
- **No `docs/development/cyrius-quirks.md`.** Kavach has no inline-asm surface and isn't a transport-layer crate — the cc5 quirks that majra/nein document (fixup cap, `var buf[N]` static-not-stack, inline-asm offsets) haven't bitten kavach yet. Open one if a quirk costs more than a single fix to work around.
- **No `docs/audit/` cadence.** P(-1) hardening landed in v3.0 ([ADR-005](adr/005-v2-hardening-pass.md)); no recurring audit cadence is owed at the current consumer-surface size. Open if a CVE pattern surfaces or a consumer asks for a structured audit artifact.
- **`docs/development/issues/`** holds issues filed against kavach itself: open ones at the top level, resolved ones under `archived/` (header ends `— RESOLVED`, with a status line naming the fixing release), and repro sources under `repros/`. Upstream issues kavach files live in the upstream repo. The 2026-09-12 aarch64 raw-syscall issue was resolved and archived at v3.12.6.
- **No `docs/standards/` or `docs/compliance/` tier.** Kavach implements industry conventions (OCI runtime spec v1.0.2, HMAC-SHA256 audit chains) but isn't a conformance-test target. Open only if a regulator-facing artifact becomes load-bearing.

---

## Open strategic questions

None outstanding for the v3.1.0 cut. This section will repopulate when:

- A consumer asks for an aarch64 binary (kavach is currently x86_64-only via CI; the cross-build dance majra documents would migrate here if a consumer asks).
- The seccomp / landlock / cgroups v2 work from the v3.2 blocked queue lands and earns its own ADR.
- A second cross-language benchmark snapshot ships and we need to decide whether to fold `benchmarks-rust-v-cyrius.md` into a per-release `docs/benchmarks/results-v*.md` directory.

---

## In-flight (blocked, not stale)

- **v3.2 blocked queue** — seccomp / landlock / cgroups v2 / SGX-IAS / Firecracker jailer (all upstream-blocked on Cyrius syscall wrappers + sigil EAR helpers). See roadmap.
- **`rust-old/` deletion** — fully captured by `docs/development/rust-old-removal.md`; pending an end-to-end parity check against v3.0 surface before the directory is removed. Tracked in roadmap v3.2.

---

## Forward doc-policy commitments

| # | Commitment | Trigger | Source | Notes |
|---|---|---|---|---|
| 1 | **ADR retention** — 001..005 stay verbatim. Superseding ADRs get a new numbered file referencing the original; never refresh ADR text in place. | Always | This file | Standard ADR convention. |
| 2 | **Benchmark snapshot retention** — `benchmarks-rust-v-cyrius.md` is the v2.0→v3.0 cutover headliner; don't refresh in place. The next comparison (if any) gets a new dated file under `docs/benchmarks/`. | When a new comparison is captured | This file | Today the surface is one file. |
| 3 | **Open audit/review tiers only on a real trigger.** Don't add empty `docs/audit/` or `docs/development/reviews/` directories — they degrade into checklist noise without a forcing function. | When a CVE pattern or a consumer ask materialises | This file | The P(-1) hardening pass shipped under ADR-005; no recurring cadence is owed yet. |
| 4 | **State / quirks files emerge from CLAUDE.md drift.** Open `docs/development/state.md` only if CLAUDE.md grows inline volatile content again. Open `docs/development/cyrius-quirks.md` only when a cc5 quirk costs more than a single in-tree fix to work around. | When CLAUDE.md drifts | This file | Majra hit both triggers in its 2.4.3 arc; kavach hasn't yet. |

---

## Refresh procedure

When docs are touched:

1. Find the affected row in the relevant tier table.
2. Update **Last touched** column to the new date.
3. Update **Status** column if the bucket changed.
4. Update **Notes** column if the next step changed.
5. If a doc moved or was archived, update its row to reflect the new home.
6. Re-anchor "Last refresh" date in the header.

When the bucket counts at the top drift by more than ~2 in any cell, refresh the at-a-glance table.

This file's refresh cadence is **opportunistic** (touched when other docs are touched), not periodic and not tied to releases. The v3.1.0 modernization cut establishes the baseline; future minor cuts' doc-sync step touches this file alongside CHANGELOG + roadmap when something here actually drifts.

---

## What this file is NOT

- Not a CHANGELOG (which records what shipped, not what's stale).
- Not a roadmap (forward work lives in [`development/roadmap.md`](development/roadmap.md)).
- Not a per-doc review log (we record the result of an audit pass, not the per-doc reasoning).
- Not a substitute for the ADR index (`adr/README.md`) — that file is the canonical list of accepted decisions.

---

*Last refresh: 2026-08-17 (v3.11.14 toolchain + chrono-include sweep). Originally 2026-05-10 (initial audit at the v3.1.0 modernization cut). Refresh in place when docs are touched.*
