---
name: Kavach Documentation Health
description: Living ledger of doc currency in the kavach repo — fresh / stale / read-through / evergreen / frozen, refreshed as docs are touched
type: state
---

# Documentation Health — kavach

> **Last refresh**: 2026-09-24 — current through **v3.12.6** (pin cc `6.6.2 → 6.6.6`; sigil `3.12.16 → 3.12.18`, ai-hwaccel `2.3.22 → 2.4.0`, samay `1.1.2 → 1.1.5`; 718 tests + 12 samay, 25 benches). Also fixed kavach's raw x86 syscall values on aarch64 (fchmod ran as `capset`; `O_NOFOLLOW` read as `O_LARGEFILE` at four sites), verified under `qemu-aarch64 -strace`, and archived that issue. `cyrius.cyml` was trimmed to configuration only and every doc that pointed into its comment blocks now points at CHANGELOG / ADR-006 / `overview.md` / CLAUDE.md. Pins swept across `CLAUDE.md`, `README.md`, `overview.md`, `roadmap.md` and `getting-started.md`; the chrono / 4095-byte hazards are recorded as fixed upstream in cc 6.5.28, and the new sigil-snapshot hazard is documented. The README's consumer stdlib set was found broken (missing `sakshi`) and corrected.
>
> **Prior refresh**: 2026-08-17 — current through **v3.11.14** (toolchain refresh + the dropped-`chrono`-include fix; pin cc `6.5.21 → 6.5.27`, deps unmoved at sigil `3.12.9` / samay `1.0.1` / ai-hwaccel `2.3.16`; 684 tests + 12 samay, 25 benches). This refresh swept the cc pin across `CLAUDE.md`, `README.md`, `overview.md`, `roadmap.md`, `getting-started.md` and `cyrius.cyml`, and added a **new standing hazard** to each: since cc 6.5.26 a `[deps].stdlib` declaration is *not sufficient* to get a module into the compilation unit — one first reached transitively is copied to `lib/` with no `include` emitted — so the explicit `include "lib/chrono.cyr"` in `src/util.cyr`, `tests/kavach.fcyr` and `tests/samay_integration.tcyr` is load-bearing and every doc that lists the stdlib set now says so. Two stale claims were also corrected: `scripts/version-bump.sh` asserted kavach had **no embedded version literal** (`src/main.cyr` had printed `kavach v3.2.0` for nine releases), and this ledger's own `VERSION` row still read `3.7.1`.
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
| ✅ **Fresh — touched in the v3.1.0 arc or the post-cut sweep** | 9 | `CHANGELOG.md`, `VERSION`, `cyrius.cyml` (new), `.github/workflows/{ci,release}.yml` (ci.yml's 4095-byte `[deps]`-window gate, added at v3.11.14, was retired at v3.12.6 — fixed upstream in cc 6.5.28; its dist gate now covers every `[lib.X]` profile), `docs/development/roadmap.md`, `docs/doc-health.md` (this file) — all from the modernization arc. Plus `README.md`, `CLAUDE.md`, `docs/guides/getting-started.md`, `docs/development/rust-old-removal.md` — refreshed in the post-cut sweep. As of v3.12.6 these carry the cyrius-`6.6.6` / sigil-`3.12.18` reality with agnosys dropped at v3.5.0 (was cyrius-`6.5.27` / sigil-`3.12.9` through v3.11.14; cyrius-`6.5.21` through v3.11.13; cyrius-`6.4.62` / sigil-`3.11.1` through v3.7.1; cyrius-`6.2.11` / sigil-`3.7.14` / agnosys-`1.4.3` through v3.4.2; cyrius-`6.0.43` / sigil-`3.5.9` through v3.4.0); all still lib-via-`cyrius deps`. |
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
| `README.md` | 2026-09-24 | ✅ Fresh | Status block for **v3.12.6** on top (incl. the aarch64 credential-write fixes). §Build → cc `6.6.6`, 718 assertions, `fmt --check` (plain `cyrius fmt` rewrites in place; the old "writes to stdout" note was wrong), `cyrius distlib --all`. Deps list → sigil `3.12.18` (from the toolchain snapshot) plus samay / ai-hwaccel; stdlib list completed (`atomic` / `math` / `sakshi`). §Consume: the documented consumer stdlib set lacked `sakshi` and no longer built — corrected and re-verified end to end on cc 6.6.6; sigil-from-snapshot noted. Older per-version status blocks are history. |
| `CHANGELOG.md` | 2026-09-24 | ✅ Fresh | **v3.12.6** stanza: pin move with the audit-chain torn-write A/B, dep table with the sigil-snapshot explanation, the aarch64 raw-syscall fixes with before/after strace, the stale confine-bundle fix, the manifest trim, the retired 4095 gate, verification, and benchmark deltas with toolchain attribution. |
| `CLAUDE.md` | 2026-09-24 | ✅ Fresh | Version → **v3.12.6**; pin → cc `6.6.6` (Language line, DO-NOT pin-bump and fmt rules). Hazards: four live — opt-in stdlib, 6.2 consolidation, sigil symbol collisions, and the **toolchain snapshot's sigil overriding `[deps.sigil]`**; the transitive-include and 4095-byte-window hazards are recorded as fixed upstream in cc 6.5.28. New DO-NOTs: no commentary in `cyrius.cyml`; no plain `cyrius distlib`; no hardcoded x86_64 syscall numbers or open-flag values. Type line names the `[lib.confine]` bundle. |
| `CONTRIBUTING.md` | 2026-04-13 | 🔵 Evergreen | Generic contributor workflow. Re-read annually. |
| `SECURITY.md` | 2026-04-13 | 🔵 Evergreen | Reporting policy + scope. Re-read annually. |
| `CODE_OF_CONDUCT.md` | 2026-04-13 | 🔵 Evergreen | Standard. |
| `VERSION` | 2026-09-24 | ✅ Fresh | **`3.12.6`** — single source of truth, read into `cyrius.cyml` via `${file:VERSION}`. |
| `LICENSE` | (initial commit) | 🔵 Evergreen | GPL-3.0-only. |
| `cyrius.cyml` | 2026-09-24 | ✅ Fresh | **Configuration only since v3.12.6** — 12,819 → 3,135 bytes, 143 comment lines → 0. History lives in CHANGELOG, rationale in ADR-006 and `overview.md`, hazards in CLAUDE.md. cc pin `6.6.6`; `[deps.sigil]` `3.12.18`, kept equal to the toolchain snapshot's sigil, which wins (CLAUDE.md hazard 4); ai-hwaccel `2.4.0` + samay `1.1.5` optional behind the default-on `scheduler` feature; `[lib]` + `[lib.confine]` module lists. |
| `benchmarks-rust-v-cyrius.md` | 2026-04-13 | 📦 Frozen — snapshot | v2.0.0-Rust ↔ v3.0.0-Cyrius release comparison. Don't refresh in place; the next cross-language comparison (if any) gets a new dated file. Today the numbers stand as the cutover headliner. |

---

## Tier 2 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `overview.md` | 2026-09-24 | ✅ Fresh | External-dependencies table → cc `6.6.6`, sigil `3.12.18` with the snapshot mechanism, stdlib list completed (`atomic` / `math` / `sakshi`), and new **samay** / **ai-hwaccel** rows carrying the `scheduler` feature-gating rationale that used to sit in `cyrius.cyml`; the agnosys row points at CHANGELOG 3.5.0. Module map carries `aho_corasick.cyr` (v3.4.0) + cgroup / credential_http; policy-modifier and deferred-surface tables as of the 2026-06-02 sweep. |

---

## Tier 3 — Decisions (`docs/adr/`)

ADRs are point-in-time records — they don't decay the way prose docs do. Each ADR is dated at write-time; superseding ADRs reference the originals.

| ADR | Status | Notes |
|---|---|---|
| `001-cyrius-port-architecture.md` | 📦 Frozen — accepted | Port philosophy. References `cyrius.toml` in commentary (L58); informational only — not a recipe. No refresh owed. |
| `002-backend-dispatch-fnptr-table.md` | 📦 Frozen — accepted | The dispatch-table pattern. Reinforced by every backend_* module shipping the same slot layout. |
| `003-fixed-point-threat-scoring.md` | 📦 Frozen — accepted | ×1000 fixed-point for threat intent scoring. |
| `004-deferred-features.md` | 📦 Frozen — accepted | The deliberate-deferral list; the roadmap's v3.2 "blocked queue" mirrors this. |
| `005-v2-hardening-pass.md` | 📦 Frozen — accepted | P(-1) hardening pass — 9 CWE-class fixes. The mitigation set is implemented and tested. |
| `006-library-surface-and-bundle-generation.md` | ✅ Accepted — amended | `[lib]` + `cyrius distlib`. Amended in place at v3.11.13 (the `err_*` superseded note) and v3.12.6 (profiles: `[lib.confine]`, `distlib --all`, the re-verified consumer stdlib set, sigil from the consumer's snapshot). |
| `README.md` | 2026-04-13 | 📦 Frozen — index | ADR index; refresh only when a new ADR is added. |

Decision velocity is low. Open a new ADR only when a load-bearing decision is reversible and would benefit from a referenceable "we decided X because Y" artifact. The v3.1.0 modernization arc didn't earn one — the CHANGELOG entry carries the rationale.

---

## Tier 4 — Development (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-09-24 | ✅ Fresh | Header → **v3.12.6** / cc `6.6.6` / sigil `3.12.18` / samay `1.1.5` / ai-hwaccel `2.4.0`. The completed "Moving the cyrius pin to 6.6.6" section was removed (its record is CHANGELOG 3.12.6); Tech debt now carries the audit chain's torn tail, the undiagnosed aarch64 fork/exec failures under qemu-user, and agnos credential injection's Linux-shaped `sys_open`; the aarch64 raw-syscall item was fixed in 3.12.6. Future-facing only since v3.4.0. |
| `rust-old-removal.md` | 2026-05-10 | 📦 Frozen — historical | Doc fulfilled its purpose at v3.1.1: rust-old/ tree deleted (1.4 MB / 25,935 lines), parity audit re-verified, sed recipe applied to `src/main.cyr` header. Keep as historical reference (per-symbol Rust→Cyrius mapping is still useful archaeology). No refresh owed; if rust-old/ is restored from git history for any reason, re-open. |
| `stiva.md` | 2026-04-13 | 📁 Supplementary | Integration note for the stiva consumer. Refresh when stiva's Cyrius port lands (tracked in roadmap v3.2 blocked queue). |

---

## Tier 5 — Guides (`docs/guides/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-04-13 | 📁 Supplementary | Index. |
| `getting-started.md` | 2026-09-24 | ✅ Fresh | Toolchain → cc `6.6.6`; stdlib list completed; the chrono hand-include described as a harmless guard (fixed upstream in 6.5.28); sigil `3.12.18` with the snapshot note; samay / ai-hwaccel bullet added; agnosys pointer → CHANGELOG 3.5.0. Build → configure → execute walkthrough still tracks src/. |
| `composite-backends.md` | 2026-04-13 | 📁 Supplementary | Defense-in-depth merge rules. No manifest references; content tracks `src/composite.cyr`. |
| `threat-tracking.md` | 2026-04-13 | 📁 Supplementary | Intent scoring + OffenderTracker + decay tuning. No manifest references; content tracks `src/scanning_threat.cyr`. |

---

## Tier 6 — Examples (`docs/examples/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-04-13 | 📁 Supplementary | Index. |
| `01-hello-noop.md` | 2026-04-13 | 📁 Supplementary | Noop backend walkthrough. |
| `02-process-with-audit.md` | 2026-04-13 | 📁 Supplementary | Process backend + audit chain. |
| `03-scanner-verdicts.md` | 2026-04-13 | 📁 Supplementary | Scanner verdict surface + WARN redaction. |
| `04-offender-tracking.md` | 2026-04-13 | 📁 Supplementary | OffenderTracker across execs. |

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
