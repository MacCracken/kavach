---
name: Kavach Documentation Health
description: Living ledger of doc currency in the kavach repo — fresh / stale / read-through / evergreen / frozen, refreshed as docs are touched
type: state
---

# Documentation Health — kavach

> **Last refresh**: 2026-05-10 (initial audit at the v3.1.0 modernization cut — cyrius pin 4.5.0 → 5.10.34, `cyrius.toml` → `cyrius.cyml`, lib/ gitignored, CI/release modernized) | **Refresh cadence**: when docs are touched, update the affected row. Pair with the release dance, but no hard release attachment.
> **Scope**: This repo only (`kavach`) — root-level files (README, CHANGELOG, CLAUDE.md, etc.) plus the entire `docs/` tree, plus `benchmarks-rust-v-cyrius.md` at the root. The `rust-old/` tree is **deliberately excluded** — it's the pre-v3.0 Rust archive (slated for removal, see roadmap) and its inline docs are not maintained.

This is a **ledger**, not a one-time audit. Rewrite-in-place as docs change. Kavach is the sandbox-execution primitive for SY, stiva, kiran, AgnosAI, hoosh, bote, and aethersafta; stale backend / policy / scanner docs propagate downstream as consumer-side mis-integrations, so doc currency carries weight even though the doc surface is small (~22 files).

Pattern lifted from the majra ledger ([`majra/docs/doc-health.md`](https://github.com/MacCracken/majra/blob/main/docs/doc-health.md)) and the agnosys ledger upstream of it — same buckets, kavach-shaped tiers (ADRs are a real surface here; no audit/review cadence yet; one frozen benchmarks artifact at the root).

---

## At a glance — 2026-05-10 inventory

**~22 markdown files** total (8 root + 13 under `docs/` + 1 benchmarks artifact at root). Buckets at the v3.1.0 modernization cut:

| Bucket | Count | What it means |
|---|---|---|
| ✅ **Fresh — touched in the v3.1.0 modernization arc** | 5 | `CHANGELOG.md`, `VERSION`, `cyrius.cyml` (new), `.github/workflows/{ci,release}.yml`, `docs/development/roadmap.md`, `docs/doc-health.md` (this file). All carry the cyrius-5.10.34 / sigil-2.9.0 / lib-via-`cyrius deps` reality. |
| 🟡 **Stale — refresh in place** | 3 | `README.md` (says "Requires Cyrius ≥ 4.0.0" + references `cyrius.toml`; needs cc 5.10.34 + cyrius.cyml + `cyrius deps` flow), `CLAUDE.md` (Version field still reads v3.0.0; MSRV line is Rust-era and meaningless under Cyrius; `cargo fmt / clippy / audit / deny` references in the dev loop don't match the `cyrius audit` reality), `benchmarks-rust-v-cyrius.md` root file (snapshot at v3.0.0; see Tier-6 frozen note — refresh only if a new comparison snapshot is captured). |
| 🟠 **Read-through outstanding** | 2 | `docs/guides/getting-started.md` (mentions `cyrius.toml` for deps — needs swap to cyrius.cyml + sigil tag 2.9.0; otherwise the build-and-run flow still tracks src/). `docs/development/rust-old-removal.md` (references `cyrius.toml` in its post-removal sed recipe; needs read-through to confirm parity checklist is still accurate). |
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

**Queued for follow-up in 3.1.x:**
- 🟡 `README.md` refresh — drop "Requires Cyrius ≥ 4.0.0", swap `cyrius.toml` → `cyrius.cyml`, add `cyrius deps` step before build.
- 🟡 `CLAUDE.md` refresh — drop Rust-era MSRV line, swap `cargo fmt / clippy / audit / deny` references to `cyrius fmt / lint / vet / audit`, bump Version field to v3.1.0.
- 🟠 `docs/guides/getting-started.md` read-through — manifest reference swap; verify the build/configure/execute walkthrough still tracks src/.
- 🟠 `docs/development/rust-old-removal.md` read-through — confirm parity checklist accuracy, swap `cyrius.toml` to `cyrius.cyml` in the post-removal sed recipe.
- ⚠️ **`cyrius fmt` drift** — pre-existing drift across nine src/ files and two tests/ files (see roadmap v3.2 `cyrius audit` clean item for the file list). CI runs fmt as `::warning::` informational at v3.1.0; flip to hard fail once drift is resolved against the cc 5.10.34 toolchain. Don't run `cyrius fmt` locally with a non-5.10.34 toolchain — fmt output is minor-version-sensitive and would commit new drift.

---

## Tier 1 — Root files

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-04-13 | 🟡 Stale | "Requires Cyrius ≥ 4.0.0" + `cyrius.toml` reference at L67 are pre-modernization. Queued for the 3.1.x refresh: bump floor to 5.10.34, swap manifest reference, document the `cyrius deps` step. The v1.x↔v3.0 comparison table is still accurate as a historical artifact. |
| `CHANGELOG.md` | 2026-05-10 | ✅ Fresh | v3.1.0 stanza records the modernization arc. v3.0.0 stanza unchanged. |
| `CLAUDE.md` | 2026-04-13 | 🟡 Stale | `MSRV: 1.89` is a Rust artifact and no longer load-bearing under Cyrius. `Version: v3.0.0` needs bump. Cleanliness-check lines reference `cargo *` tooling — swap to `cyrius fmt / lint / vet / audit`. Queued for 3.1.x. |
| `CONTRIBUTING.md` | 2026-04-13 | 🔵 Evergreen | Generic contributor workflow. Re-read annually. |
| `SECURITY.md` | 2026-04-13 | 🔵 Evergreen | Reporting policy + scope. Re-read annually. |
| `CODE_OF_CONDUCT.md` | 2026-04-13 | 🔵 Evergreen | Standard. |
| `VERSION` | 2026-05-10 | ✅ Fresh | `3.1.0` — single source of truth, read into `cyrius.cyml` via `${file:VERSION}`. |
| `LICENSE` | (initial commit) | 🔵 Evergreen | GPL-3.0-only. |
| `cyrius.cyml` | 2026-05-10 | ✅ Fresh | New in v3.1.0 — replaces `cyrius.toml`. cc pin 5.10.34, sigil pin 2.9.0, stdlib list mirrors src/. |
| `benchmarks-rust-v-cyrius.md` | 2026-04-13 | 📦 Frozen — snapshot | v2.0.0-Rust ↔ v3.0.0-Cyrius release comparison. Don't refresh in place; the next cross-language comparison (if any) gets a new dated file. Today the numbers stand as the cutover headliner. |

---

## Tier 2 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `overview.md` | 2026-04-13 | 📁 Supplementary | Module map + data flow. Last touched at the v3.0 cut. Re-read at the next feature work that lands a new module (seccomp / landlock / cgroups v2 — see roadmap v3.2 blocked queue). |

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
| `README.md` | 2026-04-13 | 📦 Frozen — index | ADR index; refresh only when a new ADR is added. |

Decision velocity is low. Open a new ADR only when a load-bearing decision is reversible and would benefit from a referenceable "we decided X because Y" artifact. The v3.1.0 modernization arc didn't earn one — the CHANGELOG entry carries the rationale.

---

## Tier 4 — Development (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-05-10 | ✅ Fresh | v3.1 cascade applied: prior "v3.1 — unblocking queue" renamed to "v3.2 — unblocking queue"; new "v3.1 — modernization arc (shipped)" section captures the cc-5.10.34 / cyrius.cyml / lib-via-deps / CI rewrite work. The cyrius `deps` symlink-bug roadmap item is **retired** — the new manifest uses `git`-based `[deps.sigil]` per majra/nein and no longer needs the path-symlink workaround. |
| `rust-old-removal.md` | 2026-04-13 | 🟠 Read-through | Per-symbol audit confirming Cyrius coverage + pre-removal checklist. Post-removal sed recipe at L115 references `cyrius.toml`; needs read-through during the rust-old/ deletion (which still sits in the v3.2 backlog). |
| `stiva.md` | 2026-04-13 | 📁 Supplementary | Integration note for the stiva consumer. Refresh when stiva's Cyrius port lands (tracked in roadmap v3.2 blocked queue). |

---

## Tier 5 — Guides (`docs/guides/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-04-13 | 📁 Supplementary | Index. |
| `getting-started.md` | 2026-04-13 | 🟠 Read-through | L15 references `cyrius.toml` for deps. Swap to `cyrius.cyml` + document the `cyrius deps` step. Otherwise the build → configure → execute walkthrough still tracks src/ as of the v3.0 cut. |
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
- **No `docs/development/issues/` directory.** Upstream issues filed by kavach live in the upstream repo. The cyrius `deps` symlink-bug item that the v3.0 roadmap carried is retired (resolved by the migration to git-based deps in the new manifest); no current self-internal blocker warrants a directory.
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

*Last refresh: 2026-05-10 (initial audit at the v3.1.0 modernization cut). Refresh in place when docs are touched.*
