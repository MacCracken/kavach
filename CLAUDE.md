# Kavach — Claude Code Instructions

## Project Identity

**Kavach** (Hindi: armor/shield) — Sandbox execution framework — 10 backends, strength scoring (0-100), policy engine, 3-scanner pipeline, credential proxy (direct + HTTP), runtime guards, threat classification, audit chain

- **Type**: Cyrius binary (with first-party consumers; `[lib]` profile may earn a slot when a consumer starts embedding kavach at the source level)
- **License**: GPL-3.0-only
- **Language**: Cyrius (pinned at `5.10.34` in `cyrius.cyml` — same first-party tree gate as majra / nein / agnosys, locked by the sigil-NI asm-offset bisect; do not bump the pin without re-running the bisect)
- **Version**: SemVer, v3.1.0 (Cyrius port; Rust v1.x/v2.x archived in git history)
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Philosophy**: [AGNOS Philosophy & Intention](https://github.com/MacCracken/agnosticos/blob/main/docs/philosophy.md)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md)
- **Recipes**: [zugot](https://github.com/MacCracken/zugot) — takumi build recipes

## Consumers

SY (agent sandboxing), stiva (container isolation), kiran (WASM scripting), AgnosAI (crew sandboxing), hoosh (tool sandboxing), bote (MCP tool handlers), aethersafta (plugin isolation)

## Development Process

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, and open issues — know what was intended before auditing what was built
1. Test + benchmark sweep of existing code
2. Cleanliness check: `cyrius fmt` (no drift), `cyrius lint` (0 warnings), `cyrius vet src/main.cyr` (include-graph audit), `cyrius audit` (full chain — fmt/lint/vet/deny/test/bench/doc)
3. Get baseline benchmarks (`./scripts/bench-history.sh`)
4. Initial refactor + audit (performance, memory, security, edge cases)
5. Cleanliness check — must be clean after audit
6. Additional tests/benchmarks from observations
7. Post-audit benchmarks — prove the wins
8. Repeat audit if heavy
9. Documentation audit — ADRs, source citations, guides, examples (see Documentation Standards in first-party-standards.md)

### Development Loop (continuous)

1. Work phase — new features, roadmap items, bug fixes
2. Cleanliness check: `cyrius fmt` (no drift), `cyrius lint` (0 warnings), `cyrius vet src/main.cyr` (include-graph audit), `cyrius audit` (full chain — fmt/lint/vet/deny/test/bench/doc)
3. Test + benchmark additions for new code
4. Run benchmarks (`./scripts/bench-history.sh`)
5. Audit phase — review performance, memory, security, throughput, correctness
6. Cleanliness check — must be clean after audit
7. Deeper tests/benchmarks from audit observations
8. Run benchmarks again — prove the wins
9. If audit heavy → return to step 5
10. Documentation — update CHANGELOG, roadmap, docs, ADRs for design decisions, source citations for algorithms/formulas, update docs/sources.md, guides and examples for new API surface, verify recipe version in zugot; refresh `docs/doc-health.md` row for any doc you touched
11. Version check — `VERSION`, `cyrius.cyml` (which pulls VERSION via `${file:VERSION}`), recipe (in zugot) all in sync
12. Return to step 1

### Key Principles

- **Never skip benchmarks.** Numbers don't lie. The CSV history (`scripts/bench-history.sh`) is the proof.
- **Tests + benchmarks are the way.** Minimum 80%+ coverage target.
- **Own the stack.** If a first-party Cyrius crate wraps an external surface, depend on the first-party crate (sigil for crypto, sandhi for HTTP, patra for SQL, sakshi for tracing, agnosys for syscall glue).
- **No magic.** Every operation is measurable, auditable, traceable.
- **Borrow when you can, allocate only when you must.** Cyrius `Str` borrows over `cstring` copies; reuse buffers across calls in the hot path.
- **Vec arena over HashMap** — when indices are known, direct access beats hashing.
- **`include` over re-implementing** — the cyrius stdlib + the first-party tree carry shared primitives; consumers pull only what their entry points actually transitively reach.
- **Structured logging on every external operation** — backend exec, scanner verdict, audit-chain append, quarantine write all emit a trace line so the audit trail is reconstructable.
- **`# SAFETY:`** comment on every raw-syscall or pointer-arithmetic block — the line above must state the invariant the call relies on.
- **async-signal-safe only in pre_exec** — no heap allocation, no mutex, no tracing after fork.

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  architecture/overview.md — module map, data flow, consumers
  development/roadmap.md — completed, backlog, future, v1.0 criteria

docs/ (when earned):
  adr/ — architectural decision records
  guides/ — usage guides, integration patterns
  examples/ — worked examples
  standards/ — external spec conformance
  compliance/ — regulatory, audit, security compliance
  sources.md — source citations for algorithms/formulas (required for science/math crates)
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims MUST include benchmark numbers. Breaking changes get a **Breaking** section with migration guide.

## DO NOT
- **Do not commit or push** — the user handles all git operations (commit, push, tag)
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- **Do not bump the Cyrius pin** without re-running the sigil-NI asm-offset bisect across the first-party tree (majra / nein / agnosys / kavach all share the 5.10.34 pin for a reason)
- **Do not run `cyrius fmt` against a non-pinned local toolchain** — fmt output is minor-version-sensitive; running 5.10.44 fmt and committing creates new drift against CI's 5.10.34
- Do not commit `lib/` — it's gitignored; `cyrius deps` is the source of truth
- Do not commit `build/` — gitignored
- Do not add unnecessary dependencies — keep it lean
- Do not skip benchmarks before claiming performance improvements
