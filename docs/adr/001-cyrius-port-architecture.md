# ADR-001 — Cyrius port architecture

**Status**: Accepted
**Date**: 2026-04-13
**Version**: v3.0.0

## Context

Kavach v1.x shipped as a Rust crate (25,935 LOC, 10 backends, 872 tests). The
AGNOS ecosystem is migrating from Rust to [Cyrius](https://github.com/MacCracken/cyrius)
— a self-hosting systems language with zero external dependencies. Kavach is in
migration-strategy Wave 5 (Security + Infrastructure).

The port must:

- Preserve the public API shape enough that downstream consumers (SY, stiva,
  kiran, AgnosAI, hoosh, bote, aethersafta) can port incrementally.
- Hold the same trust story — HMAC-SHA256 audit chain, credential proxy,
  scanning gate.
- Build on the Cyrius feature set as of toolchain v4.0.0 — no floats in core,
  no generics, no traits beyond `impl X for Y`, no async.
- Leave a clear extension pattern for the 10 backends instead of porting them
  all in one pass.

## Decision

Structure the port as **20 small include-based modules** rather than mirroring
Rust's `mod.rs` hierarchy 1:1. Each module is independently testable and maps
cleanly to a Rust source file.

Layer the system in three tiers:

1. **Pure data** (error, backend, policy, scoring, lifecycle, scanning_*, threat)
   — Cyrius structs + accessors (`#derive(accessors)`), no I/O, no state.
2. **Trust primitives** (audit, credential, quarantine) — file I/O + crypto, but
   no backend dispatch.
3. **Orchestration** (backend_dispatch, backend_<name>, sandbox_exec) — ties the
   above together via the dispatch table.

Defer everything that depends on unlanded Cyrius stdlib features, but stub them
with clear TODO markers and **do not let the deferred surface leak into the
public API**. A consumer using kavach v3.0 today should not see `async` ghosts
or `Option<Uuid>` fields that are permanently `None`.

## Consequences

**Positive**
- One-module-per-concern keeps diffs reviewable. Adding an 11th backend is a
  single-file PR.
- The layer separation means the trust core (audit, credentials) can be audited
  independently of backend plumbing.
- ~44% line reduction vs Rust (~5.4K → ~3K so far) — consistent with
  migration-strategy expectations for Wave 5.

**Negative**
- Cyrius' `include` is textual. Re-including a module in `main.cyr` and
  `tests/kavach.tcyr` requires keeping both lists in sync. Mitigated by
  `cyrius.toml` auto-includes once deps stabilize.
- No ownership/borrow-check means the caller is responsible for lifecycle of
  heap allocations (e.g., ScanResult, AuditChain). This is a one-time
  adjustment; the bump allocator pattern is well-understood in the Cyrius
  ecosystem.

**Neutral**
- Some Rust semantics (Send + Sync, async Result, `#[non_exhaustive]`) have no
  Cyrius counterpart. The port defaults to synchronous, mutable-through-pointer
  semantics. Future Cyrius capabilities (ownership rollout — see Cyrius
  roadmap v4.5+) will let us tighten this.

## Alternatives considered

- **Rewrite-the-whole-thing monolithic main.cyr**: rejected. A 3K-line single
  file is unreviewable and blocks parallel porting.
- **Port each Rust module to a Cyrius "dist" bundle** like sigil/patra: rejected.
  Kavach is an application, not a library consumed via cyrius.toml by others.
  The single-crate layout matches how consumers already depend on it.
- **Mirror Rust's async/Result/trait shape via emulation layers**: rejected.
  Adds complexity without buying anything — consumers are rewriting their call
  sites anyway.
