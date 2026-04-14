# Contributing to kavach

## Development Process

1. **Build**: `cyrius build src/main.cyr build/kavach` (Cyrius ≥ 4.4.3)
2. **Test**: `cyrius test tests/kavach.tcyr` — 349 tests must pass
3. **Bench**: `cyrius bench tests/kavach.bcyr` — 15 benches; numbers in
   [benchmarks-rust-v-cyrius.md](benchmarks-rust-v-cyrius.md)
4. **Make changes**
5. **Re-test + re-bench** — regressions block merge
6. **Audit**: `cyrius audit` (fmt / lint / vet / deny) when the lint suite
   lands for this repo

## Rules

- Every security-sensitive change needs an ADR addendum or a new ADR.
  [ADR-005](docs/adr/005-v2-hardening-pass.md) is the template.
- Trust boundary modules (`audit.cyr`, `credential.cyr`, `quarantine.cyr`,
  `scanning_*`) require constant-time crypto + overflow-checked arithmetic
  + JSON escape on all user inputs — no exceptions.
- Backend additions use the `backend_register_exec/health/destroy` pattern
  in ADR-002. One file per backend, one `backend_<name>_register()` call
  in `kavach_init()`.
- Scanner additions: keep the existing 3-scanner pipeline shape (secrets /
  code / data) or discuss a 4th scanner's place in `gate_apply` first.
- Test additions: prefer asserting the verdict + finding categories over
  brittle content-string matching. Random-ID tests should avoid `> 0`
  checks (i64 rand can be negative).

## Code Style

- Cyrius conventions from the Cyrius language guide:
  `snake_case` fns, `PascalCase` for structs + enum types,
  `UPPER_SNAKE_CASE` for enum variants and global constants.
- Comments: `#` prefix, explain *why* not *what*. ADR/CVE references
  welcome (`see ADR-005 §C1`).
- No unnecessary abstractions — three similar lines beats one premature
  helper.
- Every `alloc(N + M)` where both summands are user-influenced must go
  through `checked_sum4` or `checked_add` + `alloc_checked`.

## Benchmark discipline

Add a bench to `tests/kavach.bcyr` whenever you add a hot-path operation.
Sub-µs ops use `bench_run_batch` (avoids clock-overhead skew); everything
else uses `bench_run`. Numbers go in `benchmarks-rust-v-cyrius.md` alongside
any Rust comparator.

## License

All contributions are licensed under GPL-3.0-only.
