# The WASM backend emits no store limits beyond memory size and fuel — OPEN

**Discovered:** 2026-11-05, by agnosai (roadmap B16 re-check). **Severity:** Low.
**Affects:** kavach 3.14.2, `_wasm_append_limits` (`src/backend_wasm.cyr:226`), with wasmtime 50.0.1.
**Status:** 🔴 OPEN.

`_wasm_append_limits` emits only `-W max-memory-size=…` and `-W fuel=…`. The argv captured by agnosai's probe is
`wasmtime run -W max-memory-size=67108864 -W fuel=1000000000 -- <module>`. There is no config setter or
passthrough for `max-instances`, `max-tables`, `max-table-elements`, `max-memories` or `trap-on-grow-failure`,
all of which wasmtime 50 offers (`wasmtime run -W help`).

**Ask:** config setters for them, emitted by `_wasm_append_limits`, with `trap-on-grow-failure` on by default.
**agnosai** would map its WASM policy onto them. The Rust line's store limits, which agnosai has not been able
to port, were 10 instances, tables and memories, and a trap on a failed grow.
