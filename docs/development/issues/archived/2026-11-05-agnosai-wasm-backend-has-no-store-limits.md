# The WASM backend emits no store limits beyond memory size and fuel — RESOLVED

**Discovered:** 2026-11-05, by agnosai (roadmap B16 re-check). **Severity:** Low.
**Affects:** kavach 3.14.2, `_wasm_append_limits` (`src/backend_wasm.cyr:226`), with wasmtime 50.0.1.
**Status:** ✅ **RESOLVED in kavach 3.14.4**, as asked; see the resolution at the end.

`_wasm_append_limits` emits only `-W max-memory-size=…` and `-W fuel=…`. The argv captured by agnosai's probe is
`wasmtime run -W max-memory-size=67108864 -W fuel=1000000000 -- <module>`. There is no config setter or
passthrough for `max-instances`, `max-tables`, `max-table-elements`, `max-memories` or `trap-on-grow-failure`,
all of which wasmtime 50 offers (`wasmtime run -W help`).

**Ask:** config setters for them, emitted by `_wasm_append_limits`, with `trap-on-grow-failure` on by default.
**agnosai** would map its WASM policy onto them. The Rust line's store limits, which agnosai has not been able
to port, were 10 instances, tables and memories, and a trap on a failed grow.

## Resolution (3.14.4)

`config_wasm_max_instances`, `config_wasm_max_tables`, `config_wasm_max_table_elements` and
`config_wasm_max_memories` each set the wasmtime `-W` option of that name. 0, the default, leaves the bound to
wasmtime. `config_wasm_trap_on_grow_failure(c, on)` covers `trap-on-grow-failure`, on by default as asked.

Each was run under wasmtime 50.0.1 at its limit and over it: two tables at `max-tables=1` and `=2`, a
100-element table at `max-table-elements=10` and `=100`, two memories at `max-memories=1` and `=2`. A guest
growing past its ceiling traps by default, and with the trap off it reads -1 and exits as it chooses, for
`memory.grow` and `table.grow` alike.

⚠ The default changes what a guest sees. A guest at its memory ceiling used to get -1 from `memory.grow`, which
wasi-libc's `malloc` turns into NULL. It now traps, with a non-zero exit. A guest with its own answer to a
failed allocation calls `config_wasm_trap_on_grow_failure(cfg, 0)`.
