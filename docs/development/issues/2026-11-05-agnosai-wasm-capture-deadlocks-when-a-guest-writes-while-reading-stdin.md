# The WASM capture deadlocks when a guest writes while it reads stdin, and `timeout_ms` never fires — OPEN

**Discovered:** 2026-11-05, by agnosai (its 2.2.3 audit, re-checking its roadmap B16 against kavach 3.14.2).
**Severity:** High for any consumer that hands a WASM guest stdin. A guest can hold the calling thread
**for good**: the configured deadline does not bound it.
**Affects:** kavach 3.14.2 (`src/confine.cyr`, `confine_capture_input_env_wd` at `:531`), with wasmtime 50.0.1.
The shape dates from 3.11.8, which added the stdin pipe.
**Status:** 🔴 OPEN. Measured, not read.

## 1. What happens

`confine_capture_input_env_wd` writes the guest's whole stdin with one blocking `sys_write`, on a plain pipe,
**before** it enters the drain-and-deadline loop. A guest that reads all of its input and only then writes is
fine. A guest that writes while it reads fills its stdout pipe while kavach is still blocked writing its
stdin. From then on, kavach waits on stdin and wasmtime waits on stdout. The deadline is checked only inside
the drain loop, which kavach never reaches, so `timeout_ms` never fires.

## 2. Repro

- `repros/2026-11-05-wasm-capture-stdin-deadlock.cyr` runs a WASM guest through `sandbox_exec` with N bytes
  of stdin (`config_stdin`, `src/lifecycle.cyr:215`) and a 4 s `config_timeout_ms`.
- `repros/2026-11-05-wasm-capture-stdin-deadlock.wat` is the guest: it echoes stdin to stdout in 4 KiB chunks.

```sh
wat2wasm docs/development/issues/repros/2026-11-05-wasm-capture-stdin-deadlock.wat -o /tmp/stream.wasm
cyrius build docs/development/issues/repros/2026-11-05-wasm-capture-stdin-deadlock.cyr /tmp/kv_probe
timeout 20 /tmp/kv_probe /tmp/stream.wasm 200000
```

The probe was run by agnosai against its vendored copy of kavach, byte-identical to 3.14.2's `dist/kavach.cyr`.

## 3. Measured

| guest | input | result |
|---|---|---|
| reads all, then writes | 65,536 / 100,000 / 200,000 B | works |
| reads all, then writes | 1 MiB | 1,048,575 B back, cut by the 1 MiB stdout cap |
| echoes while reading | 100,000 B | works |
| echoes while reading | **200,000 B** | **hangs until the outer 20 s timeout**; the 4 s `timeout_ms` never fires |

The threshold is about two pipe buffers (64 KiB each by default): the stdin pipe and the stdout pipe both fill.

## 4. Ask

Deliver the input while stdout is drained: a non-blocking stdin write interleaved with the drain loop, or a
writer thread. At the least, let the deadline cover the stdin write, so a stuck guest is killed at
`timeout_ms` like any other. CHANGELOG 3.11.8 and `config_stdin`'s comment say a large input should go by
file, but nothing refuses one, and the failure is an unbounded hang, not an error.

## 5. In agnosai meanwhile

agnosai passes a WASM tool's parameters on stdin, and its request ceiling is 10 MiB. Since 2.2.3 it refuses
WASM input over one pipe buffer (64 KiB, `AGNOSAI_WASM_MAX_STDIN_BYTES` in its `src/sandbox/wasm.cyr`), the
bound under which the write cannot block. It lifts that cap when this is fixed.
