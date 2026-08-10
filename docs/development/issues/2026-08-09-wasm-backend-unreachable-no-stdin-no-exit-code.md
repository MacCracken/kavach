# WASM backend: hardcoded unavailable, no stdin channel, no guest exit code

**Status:** 🔴 OPEN — filed by a consumer, not fixed here.
**Filed:** 2026-08-09, against kavach 3.11.7 as vendored in cyrius 6.5.16.
**Consumer:** agnosai's M11, porting `rust-old/src/sandbox/wasm.rs` +
`tools/wasm_tool.rs` + `tools/wasm_loader.rs` (955 lines) off wasmtime's embedded
API onto kavach. `agnosai/docs/adr/006-cx-tool-sandbox.md`'s 2026-08-07 correction
picked kavach's WASM backend as the target specifically because it passes `--fuel`,
`--max-memory-size` and `--dir` preopens.

Three findings. **The first is a one-line fix; the second is the one that decides
whether the backend can carry a tool protocol at all.** All three were verified by
reading the source, not inferred.

---

## 1. `backend_is_available` hardcodes WASM unavailable — `src/backend.cyr:95`

```cyr
if (b == Backend.WASM) { return 0; }
```

Every sibling probes: `Backend.GVISOR` → `which_exists("runsc")`, `Backend.OCI` →
`which_exists("runc")`/`crun`, `Backend.FIRECRACKER` → `which_exists("firecracker")`.
And `wasm_health` (`src/backend_wasm.cyr:155`) already does the correct probe for
WASM — it just is not what `backend_is_available` calls.

**Consequence:** `sandbox_create` refuses any config whose backend reports
unavailable, so the WASM path is unreachable **even with `wasmtime` installed**.
`wasm_exec` cannot be entered through the public API at all; `backend_dispatch_exec`
is never reached.

**Fix:** `if (b == Backend.WASM) { return wasm_health(0); }`, matching the shape of
the four backends around it.

---

## 2. `wasm_exec` has no stdin channel — and that is the whole tool contract

`wasm_exec` (`src/backend_wasm.cyr:108`) ends in `exec_capture(args, out_buf, out_cap)`.
`exec_capture` (`lib/process.cyr`) does `sys_dup2(wfd, 1)` only:

- **fd 0 is inherited from the parent.** There is no seam to write to.
- stderr is hard-redirected to `/dev/null`.
- envp is empty.

`confine_capture` has no stdin seam either. The only stdin-capable API in kavach is
`persistent_spawn_confined_ns(command, policy, require_ns)`, which takes a **bare
command string with no argv vector** — so it cannot express
`wasmtime run --fuel N --max-memory-size M -- module.wasm`.

**Why this is decisive rather than inconvenient.** Every WASM tool protocol in this
space is stdin-in / stdout-out. agnosai's oracle builds
`MemoryInputPipe::new(input.to_owned())` and hands it to the guest as fd 0
(`rust-old/src/sandbox/wasm.rs:128`), the tool wrapper marshals
`{"parameters":{…}}` into it (`tools/wasm_tool.rs:93-98`), and the published tool SDK
pins that wire format. A backend that cannot deliver stdin can run a `.wasm` module
but cannot **pass it arguments** — so it cannot host a tool, only a fixed program.

That is why agnosai is routing around kavach for this one path and spawning
`wasmtime` through its own `agnosai_spawn_capture_input`, the same primitive its cx
and python sandboxes use. It keeps kavach for confinement everywhere else. Recorded
on the consumer side as an ADR rather than left implicit.

**Ask:** an `exec_capture_input(args, input, input_len, out_buf, out_cap)` — or an
optional stdin argument on `confine_capture` — so a backend can pipe to the guest.
The process backend would benefit identically; today nothing kavach spawns can be
given input.

---

## 3. A guest's exit code is discarded — `backend_capture_finish`

```cyr
else {
    if (n >= out_cap) { n = out_cap - 1; }
    store8(out_buf + n, 0);
    ExecResult_set_exit_code(r, 0);      # <-- always 0 on any n >= 0
    ExecResult_set_stdout(r, out_buf);
    ExecResult_set_stderr(r, "");
}
```

`wasm_exec` never overrides it. Contrast the process backend, which sets
`ExecResult_set_exit_code(rr, confine_last_exit())`.

**Consequence:** a WASM module that traps, or exits non-zero, is reported as a
**success with empty stderr**. agnosai's oracle branches on `result.exit_code != 0`
for every failure mode it has, so through this backend every failing tool would read
as having succeeded with whatever partial stdout it managed. Silent, and in the
wrong direction.

Note stderr is also always `""` here because `exec_capture` sends it to `/dev/null`,
so there is no second channel to recover the failure from.

**Ask:** plumb the child's wait status through `backend_capture_finish` the way the
process backend does, and stop discarding stderr.

---

## Smaller

- **`wasm_health(0)` takes a `sandbox` parameter it does not use** for the probe
  case, which is why the fix in §1 can pass `0`. Worth a doc line, or a
  `wasm_available()` with no parameter.
- **`_wasm_binary_path()` probes three fixed locations** and returns 0 otherwise;
  the failure string `"wasmtime not found in PATH"` says PATH, which is only one of
  the three. Minor, but a consumer matching on that message will be confused when
  the binary is in `$HOME/.cargo/bin`.

## What is good and should not change

- `wasm_exec`'s **runtime-guard precheck on the module path** before it reaches the
  shell — a `.wasm` path containing shell metacharacters is refused rather than
  interpolated. That is the right default and stronger than the embedded-API design
  it replaces, which had no path to guard.
- `--fuel`, `--max-memory-size` and `--dir` preopens are all passed. Those three are
  exactly what makes this backend worth targeting: they are the deterministic CPU
  bound, the memory bound and the filesystem bound that the cx path cannot offer.
  Findings 1-3 are what stands between that and a usable tool host.
