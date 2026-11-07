# Every exec keeps its 1 MiB capture buffer for good — OPEN

**Discovered:** 2026-11-06, by agnosai, measuring what a WASM call costs after 3.14.4 removed its input cap (agnosai
roadmap B40). **Severity:** Medium for a long-lived consumer. Nothing fails, and memory only goes up.
**Affects:** kavach 3.14.6, every backend's exec: `src/backend_wasm.cyr:342`, `backend_process.cyr:64`,
`backend_oci.cyr:278`, `backend_gvisor.cyr:124`, `backend_sy_agnos.cyr:298`, `backend_firecracker.cyr:114`,
`backend_sgx.cyr:134`, `backend_sev.cyr:69` and `backend_tdx.cyr:72`.
**Status:** 🔴 OPEN.

Each exec takes `alloc(out_cap)` or `alloc(PROCESS_MAX_OUTPUT)`, 1 MiB, from a global heap with no free, whatever the
payload writes. `backend_capture_finish` then hands that buffer to the `ExecResult` as its stdout
(`src/backend.cyr:270`), so it has to live as long as the result does, and nothing can give it back. A payload that
prints nothing costs what one printing 1 MiB costs.

| Backend | Payload | `alloc_used()` per exec | RSS |
|---|---|---|---|
| process | `/bin/true`, 400 execs | 1,051,136 B | 9.5 MB → 421 MB |
| wasm, wasmtime 50.0.1 | an empty guest, 100 execs | 1,051,440 B | 7.4 MB → 109.8 MB |

Measured on x86-64, Arch's kernel, in a consumer's process. ⚠ This is resident memory and not only address space, which
the buffer's size does not explain alone: a capture writes only what the payload wrote. Transparent huge pages over
the bump's 256 MB chunks would do it, and that is a guess and not a measurement. A host without them may read lower,
and `alloc_used()` will not.

At one call a second that is 3.6 GB an hour. agnosai cannot reach it: the buffer is inside the backend, and
`sandbox_exec` takes no allocator.

## Repro

```cyr
fn run(b, cmd) {
    var cfg = config_new();
    config_backend(cfg, b);
    config_timeout_ms(cfg, 5000);
    var s = sandbox_create(cfg);
    sandbox_transition(s, SandboxState.RUNNING);
    var r = sandbox_exec(s, cmd);
    sandbox_transition(s, SandboxState.STOPPED);
    sandbox_transition(s, SandboxState.DESTROYED);
    return r;
}

fn main() {
    alloc_init();
    kavach_init();
    run(KavachBackend.PROCESS, "/bin/true");
    var before = alloc_used();
    for (var i = 0; i < 400; i = i + 1) { run(KavachBackend.PROCESS, "/bin/true"); }
    # Reads 1,051,136. VmRSS in /proc/self/status climbs with it.
    return (alloc_used() - before) / 400;
}
```

## The ask

A result that costs what the payload wrote. Capture into a buffer that is reused, and copy `n` bytes into the result
at the end, so `/bin/true` costs its header. Or let a caller pass an allocator for the exec, so an arena can take
the buffer and the caller decides when it goes. Which one is kavach's call. The capture's 1 MiB ceiling is not the
problem and can stay.

**A note for either:** `ExecResult_stdout` is a pointer today and callers keep it, so a reused buffer needs that copy.
agnosai reads the stdout into a `Str` of its own straight after `sandbox_exec`, by `strlen`, and needs nothing past
that. Its tool tiers that go through kavach pay this per call: WASM today, and the process, Python and OCI tiers once
its roadmap B35 routes them here.
