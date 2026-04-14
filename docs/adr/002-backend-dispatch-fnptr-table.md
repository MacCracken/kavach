# ADR-002 — Backend dispatch via function-pointer table

**Status**: Accepted
**Date**: 2026-04-13
**Version**: v2.0.0

## Context

Rust kavach used a `SandboxBackend` trait + `Box<dyn SandboxBackend>`:

```rust
#[async_trait]
pub trait SandboxBackend: Send + Sync {
    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> Result<ExecResult>;
    async fn health_check(&self) -> Result<bool>;
    async fn destroy(&self) -> Result<()>;
}
```

Cyrius has no traits, no `dyn Trait`, no async. It does have function pointers
(`lib/fnptr.cyr`: `fncall0..fncall6`), enums with integer discriminants, and
global storage. We need an extension-friendly mechanism where downstream
modules can "register" a backend implementation at init time and callers
dispatch by `Backend` enum.

## Decision

Use a **flat function-pointer table indexed by the Backend enum value**.

```
var _backend_table[320];   # 10 backends × 32 bytes/slot

# Slot layout (32 bytes):
#   0: exec_fn     (sandbox, command) → ExecResult*
#   8: health_fn   (sandbox) → 1/0
#  16: destroy_fn  (sandbox) → 0 on success
#  24: reserved

fn backend_register_exec(backend_id, fp) {
    store64(&_backend_table + backend_id * 32 + 0, fp);
    return 0;
}

fn backend_dispatch_exec(sandbox, command) {
    var bid = SandboxConfig_backend(Sandbox_config(sandbox));
    var fp = load64(&_backend_table + bid * 32 + 0);
    if (fp == 0) {
        kavach_err_print(KavachError.BACKEND_UNAVAILABLE, backend_name(bid));
        return 0;
    }
    return fncall2(fp, sandbox, command);
}
```

Each backend module (`src/backend_<name>.cyr`) exposes a
`backend_<name>_register()` entry point that writes its three function
pointers into the table. `kavach_init()` calls each registered backend's
register fn; adding a new backend is a 3-line change.

## Consequences

**Positive**
- **O(1) dispatch** — a single indexed load.
- **Extensible without touching dispatch code** — new backends just register.
- **Fail-closed by construction** — unregistered slots contain 0 (zero-initialised
  BSS), dispatch returns 0, which propagates as
  `KavachError.BACKEND_UNAVAILABLE`.
- Compiles and runs cleanly on Cyrius 4.0.0 (no advanced features needed).

**Negative**
- **No compile-time check** that backend has a fn registered. A typo in the
  backend id, or forgetting to call register, surfaces at runtime as
  `BACKEND_UNAVAILABLE`. Mitigated by `test_dispatch_noop_registered`.
- **No per-backend state**: the trait pattern in Rust let each backend store
  config (e.g., `GVisorBackend{ runsc_path, ... }`). The fn-table version
  requires backends to stash per-instance state elsewhere — today we pass
  `sandbox` (which owns the config) and call back through accessors. Backends
  needing persistent per-instance state (firecracker vsock handles, oci image
  cache) will allocate via `alloc()` and attach via a
  `SandboxConfig.backend_state` field in a later iteration.

**Neutral**
- Function pointer type is not statically checked — Cyrius' fncall mechanisms
  don't enforce signatures. Convention + tests are the guarantee. This matches
  how the Cyrius stdlib already uses fnptr throughout.

## Alternatives considered

- **Switch statement in `backend_dispatch_exec`**: rejected. Every new backend
  requires touching the dispatch site — breaks the extension model. The whole
  point of this ADR was to avoid that.
- **Enum-tagged union (`match` per backend)**: Cyrius supports this, but same
  problem as switch: centralized dispatch site that all extensions must edit.
- **One-file-per-backend with `impl X for Y`**: Cyrius `impl` blocks are
  method-style resolution, not a dispatch table. Would require every call site
  to know the concrete backend type. Not what we want.

## Validation

- `test_dispatch_noop_registered` asserts that NOOP and PROCESS are registered
  after `kavach_init()` and that untouched backends (GVISOR, FIRECRACKER, etc.)
  remain unregistered.
- `test_sandbox_exec_noop` proves the dispatch path produces a valid
  `ExecResult*` through the NOOP backend.
- `test_process_backend_real_exec` proves a real fork+exec+capture through the
  PROCESS backend path.
