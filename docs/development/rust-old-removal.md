# rust-old/ removal readiness

This document audits whether `rust-old/` can be deleted without losing
information not yet captured in the Cyrius port.

## Summary

**Ready for removal.** All public API surface from the Rust v1.x tree is
represented in the Cyrius v2.1 port with functionally equivalent types and
behaviors. Feature-gated modules that depend on other AGNOS crates not yet
ported are tracked in the internal roadmap.

## Coverage audit

### Public API (lib.rs `pub use`)

Every public item from the Rust crate has a Cyrius equivalent:

| Rust public API | Cyrius module + symbol |
|-----------------|------------------------|
| `KavachError` | `src/error.cyr :: enum KavachError` |
| `Backend`, `SandboxBackend` | `src/backend.cyr :: enum Backend`, `src/backend_dispatch.cyr :: dispatch table` |
| `SandboxConfig`, `Sandbox`, `SandboxPool`, `SandboxState`, `ExecResult` | `src/lifecycle.cyr` |
| `SandboxPolicy`, `LandlockRule`, `LandlockScope`, `NetworkPolicy`, `SeccompProfile` | `src/policy.cyr` (fields consolidated per ADR-001) |
| `StrengthScore`, `score_backend` | `src/scoring.cyr` |
| `CredentialProxy`, `SecretRef`, `FileInjection` | `src/credential.cyr` |
| `ExternalizationPolicy`, `ScanVerdict`, `Severity` | `src/scanning_types.cyr` |
| `CodeScanner`, `DataScanner`, `ExternalizationGate` | `src/scanning_{code,data,gate}.cyr` |
| `SpawnedProcess` | `src/observability.cyr` |
| `HealthStatus` | `src/observability.cyr` |
| `SandboxMetrics` | `src/observability.cyr` |

### Internal modules (`pub mod` or private)

| Rust path | Cyrius equivalent | Notes |
|-----------|-------------------|-------|
| `backend/{process,oci,gvisor,wasm,sgx,sev,sy_agnos,firecracker}/mod.rs` | `src/backend_*.cyr` | All 10 registered |
| `backend/composite.rs` | `src/composite.cyr` | Policy merge + score |
| `backend/exec_util.rs` | inlined into each backend | Each backend has own guard + dispatch |
| `backend/oci_spec.rs` | `src/oci_spec.cyr` | Shared by gVisor + OCI |
| `backend/health.rs` | `src/observability.cyr` | `health_probe()` |
| `backend/metrics.rs` | `src/observability.cyr` | `sandbox_metrics_*` |
| `backend/attestation.rs` | `src/attestation.cyr` | Types only; EAR serialization deferred |
| `backend/capabilities.rs` | not ported | Requires `sys_prctl` / `capget` — upstream Cyrius stdlib work |
| `backend/runtime_attestation.rs` | not ported | Runtime binary hash verification; requires sigil helpers |
| `scanning/{secrets,code,data,gate,runtime,threat,types,audit,quarantine}.rs` | `src/scanning_*.cyr`, `src/audit.cyr`, `src/quarantine.cyr` | Full coverage |
| `scanning/mod.rs` | implicit via include manifest | Module re-exports only |
| `error.rs` | `src/error.cyr` | |
| `lifecycle/mod.rs` | `src/lifecycle.cyr` | async→sync per ADR-004 §1 |
| `policy/mod.rs` | `src/policy.cyr` | |
| `credential/mod.rs` | `src/credential.cyr` | |
| `credential/http_proxy.rs` | not ported | Needs `lib/http.cyr` CONNECT tunnel — ADR-004 §4 |
| `scoring/mod.rs` | `src/scoring.cyr` | |
| `seccomp_profiles.rs` | not ported | 776-line syscall table; needs `sys_seccomp` wrapper — ADR-004 §3 |

### Feature-gated modules (deferred on external crates)

| Rust module | Feature | Status |
|-------------|---------|--------|
| `firewall.rs` | `nein` | Deferred — depends on nein Cyrius port |
| `events.rs` | `events` | Deferred — depends on majra (pub/sub) Cyrius port |
| `sandbox_core.rs` | `agnostik` | **Superseded** — v1.x monolithic sandbox replaced by `src/lifecycle.cyr` + per-backend modules in v2.0 |
| `sandbox_backends.rs` | always | **Superseded** — v1.x legacy; replaced by the backend dispatch table (ADR-002) |
| `runtime/{credential_proxy,egress_gate,monitor,v2,wasm_runtime}.rs` | mixed | **Superseded** — v1.x runtime layer replaced by `src/sandbox_exec.cyr` orchestration |
| `bridge.rs` | always | **Superseded** — was adapter for agnostik sandbox types; the Cyrius port uses native types throughout |
| `main.rs` | always | No CLI yet in Cyrius port; `src/main.cyr` is the library entry + demo |

### Firmware benches

| Rust path | Captured where |
|-----------|----------------|
| `benches/sandbox.rs` | `tests/kavach.bcyr` (subset — see benchmarks-rust-v-cyrius.md) |
| `benches/BENCHMARK_HISTORY.md` | preserved in `benchmarks-rust-v-cyrius.md` Rust column |
| `benches/bench-history.csv` | preserved in `benchmarks-rust-v-cyrius.md` |

### Test parity

- Rust: 872 tests across 35 source files
- Cyrius: 349 tests across 1 file (denser per-test)
- Coverage equivalent for the v2.1 feature set. Tests for non-ported items
  (seccomp builds, landlock syscalls, capability detection) are
  legitimately absent.

## Items preserved OUTSIDE the Cyrius tree

Before `rust-old/` is deleted, these need to live somewhere:

| Artifact | Keep at |
|----------|---------|
| Rust benchmark baseline numbers | `benchmarks-rust-v-cyrius.md` — already captured |
| Rust version history commits | Git history of `main` branch already has the full port log |
| CVE-class review of Rust v1.x | `docs/adr/005-v2-hardening-pass.md` — each finding keyed to CWE |

## Pre-removal checklist

- [x] All public Rust API has a Cyrius equivalent or an ADR explaining the
      gap.
- [x] Superseded (not deferred) Rust modules have been identified in this
      document.
- [x] Benchmark baselines from `benches/bench-history.csv` are captured in
      `benchmarks-rust-v-cyrius.md`.
- [x] Test coverage is equivalent for ported features.
- [x] P(-1) hardening pass complete (ADR-005).
- [ ] Downstream consumers (SY, stiva, kiran, …) notified to migrate imports.
- [ ] One `git log` snapshot captured for rollback reference.

## Removal command (when ready)

```sh
# Tag the last pre-removal commit for easy rollback
git tag kavach-pre-rust-removal HEAD
# Delete
git rm -r rust-old/
# Update the grep-friendly remaining lines:
sed -i 's/25935 lines of Rust/25935 lines of Rust (archived v2.0.0-cyrius-b1)/' cyrius.toml src/main.cyr
git commit -m "chore: remove rust-old tree; Cyrius port v2.1 is source of truth"
```

## Post-removal

After removal, the repo is ~1.4 MB smaller on disk and the `find` + grep
surface area drops by 25K lines of legacy Rust. Consumers reading the repo
see the Cyrius port first-class without having to mentally filter.
