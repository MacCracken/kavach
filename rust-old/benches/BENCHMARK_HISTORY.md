# Benchmark History

Track performance across versions. Run `cargo bench` to regenerate.
Measurements are median values from criterion (100 samples).
Fork-heavy benchmarks (lifecycle, process_exec) have high variance due to OS scheduling.

---

## v0.21.3 — 2026-03-21 (post quality+perf audit, run 2)

**Changes:** exec_util extraction, single-pass secrets redaction, LazyLock regex caching,
landlock rules borrow, shell_words pre-alloc, Debug derives, visibility fixes.

| Benchmark | Median | vs Baseline | Notes |
|---|---|---|---|
| score_backend_process_strict | 2.10 ns | ~same | |
| score_all_backends_strict | 22.5 ns | ~same | |
| backend_available_all | 56.6 µs | ~same | PATH scanning dominates |
| detect_capabilities | 179 µs | ~same | reads /proc files |
| policy_strict_create | 21.0 ns | **1.4x faster** | |
| policy_serialize | 289 ns | ~same | |
| policy_deserialize | 353 ns | **1.1x faster** | |
| config_builder_full | 68.0 ns | **1.2x faster** | |
| config_serialize | 428 ns | ~same | |
| config_deserialize | 1.11 µs | noise | high variance |
| credential_env_vars_100 | 9.42 µs | noise | high variance |
| credential_file_injections_20 | 1.19 µs | ~same | |
| secrets_scan_clean_text | 516 ns | **1.1x faster** | |
| secrets_scan_with_secrets | 2.67 µs | noise | |
| secrets_redact | 1.02 µs | **2.4x faster** | single-pass replacement |
| gate_clean_output | 1.77 µs | noise | |
| state_valid_transition_check | 282 ps | ~same | optimized away by compiler |
| sandbox_full_lifecycle | 3.86 ms | noise | fork+exec jitter |
| health_check_noop | 199 ns | noise | |
| seccomp_build_basic | 2.16 µs | ~same | |
| seccomp_build_strict | 6.38 µs | noise | |
| process_exec_echo | 3.53 ms | noise | fork+exec jitter |
| process_exec_echo_with_seccomp | 3.80 ms | noise | fork+exec jitter |

---

## v0.21.3 — 2026-03-21 (pre-audit baseline)

First benchmark run before quality and performance audit.

| Benchmark | Median | Notes |
|---|---|---|
| score_backend_process_strict | 1.70 ns | |
| score_all_backends_strict | 20.9 ns | |
| backend_available_all | 54.3 µs | |
| detect_capabilities | 174 µs | |
| policy_strict_create | 29.6 ns | |
| policy_serialize | 282 ns | |
| policy_deserialize | 391 ns | |
| config_builder_full | 84.8 ns | |
| config_serialize | 455 ns | |
| config_deserialize | 681 ns | |
| credential_env_vars_100 | 7.84 µs | |
| credential_file_injections_20 | 1.11 µs | |
| secrets_scan_clean_text | 590 ns | |
| secrets_scan_with_secrets | 2.18 µs | |
| secrets_redact | 2.45 µs | 16x sequential replace_all |
| gate_clean_output | 1.47 µs | |
| state_valid_transition_check | 241 ps | |
| sandbox_full_lifecycle | 3.06 ms | |
| health_check_noop | 166 ns | |
| seccomp_build_basic | 2.22 µs | |
| seccomp_build_strict | 5.87 µs | |
| process_exec_echo | 3.05 ms | |
| process_exec_echo_with_seccomp | 3.13 ms | |
