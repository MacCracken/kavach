# `gate_apply` measures artifacts with `strlen`, so a secret after an embedded NUL is released as PASS — RESOLVED

**Filed by**: agnosai (Rust → Cyrius port, M7 — `kavach_bridge`, audit remediation)
**Date**: 2026-08-05
**Version**: kavach 3.11.6
**Severity**: High — the externalization gate under-scans, and the failure
direction is *release*. A credential the gate is there to catch is returned as
PASS.

**Status:** ✅ **RESOLVED in kavach 3.11.7** (2026-08-05). `ExecResult` gained
`stdout_len`/`stderr_len` (`-1` = unset → `strlen`, so every existing caller is
unchanged); `_concat_scan_buf` hands the scanners a buffer with no interior NUL,
which makes `strlen` correct for them rather than working around it, so **none
of the three scanners changed**; and `secrets_redact_n` redacts over a length
and reports the length it produced. The 23-byte NUL payload now BLOCKs.
Four regression tests, each mutation-verified. See the 3.11.7 section of
`CHANGELOG.md`.

## What happens

`gate_apply` takes its stdout/stderr as bare `cstring`s and measures them with
`strlen`:

```cyrius
# lib/kavach.cyr:5719
var total = strlen(stdout) + strlen(stderr);
...
# lib/kavach.cyr:5692-5701
fn _concat_with_nl(a, b) {
    var alen = strlen(a);
    var blen = strlen(b);
    ...
}
```

Every length in the scan path comes from `strlen`, so the artifact's real length
is never available to the gate. Two consequences, both measured:

**1. Under-scan — a secret after an embedded NUL is released.** The gate stops
at the first NUL and scans a prefix. Measured through
`agnosai_kavach_scan_output`:

```
"ok" NUL "AKIAIOSFODNN7EXAMPLE"   (23 bytes)  -> verdict 0 (PASS)
"ok" SP  "AKIAIOSFODNN7EXAMPLE"   (23 bytes)  -> verdict 3 (BLOCK)
```

Identical bytes but for one separator. The first scanned two bytes and passed a
live AWS-shaped key; the second scanned all 23 and blocked it.

**2. Over-read — a borrowed slice is scanned past its own end.** A Cyrius `Str`
built by `str_new` or `str_substr` shares its source's buffer and carries **no
terminator** (`lib/str.cyr:42-53`, `:634-640`). `strlen` on its data pointer
therefore runs on into whatever follows in the arena:

```
str_substr("clean-part|AKIAIOSFODNN7EXAMPLE", 0, 10)   -> verdict 3 (BLOCK)
the same 10 bytes as a literal                          -> verdict 0 (PASS)
```

Ten clean bytes blocked, because the scan read the credential sitting behind
them in memory. That direction is "merely" a false positive, but it is the same
root cause and it means the verdict depends on unrelated allocator contents.

## Why a consumer cannot fully fix this on its own

A consumer can pass a properly NUL-terminated copy, and agnosai now does — that
closes the over-read. It **cannot** close the under-scan, because the API has
nowhere to put the length: any byte sequence containing a NUL is untellable from
its own prefix once it becomes a `cstring`.

agnosai's workaround is to build a NUL-*free* copy — interior NULs replaced with
`\n`, which `_concat_with_nl` already uses as the stdout/stderr separator, so it
is a byte the scanners are known to treat as a boundary and no detector pattern
matches:

```cyrius
# src/sandbox/kavach_bridge.cyr — _agnosai_kavach_gate_bytes
var c = load8(src + i);
if (c == 0) { c = 10; }
store8(buf + i, c);
```

That scans the whole artifact and is correct for agnosai's purposes, but it is a
per-consumer copy of a transform that belongs behind the API, and it silently
mutates the artifact the gate reports on. A consumer that needs the gate to see
the exact bytes cannot have both.

**The oracle this port is checked against has neither problem**:
`rust-old/src/sandbox/kavach_bridge.rs:159` passes `stdout: output.to_string()`,
and Rust's `String` carries its length, so all 23 bytes are scanned and the
verdict is Block.

## How it was found

The agnosai M7 sandbox audit (2026-08-04) asked, per load-bearing line, "if I
deleted this, which assertion fails?". Every input in the bridge's test suite
was a `str_from("literal")` — whose bytes *are* NUL-terminated, because they sit
in the binary's data section — so no assertion could observe either half. The
suite was 93/93 green throughout.

## Reproduction

```cyrius
# Under-scan: a credential after an embedded NUL.
var nb = alloc(32);
memcpy(nb, "ok", 2);
store8(nb + 2, 0);                                  # the NUL
memcpy(nb + 3, "AKIAIOSFODNN7EXAMPLE", 20);
var r = exec_result_new();
ExecResult_set_stdout(r, nb);                       # 23 real bytes
ExecResult_set_stderr(r, "");
println_int(ScanResult_verdict(gate_apply(r, ext_policy_default())));   # 0 = PASS

# Control: the same 23 bytes with a space instead of the NUL.
store8(nb + 2, 32);
println_int(ScanResult_verdict(gate_apply(r, ext_policy_default())));   # 3 = BLOCK
```

Verified on kavach 3.11.6, cycc 6.5.6, x86-64 Linux, 2026-08-05.

## Proposed fix

Give the gate the length. Concretely, either:

1. **A length-carrying entry point** — `gate_apply_n(result, policy, out_len,
   err_len)`, or an `ExecResult` that stores lengths alongside its pointers, so
   `strlen` is never the measure. This is the complete fix and lets a consumer
   hand over exact bytes.
2. **A `Str`-taking overload** — `gate_apply_str(stdout: Str, stderr: Str,
   policy)`. Cyrius `Str` already carries a length, so this is the smallest
   change that closes both directions for a Cyrius consumer, and it matches how
   the rest of the ecosystem passes text.

Either way `_concat_with_nl` and the `max_artifact_size_bytes` check need the
same treatment — the size limit is computed from `strlen` too, so an artifact
with an embedded NUL currently under-reports its size to the cap as well.

**Not proposed**: rejecting artifacts containing NULs. That fails closed, which
is the right direction, but it would refuse legitimate binary tool output and
the gate's job is to scan it, not to refuse it.

## Consumer-side workaround (shipped)

`src/sandbox/kavach_bridge.cyr`'s `_agnosai_kavach_gate_bytes`, described above:
a NUL-terminated, NUL-free copy. It is mutation-verified — reverting to
`str_data(output)` fails two assertions in `tests/sandbox_kavach_bridge.tcyr`,
one per direction. `config_agent_id` had the same borrowed-pointer defect
(`lib/kavach.cyr:3459` stores the pointer verbatim) and now gets `str_cstr`;
that one is a genuine consumer bug and is not being asked of kavach.
