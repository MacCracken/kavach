# `BACKEND_COUNT` collides with ai-hwaccel — the `_backend_fp` bounds check is defeated

**Status:** 🔴 **OPEN** — memory-safety. The guard that exists to stop a wild function-pointer load
is disabled in any binary that links kavach and ai-hwaccel together.
**Severity:** **HIGH** — out-of-bounds function-pointer load followed by an indirect call.
**Discovered:** 2026-08-20, while linking AgnosAI in-process into **agnostic**.
**Affects:** kavach 3.11.14 + ai-hwaccel 2.3.17 co-resident. That is **agnosai 2.0.3** today
(`agnosai/cyrius.cyml` declares both), and therefore every consumer of `dist/agnosai.cyr`.

## Summary

Cyrius has one flat symbol table with last-definition-wins, and is **silent** on a duplicate `var`.
Two folded libraries define the same name with different values:

| | value |
|---|---|
| `lib/kavach.cyr:2914` | `var BACKEND_COUNT = 10;` |
| `lib/ai-hwaccel.cyr:706` | `var BACKEND_COUNT = 18;` |

kavach's dispatch guard reads it (`lib/kavach.cyr:8775`):

```cyrius
# config (backend_parse can yield -1); an out-of-range id would otherwise
# index _backend_table[320] out of bounds and load a wild function pointer.
# Returns 0 (== "no implementation") for any id outside [0, BACKEND_COUNT).
fn _backend_fp(backend_id, offset) {
    if (backend_id < 0) { return 0; }
    if (backend_id >= BACKEND_COUNT) { return 0; }
    return load64(_backend_slot(backend_id) + offset);
}
```

The comment states the guard's whole purpose. When ai-hwaccel's definition wins, the guard admits
**ids 10–17 against a 10-slot table**.

## The overrun, exactly

```
var _backend_table[320];        # lib/kavach.cyr:8764  → 320 bytes
var BACKEND_SLOT_SIZE = 32;     # lib/kavach.cyr:8765  → 320 / 32 = 10 slots
```

`_backend_slot(17)` = `_backend_table + 17 * 32` = `+544`. The table ends at `+320`, so the read is
**224 bytes past the end**. `_backend_fp` then `load64`s that as a function pointer, and
`backend_dispatch_exec` (`lib/kavach.cyr:8798-8805`) calls it:

```cyrius
var fp = _backend_fp(bid, 0);
if (fp == 0) { … return 0; }
return fncall2(fp, sandbox, command);
```

The `fp == 0` check does not help: whatever follows the table in `.bss` is unlikely to be zero, and
if it is non-zero it is called.

## Reproduction — measured, not inferred

In a project whose manifest links agnosai (which pulls kavach + ai-hwaccel):

```cyrius
# src/_bc.cyr
fn main(): i64 { alloc_init(); return BACKEND_COUNT; }
var _bc = main();
sys_exit_group(_bc);
```

```
$ cyrius build src/_bc.cyr /tmp/bcprobe
OK
$ /tmp/bcprobe; echo $?
18
```

**18, not 10.** Verified by exit code at cyrius 6.5.32.

## Why no gate catches it

- The compiler warns on a duplicate `fn` and is **silent** on a duplicate `var`. This is a `var`.
- kavach's and agnosai's `scripts/check-symbols.sh` scan `src/` only. This is a `lib/`↔`lib/`
  collision between two dependencies, which no consumer-side gate looks at.
- The build is otherwise clean — the project that found this compiles with **zero** undefined-function
  warnings.

Reachability depends on whether a backend id ≥ 10 can reach `backend_dispatch_exec`. Ids come from
sandbox configuration, and kavach's own comment notes `backend_parse` can yield `-1`, so ids are
parsed rather than always internal. Worth confirming from kavach's side whether config can produce
≥ 10; the guard was written on the assumption that it might.

## Suggested fixes

1. **Prefix it** — `KAVACH_BACKEND_COUNT`, and the same for ai-hwaccel. This is the ecosystem rule
   (`agnosai/scripts/check-symbols.sh` enforces exactly this for `src/`); the folded libraries are
   the gap. `BACKEND_SLOT_SIZE` and `_backend_table` are equally generic and equally exposed.
2. **Derive rather than declare** — `_backend_fp` could bound on `320 / BACKEND_SLOT_SIZE`, which
   cannot be shadowed by a sibling library and cannot drift from the table it guards.

(1) fixes the class; (2) makes this particular guard immune regardless.

Filing only — per this consumer's operating rule, dependency trees are not modified from a consumer
repo.

## Related

The same investigation counted **95 co-resident duplicate names** in one compile unit, 72 of them
`var`/enum where the compiler is silent. `BACKEND_COUNT` is the one confirmed to have differing
values on a memory-safety path; the rest are unaudited. A `lib/`-wide duplicate check appears to be
missing ecosystem-wide, not just here.
