# `InjectionMethod.STDIN` collides with `io.cyr`'s `var STDIN` and collapses onto `ENV_VAR`

**Status:** open. Filed from **agnosai 2.0.5** (kavach 3.11.15 → 3.12.2), found by a
`lib/`↔`lib/` symbol sweep run *before* the bump rather than after.

**Severity:** a **credential-routing** defect, not a cosmetic name clash. It is **live in the
emitted binary** for any consumer whose include ordering puts `lib/io.cyr` last — measured
below in agnosai's exact dependency set — but **no current consumer reaches the code
path**: `grep -rn 'secretref\|SecretRef\|credential_\|inject_via' src/` returns **zero** hits
in both agnosai and Agnostic. It is filed now because it is silent, it is already wrong in a
shipped binary, and the next caller of `secretref_stdin()` inherits it.

## The collision

| definition | file | value |
|---|---|---|
| `var STDIN = 0;` | `lib/io.cyr:62` (cyrius stdlib) | POSIX fd 0 |
| `STDIN = 2;` in `enum InjectionMethod` | `src/credential.cyr:10` | third injection method |

Cyrius has one flat symbol table with **last-definition-wins**, and is **silent** for `var`
and for enum members — only a duplicate `fn` warns. `io` is a declared leaf in kavach's own
`dist/kavach.deps`, so the two are co-resident in essentially every kavach consumer.

## What it does, measured

`InjectionMethod` numbers its members `ENV_VAR = 0`, `FILE = 1`, `STDIN = 2`. When
`io.cyr` wins the ordering, `STDIN` becomes **0** — and `ENV_VAR` is **also 0**. The two
members become **indistinguishable**, so both guards in `credential.cyr` fire on both kinds
of reference:

```cyrius
# src/credential.cyr:99   — builds the payload's environment
if (SecretRef_inject_via(r) == InjectionMethod.ENV_VAR) { ... }
# src/credential.cyr:162  — writes the secret to the payload's stdin
if (SecretRef_inject_via(r) == InjectionMethod.STDIN)   { ... }
```

A ref created by `secretref_stdin()` (`src/credential.cyr:44`) stores 0, so it now satisfies
the **ENV_VAR** branch: **a secret the caller asked to be delivered on stdin is exported into
the sandbox's environment instead** — readable via `/proc/<pid>/environ`, inherited by every
child, and liable to be logged. The converse also holds: an `ENV_VAR` ref satisfies the
STDIN branch. `FILE = 1` is unaffected.

This is the same class as
`archived/2026-08-20-backend-count-collides-with-ai-hwaccel.md` — a silent duplicate `var`
resolving to the wrong value — and it is the concrete instance that issue predicted when it
closed with:

> ⚠ **Not fixed, and still live:** kavach's `KavachBackend` *members* remain generic and
> unprefixed … a future library defining `PROCESS` would hit it silently.

Renaming `enum Backend` → `KavachBackend` could not have helped here: in Cyrius the enum
**qualifier is cosmetic** — only the member name resolves — which that issue also recorded.

## Repro — measured, not inferred

`docs/development/issues/repros/2026-08-22-stdin-collision.cyr`, built against **agnosai
2.0.5's exact `[deps]` set** (sigil 3.12.9, bote 3.3.3, majra 2.6.7, kavach 3.12.2,
ai-hwaccel 2.3.18, tyche 1.0.1) on cyrius 6.5.32:

```cyrius
fn main(): i64 {
    alloc_init();
    if (InjectionMethod.STDIN == InjectionMethod.ENV_VAR) { return 1; }
    return 0;
}
```

**Exits 1 — aliased.** A second probe returning `STDIN` directly exits **0**, confirming
io.cyr's definition is the one that survives. Build is clean: no error, and **no warning
mentions `STDIN`** — the compiler is silent for `var` and enum members, which is the whole
problem.

⚠ **kavach's own suite cannot catch this**, and its 713 green assertions are not evidence
against it. Which definition wins depends on the *consumer's* include ordering, so the
defect exists only in downstream binaries. Any regression test for it has to assert the
member's value in a unit that also includes `io.cyr`.

## Suggested fix

Prefix the members, exactly as 3.11.15 did for the `BACKEND_COUNT` family:

```cyrius
enum InjectionMethod {
    KV_INJECT_ENV_VAR = 0;
    KV_INJECT_FILE    = 1;
    KV_INJECT_STDIN   = 2;
}
```

Breaking for any caller naming the members — a grep across agnosai and Agnostic `src/`
returns **zero** uses, so the blast radius is kavach-internal today. Worth doing together
with the rest of the unprefixed-member sweep the `BACKEND_COUNT` issue deferred
(`PROCESS`, `WASM`, `OCI`, `NOOP`, `ENV_VAR`, `FILE`, …) rather than as a one-symbol patch:
the defining property of this class is that fixing instances one at a time leaves the next
one live.

Worth adding alongside it: an assertion in `tests/kavach.tcyr` that includes `lib/io.cyr`
and checks each `InjectionMethod` member against its literal value. Without a unit that
holds both definitions, no test in this repo can observe the failure.

## Why it cannot be worked around downstream

A consumer cannot fix this. Renaming in agnosai changes nothing — both definitions live in
`lib/`, vendored from the toolchain snapshot and the dep dists. The only place the name can
change is here.

⚠ **Nothing in the ecosystem gates this class.** `check-symbols.sh` in agnosai scans `src/`
only; Agnostic's adds a `src/`↔`lib/` rule; **neither looks at `lib/`↔`lib/`**, which is
exactly where this and `BACKEND_COUNT` both live. A gate for it is being added to the
consumers in the same pass that filed this.
