# Landlock confines 3 of 13 filesystem rights, so a confined process can still delete, rename and create anywhere on the host — RESOLVED

**Discovered:** 2026-08-03, planning agnosai's M7 sandbox milestone against [ADR-006](https://github.com/MacCracken/agnosai), which makes kavach's seccomp + Landlock the *entire* security boundary for untrusted tool code.
**Severity:** High — the confinement is materially weaker than its API implies, and the gap is silent.
**Affects:** kavach 3.11.0 (and every earlier version carrying `security_apply_landlock`).
**Status:** ✅ **RESOLVED in kavach 3.11.1** (2026-08-03). All thirteen ABI v1
rights are now named in `handled_access_fs`, plus `REFER` (v2) and `TRUNCATE`
(v3) where the running kernel knows them — see the 3.11.1 section of
`CHANGELOG.md`. Guarded by `test_landlock_denies_mutation_outside_allowed_path`,
which forks, confines the child for real, and is mutation-verified: restoring the
three-right mask makes it fail with the child's `unlink` succeeding.

## Summary

`security_apply_landlock` builds its ruleset with

```cyrius
# lib/kavach.cyr:1034-1035  (vendored; src/security/*.cyr upstream)
var handled_access = LANDLOCK_ACCESS_FS_READ_FILE
| LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_FILE;
```

Those are the only three rights declared anywhere in the file (`:984-986`).

**Landlock restricts only the rights named in `handled_access_fs`. Every right
*not* named remains fully permitted, everywhere on the filesystem.** So a process
confined by `security_apply_landlock` — including one confined through
`confine_child` (`lib/kavach.cyr:7871-7875`), which is the path every sandboxed
spawn takes — can still:

| operation | Landlock right | handled? | result |
|---|---|---|---|
| read a file | `READ_FILE` (4) | ✅ yes | refused outside the allowed path |
| write a file's contents | `WRITE_FILE` (2) | ✅ yes | refused |
| list a directory | `READ_DIR` (8) | ✅ yes | refused |
| **delete a file** | `REMOVE_FILE` (32) | ❌ **no** | **allowed anywhere** |
| **delete a directory** | `REMOVE_DIR` (16) | ❌ **no** | **allowed anywhere** |
| **create a directory** | `MAKE_DIR` (128) | ❌ **no** | **allowed anywhere** |
| **execute a binary** | `EXECUTE` (1) | ❌ **no** — not even declared | **allowed anywhere** |
| create sym/FIFO/sock/dev nodes | `MAKE_SYM` / `_FIFO` / `_SOCK` / `_CHAR` / `_BLOCK` | ❌ no | allowed |
| reparent across directories | `REFER` (8192, ABI v2) | ❌ no | allowed |
| truncate a file | `TRUNCATE` (16384, ABI v3) | ❌ no | allowed |

The read/write pair being handled is what makes this easy to miss: the obvious
smoke test — "confined process cannot read `/etc/passwd`" — **passes**, while
the same process can `unlink()` it.

## Reproduction

[`repros/2026-08-03-agnosai-landlock-handled-access.cyr`](./repros/2026-08-03-agnosai-landlock-handled-access.cyr).
Build from a project root that declares kavach (a bare `.cyr` gets no stdlib
auto-prepend):

```sh
echo victim > /tmp/agnosai_ll_victim.txt
mkdir -p /tmp/agnosai_ll_victimdir
cyrius build <repro>.cyr build/ll && ./build/ll
```

The probe applies `security_apply_landlock` with a single **read-only** rule on
one scratch directory, then operates outside it. Measured on kavach 3.11.0 /
cyrius 6.5.6, x86-64 Linux 7.1.5, 2026-08-03:

```
-- confined: read-only on one scratch dir --
  open(/etc/passwd, O_RDONLY)   REFUSED   [READ_FILE handled]
  open(victim, O_WRONLY)        REFUSED   [WRITE_FILE handled]
  mkdir(/tmp/agnosai_ll_newdir) ALLOWED   [MAKE_DIR NOT handled]
  unlink(victim.txt)            ALLOWED   [REMOVE_FILE NOT handled]
  rmdir(victimdir)              ALLOWED   [REMOVE_DIR NOT handled]
```

and afterwards, on disk:

```
  victim.txt DELETED by the confined process
  victimdir DELETED by the confined process
  newdir CREATED by the confined process
```

**One correction to an easy misreading**, because it narrows the report and the
narrower version is the true one: `O_CREAT` of a *regular file* is **not** a way
in. It needs `WRITE_FILE`, which *is* handled, so file creation is refused. The
holes measured here are directory creation, and deletion of both files and
directories. `EXECUTE` is listed above from the ABI rather than from a
measurement — it is not declared in the file at all, so it cannot be in
`handled_access`, but I did not probe it.

## Root cause

`handled_access` is a fixed three-right mask, and the per-rule `allowed_access`
below it (`:1061-1065`) only ever selects from the same three. Landlock's model
is *deny-by-default within the handled set, permit-everything outside it*, so
the mask is the whole security surface. Nothing else in the file widens it.

This reads like an incremental implementation that covered the obvious rights
first, not like a deliberate scoping decision — there is no comment recording a
choice to leave the others out.

## Proposed fix

Declare the full ABI v1 right set and put all of it in `handled_access`:

```cyrius
LANDLOCK_ACCESS_FS_EXECUTE     = 1;
LANDLOCK_ACCESS_FS_WRITE_FILE  = 2;
LANDLOCK_ACCESS_FS_READ_FILE   = 4;
LANDLOCK_ACCESS_FS_READ_DIR    = 8;
LANDLOCK_ACCESS_FS_REMOVE_DIR  = 16;
LANDLOCK_ACCESS_FS_REMOVE_FILE = 32;
LANDLOCK_ACCESS_FS_MAKE_CHAR   = 64;
LANDLOCK_ACCESS_FS_MAKE_DIR    = 128;
LANDLOCK_ACCESS_FS_MAKE_REG    = 256;
LANDLOCK_ACCESS_FS_MAKE_SOCK   = 512;
LANDLOCK_ACCESS_FS_MAKE_FIFO   = 1024;
LANDLOCK_ACCESS_FS_MAKE_BLOCK  = 2048;
LANDLOCK_ACCESS_FS_MAKE_SYM    = 4096;
```

Then extend `allowed_access` so `FS_READ_WRITE` grants the create/remove rights
*within its own path* — otherwise widening `handled_access` alone will break
every consumer that legitimately writes inside its allowed directory.

**Two ABI notes worth handling explicitly.** `REFER` (8192, v2) and `TRUNCATE`
(16384, v3) are rejected by older kernels: `landlock_create_ruleset` returns
`EINVAL` if `handled_access_fs` names a right the running ABI does not know. The
portable shape is to query the ABI version first
(`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`) and mask
down. The existing `ENOSYS`/`EOPNOTSUPP` → `Ok(0)` fallbacks (`:1047-1048`)
already establish the "degrade rather than fail" convention.

A test asserting a confined process **cannot** `unlink` outside its allowed path
would have caught this and would keep it caught.

## Consumer-side workaround

None available to agnosai. The mask is internal to `security_apply_landlock`,
and there is no parameter or setter that widens it — so a consumer cannot
compensate without forking the function, which would mean maintaining its own
copy of the confinement path.

**Impact on agnosai specifically:** ADR-006 states that because `cxvm` performs
no syscall filtering, "kavach's seccomp + landlock *are* the security boundary"
for untrusted tool code. That premise is weaker than assumed on the Landlock
half. agnosai's M7 is proceeding with the non-cx sandbox bites and is **holding
the cx confinement bite** until this is resolved or the boundary is
re-characterised, rather than shipping a sandbox whose escape test passes while
`unlink` is wide open. The seccomp half is unaffected by this report and may
independently block some of these calls depending on profile — that is worth
measuring separately, and it does not change the finding here.
