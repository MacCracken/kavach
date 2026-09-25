# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — `merge_policies` denied every path when either side had a landlock rule

`merge_policies` set `landlock_rules_len` to the sum of the two inputs' counts and never merged
their `landlock_rules` lists. A count over no list is the deny-all sentinel
(`policy_landlock_deny_all`), so `confine_child` installed a ruleset with no path rules and the
payload could open nothing, not even its own binary. The composite guide documents the rule as a
union ("Additive — both sets allowed"). The merge has failed closed this way since 3.11.3, when
`confine_child` began applying the rule list; before that, no landlock ruleset was applied at all.

Measured on 3.13.0. Policy `a` allows `/tmp`, `/usr`, `/lib` and `/lib64`; policy `b` allows
`/etc`; all read-only. `merge_policies(a, b)` gave `landlock_rules_len` 5 and `landlock_rules` 0.
Through `sandbox_exec` on the PROCESS backend, `/bin/cat` of a file in `/tmp` exited 0 with the
file's contents under `a`, and 127 with no output under the merge. With the fix it exits 0 with
the contents under the merge as well.

- **Union, as documented.** The merge copies both inputs' `security_fs_rule` entries into a fresh
  list, and its count is that list's length. Neither input's list is shared, so a later
  `policy_landlock_add` on the merge or on an input changes only that policy. Each input
  contributes the rules `confine_child` applies for it, its first `landlock_rules_len`. The union
  was checked against three sources, which agree: the guide's table, `composite.cyr`'s header
  ("additive (concat)"), and the Rust original, whose comment gives the reason: landlock names
  allowed paths, and the inner layer may need paths of its own.
- **A deny-all input keeps the merge deny-all**, as an empty list with a count of one. That side
  has said the payload gets no path, and a union would let the other side's rules hand it
  whatever they allow. (The payload `policy_landlock_deny_all` was written for, one reading its
  input from stdin, cannot start under it at all; see the next entry.) This is the stricter
  reading, the one `network_enabled` (AND) and the attestation merge take. It holds when the deny-all input's list
  also holds rules. Deny-all is recognised the way `policy_landlock_deny_all` writes it, a count
  above the list's length; the next entry makes a deny-all policy apply no rule on its own either.
- ⚠ **A composite exec whose policies name landlock rules now runs its payload.** On a kernel
  with landlock, from 3.11.3 through 3.13.0, the merge enforced deny-all and the payload's own
  binary could not be opened. It now gets the union of both policies' paths: the documented
  behaviour, and wider than what those releases enforced.
- `docs/guides/composite-backends.md`: the landlock rows (the list's union and deny-all), with the
  reasons. `composite.cyr`'s header no longer says the merge always takes the stricter side.

### Fixed — `policy_landlock_deny_all` left the policy's rules in force

`policy_landlock_deny_all` is documented as "Deny the payload every filesystem path", but on a
policy that named rules it set `landlock_rules_len` to the list's length plus one and kept the
list. `confine_child` and the persistent guest's child sequence passed the list and the count to
`security_apply_landlock`, which walks min(count, list length) rules, so every rule still
applied. Call order changed the meaning as well: `policy_landlock_add` after
`policy_landlock_deny_all` reset the count to the list's length and ended the deny-all. And the
merge above reads any count over the list as deny-all, so one policy allowed its rules alone and
denied every path merged.

Measured on this tree before the change (3.13.0's `policy.cyr`, `confine.cyr` and
`persistent.cyr`, with the merge fix above), landlock ABI 10. A policy allowing `/bin/cat`'s
runtime paths and a probe directory, then made deny-all (count 6 over a list of 5), read the probe
through `sandbox_exec` (exit 0) and as a persistent guest. With the calls the other way round
(count 5, list 5; the add returned 0), the same. `merge_policies` of the first with a plain policy
gave a count of 1 over an empty list, and `/bin/cat` exited 127 under it, directly and through
`composite_exec`. After the change none of these reads the probe, and the rules alone still do.

**Deny-all means no path.** The function's name and first doc line, the 3.11.3 entry that added it
("a ruleset that permits nothing"), the 2026-08-04 filing from agnosai it answered ("a total-deny
landlock"), the merge and the composite guide all read it that way. Only the `+ 1` did not, and
it made the call a no-op on any policy with a rule. The other reading, a ruleset only when there
are no rules, keeps that no-op: a caller who asked for no path would get the paths an earlier call
named.

- `policy_landlock_deny_all` replaces the list with a fresh empty one and sets the count to one,
  the form the merge gives a deny-all side. A caller holding the old list, or another policy
  sharing it, keeps its rules.
- `policy_landlock_add` returns -1 on a deny-all policy and leaves it deny-all. The two calls give
  the same policy in either order, as the merge does for two policies.
- One function now turns a policy into a ruleset in the child, `_spawn_apply_landlock`
  (`confine.cyr`), called by `confine_child` and by the persistent guest's sequence. For a
  deny-all policy it passes no list, so the ruleset names no path whatever the list holds; every
  other policy is walked as before. It makes no list in the child: for a count with no list, both
  paths used to allocate an empty one there, after `fork`.
- Added `policy_landlock_is_deny_all(p)`: whether the count is above the list. The child's step,
  `merge_policies` and `policy_landlock_add` all ask it, and `composite.cyr`'s private
  `_landlock_denies_all` is gone. A count set above a list of rules through the raw accessor is
  now deny-all in the child as well as in the merge; through 3.13.0 the child applied the whole
  list.
- ⚠ **A deny-all payload does not start, and never did.** Every path includes the payload's own
  executable: landlock goes on in the child before `execve`, and the exec opens the binary. Under
  a ruleset naming no path, `execveat` of the pinned binary fails with EACCES and the child exits
  127: measured with `/bin/true` and `/usr/bin/echo` through `sandbox_exec`, `/bin/cat` as a
  persistent guest, and `execveat`'s return in a forked child (-13, `/bin/true` and
  `/usr/bin/true`). This was already so on 3.13.0 for a deny-all policy with no rules.
  `policy.cyr` called deny-all "exactly right for a payload that needs no files", with agnosai's
  `cxvm` reading its bytecode from stdin as the example; that was never true for an exec'd
  payload, and the doc now says what the call does. A payload that has to start is confined with
  `policy_landlock_add`, naming its binary and, if it is dynamically linked, its loader and
  libraries.
- ⚠ **A policy that names rules and calls `policy_landlock_deny_all`, in either order, now denies
  every path, so its payload no longer starts** (exit 127). Through 3.13.0 it ran with its rules. A
  caller that used deny-all as a "deny everything else" switch should drop the call: landlock
  already denies every path the rules do not name.
- `docs/guides/composite-backends.md`: a deny-all policy applies no rule alone either, and a
  composite exec with a deny-all side does not start its payload.

### Fixed — the WASM backend ignored the policy's filesystem rules

`_wasm_append_preopens` read no landlock rule. It preopened the workdir, if one was set, and
nothing else, whatever the policy said. Its comment said the policy carried only a count, which
stopped being true at 3.11.3, and called the preopen read-only; wasmtime's `--dir` is read-write.
`score_backend` still added 3 for the rules on WASM.

Measured before the change with wasmtime 49 and landlock ABI 10, using a WASI probe that lists
its preopens and tries to read and write in each. A deny-all policy's guest read and wrote its
workdir. A policy allowing one directory, read-only or read-write, gave its guest the workdir
instead, or no directory at all when none was set. With no landlock the guest got the workdir,
and created a file in it.

**A policy with landlock is the guest's whole filesystem grant**, as it is for a process:

- Each rule the child would apply (the first `landlock_rules_len`) is preopened at its own path,
  as the Rust original mapped rules to WASI preopens. Nothing else is, the workdir included: a
  process under landlock cannot use its workdir either unless a rule names it.
- A deny-all policy preopens nothing. The guest still runs, because wasmtime reads the module on
  the host. On WASM, unlike the backends that exec their payload, a deny-all guest that reads its
  input from stdin can start.
- **Read-only rules are held by landlock on the wasmtime process.** wasmtime's CLI has no
  read-only preopen: wasmtime 49 accepts `--dir X::/a::ro` and ignores the `::ro`, and the Rust
  original used the API's `DirPerms::READ`. So the child confines wasmtime to the policy's rules,
  plus read-only access to what wasmtime needs: its binary, `/usr`, `/lib` and `/lib64` where
  they exist, and the module (see the next entry for why these began as the binary's and the
  module's directories). A guest's write under a read-only rule
  fails with WASI's EACCES. On a kernel without landlock nothing holds it, as on the process
  backend, and the guest still sees only the rules' directories, read-write.
- A confined run passes `-C cache=n`. Under the ruleset wasmtime cannot find its cache
  configuration ("config file not specified and failed to get the default"), so it compiles the
  module on every run.
- A path holding `::` is refused (exit 1) before wasmtime runs. `--dir` splits its value there
  into a host and a guest path, so `/srv/a::/etc` would preopen the host's `/srv/a` under the name
  `/etc`. This applies to the workdir as well.
- A rule on a missing path fails closed (exit 124), as on the process backend: landlock cannot
  open it.
- With no landlock nothing changes: the workdir, if set, is preopened read-write, and wasmtime
  runs unconfined. The comment now says read-write.
- Scoring is unchanged; its +3 for landlock rules now describes what WASM applies.
  `docs/architecture/overview.md` says so.
- ⚠ **A WASM guest under a policy with landlock rules now sees exactly those rules' directories.**
  It gains them (a rule allowing `/data` read-only now gives the guest `/data`), and it loses the
  workdir unless a rule names it; a deny-all guest loses the workdir too.

Found on the way, and fixed in the next entry: a landlock rule naming a file failed the exec
closed on every backend that applies landlock. So this entry first granted wasmtime the
directories of its binary and its module rather than the files. With file rules fixed, wasmtime
gets its binary and its module, each alone, and a rule naming a file gets no preopen.

### Fixed — a landlock rule naming a file failed every exec

`policy_landlock_add` accepts any path, and its doc said a rule allows "`path`, and everything
beneath it". But `security_apply_landlock` gave every rule the directory rights of its access
level: `READ_DIR` in the read-only mask, and the `MAKE_*`, `REMOVE_*` and `REFER` rights in the
read-write one. `landlock_add_rule` refuses rights that apply only to directories on a path that
is not one, with EINVAL. The child could not install the ruleset, so any policy naming a file
failed its exec closed (exit 124, `SPAWN_EXIT_LANDLOCK`). That held on the process backend,
`sandbox_spawn` and persistent guests from 3.11.3, when a rule could first be named, through
3.13.0, and on the WASM backend once the entry above gave wasmtime a ruleset.

Measured before the change on kernel 7.2.6 (landlock ABI 10). `security_apply_landlock` with one
rule on `/etc/hostname` returned "landlock_add_rule failed", errno 22, for both access levels;
the same rule on `/etc` applied. Through `sandbox_exec`, a policy allowing `/usr`, `/bin`, `/lib`
and `/lib64` and one file, all read-only, ran `/bin/cat` of that file to exit 124 and no output;
with the rule on the file's directory, cat read it. `/bin/cp` into a file a read-write rule named
exited 124 too, and so did a WASM guest whose policy named a file.

- **A rule naming a file now allows that file alone, with the rights a file can hold.** Having
  opened the rule's path, `security_apply_landlock` fstats it. For anything but a directory (the
  open follows a symlink) it masks the rule's rights with `_landlock_file_rights()`: EXECUTE,
  READ_FILE, WRITE_FILE and TRUNCATE. `FS_READ_ONLY` on a file is read and execute;
  `FS_READ_WRITE` adds write and, from ABI v3, truncate. Creating, removing or renaming the file
  takes a rule on its directory. Directory rules are unchanged.
- **The set is the kernel's.** Checked one right at a time on 7.2.6: a file takes EXECUTE,
  WRITE_FILE, READ_FILE and TRUNCATE, and refuses READ_DIR, the `MAKE_*` and `REMOVE_*` rights and
  REFER. That is the kernel's `ACCESS_FILE`, less `IOCTL_DEV` (ABI v5). `IOCTL_DEV` is a file
  right too, but kavach does not handle it (`_landlock_handled_access` stops at ABI v3), and a
  rule may grant only handled rights: on kavach's ruleset the kernel refused it.
- After the change, through `sandbox_exec`: `cat` of a file a read-only rule names prints it
  (exit 0), and a file beside it stays shut. `cp` into a file a read-write rule names writes it.
  Under a read-only rule on that file cp fails, leaving it unchanged, and a read-write rule on a
  file does not let cp create one beside it.
- `policy_landlock_add`'s doc says what a file rule allows.
- **The WASM backend.** wasmtime's host ruleset names its binary and its module, each alone,
  instead of their directories, which it named only because a file rule could not be applied. A
  rule naming a file gets no preopen, so the guest cannot reach that file: `--dir` takes only a
  directory (wasmtime refuses a file with "Not a directory"), and preopening the file's directory
  would hand the guest its siblings. A path that does not exist is still passed on and fails
  closed. With the security fix alone, wasmtime's refusal of `--dir` would have failed the exec
  instead of the 124.
- ⚠ **A policy naming a file now runs its payload with that file allowed.** Through 3.13.0 it
  failed every exec with 124: narrower than the rule asked for, and nothing ran.
- `docs/architecture/overview.md`: a rule names a directory or a file.

### Tests

Three tests, all of which fail against 3.13.0's merge (checked by restoring it: 18 assertions
fail across the three).

- `composite_merge_carries_landlock_rules`: the merged list holds both inputs' rules, each with
  its access, and the count is its length. The list is fresh: an add on the merge reaches neither
  input, and an add on an input does not reach the merge. A side with no rules adds none; with
  neither, there is no list. A count set below the list contributes only the rules it applies.
- `composite_merge_allows_either_sides_paths`: `/bin/cat` reads a path only the base allows and
  one only the overlay allows, under the merged policy through `sandbox_exec` and through
  `composite_exec`. Where landlock is present, a path neither allows stays shut, and the base
  alone cannot read the overlay's path.
- `composite_merge_deny_all_wins`: deny-all merged with rules (in either order), with a side that
  has no landlock, or with another deny-all gives an empty list and a count of one. So does a
  count above a list that holds rules, and a count with no list. The merge's list is not the
  deny-all input's, and an add on that input is refused. (Both changed with the deny-all fix:
  `policy_landlock_deny_all` no longer leaves rules in a list, and the add is refused.) Where
  landlock is present, a merge with deny-all reads nothing, directly and through
  `composite_exec`. The control, the same rules merged with a plain policy, reads the probe.

  Against 3.13.0 this test fails on its structural assertions and on the control. Its two denials
  pass there, because that merge denied every path whatever its inputs.

Five mutants of the fix, each failing the suite at the assertions written for it: reusing the
base's list (5 assertions), letting the other side's rules through a deny-all (7), ignoring the
count bound (1), dropping landlock from the merge (19), and recognising deny-all by effect, a
count over an empty list, rather than by the sentinel (1). These counts were taken before the
deny-all fix changed `composite_merge_deny_all_wins`.

Three tests for the deny-all fix, all of which fail against the code before it. They were built
against this tree's previous `src/`, with the new predicate stood in by the body of
`composite.cyr`'s old `_landlock_denies_all`: 17 assertions fail across the three, and 1 more in
`composite_merge_deny_all_wins` (the refused add).

- `landlock_deny_all_drops_the_rules`: rules then deny-all leaves an empty list and a count of
  one; it reads as deny-all, still takes the confined path, and leaves the list a caller held
  intact. An add after deny-all is refused, in either order, and the policy stays deny-all.
  Merged with a plain policy it is deny-all, as it is alone. The predicate answers 0 for a null
  policy, no landlock, rules, and a count below the list, and 1 for a count above the list (where
  an add is refused and the list left alone) and for a count with no list.
- `landlock_deny_all_denies_the_rules_paths`: the control, rules that let `/bin/cat` read the
  probe through `sandbox_exec` and as a persistent guest. Where landlock is present, the same rules
  with deny-all, in either order, read nothing on either path, and neither does their merge with a
  plain policy.
- `landlock_count_above_the_list_denies_all`: a count set above a list of rules through the raw
  accessor. Where landlock is present, neither `sandbox_exec` nor a persistent guest applies any
  of the list's rules; this runs before the add, which through 3.13.0 would have reset the count.
  Merged, the policy is deny-all; an add is refused and the list left as it was.

Seven mutants of the fix, each failing the suite at the assertions written for it: the child
walking a deny-all policy's list (2 assertions), `policy_landlock_deny_all` keeping the list (3),
`policy_landlock_add` not refusing (12), emptying the old list in place rather than replacing it
(2), the persistent guest or `confine_child` keeping its own inline walk (1 each), and the merge
recognising deny-all by effect, a count over an empty list. That one stops the suite in
`composite_merge_deny_all_wins`: the merge copies a count's worth of rules from a shorter list,
and `vec_get` aborts.

Three tests for the WASM fix, all of which fail against the backend before it: 24 assertions,
built against this tree's previous `backend_wasm.cyr`. The new `_wasm_host_policy` was stood in
there by a function returning the caller's policy, which is what the old code passed, with
wasmtime unconfined.

- `wasm_preopens_follow_the_policy`, which needs no wasmtime: with no landlock, the workdir, and
  nothing without one. A deny-all policy preopens nothing, not even the workdir. A policy with
  rules preopens exactly their paths, not the workdir. A count below the list preopens the rules
  it counts, and a count above it nothing. A path holding `::` is refused, as a rule or as the
  workdir.
- `wasm_host_policy_confines_wasmtime`, which needs no wasmtime: the ruleset holds the policy's
  rules with their access, wasmtime's binary, `/usr` and the module, and is not deny-all; the
  policy itself is left as it was. For a deny-all policy it keeps wasmtime's paths and names none
  of the policy's. A rule past the count is left out. As first written the test expected the
  binary's and the module's directories (`/` for a module under the root, the working directory
  for a bare name); the file-rule fix narrowed each to the file.
- `wasm_guest_sees_the_policys_paths`, with wasmtime: runs the probe in `tests/wasm_fs_probe.wat`,
  carried in the suite as 818 hand-assembled bytes. With no landlock the guest has its workdir and
  reads it. A deny-all guest runs with no directory. A guest under a read-only rule and a
  read-write rule has both directories and not its workdir, reads both, and writes in the
  read-write one; where landlock is present, it cannot write in the read-only one. A guest out of
  fuel still fails while confined, and a `::` rule is refused with the reason.

CI installs no wasmtime, so there the third test returns at once and the first two cover the
change.

Eight mutants of the fix, each failing the suite at the assertions written for it: deny-all
falling back to the workdir (3 assertions), rules also preopening the workdir (3), no `::` check
(4), wasmtime left unconfined (1: the read-only write, which needs wasmtime and landlock), the
host ruleset without the module's directory (11), no `-C cache=n` (7), the host ruleset taking
rules past the count (1), and a deny-all host ruleset (3). These counts were taken before the
file-rule fix changed `_wasm_host_policy` and these tests.

Two tests for the file-rule fix, and additions to the three WASM tests, all failing against the
code before it: 13 assertions, built against this tree's previous `src/` (nothing new to stand
in for).

- `landlock_rule_on_a_file_allows_reading_it`: where landlock is present, `/bin/cat` of a file a
  read-only rule names exits 0 and prints it, and a file beside it stays shut.
- `landlock_rw_rule_on_a_file_allows_writing_it`: where landlock is present, `/bin/cp` writes into
  a file a read-write rule names (its source named by a read-only file rule). Under a read-only
  rule on the destination cp fails and the file is unchanged. A read-write rule on a file cannot
  create one beside it, and a read-write rule on the directory can.
- The WASM tests: a rule naming a file is not preopened, while a missing path still is.
  wasmtime's ruleset holds its binary and the module, each alone and not its directory, for a
  module under the root (not `/`) and a bare name (not the working directory) alike. A guest
  whose policy names a file runs, has the directory rule's path, and cannot reach the file.

Seven mutants of the fix, each failing the suite at the assertions written for it: no file mask
(13 assertions), the mask on directory rules too (3), file rights without TRUNCATE (2) or
without WRITE_FILE (2), the WASM backend preopening a file rule (3), its host ruleset naming a
directory for the module (4), and its host ruleset without the binary (1). The mask on directory
rules was caught only by the WASM test until the read-write test gained its directory case.

### Verified

- x86-64: the suite, 971 → **1004**. fmt `--check` with no drift across the tree, lint with 0
  warnings, vet, `check-symbols.py`, the security scan, and fuzz (500). `cyrius distlib --all`
  changes only `dist/kavach.cyr` (`composite.cyr` is not in `[lib.confine]`), and its diff is the
  source's; `check-bundles.py` passes. The `duplicate fn` set is unchanged (130 names, all in
  `lib/`).
- aarch64: cross-built, and the suite 942 → **971** under qemu-aarch64 11.1.1. qemu-user reports
  landlock ABI 0, so the four assertions that need enforcement skip there, as the existing
  landlock tests' do. The agnos build links.
- With the deny-all fix, on x86-64 (kernel 7.2.6, landlock ABI 10): the suite, 1004 → **1037**;
  fmt `--check` with no drift across the tree, lint with 0 warnings, vet, `check-symbols.py`, the
  security scan, fuzz (500), the bench harness, and the smoke build. `cyrius distlib --all`
  changes both bundles this time, since `policy.cyr` and `confine.cyr` are in both profiles; every
  module section of each bundle matches its source, the `.deps` sidecars are unchanged, and
  `check-bundles.py` passes. The `duplicate fn` set is unchanged (the same 130 names).
- With the deny-all fix, on aarch64: cross-built, and the suite 971 → **997** under qemu-aarch64
  11.1.1. The seven new assertions that need landlock enforcement skip there. The agnos build
  links.
- With the WASM fix, on x86-64 (wasmtime 49): the suite, 1037 → **1074**; fmt `--check` with no
  drift, lint with 0 warnings, vet, `check-symbols.py`, the security scan, fuzz (500), the bench
  harness and the smoke build. `cyrius distlib --all` changes only `dist/kavach.cyr`, since
  `backend_wasm.cyr` is not in `[lib.confine]`; every module section of both bundles matches its
  source, and `check-bundles.py` passes. The `duplicate fn` set is unchanged (130 names).
- With the WASM fix, on aarch64: cross-built, and the suite 997 → **1033** under qemu-aarch64
  11.1.1. The WASM tests run there, since qemu execs the host's wasmtime, and the one assertion
  that needs landlock skips. The agnos build links.
- With the file-rule fix, on x86-64 (kernel 7.2.6, landlock ABI 10): the suite, 1074 →
  **1092**; fmt `--check` with no drift, lint with 0 warnings, vet, `check-symbols.py`, the
  security scan, fuzz (500), the bench harness and the smoke build. `cyrius distlib --all`
  changes both bundles, since `security.cyr` and `policy.cyr` are in both profiles; every module
  section of both bundles matches its source, and `check-bundles.py` passes, so the confine
  bundle compiles with the new `fstat`. The `duplicate fn` set is unchanged (130 names).
- With the file-rule fix, on aarch64: cross-built, and the suite 1033 → **1038** under
  qemu-aarch64 11.1.1. The process-backend file-rule assertions need landlock and skip there; the
  WASM additions run. The agnos build links.

### Performance

Two new benchmarks, recorded last in the harness so their allocations follow every other bench:
`merge_policies_plain` (no landlock rules, the common case) **197 ns** (191–211) and
`merge_policies_landlock` (four rules and one) **343 ns** (331–363), from one pinned run.
Carrying the rules costs about 150 ns per `composite_exec`, whose exec takes 2.7 ms.

The two are only in this tree, so `scripts/bench-ab.py HEAD .` (5 interleaved rounds per side,
pinned) compares the other 27. **26 show no measured change**; their ranges overlap, the exec
path included (`process_exec_confined` 2.704 → 2.703 ms).

- ⚠ **`http_path_extract` has separate ranges, 101 → 87 ns (−13.9%), on a function this change
  does not touch.** 3.12.9's A/B saw the same benchmark move with its function unchanged. Code
  placement is the likely cause, as there; it was not isolated.

The deny-all fix was measured against the merge fix (HEAD) with `scripts/bench-ab.py`'s own
sampling and comparison, 5 interleaved rounds per side pinned to CPU 15. The HEAD side was built
from a scratch copy of that commit's `src/`: the script's worktree under `/tmp` would have to
resolve the `../` path dependencies from there. **26 of 29 show no measured change**, among them
the exec paths, which now run `_spawn_apply_landlock` in the child (`process_exec_confined`
2.701 → 2.699 ms, `process_exec_echo` 2.707 → 2.694 ms), and both merges (`merge_policies_plain`
201 → 199 ns, `merge_policies_landlock` 347 → 342 ns). `policy_landlock_add`'s added check is not
on a benchmarked path.

- ⚠ **Three benchmarks on functions this change does not touch have separate ranges:**
  `state_valid_transition_check` 6 → 5 ns, `ct_streq_64` 198 → 206 ns (+4.0%) and
  `gate_clean_output` 355.97 → 344.31 µs (−3.3%). That is the pattern the earlier A/Bs recorded;
  code placement is the likely cause, and it was not isolated.

The WASM fix changes the WASM exec path, which no benchmark covers, so `wasm_exec` was timed
directly: the median of 21 runs of the probe, three rounds interleaved between the two builds,
pinned to one CPU. **A policy without landlock is unchanged, 5.4 → 5.4 ms. A policy with rules
goes from 5.4 ms (wasmtime unconfined and cached, the rules ignored) to 13.1 ms.**

- Most of that is `-C cache=n`: wasmtime compiling the module instead of loading it from its
  cache. Run directly, with fuel and the memory ceiling as `wasm_exec` sets them, the probe takes
  3.7 ms cached and 7.0 ms without the cache, and the cost grows with the module.
  `NO_NEW_PRIVS`, closing inherited descriptors and the landlock ruleset add about 0.1–0.3 ms
  (measured without the fuel and memory flags, where the run stays under the polling step below).
- The rest is the capture loop's polling, not work. It polls every 1 ms for its first 8 idle
  rounds and every 5 ms after, so a payload still running after about 8 ms is noticed at the next
  5 ms poll. The confined run crosses that line; the cached, unconfined run ends well inside it.
- Keeping the cache under confinement would take wasmtime's cache configuration and a writable
  cache directory in the ruleset. Not done.

The 29 benchmarks, `scripts/bench-ab.py`'s method against the deny-all fix (HEAD): **26 show no
measured change**, among them the exec paths (`process_exec_confined` 2.677 → 2.682 ms) and both
merges.

- ⚠ **Three benchmarks on functions this change does not touch have separate ranges:**
  `ct_streq_64` 205 → 198 ns (−3.4%), `http_allowlist_hit` 70 → 75 ns (+7.1%) and
  `http_allowlist_miss` 79 → 81 ns (+2.5%). `backend_wasm.cyr` is the only source file changed;
  code placement again, not isolated.

The file-rule fix adds one `fstat` per rule in the child, before the ruleset is applied: 455 ns on
an `O_PATH` descriptor (200,000 calls, three rounds, pinned), against an exec of about 2.7 ms. No
benchmark applies a landlock rule (`process_exec_confined` runs `policy_strict()`, which names
none), so the harness cannot see it. Against the WASM fix (HEAD), `scripts/bench-ab.py`'s method:
**28 of 29 show no measured change**, among them the exec paths (`process_exec_confined` 2.698 →
2.747 ms, ranges overlapping).

- ⚠ **`http_allowlist_miss` has separate ranges, 82 → 88 ns (+7.3%)**, on a function no source
  file this change touches reaches. Its neighbour `http_allowlist_hit` had separate ranges in
  the WASM fix's A/B and overlaps here; code placement, not isolated.

## [3.13.0] — 2026-09-25

TEE attestation I. kavach now verifies SGX and TDX quotes, and a `SandboxPolicy` can require
attestation: `sandbox_exec` then releases a guest's output only if its quote verifies to the
policy's root, carries the exec's nonce and names an allowed measurement. The cryptography is
sigil's; kavach adds the policy, the nonce, the debug check and the gate. kavach's own SGX and TDX
launchers cannot fetch a quote yet, so they refuse such a policy. The fetch stays open on the
roadmap: it needs hardware to be verified on. Also: a heap overflow in
`kavach_attestation_result_new`, a CI check that the dist bundles compile for a consumer (it
caught a confine-bundle break in this release before it shipped), and aarch64 recorded as
supported, apart from namespaces and rootfs entry. 879 → **971** assertions on x86-64; 850 →
**942** on aarch64 under qemu.

### Added — SGX and TDX quote verification (`src/attestation.cyr`)

`kavach_attest_quote(backend, quote, quote_len, policy, nonce, nonce_len, now)`, over
`kavach_attest_sgx_quote` and `kavach_attest_tdx_quote`, returns an `AttestationResult`. The first
check that fails makes it `KAVACH_TRUST_CONTRAINDICATED`, with the reason in `details`:

1. The policy names a root and a measurement, the nonce is 1 to 64 bytes, and `now` is not 0,
   which sigil reads as "skip the certificates' validity dates".
2. The quote parses: SGX DCAP v3 with a P-256 attestation key; TDX v4, P-256 or P-384.
3. It verifies to the policy's root through sigil 3.12.18's `*_quote_verify_full_into`: the PCK
   chain carried in the quote, walked to the root with each certificate's validity dates; the
   PCK's signature over the Quoting Enclave's report; that report's binding of the attestation
   key; and the attestation key's signature over the quote header and body.
4. The guest is not a debug guest, unless the policy allows one. SGX `ATTRIBUTES.DEBUG` is bit 1
   (Linux's `SGX_ATTR_DEBUG`), TDX `TD_ATTRIBUTES.DEBUG` bit 0 (`TDX_TD_ATTR_DEBUG`).
5. The report data starts with the nonce.
6. The measurement is allowed: MRENCLAVE for SGX, MRTD for TDX.

A pass is `KAVACH_TRUST_AFFIRMING`, or `KAVACH_TRUST_WARNING` for a debug guest the policy allowed.
`kavach_attest_passes(result, policy)` says whether a result lets output through;
`attestation_is_acceptable` cannot, because `NONE` (no attestation done) sits above `WARNING` in its
order. The measurement, MRSIGNER and ISVSVN are reported only once step 3 has passed. sigil's
verifier works in a 64 KiB arena that kavach resets for each quote, so repeated verification does
not grow the heap.

**Not evaluated**, and `details` says so on every pass: Intel's TCB level, QE identity and
revocation. They need collateral sigil does not evaluate, so a genuine platform with an
out-of-date or revoked TCB passes. For TDX, the RTMRs, which measure the kernel and its command
line, are not checked; the allowlist pins MRTD, the TD's firmware.

### Added — the measurement allowlist in `SandboxPolicy`, and the gate in `sandbox_exec`

- `policy_attest_allow(p, hex)` allows a measurement: 64 hex digits for MRENCLAVE, 96 for MRTD,
  upper case folded, -1 for anything else. One entry makes the policy require attestation
  (`policy_wants_attestation`).
- `policy_attest_root(p, der, len)` sets the root; the bytes are copied. kavach ships no root. In
  production it is Intel's SGX root CA, which TDX quotes chain to as well.
- `policy_attest_allow_debug(p, on)`, off by default.
- `SANDBOX_POLICY_SIZE` 104 → 136. The four fields are appended, so no existing offset moves.
  `policy_new` zeroes them.

Under a policy that requires attestation, `sandbox_exec`:

1. refuses a backend that cannot attest (anything but SGX and TDX), before anything runs;
2. draws a 32-byte nonce from `getrandom`, or takes the caller's: `sandbox_exec_set_attest_nonce`
   carries a relying party's challenge and is used once;
3. dispatches. The backend has its guest put `backend_attest_nonce()` at the start of the quote's
   report data, and hands the quote back with `backend_attach_quote(buf, len)`;
4. verifies the quote as of the wall clock (`sandbox_exec_set_attest_time` overrides it, for
   recorded evidence and fixtures), records the trust level in the audit chain, and returns 0,
   withholding the output, unless the result passes. `sandbox_exec_last_attestation()` keeps it.

The nonce and quote are cleared on every path out of the dispatch, so none is left for the next.
The paths that cannot check a quote refuse a policy that requires one: `sandbox_spawn`,
`persistent_spawn_confined[_ns]` and `composite_exec`. `merge_policies` keeps the requirement: if
either input requires attestation the merge does, the allowlists are intersected, and debug is
allowed only if both allow it. Two different roots, or allowlists with nothing in common, leave a
single entry that matches no measurement, so the merged policy still requires attestation and
admits no guest.

### Not done — fetching the quote from the running guest

The roadmap's other 3.13.x item. It needs SGX or TDX hardware to be verified on; the development
machine is AMD. kavach's side of the hand-off is in place, and both launchers refuse a policy that
requires attestation, with a diagnostic, before they run anything. What each lacks first (roadmap
3.13.x):

- **SGX**: `backend_sgx.cyr` writes a manifest template and never renders it (`gramine-manifest`)
  or signs it (`gramine-sgx-sign`), so `gramine-sgx` has no enclave to start.
- **TDX**: `backend_tdx.cyr` passes QEMU no TDVF firmware. It and `backend_is_available` decide
  TDX is present from `/dev/tdx_guest`; `modinfo tdx_guest` on the development host reads "TDX
  Guest Driver", `drivers/virt/coco/tdx-guest`, the device inside a TD. So a TDX host reports the
  backend unavailable. The check stays until the launch is shown to boot: fixing only the check
  would send execs to a launch not shown to work.

A consumer with a launcher that works can register it at the SGX or TDX slot and get the gate
([example 5](docs/examples/05-tee-attestation.md)).

### Fixed — `kavach_attestation_result_new` wrote past its allocation

`AttestationResult` has seven fields, 56 bytes; the constructor allocated 48. `details`, at offset
48, went over the first word of whatever was allocated next. At construction that word was
overwritten in turn, but a later `AttestationResult_set_details` corrupted the next object. Writing
the verifier found it: `details` is set after the measurement's hex string is allocated, and the
string lost its first eight bytes. `ATTESTATION_RESULT_SIZE` is 56;
`attestation_result_fits_its_allocation` plants a word after a result and checks that it survives.

### Added — `scripts/check-bundles.py`, a CI step and a `version-bump.sh` step

For each `dist/*.cyr` it builds a throwaway consumer that vendors only the stdlib leaves the
bundle's `.deps` sidecar lists, and fails on a failed build or on any `undefined function`,
reachable or not. The freshness gate proves the bundles match the source, not that they compile:
the confine bundle shipped 3.12.4 and 3.12.5 unable to (CHANGELOG 3.12.6). This release's first
`policy_attest_allow` called `is_digit_c`, which lives in `scanning_secrets.cyr` and is not in
`[lib.confine]`. The in-tree build and every test passed, and a consumer of
`dist/kavach-confine.cyr` failed to compile. The digit check is inline now; with `is_digit_c`
restored, the script names it and fails.

### Platforms — aarch64 recorded as supported

Apart from namespaces and rootfs entry, which stay refused until the stdlib names `unshare` and
`chroot` (ADR-007). The evidence the roadmap asked for: the `aarch64 (native)` CI job, blocking
since 3.12.9, reported `853 passed, 0 failed (853 total) — seccomp loaded` for the 3.12.9 commit
(its check-run annotation, re-read for this entry). `overview.md` has a Platforms table.

### CI

- The aarch64 notices' titles had a comma, and a workflow command's title ends at the first comma:
  the 3.12.9 annotations are titled `tests (aarch64`. They are `tests (aarch64 / qemu)` and
  `tests (aarch64 / native …)` now.
- "Dist bundles compile for a consumer", after the freshness check.

### Tests

The vectors are sigil's (`tests/attest_vectors.cyr`, copied from its `sgx_verify_full.tcyr` and
`tdx_verify_full.tcyr`): an SGX DCAP v3 quote and two TDX v4 quotes (P-256, P-384), each carrying a
PEM PCK chain up to sigil's test root, and an unrelated root. The TDX quotes are debug TDs
(`TD_ATTRIBUTES` 0x0101010101010101), which makes them the default policy's reject case and the
allowed-debug `WARNING` case. The tests verify as of a fixed time inside the certificates' window,
never the clock.

- **Accept:** the SGX quote, affirmed, with its MRENCLAVE, MRSIGNER and ISVSVN; with a 64-byte
  nonce; with an upper-case allowlist entry; through the dispatcher. The TDX quotes on both curves,
  at `WARNING` with debug allowed.
- **Reject:** an unrelated root; before and after the validity window; time 0; a changed MRENCLAVE
  or MRTD; the DEBUG bit set (which breaks the signature); a measurement off the allowlist;
  another exec's nonce; nonces of 0 and 65 bytes; no root; no allowlist; a truncated quote; each
  format given to the other's verifier; a backend with no quote format; a debug TD under the
  default policy.
- **The gate**, through a stand-in SGX backend: a fresh quote is released; the same quote on the
  next exec is refused, the caller's nonce having been used once; a guest with no quote; a
  measurement off the allowlist; a backend that cannot attest, refused before it runs; kavach's SGX
  and TDX launchers answering with their diagnostic; a diagnostic leaving no nonce behind; a
  policy without an allowlist running as before.
- The three refusing paths, `merge_policies`' rules, the policy helpers' validation, the root copy,
  and the result's allocation.

Twenty mutants, each disabling one check: the debug, nonce, allowlist and time checks; the SGX
DEBUG offset; a debug guest reported `AFFIRMING`; the gate; the pre-dispatch backend check; nonce
reuse; the post-dispatch reset; the SGX and TDX refusals; the three refusing paths; the merge and
its root rule; case folding; the root copy; the result size. Each fails the suite at the assertion
written for it.

### Verified

- x86-64: the suite, 971/971; the bench harness; fuzz (500); fmt `--check`; lint, 0 warnings;
  vet; `check-symbols.py`; the security scan; `check-bundles.py`. `cyrius distlib --all`
  regenerated both bundles.
- aarch64: cross-built, and the suite 942/942 under qemu-aarch64; the agnos build links.
- Both bundles, each consumed with only its sidecar's stdlib: the full bundle verified the SGX
  vector (`AFFIRMING`); the confine bundle refused `sandbox_spawn` under a policy that requires
  attestation.
- The DEBUG bits, against Linux's `arch/x86/include/asm/sgx.h` (`SGX_ATTR_DEBUG = BIT(1)`) and
  `arch/x86/include/asm/shared/tdx.h` (`TDX_TD_ATTR_DEBUG_BIT 0`).
- Example 5 built against `dist/kavach.cyr`; its output is copied from the run.

### Performance

`bench-history.csv` gains a **3.13.0** row, pinned, with two new benchmarks: `attest_sgx_quote`
**50.7 ms** and `attest_tdx_quote_p384` **47.8 ms**, the whole of `kavach_attest_*` on the
vectors. Almost all of it is sigil's ECDSA; a TEE launch takes far longer. The comparison is
`scripts/bench-ab.py 3.12.9 .`: 6 interleaved rounds per build, pinned.

| bench | 3.12.9 | 3.13.0 | Δ |
|---|---|---|---|
| `process_exec_echo` | 2.763 ms | 2.704 ms | −2.1% (ranges overlap) |
| `process_exec_confined` | 2.711 ms | 2.701 ms | −0.4% (ranges overlap) |
| `process_exec_large_output` | 126.844 ms | 128.085 ms | +1.0% (ranges overlap) |
| `policy_strict_create` | 38 ns | 45 ns | +18.4% (separate) |
| `config_builder_full` | 96 ns | 104 ns | +8.9% (separate) |
| `gate_clean_output` | 334.50 µs | 352.63 µs | +5.4% (separate) |
| `code_scan_large_ac` | 506.01 µs | 526.79 µs | +4.1% (separate) |

- **`sandbox_exec` shows no measured change.** The row-against-row +8.9% on `process_exec_echo`
  is gone in the interleaved runs.
- **`policy_strict_create` and `config_builder_full`** are the policy growing from 13 words to 17:
  `policy_new` zeroes four more, about 7 ns.
- ⚠ **`gate_clean_output` and `code_scan_large_ac` have separate ranges on a path this release does
  not touch.** Not the 16 KB of vectors in the bench program: built with and without them, it
  measured 351.31 and 350.99 µs. So the change is in `src/`, where no function they call changed,
  but functions and globals added ahead of the scanners move where theirs land. 3.12.9's A/B saw
  the same on `http_path_extract`, whose function had not changed either. Code placement is the
  likely cause; it was not isolated.


## [3.12.9] — 2026-09-25

The P(-1) closeout before 3.13 feature work. It fixes a credential-routing defect filed from
agnosai. It adds a CI gate for the class of bug behind it: a kavach name that another module in
the build silently takes over. It closes two ways around the seccomp deny list, makes a rootfs
always enter its own mount namespace, and fixes an agnos `mkdir` that took the mode as a path
length. It also makes the native aarch64 CI job blocking, pins the benchmarks, and audits the
docs. A security review of twelve modules found six more defects, all fixed here with tests: a
heap overflow in OCI spec generation, host fds leaking into persistent guests, netlink audit
controls reported as applied when the kernel refused them, two symlink-following quarantine
writes, and a stale flag that let `sandbox_exec` skip the externalization gate. 812 → **879**
assertions on x86-64; 791 → **850** on aarch64 under qemu.

### Breaking

No first-party consumer (aethersafha, agnosai, mehman, stiva) uses any of these names; each
migration is a mechanical rename.

- **Renamed:**
  - `InjectionMethod`'s `ENV_VAR` / `FILE` / `STDIN` → `KAVACH_INJECT_ENV_VAR` / `_FILE` /
    `_STDIN`;
  - `AttestationTrust`'s `CONTRAINDICATED` / `WARNING` / `NONE` / `AFFIRMING` → `KAVACH_TRUST_*`;
  - `syserr_new` / `_pack` / `_kind` / `_errno` / `_message` / `_print` → `kavach_syserr_*`,
    and `result_print_err` → `kavach_result_print_err`;
  - `attestation_result_new` → `kavach_attestation_result_new`;
  - `agnosys_json_emit_cstr_or_null` → `kavach_json_emit_cstr_or_null`;
  - `struct AuditEntry` → `KavachAuditEntry`, so its accessors are `KavachAuditEntry_*`.
- **Removed, unused in kavach and in every consumer:** `agnosys_is_hex_char`,
  `agnosys_is_name_char`, `agnosys_cstr_starts_with`, `agnosys_run_capture`,
  `agnosys_run_checked` (which exec'd by path), `agnosys_read_fd_to_str`, `is_syscall_err`,
  `wrap_syscall`, `file_restrict_mode`, and `observability.cyr`'s `SpawnedProcess` with
  `spawned_process_new`.
- **The exec-safe seccomp filter denies more.** `clone` with any `CLONE_NEW*` flag and the new
  mount API are now killed, and `clone3` returns `ENOSYS`. A payload that creates namespaces (a
  nested container runtime, a user-namespace sandbox) dies under the filter.
- **`confine_child` with a rootfs creates namespaces even when `want_ns` is 0**, and fails closed
  (exit 123) where the host has none. Only a direct caller of the exported function sees this;
  kavach's own paths always passed 1 with a rootfs.
- **Calls that failed quietly now return errors.** `audit_set_enabled`, `audit_add_rule`,
  `audit_delete_rule` and `audit_send_event` return the kernel's refusal; unprivileged, that is
  EPERM. `quarantine_update_status` returns `KAVACH_ERR_IO_ERROR` for a failed write, a symlinked
  entry, or an unknown id. `quarantine_storage_new` returns 0 for a `base_dir` that is a symlink
  or not ours.

### Fixed — a stdin secret could be returned as an env var (`InjectionMethod.STDIN`)

Filed from agnosai 2.0.5 on 2026-08-22, open since. cyrius hoists enum members to global names
under last-definition-wins and is silent when two constants share a name; the enum qualifier is
cosmetic. The stdlib's `lib/io.cyr` defines `var STDIN = 0`, and kavach's `InjectionMethod` had
`STDIN = 2` next to `ENV_VAR = 0`. agnosai measured the result in its own dependency set: where
`io.cyr` came last, `InjectionMethod.STDIN == InjectionMethod.ENV_VAR`. Then:

- `credential_proxy_env_vars` returned each stdin secret as an env pair with a null variable name;
- `credential_proxy_stdin_payload` picked up every env-var secret as well.

kavach's own unit orders `io.cyr` first, so its tests never saw it.

- **Fix.** The members are `KAVACH_INJECT_*` (ADR-006's crate prefix). `AttestationTrust`
  went the same way in the same pass: `attestation_is_acceptable` compares its members
  numerically, so a foreign `WARNING` resolving to 3 would have passed an `AFFIRMING` bar, and
  dhancha already defines `NONE = 0`.
- **Test.** `credential_methods_do_not_alias` pins the three values. It asserts that `STDIN` is
  the stdlib's 0 in kavach's unit, which a re-added bare `STDIN` member fails. It also routes a
  mixed list of env, stdin and file refs, each exactly once.
- The issue is archived with its resolution.

### Added — a CI gate for names another module can take over (`scripts/check-symbols.py`)

Fixing these one at a time leaves the next one live, so 3.12.9 gates the class.

- **What it checks.** The gate parses every top-level `fn`, `var`, enum member, and derived struct
  accessor in kavach's `[lib]` modules and in every `lib/` module (skipping macOS / Windows
  blocks, which kavach never builds). Enum members get cyrius's implicit numbering.
- **What fails.** A name kavach defines twice; a `fn` or accessor shared with `lib/`; or a
  constant shared with `lib/` at a different value.
- **What is only reported.** The 29 errno constants kavach shares with sigil and the stdlib at
  equal values. `--tree ..` also lists names shared with sibling first-party bundles, which no
  single repo's CI sees.
- **On 3.12.8 it reports exactly 20 violations**, all fixed here:
  - the internal `SpawnedProcess_pid` / `_set_pid` duplicate, from a dead second struct;
  - `STDIN = {0, 2}`;
  - seventeen functions shared with sigil: the `syserr_*` family, `result_print_err`, seven
    `agnosys_*` helpers, `is_syscall_err`, `wrap_syscall` and `attestation_result_new`.
- **On 3.12.9 it reports none.** `duplicate fn` warnings in a kavach build go from 149 to 130, and
  the remaining 130 are all `lib/`-internal (below).
- **Also renamed:** kavach's `AuditEntry`. stiva, a consumer, defines its own `AuditEntry`, where
  `timestamp` is field 0 rather than 3, and both generated `AuditEntry_timestamp`. In stiva's
  binary one accessor served both structs. stiva does not use kavach's audit chain, so it was
  latent there.
- Exceptions go in `scripts/symbol-allow.txt`, which is empty.

### Fixed — two ways around the exec-safe deny list

The filter denies `mount` and `unshare` because a payload must not re-namespace itself or mount,
but two other routes reached the same place.

- **The new mount API.** `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`,
  `mount_setattr` and `open_tree_attr` (428–433, 442, 467; the same on both architectures) are
  now denied. `fsopen` + `fsconfig` + `fsmount` + `move_mount` builds and attaches a filesystem
  without `mount(2)`.
- **`clone` and `clone3`.** `CLONE_NEWUSER | CLONE_NEWNS` in a clone makes a child that can mount
  in its own namespace. The filter now loads `clone`'s flags and kills on any of the seven
  `CLONE_NEW*` bits (`0x7E020000`). The exit-signal byte stays out of the mask, so a plain fork
  passes. `clone3` passes its flags in a struct seccomp cannot read, so it gets `ENOSYS`, not
  `KILL`: glibc then falls back to `clone`, which the filter tests.
- **Measured.** A multithreaded Python program (`pthread_create` tries `clone3` first) runs under
  the filter and exits 0.
- **Size.** The filter is 40 instructions on x86-64 (27 before) and 38 on aarch64.
- **Tests.** Four new probes in `seccomp_kills_what_it_denies`:
  - `clone(CLONE_NEWNS)` dies by SIGSYS, where unfiltered it returns;
  - `clone3` gets `ENOSYS`, where unfiltered the kernel refuses its empty struct with `EINVAL`;
  - `fsopen` dies by SIGSYS, where unfiltered it returns;
  - `clone(SIGCHLD)`, a plain fork, still runs under the filter.

  The shape test reads back every tail instruction. The x86-only i386-gate probe now skips on its
  own instead of returning early.

### Fixed — a rootfs is always entered inside a mount namespace of its own

`_spawn_enter_rootfs` makes `/` private and then chroots. `confine_child_wd` created namespaces
only when `want_ns` was set, so a caller passing 0 with a rootfs ran that `mount` in its own mount
namespace, which as root is the host's. kavach's callers always passed 1 with a rootfs, but the
function is exported (`dist/kavach-confine.cyr`). Now a rootfs implies its namespaces.

`rootfs_always_gets_a_mount_namespace` runs the sequence in a child with `want_ns = 0` and
compares `/proc/self/ns/mnt` with the parent's. It ends in a new namespace here, and accepts the
fail-closed 123/118 on a host without namespaces. Without the fix it exits 119.

### Fixed — agnos: `mkdir` took the mode as a path length

`sys_mkdir` is `(path, mode)` on Linux and `(path, pathlen)` on agnos. The compiler cannot catch
that: the arity is the same, only the meaning differs. kavach called the Linux form at seven sites
that compile for agnos. There every `sys_mkdir(dir, 448)` asked for a directory named by the first
448 bytes at `dir`, and the quarantine store is reachable on agnos. The sites now go through
`kv_mkdir`, a shim beside `kv_unlink` / `kv_rmdir`.

The sweep compared every `sys_*` call that compiles for agnos with the agnos peer's signature. The
other mismatches (`sys_unlink`, `sys_rmdir`, `sys_waitpid`) are already the agnos arms of those
shims.

### Fixed — defects from a security review of twelve modules

The P(-1) audit ran a review over `credential_http`, `quarantine`, `scanning_gate`,
`sandbox_exec`, `cgroup`, `persistent`, `spawn`, `backend_wasm`, `backend_firecracker`,
`oci_spec`, `mac` and `kernel_audit`. Each finding was reproduced before it was fixed. Each fix
has a test that fails without it (a mutant per fix). The HTTP proxy's parsing, allowlist and
loopback bind, `oci_json_escape`, and `mac.cyr`'s context validation came back clean.

- **Heap overflow in OCI spec generation.** With a rootfs, `oci_generate_spec` writes argv as
  `"tok",` per token, and the buffer counted the command once with no framing: past about 1000
  tokens it wrote past `buf`, and the review's 1500-token probe crashed. The token count is now
  part of the size. A final check refuses the spec if the writes ever reach the capacity: a bump
  allocator hides such a write, since the bytes land in memory already handed out and the spec
  still looks right, which is how this one survived. `oci_spec_argv_many_tokens` builds 3000.
- **Host fds leaked into persistent guests.** `sandbox_spawn` and the confined capture close
  inherited fds before exec; the persistent guest never did. The credential proxy's listener was
  also not close-on-exec, and the review found it at fd 3 inside a confined guest, where the guest
  could accept on it. The persistent child now runs the same sweep (keeping only the pinned exec
  fd). The listener is created with `SOCK_CLOEXEC` and connections accepted with
  `accept4(…, SOCK_CLOEXEC)`. `SOCK_CLOEXEC` moved to `util.cyr` so every build has it.
  `persistent_guest_closes_inherited_fds` plants fd 57 and lists the guest's fds;
  `credential_http_listener_is_cloexec` reads the flag back.
- **Netlink audit controls reported success the kernel had refused.** `audit_set_enabled`,
  `audit_add_rule` / `audit_delete_rule` and `audit_send_event` returned Ok as soon as the request
  was sent; none read the reply. The kernel answers a refusal with an NLMSG_ERROR regardless, so,
  unprivileged, enabling auditing or adding a watch failed with EPERM and the caller was told it
  was in place. They now ask for an ack and return the kernel's answer. Each request has its own
  sequence number; every request used to be seq 1, so a stale reply looked current.
  `audit_get_status` read the errno with a zero-extending load: -1 came back as 4294967295. The
  test suite had never included `kernel_audit.cyr`; `audit_control_reports_kernel_refusal`
  (unprivileged only: as root it would really change the host) checks all three calls. Under
  qemu-user the refusal is EINVAL (qemu's netlink translation), and the test accepts any errno.
- **`quarantine_update_status` followed symlinks and hid failures.** It wrote with
  `file_write_all`, which creates at 0644 and follows a link, and returned OK whatever happened.
  A `.meta` symlink truncated and overwrote its target, and a lost approve or reject was reported
  as recorded. It now opens the existing entry with `O_TRUNC | O_NOFOLLOW` (no `O_CREAT`) and
  returns `KAVACH_ERR_IO_ERROR` on any failure.
- **`quarantine_storage_new` chmod'ed through a symlinked `base_dir`.** `chmod` by path followed
  a pre-planted link to its target, and every entry after it was stored there. It now opens the
  directory `O_DIRECTORY | O_NOFOLLOW`, checks the owner, `fchmod`s the fd, and returns 0 for
  anything else.
- **A stale flag let `sandbox_exec` skip the gate.** The "this result is a diagnostic" flag is
  process-global. It was set by the diagnostic constructors and cleared only by
  `backend_capture_finish`, so a backend building its result another way (noop does; a consumer's
  registered backend may) inherited the previous exec's flag. The review's probe got an RSA private
  key through unscanned that way; the test reproduces the skip on the noop backend. The flag is now
  cleared before every dispatch (`backend_diagnostic_reset`).
- **The cgroup prelude exec'd a bare `sh`.** `execve` does no PATH search, so on a host where
  kavach creates cgroups every limited payload either ran `./sh` from its working directory or
  exited 127 without running. It is `/bin/sh` now, pinned like every other exec.
- **The credential proxy's memory grew with every request.** Each request allocated 8 KiB from an
  allocator that never frees (the review measured about 8.5 KB a request). One buffer per proxy is
  reused now, since
  connections are served one at a time. `credential_http_proxy_serves_over_loopback`, the proxy's
  first end-to-end test, serves two requests on it (200 with the secret, 403 off the allowlist).

### CI

- **`aarch64 (native)` is blocking.** It ran green on both 3.12.8 runs (CI and the release gate).
- **Every test job now emits a notice** with its pass count and, where it matters, whether
  seccomp loaded. Job logs need admin rights; the checks API serves notices without
  authentication, so a run can be read from outside. A green run had only said that nothing
  failed.
- **A symbol-collisions step** runs `scripts/check-symbols.py`.
- **Actions moved off Node 20**, which runners were forcing onto Node 24 with a deprecation
  warning: `checkout` v7, `upload-artifact` v7, `download-artifact` v8, and
  `softprops/action-gh-release` v3. Each major's release notes were checked; nothing here depends
  on what changed.

### Benchmark tooling

- `scripts/bench-history.sh` runs the benchmarks pinned to one CPU (`taskset`; the last CPU,
  or `KAVACH_BENCH_CPU`). Unpinned, the exec rows were bimodal, so 3.12.7 and 3.12.8 each needed
  a separate pinned comparison.
- `scripts/bench-ab.py <ref-a> <ref-b>` builds two refs, or one ref and the working tree (`.`), in
  temporary worktrees. It runs them interleaved on one CPU and prints medians, whether the ranges
  overlap, and the delta. It replaces the ad-hoc scripts used for 3.12.6 to 3.12.8.

### Docs

- **ADR-004** gets a status table checked against the source. Seven of its nine deferrals have
  shipped; async exec and full regex remain, and so does §2's quote verification (3.13–3.14).
- **ADR-006** gets an amendment: its §4 overlaps are closed, and gated.
- **The guides and examples** were checked against the current API. No removed or renamed call
  remained, but they used `Backend.X`. The enum has been `KavachBackend` since 3.11.15; the old
  qualifier compiled only because qualifiers are cosmetic.
- **`overview.md`** has the `KAVACH_INJECT_*` names. Its scoring rows now say when the process
  backend isolates the network, and that the three Landlock network and scope rows add score for
  controls nothing applies; the roadmap tracks either applying them or no longer scoring them.
- **`SECURITY.md`**'s Supported Versions table listed 2.1.x as the active Cyrius line; 1.x and 2.x
  were the Rust line. It now names 3.12.x, with fixes forward-only.
- **The roadmap** drops 3.12.9. Its ADR-004 references pointed at the wrong sections. Two
  decisions go to "Beyond 3.x": the generic public names still shared with sibling bundles, and
  the Landlock network rules. The aarch64-support record goes to 3.13.x.
- **CLAUDE.md** gains two DO-NOTs, one for names another module can own and one for `sys_*` calls
  whose agnos form differs.

### Verified

- fmt 0 drift; lint 0 in `src/` (the test file keeps its 7 pre-existing long lines); `vet` clean;
  `check --with-deps src/lib.cyr` clean; `scripts/check-symbols.py` ok (1064 names, 61 `lib/`
  modules).
- Builds: plain, `CYRIUS_DCE=1`, `--agnos` and `--aarch64`. All four have 0 undefined and no
  raw-syscall warning. `duplicate fn` names: 149 → **130**; every one kavach owned is gone.
  - 129 of the 130 are the stdlib's `bayan-json.cyr` against its `bayan.cyr`. samay and
    ai-hwaccel pull bayan 1.5.7's JSON profile beside the 6.6.6 snapshot's bayan 1.5.6, and one of
    the doubled functions (`bayan_f64_parse`) differs: 1.5.7's fix for parsing past 19
    significant digits.
  - The 1.5.7 copy is defined last and wins. kavach parses no JSON floats. It resolves when the
    cyrius snapshot carries bayan 1.5.7.
  - The last is `uname_release`, sigil against the stdlib's `sys.cyr`.
- Tests **879/879** (x86-64); **850/850** (aarch64) under Ubuntu 24.04's qemu 8.2.2, also with
  `CYRIUS_DCE=1`, and under 11.1.1. samay **12/12**; fuzz ok.
- Mutants: 14, each failing at least one assertion without its fix. Eight are for the review's
  findings (both halves of the fd leak count separately), and six for the filter tail, the mount
  API, the rootfs namespace, and a re-added bare `STDIN`.
- `distlib --all --check` fresh; `deps --verify` 75/0; the CI security scan, run under `bash -e`
  with GNU grep, is clean.
- Consumers on cyrius 6.6.6, both building clean and running:
  - a confine-only one, declaring exactly the 18 sidecar leaves: a 40-instruction exec filter, with
    seccomp available;
  - one with a real `[deps.kavach]` and the README's 33 leaves, which vendors the 3.12.9 bundle and
    runs `sandbox_exec`.

### Performance

`bench-history.csv` gains a **3.12.9** row, the first taken pinned to one CPU. The comparison is
`scripts/bench-ab.py 3.12.8 .`: 5 interleaved rounds per build, pinned.

| bench | 3.12.8 | 3.12.9 | Δ |
|---|---|---|---|
| `process_exec_echo` | 2.842 ms | 2.809 ms | −1.2% (ranges overlap) |
| `process_exec_confined` | 2.785 ms | 2.681 ms | −3.7% (ranges overlap) |
| `gate_clean_output` | 338.03 µs | 333.90 µs | −1.2% (ranges overlap) |
| `credential_env_vars_100` | 14.71 µs | 14.35 µs | −2.4% (ranges overlap) |
| `http_path_extract` | 97 ns | 101 ns | +4.1% (separate) |

- **No measured change from any code this release touched.** The exec filter is 13 instructions
  longer, and `process_exec_confined` does not show it.
- **`http_path_extract` is the one row with separate ranges**, and its function
  (`_http_extract_secret_name`) is unchanged. Other functions in the same file changed size, and
  this row has moved with code placement since 3.12.6 (marked † there).
- ⚠ **A first run of the same A/B read `gate_clean_output` +10.8% with separate ranges.** It ran
  while the security review was building and testing unpinned in the background. Re-run on a quiet
  host, it is −1.2% with overlapping ranges.
- ⚠ **Row against row, the CPU-only benchmarks read +2% to +9%** against 3.12.8, whose row was
  unpinned. The interleaved comparison shows none of that, so the difference is the pinned CPU. The
  exec rows, bimodal unpinned in 3.12.7 and 3.12.8, are within ±1.6% of the previous row.


## [3.12.8] — 2026-09-25

The ABI repairs pinned ahead of 3.13. The seccomp filter now checks the architecture. Every
syscall number kavach writes is correct for the architecture it runs on, or refuses to compile
there. CI builds and runs aarch64. This is the first release whose whole test suite passes on
aarch64 (under qemu-user, 791/791; 3.12.7 failed 19 assertions and then segfaulted).

Two behaviour changes, both fail-closed; see **Breaking**. A 32-bit or x32 syscall under a kavach
seccomp filter now kills the process. On aarch64, namespaces and rootfs entry are refused until
the stdlib names `unshare` and `chroot`. ADR-007 records the decisions.

### Breaking

- **A 32-bit payload dies under a kavach seccomp filter.** Every filter now kills any
  `seccomp_data.arch` other than the build's own, and on x86-64 any x32 call. An i386 binary on
  x86-64, or an AArch32 binary on aarch64, is killed at its first syscall after exec. To run one,
  use a policy with `seccomp_enabled = 0`.
- **Removed from `src/sys_security_syscalls.cyr`, and so from both bundles:** `SYS_SOCKET_NR`,
  `SYS_BIND_NR`, `SYS_SENDTO_NR`, `SYS_RECVFROM_NR`, `SYS_PIVOT_ROOT_NR`, and that file's second
  copy of `SYS_AGNOS_AUDIT_LOG` (`kernel_audit.cyr` keeps its own). They were raw x86-64 numbers,
  and no first-party repo references them. Migrate to the stdlib's `sys_socket`, `sys_bind`,
  `sys_sendto` and `sys_recvfrom`, or its `SYS_*` names. `SYS_UNSHARE` and `SYS_CHROOT_NR`
  remain, but are now declared only when building for x86-64.

### Fixed — the seccomp filter checks the architecture

Both filters loaded only `seccomp_data.nr` and compared it with x86-64 numbers. seccomp(2) warns
that this is not enough: each ABI numbers syscalls differently, and one process can use more than
one.

- **On x86-64, a denied call could be made through the i386 gate.** Measured against the 3.12.7
  exec filter, built from the tag, on a kernel with IA32 emulation and x32 enabled:
  - a native `umount2` was killed;
  - the same `umount2` through `int 0x80` (i386 number 52, which x86-64 reads as `getpeername`)
    ran, and returned `ENOENT`;
  - an x32 `getpid` ran, and so did an i386 `getpid`.
- **On aarch64, the filter denied the wrong calls.** x86-64 `ptrace` (101) is aarch64
  `nanosleep`, so the filter killed `nanosleep`, and the real `ptrace` (117), `mount` (40) and
  `unshare` (97) went through. This is read from the tables, not run: qemu-user refuses to load
  filters, and it has not been on hardware.
- **Fix.** Every filter starts with an architecture check. It loads `arch`, kills anything but the
  build's `AUDIT_ARCH_*`, then loads `nr`. On x86-64 it also kills any `nr` with bit 30 set (x32).
  The deny and allow tables are per-architecture, one column each, with native numbers from
  `asm/unistd_64.h` and `asm-generic/unistd.h`. They are deliberately not the stdlib's `SYS_*`
  names, which on aarch64 include x86 numbers renumbered only at a `syscall()` site.
- **One builder.** Both filters come from `_seccomp_build`, and the basic filter's 23 hand-written
  instructions are gone. Each filter is 27 instructions on x86-64 (was 23) and 25 on aarch64,
  which has no `sysfs` or `arch_prctl`.
- **New API:** `security_seccomp_native_arch()`, plus the constants `AUDIT_ARCH_X86_64`,
  `AUDIT_ARCH_AARCH64`, `BPF_JMP_JGE_K`, `SECCOMP_DATA_NR`, `SECCOMP_DATA_ARCH` and
  `X32_SYSCALL_BIT`.

**Tests.**

- `exec_seccomp_filter_shape` and the new `basic_seccomp_filter_shape` read back every prologue
  byte. They check the per-architecture counts (20 or 19), that each JEQ lands on its target, and
  that the x32 branch lands on the KILL. They also check `mount`, `ptrace` and `unshare` in the
  right numbering, and that `nanosleep` is not denied. The expected pairs are written out in the
  test, not read from the tables.
- `seccomp_kills_what_it_denies` forks a child per way into the kernel: a denied native call, an
  x32 call, and `int 0x80`. Each is expected to die by SIGSYS under the filter and to return
  without it. The two x86-only ways run on x86-64 only.
- The same probes, built against the 3.12.7 tree, reproduce the gap: the native call is killed,
  and the x32 call, the i386 `getpid` and the i386 `umount2` all run.

Five mutants each fail:

- no x32 check: 3 failures, including the SIGSYS probe;
- the x32 jump off by one: 16. The kernel rejects that filter, and every seccomp test now says so;
- the arch JEQ inverted: 12;
- `nr` loaded where `arch` should be: 10;
- the x86-64 column swapped for aarch64's: 20.

### Fixed — `security_syscall_name_to_nr` answers in the build's numbering

It returned the x86-64 number on every architecture. The map is now two-column like the filter
tables. A name the build's architecture lacks maps to -1, rather than to another call's number.
On aarch64 that is `open`, `stat`, `access`, `pipe`, `dup2`, `fork`, `mkdir`, `rmdir`, `unlink`
and `chmod`, whose libc uses the `*at` forms, `pipe2`, `dup3` and `clone`.

### Fixed — aarch64 refuses `unshare` and `chroot` instead of running other calls

The stdlib names neither call, and kavach issued the x86-64 numbers. Measured under
`qemu-aarch64 -strace` on cyrius 6.6.6 codegen:

- raw 272 runs `kcmp`;
- raw 161 runs `sethostname`, with the rootfs path as the name and whatever `x1` held as the length;
- native 51 is renumbered to 204, `getsockname`;
- native 97 does reach `unshare`.

What that meant through 3.12.7:

- Namespace creation on aarch64 failed, closed: `kcmp`, handed the clone flags as a pid, answers
  `ESRCH`. So no aarch64 sandbox got a namespace.
- Rootfs entry was never reached on kavach's own paths, because the namespace step before it
  failed first. Reached as root, with a stray length of 64 or less, it would have renamed the
  host's UTS namespace and returned 0. The payload would have run in the host's filesystem,
  reported as confined.

**Why not the native numbers.** 51 cannot be reached through `syscall()` at all. 97 works today
only because nothing claims it. The cyrius guide's rule 3 is to never write an aarch64-native
number under an aarch64 `#ifdef`, because the translation rows match numbers, not intent. That is
already live in the first-party tree: takumi's native `ppoll` (73) runs as `flock` since cyrius
6.6.4 added a `73→32` row (measured; takumi pins 6.6.2, so it is not hit yet).

**Fix.**

- `security_create_namespace` returns not-supported on aarch64, and `spawn_namespaces_available`
  answers 0.
- `_spawn_enter_rootfs` returns -1 before its private mount.
- `SYS_UNSHARE` and `SYS_CHROOT_NR` are declared only under `#ifdef CYRIUS_ARCH_X86`, so an
  aarch64 use is a compile error.
- A confined child that needs either call exits 123, the code it already exited with.
- Requested upstream: `cyrius/docs/development/issues/2026-09-25-kavach-unshare-chroot-unnamed-aarch64-chroot-unreachable.md`.
  The refusals lift when the stdlib declares `SYS_UNSHARE` and `SYS_CHROOT`.

### Fixed — the OCI state-root check reads `struct stat` at the right offsets

`_oci_dir_is_ours` read `st_mode` and `st_uid` at x86-64 offsets (+24, +28) on every
architecture. aarch64 keeps them at +16 and +24, so there it compared the owner's low bits as the
mode and the group as the owner, and refused every state root. Every OCI run on aarch64 failed.
That was 8 of the 9 failing test groups under qemu at 3.12.7 (17 of 19 assertions). It was also
the segfault: `oci_err_path_is_uid_scoped` handed the refused (null) path to `strstr`.

- **Fix.** It reads through the stdlib's `STAT_MODE` and `STAT_UID`. agnos returns before
  reading, because agnos's `stat` has no owner field.
- **Tests.** `oci_state_root_rejects_a_hostile_dir` now covers the owner branch with `/proc/1/fd`,
  a root-owned directory at mode 0500 on any Linux host. It passes the type and permission checks,
  so only the owner check can refuse it.
- **Mutants.** Without the owner check, exactly this assertion fails. Reading the uid at the mode
  offset fails 18. Seventeen are the same assertions in the same eight OCI groups that failed on
  aarch64 at 3.12.7, which confirms what those were. The eighteenth is the scratch-path check
  where aarch64 segfaulted.
- **The segfault.** `oci_err_path_is_uid_scoped` now stops on a null path instead of crashing the
  suite.

### Changed — stdlib names in place of raw numbers

- `kernel_audit.cyr` opens its netlink socket through `sys_socket`, `sys_bind`, `sys_sendto` and
  `sys_recvfrom`. They were raw 41, 49, 44 and 45, right on aarch64 only because cyrius renumbers
  those four.
- `kv_sleep_ms` uses `sys_nanosleep`, where it passed a raw 35. This was planned for 3.12.9 and
  pulled forward.
- `src/` now contains no `syscall(<number>)` at all.
- `dist/kavach-confine.deps` drops `net`. It was kept only because comments in the trimmed
  `sys_security_syscalls.cyr` named `sock_recv`, a `net.cyr` symbol. A consumer declaring exactly
  the new 18 leaves builds and runs on x86-64 and aarch64.

### CI

- **`aarch64` (blocking).** Cross-builds `src/main.cyr` for aarch64 and agnos, smoke-runs the
  aarch64 binary, and runs the test suite under qemu-aarch64. Locally that is 791/791 under
  Ubuntu 24.04's qemu 8.2.2 (also with `CYRIUS_DCE=1`, as CI builds) and under 11.1.1.
- **`aarch64-native` (informational).** Runs the same test binary on an `ubuntu-24.04-arm`
  runner, where seccomp filters actually load. The aarch64 tables have not met a real kernel yet,
  so this job reports without blocking until its first green run. Then drop `continue-on-error`,
  and aarch64 exec support can be claimed.
- **The security scan's `syscall 59` gate never fired.** The scan ran plain `grep`, where `\(`
  opens a group, so that pattern did not compile. GNU grep printed "Unmatched ( or \(", the scan
  discarded that stderr, and every tree passed the gate, including one with a planted
  `syscall(59, …)`. (The `/etc` pattern has no `\(` and did work.)
  - It now uses `grep -E`, and a pattern that does not compile fails the job.
  - Two new gates: any `syscall(<number>)` in `src/`, and any `SYS_*` number declared outside
    `sys_security_syscalls.cyr` and `kernel_audit.cyr`.
  - The script, extracted from the workflow and run under `bash -e` with GNU grep, passes this
    tree and flags 3.12.7's raw 35. It also flags a planted `syscall(59, …)` (under both syscall
    gates) and a planted `SYS_FOO = 12`.

### Tests

- x86-64: 753 → **812** assertions.
- aarch64 under qemu-user: 3.12.7 failed 19 assertions in 9 groups and then segfaulted; 3.12.8
  passes **791/791**.
- **Seccomp-dependent tests fail closed.** `process_real_exec` and the persistent default path
  assumed seccomp loads. On a host that refuses it (qemu-user answers `PR_SET_SECCOMP` with
  `EINVAL`, seen in `-strace`), they now assert the fail-closed 125, as
  `sandbox_spawn_applies_seccomp` already did.
- **"This host has no seccomp" is now asked with a one-instruction filter**
  (`_t_host_loads_seccomp`), not with kavach's own. `spawn_seccomp_available` probes with the exec
  filter, so a filter the kernel rejected used to read as "no seccomp here", and every test
  allowing for that host accepted the bug. `seccomp_filter_actually_loads` now fails when the host
  loads the trivial filter and not kavach's.
- **Two tests no longer crash the suite on a regression; each now reports a failed assertion.**
  - `sandbox_spawn_applies_seccomp` handed `spawn_exit_name`'s 0 (not a confinement code) to
    `strstr`, which crashed the run under the arch mutants.
  - `oci_err_path_is_uid_scoped` handed a null path to `strstr`, which is the segfault aarch64
    hit at 3.12.7.
- The prlimit helper is generalized to `_t_set_rlimit`. The SIGSYS probes zero `RLIMIT_CORE`, so
  an expected kill does not store a core dump.

### Docs

- ADR-007: native-ABI-only filters, per-architecture tables, and refusal over native numbers.
- The roadmap drops 3.12.8 as shipped. 3.12.9 gains three items found here:
  - a deny list that `mount` alone does not cover (the new mount API, and `clone`/`clone3` with
    namespace flags);
  - `confine_child` entering a rootfs with no mount namespace when a caller passes `want_ns = 0`;
  - flipping the native aarch64 job to blocking.

  "Blocked — awaiting upstream" gains the aarch64 refusals, which lift with the cyrius filing.
- `SECURITY.md` lists the architecture check as resolved.
- The CLAUDE.md syscall rule now covers native numbers.

### Verified

- fmt 0 drift; lint 0 in `src/` (the test file keeps its 7 pre-existing long lines); `vet` clean;
  `check --with-deps src/lib.cyr` clean.
- Builds: plain, `CYRIUS_DCE=1`, `--agnos` and `--aarch64`. All four have 0 undefined, no
  raw-syscall warning, and the same 149 `duplicate fn` names as 3.12.7.
- Tests **812/812** (x86-64) and **791/791** (aarch64, qemu 8.2.2 and 11.1.1). samay **12/12**;
  fuzz ok.
- `distlib --all --check` fresh; `deps --verify` 75/0.
- Consumers on cyrius 6.6.6, both building clean and running:
  - a confine-only one, declaring exactly the 18 sidecar leaves: 27 filter instructions on
    x86-64, 25 on aarch64 under qemu;
  - one with a real `[deps.kavach]`, which vendors the 3.12.8 bundle and runs `sandbox_exec`.

### Performance

`bench-history.csv` gains a **3.12.8** row. The comparison below is medians of 5 interleaved
runs against a build of the 3.12.7 tag, pinned to one CPU.

| bench | 3.12.7 | 3.12.8 | Δ |
|---|---|---|---|
| `process_exec_echo` | 2.672 ms | 2.714 ms | +1.6% (ranges overlap) |
| `process_exec_confined` | 2.773 ms | 2.666 ms | −3.9% (ranges overlap) |
| `audit_chain_record_to_tmpfs` | 12.05 µs | 12.56 µs | +4.2% (ranges overlap) |
| `cgroup_wrap_argv` | 350 ns | 364 ns | +4.0% (ranges overlap) |

- **The architecture check costs nothing measurable.** It adds four BPF instructions to each
  syscall of a confined child on x86-64 (three on aarch64), against a fork and exec of about
  2.7 ms.
- **No row moved with separate ranges.** Every other row is within ±2.6%, and neither the `audit`
  nor the `cgroup` code changed.
- ⚠ **The release row is a single unpinned run**, and it reads +3% to +8% on CPU-only benchmarks
  whose code did not change, and −19.9% on `process_exec_confined`. None of that survives the
  pinned comparison. It is the frequency-scaling behaviour recorded at 3.12.7; the fix for the
  tooling is on the 3.12.9 list.

## [3.12.7] — 2026-09-24

Closes the last open ADR-005 residual, H4, and keeps the audit log readable after a torn record.
No API change; `kv_exec_pin`, `kv_exec_child` and `kv_exec_capture` are new.

### Fixed — H4: a child execs the binary kavach pinned, not whatever is at the path (ADR-005 §H4)

A binary chosen by path was exec'd by that path in the forked child. So a local attacker who could
write to a directory on that path could swap the file between kavach committing to it and the
exec. That applied to the runtimes found with `kavach_path_exists` (runc/crun, runsc, firecracker,
qemu for SEV and TDX, gramine-sgx, wasmtime) and to the absolute program a command names. ADR-005
recorded it as the one open residual, waiting on `execveat`. The stdlib now has `sys_execveat`, so
it is closed here.

- **Pinning.** `kv_exec_pin` (`src/util.cyr`) opens the binary in the parent, before fork, as an
  `O_PATH|O_CLOEXEC` fd, and checks that it is a regular file with an execute bit. The child execs
  that fd with `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` through `kv_exec_child`.
- **Refused, not downgraded.** An absolute path that cannot be pinned (missing, not a regular
  file, no execute bit) is not exec'd at all, and the child exits 127 as a failed exec always did.
  Falling back to the path would reopen the window.
- **By path, deliberately**, in three cases:
  - a relative path, which the child's working directory decides;
  - a child that enters a rootfs, where the path must resolve inside it;
  - agnos, which has no `execveat`.
- **Scripts.** A `#!` file exec'd from a close-on-exec fd fails with `ENOENT`: the kernel hands
  the interpreter `/dev/fd/N`, and the exec has already closed it. The child retries once through
  a `dup` of the fd, which has close-on-exec clear, so the interpreter reads the pinned file.
- **Coverage.**
  - kavach's own four exec sites: the confined capture, `sandbox_spawn`, persistent guests, and
    the OCI runtime run;
  - the nine runtime launches that went through the stdlib's `exec_capture`. They now use
    `kv_exec_capture`, a copy of the stdlib function (cyrius 6.6.6) that keeps its parent-death
    guard, read deadline and reaping, and changes only the exec.
- **The fd sweep.** The confinement sweep that closes inherited fds before exec spares the pinned
  fd. That fd is close-on-exec, points at a file, and only exists when there is no rootfs, so it is
  never the directory-outside-the-root that makes a chroot escapable.
- **No `O_NOFOLLOW`**, unlike the fix ADR-005 sketched. Many system binaries are symlinks
  (`/bin/sh` → `dash`), and the fd pins the final file either way.

**Tests:**

- `exec_pin_survives_a_binary_swap` pins a copy of `/bin/true`, renames a copy of `/bin/false`
  over its path, and execs. The pinned exec exits 0. A control exec by path exits 1, which proves
  the swap happened.
- `exec_pin_survives_a_script_swap` does the same for a `#!` script (3 vs 4), and covers the dup
  retry.
- `exec_pin_classifies_paths` and `exec_capture_pinned_captures_stdout` cover the rest.

Four mutants each fail:

- exec by path in the pinned branch: both swap tests;
- no script retry: 13 failures, including every OCI test with a script runtime;
- a failed pin downgraded to by-path: the classification test;
- a sweep that closes the pin: 14 failures.

735 → **753** assertions.

**Checked on aarch64** by cross-building with `cyrius build --aarch64` and running under
`qemu-aarch64 -strace`. The trace shows the parent's `openat(…, O_RDONLY|O_CLOEXEC|O_PATH)`, the
child's `execveat(3, "", …, AT_EMPTY_PATH)`, the `dup(3) = 4` retry for a script, and
`execveat(4, …)`. The pinned script exits 3, while exec by path after the swap exits 4. `--agnos`
builds clean.

### Fixed — a torn fragment no longer swallows the next audit record

`_audit_append` (3.12.6) cuts a short write back under the lock. Three cases still leave the partial
record at the tail:

- a writer killed inside its `write`;
- agnos, where `sys_ftruncate` is `-ENOSYS`;
- a log marked append-only (`chattr +a`), where `ftruncate` is `EPERM`.

The next record was then appended straight onto the fragment, and the merged line parsed as
neither.

Under the lock, the append now reads the log's last byte. When it is not `\n`, the record goes out
with one in front of it, in the same single write, so the existing cut-back removes both together.
The fragment keeps a line of its own, as evidence, and every record after it is whole. Only a byte
actually read decides, so a failed read adds nothing. The file offset is first put back at the end,
because agnos writes at it. The log is now opened `O_RDWR` for the read.

- **On aarch64**, under `qemu-aarch64 -strace`: a log planted with a 30-byte fragment gets
  `lseek(3,29,SEEK_SET)`, a 1-byte `read`, then one 187-byte `write` (`\n` plus the 186-byte
  genesis). The next append reads a `\n` and adds nothing. Both real records verify against the
  chain HMAC; the fragment is the one line that does not.
- **Cost:** two syscalls per append (`lseek` and a 1-byte `read`; the stdlib has no `pread`).
  `audit_chain_record_to_tmpfs` went from 11.80 to 12.39 µs (+5.0%), medians of 5 interleaved,
  CPU-pinned runs, with ranges just overlapping. No other row moved, and the binary size is
  unchanged.
- **Test:** `test_audit_append_starts_a_fresh_line_after_a_torn_tail` plants a fragment. It checks
  that the fragment keeps its line byte for byte and that every record after it is whole, and it
  fails with the guard removed. Prepending unconditionally fails three existing tests on the blank
  lines it adds. 730 → **735** assertions.
- `--agnos` builds clean. The agnos read path is compile-checked only.

### Docs — the roadmap is a sequence of pinned releases

The roadmap was checked item by item against `src/`, the 6.6.6 stdlib and sigil 3.12.18, then
reorganized into pinned releases from 3.12.8 through 3.20.x.

- **Removed as shipped** (their record is in this file): `sandbox_spawn` (3.9.0); seccomp (3.9.0)
  and Landlock (3.11.1) in the exec child; OCI spec resource limits (3.3.1); the `[lib]` bundle
  (3.6.0); and H4, in this release.
- **3.12.8 — ABI repairs**, found while doing H4, all from reading the code against the cyrius
  6.6.6 syscall tables:
  - the seccomp filter never checks `seccomp_data.arch`, and its deny list is x86-64 numbers;
  - rootfs entry calls x86-64 `chroot` (161) and namespace creation x86-64 `unshare` (272), with
    no translation row for either on aarch64;
  - `_oci_dir_is_ours` reads x86-64 `struct stat` offsets.
- **3.12.9** is the P(-1) closeout.
- **3.13–3.15** take the security items that were blocked on upstream until now: SGX / TDX
  attestation, then SEV-SNP and SGX sealing, then the Firecracker jailer.
- **3.16–3.18** are the three phases of the agent-injection-defense L4 gate.
- **3.19** is the VM backend foundation, and **3.20** the scanner performance work.

The stale v3.4.0 deferred-features table in `docs/architecture/overview.md` and the known-items
list in `SECURITY.md` now match the source. ADR-005 records H4 as resolved.

### Verified

- fmt 0 drift; lint 0; `vet` clean; `check --with-deps src/lib.cyr` clean.
- Builds: plain, `CYRIUS_DCE=1`, `--agnos` and `--aarch64`. All four have 0 undefined and the same
  149 `duplicate fn` names; the aarch64 build has no raw-syscall warning. The DCE binary went from
  3,199,392 to 3,203,520 B.
- Tests **753/753**, samay **12/12**, fuzz ok.
- `distlib --all --check` fresh; `deps --verify` 75/0.
- Both bundles rebuilt into consumer projects on cyrius 6.6.6: a confine-only one, and one that
  uses a real `[deps.kavach]`. Both build clean and run.

### Performance

`bench-history.csv` gains a **3.12.7** row. The comparison below is medians of 5 interleaved runs
against a build of the 3.12.6 tag, pinned to one CPU.

| bench | 3.12.6 | 3.12.7 | Δ |
|---|---|---|---|
| `process_exec_echo` | 2.86 ms | 2.85 ms | −0.4% (noise) |
| `process_exec_confined` | 2.76 ms | 2.78 ms | +0.5% (noise) |
| `audit_chain_record_to_tmpfs` | 11.67 µs | 12.42 µs | +6.4% (ranges overlap) |

- **H4 costs nothing measurable.** It adds one `open` and one `fstat` per exec, against a fork
  and exec of about 2.8 ms.
- **The fresh-line guard** adds two syscalls per append: +6.4% pinned. Unpinned, it is +13.7%
  with separate ranges (11.84 → 13.47 µs).
- ⚠ **Unpinned, exec timings are bimodal for both builds** on this machine's CPU, where frequency
  scaling is active. `process_exec_confined` spans 2.74–3.82 ms for 3.12.6 and 2.77–3.91 ms for
  3.12.7, so an unpinned median moves with whichever mode the runs land in. The release row is a
  single unpinned run, which is why its exec rows read +7% to +24% against the 3.12.6 row. The
  pinned comparison above shows no change.
- **Rows that moved with separate ranges, on paths this release does not touch:**
  - the placement-sensitive rows 3.12.6 described: `ct_streq_64` +15.2%, `http_allowlist_hit`
    −17.1%, `http_allowlist_miss` −19.6%, `http_path_extract` −3.1%;
  - `code_scan_large_naive` −3.6% and `process_exec_large_output` −0.8%;
  - `credential_env_vars_100` +4.3%, which has not been investigated.

## [3.12.6] — 2026-09-24

Toolchain and dependency refresh; an audit-log append that is all or nothing; fixes for raw x86
syscall values that aarch64 ran as other calls, and for opens that used the Linux argument order on
agnos; a `[lib.confine]` bundle that had not compiled since 3.12.4; and a lean manifest. No API
change.

### Changed — cyrius pin 6.6.2 → **6.6.6**

The reason to take it: **the HMAC audit chain could log a torn record as written.** Before 6.6.6,
`file_append_locked` made one `write(2)` and returned its count, so a short write appended a prefix
of the record and returned a positive number; `audit_chain_record`'s `< 0` test read that as success
and advanced the chain head over a line that does not parse. 6.6.6 loops until the record lands and
returns a negative errno on a short write. Measured A/B, 2 KB records under `ulimit -f 4` with
SIGXFSZ ignored:

| | 3.12.5 on 6.6.2 | 3.12.6 on 6.6.6 |
|---|---|---|
| records accepted / refused | 2 / 6 | **1 / 7** |
| `audit_chain_len` | 3 | **2** |
| complete records in the log | 2 | 2 |

The old chain claimed three records while the log held two complete ones plus a 1,685-byte torn tail.
The new chain matches the log. The bytes that did land were still left at the tail; `_audit_append`
(below) removes them too.

No kavach source needed migrating: the `duplicate fn` set is the same 149 names before and after,
0 undefined, and nothing trips 6.6.6's new refusals. The binary grew 3,187,480 → 3,199,336 B.

### Changed — dependency pins

| dep | from | to |
|---|---|---|
| `sigil` | 3.12.16 | **3.12.18** |
| `ai-hwaccel` | 2.3.22 | **2.4.0** |
| `samay` | 1.1.2 | **1.1.5** |
| `bayan` (transitive, via samay) | 1.5.5 | **1.5.7** |

⚠ **sigil is 3.12.18, not the latest tag (3.13.1), because kavach cannot consume 3.13.1 on this
toolchain.** kavach declares `tls`; the stdlib's `tls_native.cyr` includes `lib/sigil.cyr`, so
`cyrius deps` vendors sigil from the toolchain snapshot. Since cyrius 6.5.39 it will not let a
`[deps.sigil]` artifact overwrite a stdlib leaf it has already copied (`warning: refusing to
overwrite stdlib leaf 'sigil'`). The 6.6.6 snapshot carries 3.12.18, so a 3.13.1 pin would name a
version the build never sees. Pinned to 3.12.18 so the manifest matches the build (`lib/sigil.cyr`
is byte-identical to sigil's 3.12.18 `dist/sigil.cyr`). The same override was active under 6.6.2
but went unnoticed because that snapshot carried exactly the pinned 3.12.16. sigil 3.13.x arrives
with the cyrius release whose snapshot carries it. None of its breaking changes (ed25519/ECDSA
verify strictness, quote parsers, keyring chains, `hash_file`) touch a kavach call site.

sigil 3.12.18's `.deps` sidecar adds `sys` (for `sys_uname` / `uname_release`). `cyrius deps` now
vendors `lib/sys.cyr` from it, so kavach's own `[deps].stdlib` is unchanged. The lock goes from 73
to 75 hashed files (`sys.cyr`, plus 6.6.5's `alloc_cx.cyr` peer) and now records `cyrius 6.6.6`.

samay and ai-hwaccel both pin cyrius 6.6.6 and their stdlib sidecars are unchanged. kavach reaches
them only through `src/samay_bridge.cyr`, which is not in `[lib]`. The samay integration suite is
12/12.

### Fixed — a refused audit record no longer leaves its torn bytes in the log

The pin move alone stops the chain head from advancing over a short write (above), but the bytes
that did land stayed at the tail of the log. The next record was appended onto that partial line,
so the merged line parsed as neither record: a refused record took the next good one down with it.

`audit_chain_record` now appends through `_audit_append` (`src/audit.cyr`) instead of the stdlib's
`file_append_locked`:

- **Whole or not at all.** Under `LOCK_EX` it reads the pre-append length (`lseek(SEEK_END)`),
  writes the record, and on a short write `ftruncate`s back to that length before unlocking. A
  refused record leaves the log byte-for-byte as it was.
- **One `write`, not a full-write loop.** A regular file writes short only at a size limit, a full
  disk or quota, or a fatal signal, and a retry completes the record in none of them. Under
  `RLIMIT_FSIZE` a retry is harmful: it starts at the limit, the kernel answers that write with
  SIGXFSZ, and the default action kills the process before any rollback runs. That is what happens
  with the pin move alone when SIGXFSZ is not ignored, and to this fix if built with a loop.
- **0600 from the start.** The `open(2)` creates the log at 0600, so the create-at-0644-then-`chmod`
  window is gone. A log that already exists is still tightened to 0600, now by `fchmod` on the open
  fd rather than `chmod` on the path. This supersedes the audit-log clause of ADR-005 §C4, which
  now carries a note.
- **No lock, no append.** The rollback is only safe under the lock, so a failed `flock` refuses the
  record rather than writing it unlocked. EINTR is retried.
- Every call is a stdlib wrapper (`file_open`, `sys_fchmod`, `file_lock`, `xlseek`, `file_write`,
  `sys_ftruncate`) with named `O_*` flags, so nothing is a raw x86 number. `sys_fchmod` is compiled
  out on agnos, which has none.

Measured with the repro above (eight 2 KB records on x86_64), then a second run with no
limit appending to the same log. Every log was checked with an out-of-tree HMAC-chain verifier:

| | pin move alone | with `_audit_append` |
|---|---|---|
| `ulimit -f 4`, SIGXFSZ ignored: accepted / refused, `chain_len` | 1 / 7, 2 | 1 / 7, 2 |
| the log after that run | 4,096 B: 2 lines + a 1,685-byte torn tail | **2,411 B: 2 lines, no tail** |
| after the second run, lines that verify | 9 of 11 (its genesis is inside the torn line, which breaks the next record's link) | **11 of 11** |
| `ulimit -f 4`, SIGXFSZ at its default action | killed (exit 153), torn tail left | **exit 0**, 1 / 7, log intact |
| full disk (12 KiB tmpfs, ENOSPC) | 12,288 B with a 977-byte torn tail | **11,311 B, no tail**, 6 of 6 verify |

The same repro on aarch64, under `qemu-aarch64 -strace`, issues these calls: `openat(…,
O_WRONLY|O_APPEND|O_CREAT,0600)`, `fchmod(3,0600)`, `flock`, `lseek(3,0,SEEK_END)`, and, for each
of the 7 refusals, a 1,685-byte short `write` followed by `ftruncate(3,2411) = 0`. It exits 0 with
the log intact.

**Not covered.** Three cases still leave the partial record at the tail: a process killed during
the `write` itself; agnos, where `sys_ftruncate` is `-ENOSYS`; and a log marked append-only
(`chattr +a`), where `ftruncate` is `EPERM`. The last two print "a torn record could not be removed
from the log". The roadmap tracks the fix for all three, which is to start the next record on a
fresh line.

`file_restrict_mode` (`src/util.cyr`) no longer has a caller in kavach or in any consumer checked
out alongside it. It stays exported, so the bundle surface does not change.

**Tests:**

- `test_audit_refused_append_leaves_no_torn_tail`. A forked child caps its own `RLIMIT_FSIZE` at
  4 KiB and records 2 KB payloads past it, with SIGXFSZ at its default action. The stdlib has no
  rlimit wrapper, so the child calls `prlimit64` by the kernel's own number per arch: x86_64 302,
  aarch64 261. Neither is an ESYSXLAT row. The parent then checks three things: the child
  survived, every record in the log is a whole line of its own, and a new chain appended afterwards
  stays whole. The test fails against the pin-move-only `audit.cyr`, against this fix built with a
  full-write loop, and against this fix with the truncate removed.
- `test_audit_log_mode_0600`. A fresh log is 0600, and a log widened to 0644 is tightened back on
  the next append. The test fails with the `fchmod` removed.

### Fixed — raw x86 syscall values misbehaved on aarch64

kavach hardcoded two x86_64-only values, and aarch64 Linux executed them as something else. Each
fix was checked by cross-building with `cyrius build --aarch64` and running under
`qemu-aarch64 -strace`:

| call site | 3.12.5 on 6.6.2 | 3.12.6 on 6.6.6 |
|---|---|---|
| `file_write_secure_modal`: fchmod as raw `syscall(91)` | `capset`; asked 0644, file stays 0600 | `fchmod(3,0644) = 0`; file is 0644 |
| open flag `131072` (x86 `O_NOFOLLOW`), four sites | `O_LARGEFILE`; `O_NOFOLLOW` lost | `O_NOFOLLOW` |
| `_oci_take_file` on a planted symlink | follows it, reads the target | `ELOOP`; reads nothing |
| `kv_sleep_ms`: raw `syscall(35)` | `unlinkat`; no sleep | `nanosleep`; sleeps |

- **fchmod.** `sys_fchmod(fd, mode)` replaces `syscall(91, …)`. Its result is now checked, so a
  failed chmod fails the write instead of being ignored. The 6.6.6 aarch64 build had flagged the old
  line: "raw syscall 91 is x86_64 `fchmod`; on ELF-aarch64 that number is `capset`". agnos has no
  fchmod (91 there is `gpu_blit_bb`) and no POSIX modes, so no chmod is issued on that target.
- **O_NOFOLLOW.** The literal was at four sites: both secure writes in `src/util.cyr`, and both
  OCI scratch-file opens in `src/backend_oci.cyr`. The filed issue named only one. All four now
  use the stdlib's `O_*` names: `O_NOFOLLOW` is `0x20000` on x86_64 and `0x8000` on aarch64.
  `_oci_take_file` has no `O_EXCL`, so this flag is its only defence against a planted symlink.
- **nanosleep** needed no kavach change: cyrius 6.6.5 translates raw x86 `35`.
- **Tests.** `credential_inject_files` claimed to check the mode but only checked the content; it
  now asserts 0644. A new `oci_take_file_refuses_a_symlink` plants a link, with a regular-file
  control. Each fails against a mutant of its fix ("got 384, expected 420"; "got 15, expected 0").
- Resolves `docs/development/issues/archived/2026-09-12-raw-x86-syscall-numbers-on-aarch64.md`.

The whole suite, cross-built and run under qemu-user, fails the same 19 assertions in the same
9 fork/exec groups (`process_real_exec`, `oci_run_*`) on both 3.12.5 and 3.12.6, and both runs
crash at the same point. That is pre-existing, and it is not yet known whether qemu-user or kavach's
aarch64 exec path is at fault (roadmap). The groups this fix touches pass there.

### Fixed — agnos: opens used the Linux `sys_open` argument order

On agnos `sys_open` takes `(name, namelen, AO_flags)`, not `(path, O_flags, mode)`, so a raw
Linux-shaped call passes its flags as the name length. Nine such calls were compiled for agnos
outside any agnos guard:

- credential file injection (`file_write_secure_modal`);
- the MAC file helpers `mac_read_file` and `mac_write_file`;
- `audit_read_proc_events`;
- the three opens in `_spawn_redirect_stdio`;
- the two OCI scratch-file opens. `_oci_take_file` still runs on agnos after `_oci_run` refuses.

All nine now go through the stdlib's `file_open`, as `file_write_secure_r` and `_audit_append`
already did. On Linux `file_open` is plain `sys_open`; on agnos it supplies the name length and
maps `O_*` to `AO_*`. The two raw `sys_open` calls left (`persistent.cyr`, `security.cyr`) sit
inside `#ifndef CYRIUS_TARGET_AGNOS` blocks. The open flags are the stdlib's `O_*` names at every
site: per arch on Linux, and from `lib/io.cyr` on agnos, whose values `file_open` translates.

Checked by the `--agnos` build (0 undefined, 0 errors). On Linux the call is unchanged, and the
x86_64 and aarch64 results above are the same after this change. It has not been run on agnos,
because no agnos runtime was available.

### Fixed — `dist/kavach-confine.cyr` did not compile on the toolchain it shipped for

The `[lib.confine]` bundle was last folded at 3.12.3. 3.12.4's value-form migration changed five
of its modules (`util`, `sys_error`, `spawn`, `confine`, `backend_process`), but only
`dist/kavach.cyr` was regenerated. `scripts/version-bump.sh` and the CI freshness gate both ran
plain `cyrius distlib`, which folds `[lib]` only. So 3.12.4 and 3.12.5 shipped a confine bundle
that still had the 1-argument `result_print_err(res)` over the deleted `payload()`.

A consumer project that vendors only the confine sidecar's stdlib and includes the bundle (thoth's
shape) fails with **10 compile errors** on cyrius 6.6.6 against the 3.12.5 bundle
(`'result_unwrap' expects 2 arguments, got 1`, …). Against the 3.12.6 bundle it builds and runs.

- Both bundles regenerated. The confine sidecar drops `tagged`, which value-form Results no longer
  need; the full bundle's sidecar gains `sys`, by way of sigil.
- `scripts/version-bump.sh` runs `cyrius distlib --all`, which folds the base and every `[lib.X]`
  profile.
- CI "Verify dist bundles fresh" runs `cyrius distlib --all` and fails on any change under `dist/`.
  It checks `git status`, not `git diff`, so a new profile's never-committed bundle fails too.

### Fixed — the README's consumer stdlib set no longer built

The "Consume kavach as a library" section tells consumers which `[deps].stdlib` to declare
(kavach's own list minus the test-only `args` / `assert` / `bench`). The copy it printed had fallen
behind that list: it was missing `atomic`, `math` and `sakshi`. Checked on cyrius 6.6.6 with a
consumer running the full M1 flow (`kavach_init` → … → `sandbox_destroy`):

- With the documented set, cyrius refuses to emit a binary (`sakshi_span_*` undefined).
- With the corrected set, through a real `[deps.kavach]` dependency, it builds with 0 undefined
  and exits 0.

The section also said a consumer's sigil resolves from kavach's `[deps.sigil]`. It comes from the
consumer's own toolchain snapshot.

### Changed — `cyrius.cyml` is configuration only

12,819 → 3,135 bytes; 143 comment lines → 0. Everything the comments said already lives elsewhere:

- `[lib]` and the `src/main.cyr` / `src/lib.cyr` exclusions: ADR-006 §1–2.
- The `[lib.confine]` rationale: this file at 3.12.3, and an ADR-006 addendum.
- The opt-in stdlib modules and the sigil `err_*` history: CLAUDE.md pin-move hazards, and this
  file at 3.4.1, 3.4.2 and 3.11.13.
- The `scheduler` feature gating of samay / ai-hwaccel: `docs/architecture/overview.md` external
  dependencies, and this file at 3.8.3.
- The agnosys drop: overview, and this file at 3.5.0.
- The chrono include and the 4095-byte window: this file at 3.11.14, and CLAUDE.md.

### Removed — the CI "4095-byte `_auto_deps` window" gate

Both manifest hazards that shaped the old file were **fixed upstream in cyrius 6.5.28**, and both
were filed from kavach 3.11.14.

- **The 4095-byte window.** `_auto_deps` now reads 65,535 bytes and fails loudly if a manifest is
  longer (`cbt/deps.cyr` at 6.6.6). The gate was enforcing a limit the pinned toolchain no longer
  has, so all it could still do was fail a valid manifest.
- **A declared stdlib module losing its `include` when first reached transitively.** Verified: with
  the explicit `include "lib/chrono.cyr"` removed from `src/util.cyr`, the 6.6.6 build resolves
  with 0 undefined. The three explicit includes stay, as harmless redundancy.

### Verified

Local build, and a copy of the tree resolved from git tags as CI does:

- `deps --verify` 75/0; fmt 0 drift; lint 0. The fmt and lint gates were checked against
  deliberately bad files to prove they still fire.
- `vet` clean; plain, `CYRIUS_DCE=1`, `--agnos` and `--aarch64` builds clean, with 0 undefined,
  the same 149 `duplicate fn` names, and no raw-syscall warning in the aarch64 build;
  `check --with-deps src/lib.cyr` clean; `distlib --all --check` fresh, and both `.deps` sidecars
  unchanged by the fixes. Binary 3,199,392 B (`CYRIUS_DCE=1`).
- Tests **730/730** (713 before this release), samay **12/12**, fuzz ok.
- Both bundles rebuilt into consumer projects on cyrius 6.6.6: a confine-only one (thoth's shape),
  and one using a real `[deps.kavach]` that runs `kavach_init` → … → `sandbox_destroy`.

In the tag-resolved copy, `test_confine_capture_workdir`'s control assertion ("not /tmp") fails
because that copy lives under `/tmp`. Run from a directory outside `/tmp`, it passes 730/730.

### Performance

`bench-history.csv` gains a **3.12.5** row, recorded retroactively on 2026-09-24 at the unchanged
3.12.5 tree on cyrius 6.6.2 (3.11.15 through 3.12.5 shipped without rows), and a **3.12.6** row
recorded on the final code. CSV rows are single runs. Every comparison below uses medians of 5
interleaved, CPU-pinned runs of each binary.

**Toolchain: 3.12.5 on 6.6.2 vs the pin move on 6.6.6.** Listed rows have non-overlapping ranges.
Of the other 16, `cgroup_policy_has_limits` moved by one 1 ns step and the rest are within noise.
Rows marked † move with code placement (see the next table), so their deltas here cannot be
attributed to the compiler's code.

| bench | 3.12.5 (6.6.2) | pin move (6.6.6) | Δ |
|---|---|---|---|
| `secrets_scan_clean_text` | 15.05 µs | 16.67 µs | +10.8% |
| `secrets_scan_with_secrets` | 7.49 µs | 8.07 µs | +7.7% |
| `secrets_redact` | 6.46 µs | 7.22 µs | +11.7% |
| `process_exec_large_output` | 122.06 ms | 128.60 ms | +5.4% |
| `code_scan_large_naive` | 6.00 ms | 5.64 ms | −5.9% |
| `http_path_extract` † | 110 ns | 118 ns | +7.3% |
| `http_allowlist_hit` † | 68 ns | 73 ns | +7.4% |
| `http_allowlist_miss` † | 77 ns | 86 ns | +11.7% |
| `ct_streq_64` † | 195 ns | 172 ns | −11.8% |

⚠ **The `secrets_*` and `process_exec_large_output` regressions are toolchain-side.** None of this
release's source changes touch those paths, and those rows do not move with placement. Building the
same kavach tree on 6.6.4, 6.6.5 and 6.6.6 shows:

- the `secrets_*` rows rise at each step (`secrets_redact` 6.43 → 6.69 → 7.07 µs);
- `process_exec_large_output` steps up at 6.6.5.

6.6.5 pads every call made inside an expression to 16-byte stack alignment. That is an ABI
correctness fix, and a plausible cost for call-dense scan loops; it is not root-caused further here.

**Placement.** Four rows move when code that never runs is added. All three builds are on 6.6.6:
the pin move alone; the same plus an unexecuted copy of `_audit_append`, reached only from a branch
that is never taken, so the old append still runs; and the final code.

| bench | pin move | + unexecuted copy | final |
|---|---|---|---|
| `ct_streq_64` | 168 ns | 185 ns (+10.1%) | 188 ns (+11.9%) |
| `http_path_extract` | 114 ns | 96 ns (−15.8%) | 96 ns (−15.8%) |
| `http_allowlist_miss` | 84 ns | 78 ns (−7.1%) | 79 ns (−6.0%) |
| `http_allowlist_hit` | 71 ns | 69 ns (−2.8%) | 69 ns (−2.8%) |

The unexecuted copy moves these rows as far as the fix does, so the shifts come from where code
lands, not from what runs. The other 21 rows, the `secrets_*` rows among them, stayed within noise.
Read the † rows' history with this in mind: the toolchain move shifts placement far more than one
function does.

**The all-or-nothing append costs the same as the call it replaces.** It adds one `lseek`, and
`fchmod(fd)` replaces `chmod(path)`, which also drops a path walk. In the same runs,
`audit_chain_record_to_tmpfs` went from 11.80 µs to 11.35 µs (−3.8%), with overlapping ranges.

## [3.12.5] — 2026-09-10

### Fixed — `audit_entry_new` mis-bound against agnostik

kavach and agnostik both exported `audit_entry_new`, at different arities for different types:
kavach's a zero-argument constructor for a 48-byte entry, agnostik's
`audit_entry_new(id, agent_id, action, severity)` over its own 112-byte record. Any consumer
vendoring both — **aethersafha** — got "last definition wins", so every call to the loser read
garbage. cyrius 6.6.2 makes a same-name different-arity duplicate a hard error, which is the only
reason it surfaced.

kavach's side moved to `kavach_audit_entry_new`: one caller here against agnostik's five.
Second instance of this class after `health_check_new` (agnostik ↔ argonaut, fixed in agnostik
1.6.1).

## [3.12.4] — 2026-09-10


**Migrated to the cyrius 6.6.x value form.** All four trees green — main, tcyr, bcyr, fuzz.

### Changed — cyrius pin 6.5.35 → **6.6.2**

cyrius 6.6.0 flipped `Result` / `Option` / `Either` declared `: stack` to a **value form**: a
payload variant returns a `(tag, payload)` REGISTER PAIR and allocates nothing. `payload()` is
deleted permanently.

**43 sites migrated** across 11 files. The compiler enumerated every one.

⚠ **13 were the propagation trap.** `if (is_err_result(res) == 1) { return res; }` migrated
naively returns the **payload alone**, so `Err(77)` reaches the caller as `tag=77`,
`is_err_result == 0` — an error that reads as SUCCESS. In `kernel_audit` (×7), `mac` (×4) and
`util` (×2) that would have turned a refused audit-rule load or a failed MAC transition into a
silent success. All re-wrapped as `return Err(res_v);`.

### ⚠ BREAKING — `result_print_err` takes both halves

```
- fn result_print_err(res)
+ fn result_print_err(res_tag, res)
```

A `Result` passed as a *parameter* is now two registers. Call it as
`var t, v = f(); result_print_err(t, v);`.

⭐ **This also removes a hard build error, not just a stale signature.** kavach's 1-arity
definition and sigil's 2-arity one were both in scope, and cyrius 6.6.2 makes a same-name
different-arity duplicate a **hard error** (it was a silent "last definition wins" before, meaning
every call to the loser mis-bound). Signature now matches sigil and agnodrm, which made this move
first — kavach was the last of the three still on the boxed form.

### Changed — dependency pins

| dep | from | to |
|---|---|---|
| `sigil` | 3.12.9 | **3.12.16** |
| `ai-hwaccel` | 2.3.19 → **2.3.22** | |
| `samay` | 1.0.1 | **1.1.2** |

⚠ The `samay` bump was **required, not hygiene**. samay ≤1.1.1 was pinned to cyrius 6.5.36 and
carried unmigrated value-form code in its shipped bundle, plus a stale `bayan` 1.5.2 pin whose
`dist/bayan-json.cyr` still reads payloads the boxed way (`load64(fd_r + 8)`). Both reached kavach
through vendoring and neither was kavach's to patch. samay 1.1.2 fixes both upstream.

### Fixed — a doc comment that taught the trap

`src/sys_error.cyr`'s "Propagate error" block documented the pre-flip idiom verbatim, ending
`if (is_err_result(res) == 1) { return res; }` — the exact silent-failure shape, in the file that
defines error handling. Rewritten to the value form with the failure mode spelled out.

## [3.12.3] — 2026-08-24 — a lean confined-exec profile for consumers that cannot take the whole engine

### Added

- **`[lib.confine]` — a lean confined-exec distlib profile.** `cyrius distlib confine` →
  `dist/kavach-confine.cyr`, **4,796 lines** against the full fold's 11,524: the confinement path
  (namespaces, seccomp, Landlock, cgroups, the runtime guard, the process backend) without the exotic
  backends (firecracker / gVisor / SEV / SGX / TDX / WASM / OCI), the externalization scanners, the
  credential proxy, attestation, or the audit chain.

  Requested by **thoth**, whose `shell` and `edit` tools run unconfined and whose own source says so
  plainly ("a COARSE convenience pre-filter, NOT a sandbox"). thoth cannot take the full fold for two
  measured reasons: at 11,524 lines it pushes thoth's **expanded source past the cyrius preprocessor's
  8 MB ceiling** (a hard error, not a warning — `preprocess_out` is a fixed arena slot), and most of what
  it carries duplicates seams thoth already consumes (kavach's audit chain vs thoth's vendored libro, the
  scanners vs t-ron). Same arrangement sit's `[lib.read]` and sankoch's `[lib.zlib]` already give their
  consumers.

### Changed

- **`cstr_contains` and `str_to_lower_into` moved `src/scanning_code.cyr` → `src/util.cyr`.** Both are
  generic string helpers with no scanner content, and **`src/scanning_runtime.cyr` also calls them** — so
  the confine profile could not close without dragging the entire code scanner and its 25 pattern groups
  into a bundle whose whole point is to carry only the confinement path. Cyrius has ONE flat namespace
  regardless of file, so **every existing caller is unaffected** and the full `dist/kavach.cyr` is
  equivalent apart from the moved definitions.

### Changed — toolchain and dependency refresh

- **Cyrius pin `6.5.32` → `6.5.35`** and **ai-hwaccel `2.3.16` → `2.3.18`**. sigil (`3.12.9`) and samay
  (`1.0.1`) re-checked against their upstream `VERSION` and already latest, so no move.

  Validated with the full pin-move sequence CLAUDE.md prescribes — `deps → build → lint → vet → test` —
  and checked against all five documented pin-move hazards rather than just the pass/fail:
  **(3)** the `duplicate fn` set is unchanged at 17 names, all the known sigil↔kavach `sys_error.cyr`
  and `agnosys_*` overlaps; neither symbol moved in this release appears in it.
  **(4)** no new `undefined function` on a stdlib symbol.
  **(5)** the `[deps]` marker sits at byte **3796** — see below.

  ⚠ **`lib/patra.cyr` was stale at 1.13.9 after `cyrius deps`** (the snapshot carries 1.13.10). `deps`
  only overlays declared `[deps.NAME]` modules; it does not refresh a stdlib leaf that is already
  present. Fixed with `cyrius lib sync --full` followed by a file-by-file `cmp` sweep against
  `~/.cyrius/versions/6.5.35/lib` — 0 differing after. `lib/` is gitignored, so this affects local and CI
  builds rather than the tree, but a stale floor is exactly the kind of thing that reproduces as "works
  on my machine".

  Pre-existing and **not** introduced here, recorded so it is not re-diagnosed: `json_v_parse_str` is
  referenced by `samay`, `yantra` and `ai-hwaccel` and defined by none of them — stale after bayan 1.3.0
  renamed `_parse_str` → `_parse_buf`. ai-hwaccel **2.3.16 referenced it too**, so the bump did not cause
  it. It is a warning on an unreachable path; the build is clean.

- **CLAUDE.md's pin reference corrected** — it read `6.5.27` while the manifest was already on `6.5.32`.

### Fixed — the `[lib.confine]` block was filed above `[deps]` and broke the build

- ⛔ **The first cut of this release put `[lib.confine]` and its commentary ABOVE the `[deps]` array**,
  pushing the `[deps]` marker from byte 3796 to **5352** — past the **4095-byte `_auto_deps` window**.
  That is hazard (5) in CLAUDE.md, the one this project already hit for real at v3.11.14 and built a CI
  gate for, walked into again by the next person adding a documented section. The gate did its job and
  failed loud with the byte offset.

  The block now sits at the END of the manifest, below every `[deps.*]` section, which is where
  CLAUDE.md says long commentary belongs. Offset back to **3796** (headroom 299).

  ⭐ The lesson the gate's own comment already states, restated because it was still not enough: the
  natural place to document a section is directly above it, and for `[deps]` that is the one place it
  must never go. A profile block is not a dep block, but anything added above `[deps]` costs the window
  regardless of what it is.

### Note for consumers

`sys_error.cyr` is in the confine profile, so a consumer that also links **sigil** will see benign
`duplicate fn 'syserr_*'` warnings: kavach and sigil both inherit the same `sys_error.cyr` from agnosys,
so the definitions are **identical** and last-def-wins is a no-op. Documented rather than silenced —
a duplicate-symbol warning that turns out to be harmless still deserves to be explained, because the next
one might not be.

## [3.12.2] — 2026-08-21 — `config_workdir` was decorative; the payload now lands in it

### Fixed — a sandbox's configured working directory was never applied

`config_workdir` has existed since before 3.12.0 and **its only reader was the WASM backend's
`--dir` preopen** (`_wasm_append_preopens`). Every process- and OCI-backend caller set a
workdir and got cwd `/`: `_spawn_enter_rootfs` `chdir("/")`s after chroot and nothing refined
it, and `oci_generate_spec` hardcoded `"cwd":"/"`. Exactly the `SandboxConfig.externalization`
shape — a setter that stores and is never consulted.

Reported by stiva, where `stiva run -w /app` was accepted, stored, threaded onto its
`RuntimeSpec` and silently ignored.

- `_spawn_enter_workdir(workdir)` — `chdir` into the configured directory, **after**
  `_spawn_enter_rootfs`, so the path resolves *inside* the container rather than against the
  host. `workdir == 0` is not a request and is a no-op.
- `confine_child_wd(…, workdir)` and `confine_capture_input_env_wd(…, workdir)`; the existing
  `confine_child` / `confine_capture_input_env` forward `0`, so **every 3.12.0/3.12.1 caller is
  unchanged**.
- `sandbox_spawn` and the process backend read `SandboxConfig_workdir` and pass it down.
- `oci_generate_spec` emits `process.cwd` from the config (JSON-escaped), replacing the
  hardcoded `"/"` — so the runc path honours it too.

⚠ **It FAILS CLOSED.** A workdir that cannot be entered `_exit`s the child with the new
`SPAWN_EXIT_WORKDIR` (117) rather than running the payload from the wrong directory. runc
behaves the same way. A silently-wrong cwd is a worse outcome than a refused spawn.

⚠ **Applied whether or not the child is confined.** A working directory is process setup, not
a confinement primitive — the same reasoning that makes `envp` unconditional. The capture path
therefore applies it *after* the `do_confine` block and passes `0` down to `confine_child_wd`,
so it lands exactly once. An earlier draft applied it only under confinement, and an
unconfined capture silently ignored the caller's workdir — the same defect in a new place,
caught by the test asserting on the payload's `$PWD` rather than on the setter.

⚠ **The parameter list has reached 14 by strict append-and-wrap.** That has kept every release
source-compatible and is at the end of its useful life; the next capability here should take a
config struct rather than a 15th positional.

701 → **713 assertions**, 0 failed — `test_confine_capture_workdir` (the payload's actual
`$PWD`, plus the fail-closed path) and `test_oci_spec_cwd_from_config` (the runc half, which the
process-backend test does not touch, including escaping of a caller-supplied path).

⚠ **Both halves needed their own test, and the second was nearly missed.** An end-to-end probe
through stiva was inconclusive — a container with no `/bin/sh` fails at exec *before* runc ever
chdirs, so a missing `cwd` and a present one produce the identical error. Asserting on the
generated spec settled it directly. When a runtime error could have two causes, assert on the
artifact, not on the symptom.

## [3.12.1] — 2026-08-21 — the command blocklist made kavach unusable as a container runtime

### Fixed — a rootfs'd sandbox could not run a shell, so most images could not start

`check_command`'s interpreter blocklist (`sh`, `bash`, `zsh`, `dash`, `python`,
`python3`, `perl`, `ruby`, `php`, `lua`, `node`, `deno`, `bun`, `gcc`, `cc`, …) was
enforced on **every** backend, unconditionally, via `runtime_guard_config_default()` —
`backend_process`, `spawn`, `backend_oci`, `backend_gvisor`, `backend_firecracker` and six
more. A sandbox carrying its own `rootfs` got it too.

That made the `rootfs` field added at 3.9.1 — which exists so kavach can back a container
runtime — largely useless. Reproduced end-to-end in stiva:

```
$ stiva run <image>          # no CMD, so stiva defaults the command to /bin/sh
[INFO] executing one-shot container via kavach: /bin/sh
[INFO] container execution complete, exit_code=126
blocked command: sh
```

The same refusal hit any image whose entrypoint is a shell or an interpreter — which is
most of them. No such container could ever start, on any backend.

**The blocklist's premise does not hold once there is a rootfs.** It exists to stop an agent
sandbox shelling out to an interpreter **on the host**, where `sh` resolves to the host's
`/bin/sh` and running it is an escape. With a rootfs the name resolves *inside the
container's filesystem*, to a binary the caller supplied, reached only after
`_spawn_enter_rootfs` has chrooted and the namespaces are up. The isolation there is the
rootfs, the namespaces, seccomp and the cgroup — not the payload's filename.

New `runtime_guard_config_for_rootfs(rootfs)` returns the default config with **only** the
command blocklist cleared, and only when `rootfs != 0`. The five container-capable backends
call it instead of `runtime_guard_config_default()`.

⚠ **Nothing changes for a rootfs-less sandbox.** `rootfs == 0` returns the unchanged
default, so every agent-sandbox consumer keeps the blocklist exactly as before. The
narrowing is conditional on a field only a container runtime sets, and
`test_runtime_guard_rootfs_narrowing` asserts **both** halves — the negative one is the
load-bearing one, because if the rootfs-less path ever stopped enforcing the blocklist,
nothing else in the suite would notice.

⚠ **Only the blocklist is dropped.** Sensitive-path detection (`cat /etc/shadow`) and
shell-metacharacter detection (`curl … | sh`, `echo hi; bash -c …`) stay on inside a
container, and the test asserts that too — otherwise this would be a hole rather than a fix.

*(Note for the next test author: `_check_shell_meta` matches chaining/piping **into a
shell** — `| sh`, `; bash` — not arbitrary metacharacters. `echo hi; rm -rf /` is not
flagged by it. Asserting on that shape fails against correct code.)*

692 → **701 assertions**, 0 failed.

## [3.12.0] — 2026-08-21 — a sandbox can be given an environment

### Added — `config_env`: an explicit, caller-supplied payload environment

Every kavach exec path built `envp` as a hardcoded empty array — `src/spawn.cyr:136`,
`src/confine.cyr:419`, `src/persistent.cyr:135`, `src/backend_oci.cyr:171` — and the OCI
spec emitted a fixed `"env":["PATH=…","TERM=xterm"]` (`src/oci_spec.cyr:191`). There was no
way for a caller to hand a payload a variable, and `SandboxConfig` had no field to carry one.

**This does not reverse the standing position that the caller's environment is never leaked
into a sandbox** (`src/backend_oci.cyr:24-30`). The two are opposites. Inheritance is
implicit and carries whatever the host happened to export; `config_env` takes a list the
caller wrote down. Nothing is inherited — a variable reaches the payload only because
someone put it in the vec. The default is `0`, which is the empty envp every path used
before, so **every existing consumer is byte-identical**.

New surface:

- `config_env(c, v)` — attach a vec of `"KEY=VALUE"` cstrs to a `SandboxConfig`.
- `kv_envp_from_vec(v)` — build a NULL-terminated `envp`; `v == 0` yields the empty one.
- `confine_capture_input_env(…, env)` — the capture path with an explicit environment.
  `confine_capture_input` forwards `env = 0`, so no existing caller changed — the same
  wrapper discipline `confine_capture` follows for `input`.

Honoured by the **process backend** (`src/backend_process.cyr`), **`sandbox_spawn`**, and the
**OCI backend's `process.env`**. On the OCI path an explicit list **replaces** the default
PATH/TERM pair rather than appending to it: an OCI image declares its own `PATH`, and
silently prepending kavach's would shadow it. A caller wanting the defaults includes them.

Not honoured by **persistent sandboxes** (`_persistent_spawn_inner`), which have no config in
scope; noted at the call site rather than left to be discovered.

`SandboxConfig` goes **112 → 120 bytes**, `env` appended so no existing field offset moves —
the discipline `fuel` followed at 112, `stdin`/`stdin_len` at 104 and `require_ns` at 88. The
layout guard in `tests/kavach.tcyr` is updated and still asserts every prior field reads back
at its old offset.

### Why this was reported — and the testing lesson attached to it

Filed by **stiva**, whose containers silently lost the OCI image's declared `process.env`. It
parsed the image config, persisted the variables to `state.json`, and built them into its
`RuntimeSpec` — then had no setter to hand them to kavach, so `build_sandbox` dropped them.
Every container ran without the environment its image declared. The Rust runtime stiva was
ported from applied them via `Command::env`, making it a parity regression with no fix
expressible on the consumer side.

⚠ **It survived a 2175-test suite because the test asserted the wrong half.** stiva checked
that its spec *carried* the env — which it did — and never that a payload could *read* it.
`test_confine_capture_env` is written to that lesson: it runs `/bin/sh -c 'printf %s "$VAR"'`
and asserts on what the payload observed, plus the negative case that an unset config still
yields an empty environment.

⚠ A note for whoever writes the next such test: **do not probe with `PATH`.** `/bin/sh`
synthesises a default when the variable is absent, so `$PATH` is non-empty even under
`execve` with a genuinely empty `envp` — measured, `env -i /bin/sh -c 'printf %s "$PATH"'`
prints 39 characters. Asserting on `PATH` tests the shell, not the environment, and fails
against correct code. The test probes `HOME`, which is not synthesised.

684 → **692 assertions**, 0 failed.

## [3.11.15] — 2026-08-19 — definitive names for three symbols ai-hwaccel also defined

### Security — `_backend_fp`'s bounds check was disabled wherever ai-hwaccel was co-resident

`var BACKEND_COUNT = 10;` collided with ai-hwaccel's `var BACKEND_COUNT = 18;`. Cyrius has one flat
symbol table with last-definition-wins and is **silent** on a duplicate `var`, so in any binary
linking both, kavach's guard read **18**:

```cyrius
# an out-of-range id would otherwise index _backend_table[320] out of bounds
# and load a wild function pointer.
if (backend_id >= BACKEND_COUNT) { return 0; }
```

`_backend_table` is 320 bytes at `BACKEND_SLOT_SIZE = 32` — **10 slots**. With the guard admitting
0–17, `_backend_slot(17)` reads **224 bytes past the table**, and `backend_dispatch_exec` then
`fncall2`s the result. The `fp == 0` check does not help: non-zero `.bss` gets called.

Measured, not inferred — a probe returning `BACKEND_COUNT` as its exit code printed **18** at
cyrius 6.5.32 in a project linking both libraries through agnosai.

Nothing caught it: the compiler is silent for `var`, and `scripts/check-symbols.sh` here and in every
sibling scans `src/` only, so a `lib/`↔`lib/` collision between two dependencies is invisible.

⚠ This is the **second** instance of the same class in this file. The comment above
`kavach_backend_name` already records renaming `backend_name` at 3.8.2 for exactly this reason —
ai-hwaccel, pulled transitively via `[deps.samay]`, defining its own over a different enum. That fix
addressed the instance; this one addresses the remaining names.

### Changed — three symbols renamed

| was | now | why |
|---|---|---|
| `var BACKEND_COUNT` | `var KAVACH_BACKEND_COUNT` | the collision above |
| `enum Backend` | `enum KavachBackend` | type name, also defined by ai-hwaccel |
| `fn path_exists` | `fn kavach_path_exists` | also defined by ai-hwaccel |

**Not breaking for the enum rename** — and the reason is worth recording, because it also bounds
what that rename achieved. In Cyrius an enum **qualifier is cosmetic**: `Backend.WASM` and
`KavachBackend.WASM` both resolve to the member `WASM`, and the type name plays no part in
resolution. Verified in agnosai, which calls `Backend.WASM` / `Backend.NOOP` / `Backend.PROCESS` /
`Backend.OCI` at 8 sites and builds unchanged against this release, with every value correct.

So of the three renames only two closed a real collision:

- `BACKEND_COUNT` — **the memory-safety fix.** A `var`, silently resolved, wrong value.
- `path_exists` — a real `fn` collision; last-definition-wins picked one implementation for both
  libraries. This one at least warned at build time.
- `enum Backend` — **defensive, not load-bearing.** It removes a duplicate symbol-table entry, but
  since the qualifier is never resolved through, the collision was inert.

⚠ The corollary matters more than the rename: because only member names resolve, renaming the enum
**type** does not protect the members. `PROCESS`, `WASM`, `OCI`, `NOOP` and the rest are still
generic, still unprefixed, and still the real exposure. They collide with nothing in the current
fold — verified across all of `lib/` — but that is luck, not design.

Left alone here to keep this release to the live defect.

### Fixed — the Format check gate could never pass, and said so about every file

The step diffed `cyrius fmt`'s **stdout** against the committed file. `cyrius fmt` rewrites the file
**in place** and prints nothing (`cyrius fmt` usage: *"(no flag) rewrite the file in place"*), so the
comparison was always against an empty stream: every file reported drift, including ones
`cyrfmt --check` calls correctly formatted.

The step's own comment had the premise exactly backwards — it claimed fmt "writes formatted source
to stdout" and that `--check` "only sets the exit code without emitting output, so diffing its
stdout always reports spurious drift". `--check` emitting no stdout is the *correct* behaviour and
the flag built for this job; the diff-the-stdout form is what produced the spurious drift.

Because the step was `(informational)` and never `exit 1`, this was invisible: CI stayed green while
the output was pure noise, and the roadmap v3.2 item to "flip this step to `exit 1` once src/ and
tests/ are clean" could never be judged done — the gate would have failed on a perfectly clean tree.

Now uses `cyrius fmt "$f" --check`, and is **blocking**.

### Fixed — 21 files carrying fmt drift

`src/{credential,composite,confine,security,persistent,backend_process,scanning_gate,scanning_code,scanning_secrets,scanning_data,audit,scanning_runtime,backend_oci,credential_http,backend_sy_agnos,backend_wasm,quarantine,mac}.cyr`
and `tests/{kavach.tcyr,kavach.bcyr,samay_integration.tcyr}`.

**Pre-existing** — verified: all 21 were already unformatted at tag 3.11.14, so the rename in this
release added none of it. This is the v3.2 backlog item, cleared here so the gate above could be made
blocking rather than left as noise. Build clean and **698 assertions green, 0 failed** — identical
to the pre-change baseline.

### Changed — Cyrius pin 6.5.27 → 6.5.32

Also clears real drift: the installed toolchain was 6.5.32 while the manifest pinned 6.5.27, which
means `lib sync --full` and `deps` were provisioning from a version the manifest did not name.

**698 assertions green, 0 failed** — identical to the pre-rename baseline. Build clean.
`dist/kavach.cyr` regenerated (11,280 lines) and verified to carry the new names and none of the old.
Cross-checked against `dist/ai-hwaccel.cyr` 2.3.18: **0 remaining collisions** between the two.


## [3.11.14] — 2026-08-17 — a declared stdlib module that arrives transitively is never included

### Changed

- **Cyrius toolchain pin `6.5.21` → `6.5.27`.** Validated with the full
  `deps → build → lint → vet → test → bench` chain on the new toolchain:
  **684 assertions green** (unchanged from v3.11.13), plus the 12-assertion
  `samay_integration` suite, lint **0**, `vet` 44 deps / 0 untrusted / 0
  missing, `deny` 0 violations, fuzz clean, `fmt` **0 drift**.

- **Dependency pins re-verified against upstream, all already latest** — sigil
  `3.12.9`, samay `1.0.1`, ai-hwaccel `2.3.16`. No dep moved this release; the
  toolchain did.

- **`lib/` re-vendored from an empty tree.** The working copy had drifted to
  **104 modules** against **70 declared** — 34 files (`mabda`, `niyama`,
  `ganita`, `patra`, `regex`, `unicode/`, …) left over from a whole-snapshot
  sync rather than `cyrius deps`. `rm -rf lib && cyrius deps` restores the
  declared set as the source of truth; `cyrius.lock` goes 110 → 70 entries.

- **`duplicate fn` warnings hold at 20** — the post-v3.11.13 baseline, with no
  new collisions from the pin move. Still the documented `syserr_*` (9),
  `agnosys_*` (7), `path_exists`, `attestation_result_new`, and the
  intra-kavach `SpawnedProcess_pid` / `_set_pid` pair.

### Fixed

- **⛔ `chrono` was declared, vendored, and silently never included — the whole
  tree stopped building.** Under cc **6.5.26+**, `[deps].stdlib`'s `chrono`
  entry resolves to a **no-op**, so every `clock_epoch_secs` (audit,
  quarantine, oci_spec, observability, attestation, scanning_threat,
  scanning_runtime), `clock_now_ns` (lifecycle) and `sleep_ms` (spawn) call
  became an undefined function and `cycc` refused to emit a binary.

  ⚠ **The manifest was correct, and that is what made it expensive.**
  `lib/chrono.cyr` is copied into `lib/`, `cyrius deps` reports success, and
  `cyrius.lock` records it — but no `include` is ever prepended, and no
  diagnostic names `chrono`. The error names a *symbol*, several steps later.

  The cause is an **ordering** bug in the resolver, upstream, not in kavach.
  `_dep_copy_stdlib_recursive` (cyrius `cbt/deps.cyr:521`) tests its seen-set
  on its **first** line and returns before the `is_top == 1` push at
  `cbt/deps.cyr:582`. A module first reached **transitively** (`is_top=0`) is
  marked seen, so its own later top-level declaration can never be upgraded.
  cc 6.5.26 added `lib/async_macos.cyr`, which carries
  `include "lib/chrono.cyr"`, and `lib/async.cyr` includes *that* — so from
  6.5.26 on, chrono arrives through `async`, and any manifest listing `async`
  before `chrono` loses chrono's prepend. Ours did, alphabetically.

  **Bisected** with a three-line program and one manifest: clean on
  6.5.21–6.5.25, broken on 6.5.26 and 6.5.27, flipping on nothing but the
  order of two entries in one array. Filed upstream with a self-verifying
  repro — cyrius
  `docs/development/issues/2026-08-17-stdlib-transitive-pull-drops-top-level-include.md`.

  **Fixed here with an explicit `include "lib/chrono.cyr"`** in
  [`src/util.cyr`](src/util.cyr) — kavach's first `[lib].modules` entry — plus
  one each in [`tests/kavach.fcyr`](tests/kavach.fcyr) and
  [`tests/samay_integration.tcyr`](tests/samay_integration.tcyr), which include
  no `src/` module and so cannot inherit it.

  ⚠ **Deliberately NOT fixed by reordering `[deps].stdlib`.** Moving `chrono`
  above `async` also works and is a smaller diff, but it encodes an assumption
  about *upstream's* include chains into our manifest and silently un-fixes
  itself the next time a stdlib module grows an `include`. The explicit include
  is order-independent. Cyrius include resolution is include-once, so it is a
  no-op wherever the auto-prepend works — including on 6.5.21–6.5.25.

- **⭐ Consumers are covered by the same one-line fix.** `cyrius distlib`
  preserves `include "lib/..."` lines into the bundle and emits
  `dist/kavach.deps` in bundle order, so `chrono` moved to the **top** of the
  sidecar, ahead of `async`. The sidecar is consumed by `_dep_pull_leaves`,
  which calls the *same* buggy resolver at `is_top=1` — so without this, every
  downstream consumer (SY, stiva, kiran, AgnosAI, hoosh, bote, aethersafta,
  mehman's M1 host) would have hit the identical undefined-`clock_*` failure on
  a machine where nobody changed anything. Two independent protections, one
  line.

- **⛔ A second silent resolver cliff, found by documenting the first one: `[deps]`
  must start within the first 4095 bytes of `cyrius.cyml`.** Writing the
  explanation above the `[deps]` array pushed the section marker from byte
  **3676 → 5288**, and the tree stopped building again — this time with *nothing
  at all* prepended.

  ⚠ **The manifest was never re-read, so the symptom pointed nowhere near it.**
  `cyrius build` reaches the resolver through `_auto_deps` (cyrius
  `cbt/deps.cyr:1983`), which does `alloc(4096)` + `file_read_all(manifest, buf,
  4095)` and scans **only that prefix** for `[deps]` / `[deps.`. Past 4095 the
  marker is invisible, `_auto_deps` returns 0, `cmd_deps()` never runs, and no
  `include` is emitted for anything. The build died on
  `undefined variable 'IoNotFound'` in `src/util.cyr` — a file whose only change
  was four kilobytes away, in a different file.

  ⛔ **A populated `lib/` does not save you, which is what made it stick.**
  `cmd_deps` reads **32767** bytes, so an explicit `cyrius deps` sees the section
  fine and vendors all 70 modules. They sit on disk, complete and correct, while
  the build behaves as if nothing were declared. Running `cyrius deps` — the
  obvious thing to try — changes nothing and argues for the wrong hypothesis.
  Two readers of one file, disagreeing by 8×.

  Boundary measured exactly, by padding the manifest: clean at byte **4095**,
  broken at **4100**. **Not a regression** — reproduced on 6.0.43, 6.2.11,
  6.3.40, 6.4.62, 6.5.21 and 6.5.27, i.e. the entire 6.x line. kavach had been
  sitting at **3676 / 4095** with no idea the ceiling existed. Filed upstream
  with its own repro — cyrius
  `docs/development/issues/2026-08-17-auto-deps-4095-byte-manifest-window.md`.

  **Fixed structurally, not by deleting the documentation**: `cyrius.cyml` now
  carries a 4-line pointer above `[deps]` and the full **MANIFEST HAZARDS** block
  *below* the array, where its length is free. Headroom back to **299 bytes**.

- **New CI gate: "Manifest [deps] within the 4095-byte auto_deps window".** A
  comment edit is an easy way back into the above and the symptom does not point
  at the manifest, so [`ci.yml`](.github/workflows/ci.yml) now fails the build
  when the marker crosses 4095 — naming the byte offset — and warns under 300
  bytes of headroom.

- **The demo banner had printed `kavach v3.2.0` for nine releases.**
  `src/main.cyr` carried a hardcoded literal that was never bumped after
  v3.2.0, while `VERSION` read `3.11.13`. Nothing caught it: CI's smoke test
  greps only for `kavach v`, and `src/main.cyr` is excluded from
  `[lib].modules`, so the wrong number never reached `dist/` or a consumer.
  ⚠ `scripts/version-bump.sh` **asserted in a comment that no such literal
  existed** — the reason nobody looked. The literal is corrected, the script
  now owns it as a bump step, and the false comment is replaced with the
  history.

- **`tests/samay_integration.tcyr` fmt drift closed.** One wrapped-call
  continuation indent, drifting under both 6.5.21 and 6.5.27 (so **not**
  introduced by this pin move). The tree is now `fmt`-clean end to end. Safe to
  fix here because the pin matches the installed `cycc`.

### Performance

Recorded as `3.11.14` in [`benches/bench-history.csv`](benches/bench-history.csv)
(25 benches), on a settled box (load **0.18**), against the v3.11.13 row.

**Broad improvement across the CPU-bound set, −4 % to −10 %:** `cgroup_wrap_argv`
398 → **359 ns** (−9.8 %), `http_path_extract` 119 → **108 ns** (−9.2 %),
`policy_strict_create` 65 → **60 ns** (−7.7 %), `credential_env_vars_100` 14.7 →
**13.6 µs** (−7.5 %), `gate_clean_output` 335.8 → **312.1 µs** (−7.1 %),
`score_all_backends_strict` 342 → **318 ns** (−7.0 %), `secrets_scan_with_secrets`
7.6 → **7.1 µs** (−6.9 %), `code_scan_large_ac` 505.4 → **474.5 µs** (−6.1 %).
No source change explains these; they track the 6.5.22–6.5.27 codegen.

⚠ **Two fork/exec benches moved the other way, and the first published number
for one of them was wrong.** `process_exec_echo` 2.73 → **2.93 ms** (+7.8 %) is
reproducible — four consecutive runs at 2.930–2.953 ms. `process_exec_confined`
2.77 → **3.24 ms** (+14.3 %) is **not** a tight measurement: 50 iterations with
min 2.60 ms and max 4.17 ms, a 60 % spread, so the mean is tail-driven. Nothing
in this release touches the exec path, and the sibling `process_exec_large_output`
(same fork+exec, dominated by I/O volume) *improved* 120.7 → **116.5 ms**
(−3.5 %), as did `sandbox_full_lifecycle` (−3.6 %) — so a systematic fork
regression is not supported by the data. Recorded as-is rather than explained
away; re-check at the next release before treating it as signal.

⛔ **The first `3.11.14` row taken was CONTENDED and was discarded, not
published.** Measured at load 1.09, it read `cgroup_wrap_argv` **505 ns
(+26.9 %)** — a regression that does not exist. Three settled re-runs gave
368/377/379 ns and the re-recorded row reads 359 ns, i.e. a −9.8 % *improvement*.
The CSV carries only the settled row. Waiting for load to fall below 0.40 was
the whole difference between publishing a fabricated 27 % regression and a real
10 % win.

## [3.11.13] — 2026-08-14 — kavach and sigil were sharing 14 error-constructor names

### Breaking

- **The bare `err_*` error constructors are now `kavach_err_*`.** kavach and
  sigil both inherit `sys_error.cyr` from agnosys, so both minted the *same
  fourteen* bare constructor names. cyrius auto-prepends every `[deps.*]`
  module into the compilation unit, so the two sets landed in one namespace and
  the compiler resolved them under **last-def-wins** — emitting a
  `duplicate fn` warning per name and picking whichever copy came later in
  source order.

  ⚠ **No behaviour changed, and that is the point.** The two copies were
  checked against each other rather than assumed to differ: kind values
  (1–8), `syserr_pack`/`syserr_new` layout, the `0x100000` packed-vs-heap
  threshold, and every `syserr_print` arm are **byte-identical** — down to a
  shared off-by-one that writes `"kernel module not loaded: "` as 25 bytes for
  a 26-byte string. Both are still near-verbatim forks of the same agnosys
  file, which is exactly why fourteen silent last-def-wins collisions survived
  the entire 3.x line unnoticed.

  The hazard is **structural, not present-tense**. Nothing in the build stops
  either side from diverging: a consumer's error classification would change
  with no error, no test failure, and no signal beyond one `duplicate fn`
  warning buried among 34. And the files *have* started to drift — sigil's
  enum members are `SIGIL_ERR_*` plus `SYSE_UNKNOWN`/`SYSE_IO`, kavach's are
  `KAVACH_ERR_*`. The values still coincide, so behaviour still coincides;
  the first edit on either side that moves one would not. This is the same
  shape as the `ERR_UNKNOWN` collision
  [ADR-006](docs/adr/006-library-surface-and-bundle-generation.md) closed for
  the *enum* half at v3.6.0 — fixed there by verifying the latent hazard
  rather than waiting for a consumer to hit it, and closed here on the same
  reasoning.

  sigil closed its side at **3.12.8** (`err_*` → `sigil_err_*`). kavach closes
  its own here. Migration is a mechanical prefix — the arities, argument order,
  and return values are unchanged:

  | v3.11.12 and earlier | v3.11.13 |
  |---|---|
  | `err_syscall_failed(errno, msg)` | `kavach_err_syscall_failed(errno, msg)` |
  | `err_syscall_failed_nr(errno)` | `kavach_err_syscall_failed_nr(errno)` |
  | `err_invalid_argument(msg)` | `kavach_err_invalid_argument(msg)` |
  | `err_invalid_argument_nr()` | `kavach_err_invalid_argument_nr()` |
  | `err_permission_denied(op)` | `kavach_err_permission_denied(op)` |
  | `err_permission_denied_nr(errno)` | `kavach_err_permission_denied_nr(errno)` |
  | `err_not_supported(feature)` | `kavach_err_not_supported(feature)` |
  | `err_not_supported_nr()` | `kavach_err_not_supported_nr()` |
  | `err_module_not_loaded(module)` | `kavach_err_module_not_loaded(module)` |
  | `err_would_block()` | `kavach_err_would_block()` |
  | `err_unknown(msg)` | `kavach_err_unknown(msg)` |
  | `err_io(errno, msg)` | `kavach_err_io(errno, msg)` |
  | `err_from_errno(errno)` | `kavach_err_from_errno(errno)` |
  | `err_from_syscall_ret(ret)` | `kavach_err_from_syscall_ret(ret)` |

  **Unchanged, deliberately:** the `syserr_*` accessors (`syserr_kind`,
  `syserr_errno`, `syserr_message`), the `KAVACH_ERR_*` enum members (already
  namespaced at v3.6.0), and the stdlib-owned `err_code_of` / `err_code`, which
  kavach does not define and must not shadow.

  The prefix is the **crate name**, per the convention ADR-006 set for
  `KAVACH_ERR_*` — repo names are globally unique across the first-party tree,
  so `<crate>_err_*` generalizes without the prefixes themselves colliding.
  sigil arrived at the same convention independently.

### Changed

- **Cyrius toolchain pin `6.5.20` → `6.5.21`.** Clean
  `deps → build → lint → vet → test → bench` on the new pin. No stdlib symbol
  migration was required; the `[deps]` stdlib list is unchanged, and the five
  opt-in modules whose absence SIGILLs at runtime (`ct`, `keccak`, `thread`,
  `thread_local`, `async`) are all still declared and vendored.
- **sigil `3.12.7` → `3.12.9`** — latest. 3.12.8 carries the `sigil_err_*`
  namespacing this release pairs with; 3.12.9 delocalises the RSA sign and
  bignum workspaces off `cbank()` lanes (−9.53 MiB of `.bss`). kavach uses
  sigil for HMAC-SHA256 of the audit chain (`src/audit.cyr`) and constant-time
  comparison (`src/util.cyr`) — neither touches the asymmetric stack, so the
  3.12.9 work is a pure inheritance.
- **ai-hwaccel stays `2.3.16` and samay stays `1.0.1`** — both already latest.
- **`lib/` re-vendored from scratch** (`rm -f lib/*.cyr cyrius.lock`,
  `cyrius deps`): 76 deps locked across 69 modules, `cyrius deps --verify`
  green. This is the curated `[deps]` set CI reproduces on a fresh checkout,
  not a `cyrius lib sync` full snapshot.
- `duplicate fn` warnings on a fresh checkout: **34 → 20**, measured rather
  than counted by hand — v3.11.12's tree was rebuilt against a staged sigil
  3.12.7 to get the 34, and the 14 that went are exactly the `err_*` set.
  (Note `cyrius build` re-runs `cyrius deps` first, so reproducing the old
  state needs the sigil bundle staged behind `[deps.sigil].path`, not swapped
  into `lib/`.) The remaining 20 (`syserr_*` and the seven
  `agnosys_*` helpers vs sigil, `path_exists` vs ai-hwaccel,
  `attestation_result_new` vs sigil, and `SpawnedProcess_pid`/`_set_pid`
  internal to `src/`) are pre-existing and untouched here.

### Docs

- `CLAUDE.md` corrected: the pin bullet and the DO-NOT rule still read `6.4.62`
  / "the tree is on cc 6.4 now" and the identity bullet still read `v3.7.1`.
  Added symbol collision with sigil as a third named pin-move hazard alongside
  the opt-in-stdlib and stdlib-consolidation ones.
- `README.md` — three fixes. The §Status block led with **v3.7.1**, six
  releases stale, advertising cc `6.4.62` / sigil `3.11.1` / 422 assertions /
  22 benches as current; §Build handed the reader those same versions as
  prerequisites. The "constructor/accessor API … is unchanged" note is now
  correct for the constructor half, and the "Benign symbol overlaps" caveat no
  longer lists `err_*` (nor calls the survivors benign). §Build also stopped
  recommending `cyrius audit` as a project gate — that is the **toolchain's own
  self-host audit**; `fmt`/`lint`/`vet` are now named individually.
- `docs/guides/getting-started.md` — missed by the v3.8–v3.11 releases
  entirely; its build prerequisites still instructed cc `6.4.62` / sigil
  `3.11.1`.
- `docs/adr/006-library-surface-and-bundle-generation.md` — two edits. A
  superseding note on the v3.6.0 enum decision (a note, not a rewrite — the
  record stands), and §4 "Symbol-overlap posture", which classified the
  `err_*` clash as **"Benign"** and told consumers the warnings were expected
  and safe. That is the exact claim this release refutes, and README §Known
  integration caveats points readers *at* it.
- `docs/doc-health.md` — header plus every per-doc row for a doc this change
  set touched; the rows still certified `README.md`, `CLAUDE.md`,
  `overview.md`, `roadmap.md`, `getting-started.md`, and `cyrius.cyml` as
  "Fresh" against v3.7.1 facts.
- `cyrius.cyml` — the `[deps.sigil]` comment block said "Pinned at 3.11.1 —
  latest" and "validated … under cc 6.4.62"; both corrected, and the collision
  history recorded at the pin so a future bump does not reintroduce a bare
  `err_*`.

### Performance

**Neutral — this release changes no semantics.** The rename is a pure
identifier substitution and the pin/dep moves do not touch the measured paths.
Verified rather than assumed: v3.11.12 was re-measured on the same machine from
a detached worktree at `a9d4bd4`, and every benchmark lands inside run-to-run
variance.

| benchmark | 3.11.12 (re-measured) | 3.11.13 (recorded row) | 3.11.13 steady state |
|---|---|---|---|
| `http_path_extract` | 107 ns | 119 ns | 114 ns (3 further runs) |
| `http_allowlist_hit` | 76 ns | 80 ns | 76–77 ns |
| `http_allowlist_miss` | 80 ns | 84 ns | 81 ns |
| `backend_parse` | 153 ns | 161 ns | — |
| `gate_clean_output` | 326.2 µs | 335.8 µs | — (min 306.8 µs, max 491.6 µs) |
| `code_scan_large_ac` | 481.9 µs | 505.4 µs | — (min 465.2 µs, max 653.6 µs) |

The recorded row is a single cold run and sits at the high end; three further
runs put the three `http_*` figures back on top of the 3.11.12 numbers. The
CSV keeps the cold run rather than a hand-picked best, so the row is
reproducible from `./scripts/bench-history.sh 3.11.13`.

⚠ **`benches/bench-history.csv` has no rows for 3.11.8 through 3.11.12** —
five releases cut without the baseline CLAUDE.md requires. The 3.11.13 row is
therefore recorded against **3.11.7** as its nearest predecessor, and the
deltas below are *cumulative over six releases*, not attributable to this one:

- Wins: `process_exec_confined` 5,059 µs → 2,768 µs (**−45.3%**),
  `process_exec_echo` 4,878 µs → 2,731 µs (**−44.0%**), `policy_strict_create`
  93 ns → 65 ns (**−30.1%**), `config_builder_full` 178 ns → 134 ns
  (**−24.7%**), `health_check_noop` 4,879 ns → 3,742 ns (**−23.3%**),
  `cgroup_wrap_argv` 475 ns → 398 ns (**−16.2%**), `sandbox_full_lifecycle`
  7,505 ns → 6,372 ns (**−15.1%**), `secrets_redact` 7,575 ns → 6,473 ns
  (**−14.5%**).
- Drift: `http_allowlist_hit` 63 ns → 77 ns, `http_path_extract` 103 ns →
  114 ns, `http_allowlist_miss` 74 ns → 81 ns. The worktree measurement puts
  all three at their current values *already at 3.11.12*, so they accrued
  somewhere in 3.11.8–3.11.12 and are a follow-up, not a regression here.

25 benchmarks recorded for 3.11.13. Tests: **684 passed / 0 failed**, plus 12
(samay integration) and 2 — unchanged from 3.11.12, as a pure rename should be.

### Known issues

- **`warning: undefined function 'json_v_parse_str'` comes from samay 1.0.1**,
  not kavach. bayan 1.3.0 (cyrius 6.5.0) renamed it `bayan_json_v_parse_str`;
  ai-hwaccel took that migration at 2.3.16, samay has not. samay is optional
  behind the default-on `scheduler` feature and kavach never calls the symbol
  — `dist/kavach.cyr` contains zero samay references — so the warning is inert
  here. Fix belongs upstream in samay.

## [3.11.12] — 2026-08-13 — the WASM backend defaulted to an UNBOUNDED guest

### Fixed

- **A default policy meant no memory ceiling at all.** `config_new()` installs
  `policy_basic()`, which sets seccomp and leaves `memory_limit_mb` at **0**, and
  `_wasm_append_limits` emitted `-W max-memory-size` only when that was `> 0`.
  So every caller on the default ran its guest with **no bound whatsoever** —
  and a wasm32 guest can claim up to **4 GiB**.

  ⚠ **Verified against wasmtime 47 rather than argued**: a hand-built module
  declaring a **128 MiB** memory instantiates fine bare and is refused under a
  64 MiB ceiling. The backend now always emits a ceiling, falling back to
  `WASM_DEFAULT_MEMORY_LIMIT_MB` when the policy names none.

  **64 MiB is not invented** — it is what Rust's own `WasmSandbox` defaults to
  (`DEFAULT_MAX_MEMORY_BYTES`), so kavach now matches the embedding host it is
  standing in for. An explicit `SandboxPolicy_set_memory_limit_mb` still wins,
  and `policy_strict()` keeps its 512.

  ⚠ **This is a behaviour change for any caller that relied on the absence of a
  ceiling.** A sandbox defaulting to unbounded is the wrong default; a caller
  wanting a larger guest now has to say so.

  Reported by agnosai, whose ADR 019 had carried the memory half of this as an
  open residual after the fuel half was closed in 3.11.11.

### Added

- `WASM_DEFAULT_MEMORY_LIMIT_MB` and `_wasm_effective_memory_mb(policy)`.
- `test_wasm_default_memory_ceiling` — **684 assertions** (was 676). It asserts
  the fallback, that an explicit limit still wins, that `policy_strict` keeps
  512, and end to end that a 128 MiB guest is refused on the default policy
  while a small one still runs. Mutation-verified: restoring the `mem > 0` guard
  fails the end-to-end arm.

## [3.11.11] — 2026-08-13 — an explicit WASM fuel budget

### Added

- **`config_fuel(c, fuel)`** — a WASM instruction budget in wasmtime `--fuel`
  units, set directly instead of inferred.

  ⚠ **Until now the only fuel was `timeout_ms * 1_000_000`**, so a caller
  wanting Rust's `Store::set_fuel(1_000_000_000)` had no way to ask for it
  without also shortening its timeout to one second. That derivation turns a
  **wall-clock** bound into a **CPU** bound, and the two are not
  interchangeable: at the default 30 s timeout the guest ran with **3e10 fuel,
  30x** what an embedding wasmtime host would set.

  Reported by agnosai 2026-08-13, whose `WasmSandbox` advertises the oracle's
  1e9 through `agnosai_wasm_sandbox_fuel` while the guest actually ran with
  thirty times that — an accessor reporting a limit that never reached the
  runtime.

  **`0` keeps the old behaviour** and is the default, so nothing that does not
  call `config_fuel` changes: `_wasm_effective_fuel` falls back to the
  timeout-derived value.

### Changed

- `SandboxConfig` grows **104 -> 112 bytes**. `fuel` is **appended**, so no
  existing field offset moves — the same discipline `require_ns` followed at 88
  and `stdin`/`stdin_len` at 104. The read-backs in `test_config_stdin` are what
  say the append was clean.
- Toolchain pinned to **cyrius 6.5.20** (was 6.5.18).

### Added — tests

- `test_wasm_exec_explicit_fuel`, **676 assertions** (was 674). A budget of `1`
  is the discriminator: it exhausts, so the guest does not exit 0, where the
  5 s timeout would otherwise derive 5e9 and run it fine. Mutation-verified —
  ignoring the field fails both the end-to-end run and the fallback assertion.

## [3.11.10] — 2026-08-11 — the WASM backend's wasmtime flags were never valid

### Fixed — `wasmtime run` rejected our argv outright, and no test could see it

`_wasm_append_limits` emitted `--max-memory-size <bytes>` and `--fuel <N>` as
top-level `wasmtime run` flags. wasmtime answers:

```
error: unexpected argument '--max-memory-size' found
```

and runs nothing. Both options live in wasmtime's `-W` group and are spelled
`-W max-memory-size=N` and `-W fuel=N`. `--dir` was and remains correct.

⚠ **This is not a wasmtime-47 regression — the spelling was never right.** The
`-W` option group has existed since wasmtime 14 (2023). Verified against the
installed **wasmtime 47.0.3**: the old argv errors, the new argv runs a module
and exits 0.

⚠ **Nothing in this repo had ever run a real module.** `test_wasm_exec_without_wasmtime`
and `test_wasm_exec_missing_file` both fail *before* argv is assembled, so a wrong
flag was structurally invisible. The backend was also unreachable through the
public API until 3.11.8, so it had never been exercised end to end by a consumer
either.

### Added — `test_wasm_exec_real_module`, the test that would have caught it

Runs a real module through `wasm_exec` and asserts the guest exited 0, plus that
wasmtime did not emit `unexpected argument`. Verified to **fail** on the old
spellings.

The module is 36 bytes, hand-assembled in the test rather than checked in: magic
+ version, a `() -> ()` type, one function, an exported `_start`, and a body of a
single END opcode. Building it from `.wat` would need `wat2wasm`, and pulling in
a Rust wasm target to test a shell-out would be a heavier dependency than the
thing under test.

⚠ **The test sets a memory limit AND a timeout, and that is load-bearing.**
`policy_new()` zeroes the struct and `_wasm_append_limits` emits each flag only
when its value is > 0 — so under a default config the argv is a bare
`wasmtime run -- <path>`, which is valid under every spelling. The first version
of this test did exactly that and passed with the broken flags restored. A
memory limit makes `-W max-memory-size=` reachable; a timeout makes `-W fuel=`
reachable through `_wasm_fuel_from_timeout`.

### Changed — lint is clean across `src/` and `tests/`, was 8 warnings

All pre-existing and all in `tests/kavach.tcyr`: six over-long lines, two
double-blank-line runs. Three of the six were long string fixtures — an OCI stub
script, a runc diagnostic, and a both-streams shell script — now assembled with
`str_builder`, with **byte-equality asserted for each** before the edit was
written.

⚠ **Cyrius has no adjacent-literal concatenation** (`"abc" "def"` is
`expected ';', got string`), and a `\`-continued literal is unsafe because
`cyrius fmt` reindents inside multi-line strings and the spaces land *in* the
string. `str_builder` is the only safe split for a fixture whose exact bytes
matter — and for a shell script, they do.

**Gate:** 2 suites, **669 + 12 assertions, 0 failures**, on wasmtime 47.0.3.
`cyrius lint` clean across `src/` and `tests/`; `fmt` clean; `vet` 44 deps /
0 untrusted; `deny` 0 violations; `dist/kavach.cyr` regenerated at 3.11.10,
idempotent, self-check current, and the fix verified present in the bundle.

## [3.11.9] — 2026-08-10 — toolchain + deps; 3.11.8's sakshi residual is cleared

Maintenance only: **no `src/` file changed** and `dist/kavach.cyr` regenerates
**byte-identical**.

### Changed

- **Toolchain pin 6.5.17 → 6.5.18; `[deps.sigil]` 3.12.6 → 3.12.7.**
  `[deps.ai-hwaccel]` 2.3.16 and `[deps.samay]` 1.0.1 were already latest —
  checked, not assumed.

  ⚠ **This clears 3.11.8's "known residual".** That release recorded
  `lib/sakshi.cyr` resolving to 2.4.8 instead of the snapshot's 2.4.10, traced to
  sigil declaring `[deps.sakshi] tag = "2.4.8"` in its own manifest and `cyrius
  deps` overlaying that on top of the toolchain snapshot. sigil 3.12.7 drops the
  git dep entirely — sakshi is now folded into the stdlib — so the overlay is
  gone and **`lib/sakshi.cyr` holds at 2.4.10 through a build, with no shadow
  warning.** Nothing was changed on this side; the fix was upstream, where the
  residual said it belonged.

  Verified: `distlib` exits 0, `dist/kavach.cyr` regenerates **byte-identical**,
  and `tests/kavach.tcyr` is 665 assertions / 0 failures.

## [3.11.8] — 2026-08-09 — the WASM backend was unreachable, deaf and blind

From a consumer report filed by agnosai while porting `rust-old/src/sandbox/wasm.rs` +
`tools/wasm_tool.rs` onto this backend —
`docs/development/issues/2026-08-09-wasm-backend-unreachable-no-stdin-no-exit-code.md`.

**The through-line: the process backend fixed this whole class of bug for itself in
3.11.4/3.11.5, and the WASM backend was left behind on the old `exec_capture` call.**
Its doc comment already said `exec_capture` "discards the wait status and has no seam
for a deadline"; `wasm_exec` was still calling it.

### Fixed

- **`backend_is_available(Backend.WASM)` was a hardcoded `0`** (`src/backend.cyr`), while
  `wasm_health` right beside it did the correct probe and every sibling backend probed
  properly. `sandbox_create` refuses a backend that reports unavailable, so **the entire
  WASM path was dead through the public API even with `wasmtime` installed** — a consumer
  could register the backend, configure it, and never reach `wasm_exec`. It now probes
  with `_wasm_binary_path`, which moved from `backend_wasm.cyr` into `backend.cyr` so the
  single-pass include order allows the call.

- **The guest's exit code was discarded.** `backend_capture_finish` stamps `0` on any
  successful capture and `wasm_exec` never overrode it, so **a module that TRAPPED
  reported success** with whatever partial stdout it managed. A consumer branching on
  `exit_code != 0` — the entire failure taxonomy of a tool protocol — saw every failure as
  a success. `wasm_exec` now routes through `confine_capture_input` and reports
  `confine_last_exit()`, exactly as the process backend has since 3.11.4.

- **The guest's stderr was hard-redirected to `/dev/null`**, so `ExecResult.stderr` always
  read `""` — a different and false claim from "the guest wrote nothing". Now
  `confine_last_stderr()`.

- **`SandboxConfig.timeout_ms` and `policy` were ignored on this path.** `exec_capture` has
  no seam for either; the confined capture enforces both.

### Added

- **`confine_capture_input(...)` — a stdin channel.** A third pipe, created only when
  there is input to send. Before this the child inherited the parent's fd 0, so a backend
  could run a program but **could not pass it arguments**, which is the whole contract of
  every WASM/CLI tool protocol. As agnosai put it: *a WASM tool that cannot receive
  parameters is not a port of this file.*

  ⚠ `input == 0` keeps the **inherit** behaviour rather than handing the child an empty
  stdin — every pre-3.11.8 caller reaches here through `confine_capture` with `0`, and an
  immediate EOF would change what an interactive payload sees.

  ⚠ The pipe is **closed after the write**. Without that a guest reading to EOF blocks and
  hits the deadline, so a protocol mistake would present as a timeout. Pinned by a test.

  ⚠ A short write is **not** retried. Pipe capacity is 64 KiB and the child is not reading
  yet, so a larger payload would block before `execve` — a deadlock, not a slow write.
  Callers with a large payload should pass it by file; stated rather than papered over
  with a partial write nobody checks.

- **`SandboxConfig.stdin` / `.stdin_len`, with `config_stdin(c, ptr, len)`.** The struct
  goes 88 → 104 bytes, appended so **no existing field offset moves** — the discipline
  `require_ns` followed at 88, and asserted by a test that re-reads three older fields.
  The buffer is not copied and must outlive the `sandbox_exec` that consumes it.

### Changed

- **Toolchain pin 6.5.10 → 6.5.16**, with `lib/` re-synced.

### Verified

- `tests/kavach.tcyr` — **665 assertions, 0 failures** (638 → 665).
- The new assertions are behavioural, not structural: `/bin/cat` proves stdin actually
  reaches the guest and comes back byte for byte; `/bin/false` proves exit 1 is reported
  where `exec_capture` reported 0; `/bin/sh -c 'echo oops 1>&2; exit 3'` proves stderr and
  an explicit code both survive; and the availability test asserts
  `backend_is_available == wasm_health` rather than a fixed value, so it is honest on a
  box with wasmtime and on one without.
- fmt / lint clean on every file this release touched.

### Changed — toolchain and dependencies

- **`[deps.sigil]` 3.12.2 → 3.12.6.** It was four patch releases behind.
- `[deps.ai-hwaccel]` 2.3.16 and `[deps.samay]` 1.0.1 were already current — checked, not
  assumed.
- **Pin 6.5.16 → 6.5.17.** ⚠ **This is what makes this release's CI green.** Under 6.5.16
  `cyrius distlib` exited 1 on this bundle: its self-check compiled the generated bundle
  *without* the stdlib leaves it had just written to `dist/kavach.deps`, and
  `src/util.cyr`'s bounds-checked `sl[i]` reads lower to `_slice_idx_get_W` helpers that
  the undefined-**fn** downgrade cannot reach. The bundle was correct throughout — it
  compiled cleanly against its own sidecar — and the failure was **not** caused by any
  source change here. Filed as
  `cyrius/docs/development/issues/2026-08-10-distlib-self-check-fails-on-slice-subscript.md`
  and fixed in 6.5.17.

  ⚠ The consumer-side workaround would have been to drop the bounds-checked slice in
  `is_safe_text` / `is_safe_argument` — the two functions that validate untrusted input,
  where trap-on-out-of-range is the entire point. That was not taken.

  Verified at the new pin: `distlib` exits 0, `dist/kavach.cyr` regenerates
  **byte-identical**, a clean-room consumer builds from the bundle plus its sidecar, and
  `tests/kavach.tcyr` is 665 assertions / 0 failures.

### Known residual

- ⚠ **`lib/sakshi.cyr` resolves to 2.4.8, not the 6.5.17 snapshot's 2.4.10.** `cyrius deps`
  overlays each git dep's own `[deps.sakshi]` resolution on top of the snapshot, and
  **sigil 3.12.2 declares `tag = "2.4.8"`** — so a `cyrius lib sync --full` is undone by
  the next build's implicit resolve. The only signal is an unnamed "1 bundled lib(s)
  differ" shadow warning, and `deps --verify` cannot catch it because the lock is written
  *from disk* and records the downgraded file's hash. Nothing kavach calls needs 2.4.9+,
  so this is staleness, not breakage.

  ⚠ **agnosai's fix for this does not transfer, and trying it breaks consumers.** agnosai
  and majra add a defensive `[deps.sakshi]` to their own manifests, which wins the
  overlay. Doing that here was tried and reverted: declaring sakshi as a git dep makes
  `distlib` reclassify it out of the **stdlib leaves**, so `dist/kavach.deps` loses its
  `sakshi` line and a clean-room consumer then fails with five undefined `sakshi_*`
  functions. The defensive pin is safe for a *binary* and unsafe for a library that
  publishes a bundle.

  ⚠ **Bumping `[deps.sigil]` to 3.12.6 does not clear it**: sigil 3.12.6 still declares
  `[deps.sakshi] tag = "2.4.8"` itself. The fix is one line in sigil, and it would clear
  this for every sigil consumer at once — it is not kavach's to make.

## [3.11.7] — 2026-08-05

### Security

- **The externalization gate measured artifacts with `strlen`, so a secret after
  an embedded NUL was released as PASS.** `strlen` is not a length — it is a
  distance to the first NUL — and every measurement in the scan path used it:
  the size cap at `gate_apply`, `_concat_with_nl`'s two `memcpy` bounds, and
  each scanner's own `n`. An artifact whose stdout contained a NUL was therefore
  scanned only up to it.

  Measured, on identical 23-byte payloads differing in one separator byte:

  | stdout | verdict |
  |---|---|
  | `"ok" NUL "AKIAIOSFODNN7EXAMPLE"` | **PASS** — a live credential released |
  | `"ok" SP  "AKIAIOSFODNN7EXAMPLE"` | BLOCK |

  The reverse also bit, for the same reason: a caller passing a **borrowed
  slice** — a Cyrius `Str` from `str_new`/`str_substr`, which shares its
  source's buffer and adds no terminator — had `strlen` run off the end into
  whatever followed in the arena. Ten clean bytes BLOCKed on a credential that
  was not part of the artifact at all. So the verdict could depend on unrelated
  allocator contents.

  Three changes, and **none of the three scanners was touched**:

  - **`ExecResult` carries `stdout_len` / `stderr_len`**, with
    `exec_result_set_stdout_n` / `_set_stderr_n` to supply them and
    `exec_result_stdout_len` / `_stderr_len` to read them. `-1` means unset and
    falls back to `strlen`, so **every existing caller behaves exactly as
    before**. The sentinel is `-1` rather than `0` because `0` cannot be told
    from a genuinely empty artifact — with a `0` default the gate would have
    concluded every result was empty and scanned nothing.
  - **The scan buffer is guaranteed NUL-free.** `_concat_scan_buf` copies both
    streams over their true lengths and rewrites every *interior* NUL to a
    newline. That makes `strlen` **correct** for the scanners rather than
    working around it — they see the whole artifact and needed no change. A
    newline specifically because `_concat_with_nl` already separates stdout from
    stderr with one: it is a boundary the scanners handle and no secrets, code
    or data pattern contains it, so the substitution neither hides a match nor
    invents one. Dropping the bytes instead would splice unrelated spans
    together and could fabricate a pattern that was never in the artifact.
  - **Redaction covers the whole artifact.** `secrets_redact_n(text, n, out_len)`
    redacts over a length and reports the length it produced. Both halves
    matter: its output copies non-matching spans verbatim, so it carries any NUL
    the input had, and re-measuring that output with `strlen` would truncate the
    very artifact the caller is about to release. `secrets_redact` keeps its
    signature for cstring callers.

  **The artifact itself is never rewritten** — the NUL-free buffer is a scanning
  copy. What a caller releases is still its own bytes.

  **Measured, because the rewrite replaces two `memcpy`s with byte loops** and
  that is a fair thing to worry about on the gate's hot path. It is not a
  regression — the scan dominates the copy by orders of magnitude:

  | benchmark | byte loop (3.11.7) | `memcpy` baseline |
  |---|---|---|
  | `gate_clean_output` | **311.0 µs** | 314.4 µs |
  | `secrets_scan_clean_text` | **15.08 µs** | 15.23 µs |
  | `secrets_redact` | **7.56 µs** | 7.61 µs |

  Same binary, same box, baseline produced by reverting only the two loops. The
  differences are inside run-to-run noise in both directions.

  Filed by agnosai as
  `2026-08-05-gate-apply-measures-with-strlen-so-it-cannot-scan-a-length-carrying-string.md`.
  Four regression tests, each mutation-verified — reverting the NUL rewrite, the
  size-cap length, the `-1` sentinel, or the redaction length fails 1, 1, 11 and
  2 assertions respectively. **The size-cap test was vacuous on its first
  attempt** (its artifact carried a secret, so it blocked either way) and is now
  built on clean content with a PASS sanity check ahead of it.

### Fixed

- **`--agnos` still failed to build, at two sites the 3.11.x line added itself.**
  `2026-08-01-linux-only-backends-break-every-agnos-consumer.md` named five
  `sys_unlink`/`sys_rmdir` arity mismatches, and the `kv_*` shims closed those —
  but the issue's actual claim, *every `--agnos` consumer fails to compile*,
  remained true. `cyrius build --agnos src/main.cyr` was verified failing on
  3.11.6.

  Two references to Linux-only syscall constants sat in function bodies that
  were never excluded from the agnos build:

  - `confine.cyr` — `SYS_FCNTL`, from the non-blocking round-robin drain added
    in **3.11.5**.
  - `persistent.cyr` — `SYS_PRCTL`, from the namespace work added in **3.11.6**.

  Both functions already returned early on agnos, but **a preprocessor arm is
  not a compiler arm**: an `#ifdef` early return does not stop the lines below
  it from being compiled, and an undefined symbol is a hard error whether or not
  it can execute. Because `cyrius build` auto-prepends every `[deps.*]` module,
  that failed *any* `--agnos` consumer declaring `[deps.kavach]`, including one
  that never touches either backend. Both bodies are now wrapped in
  `#ifndef CYRIUS_TARGET_AGNOS`, matching the pattern the rest of `confine.cyr`,
  `security.cyr` and `util.cyr` already use.

  Verified by the issue's own repro: `--agnos` builds, and the native build is
  unchanged.

  **Not part of this fix, recorded so it is not mistaken for one:**
  `util.cyr:329` issues a raw `syscall(91, fd, mode, 0)` for `fchmod`. It
  compiles everywhere because 91 is a literal, but 91 is the *Linux* number —
  on agnos it names something else. That is a latent correctness bug on agnos,
  not a build failure, and it is left alone here rather than folded into a
  release about compilation.

- **`2026-07-26-oci-backend-never-reports-the-container-exit-code.md` was fixed
  in 3.9.2 and never archived.** No code change here — verified against live
  code during this cut (`src/backend_oci.cyr:357` stores `_oci_last_exit`) and
  the file is moved to `archived/` with a status line saying so. Recorded
  because an open-looking issue that is actually closed costs the next reader
  the same time twice.

### Performance

- **Every process exec paid ~7 ms of dead sleep, and nothing could have seen
  it.** `confine_capture`'s drain loop (3.11.5) slept a flat `CONFINE_POLL_MS`
  = 5 ms on every idle iteration — including the ones before the payload has
  written its first byte, which for a short payload is the *whole* run. It now
  spends its first `CONFINE_POLL_RAMP` = 8 idle iterations at 1 ms before
  falling back to 5 ms, so a fast payload is noticed in about a millisecond and
  a slow one still converges to the old interval. The CPU argument the sleep was
  added for is unchanged for exactly the case it was made about.

  | benchmark | 3.11.6 (flat 5 ms) | 3.11.7 (ramp) | |
  |---|---|---|---|
  | `process_exec_echo` | 11.96 ms | **4.88 ms** | −59% |
  | `process_exec_confined` | 12.41 ms | **5.06 ms** | −59% |
  | `process_exec_large_output` | 140.88 ms | **115.88 ms** | −18% |

  Attribution is direct, not inferred: the same binary with only
  `CONFINE_POLL_MS` changed from 5 to 1 measures 4.78 ms on `process_exec_echo`,
  so the interval was the cost and the ramp recovers it. Set
  `CONFINE_POLL_RAMP = 0` to restore the flat interval.

- **Three benchmarks added, because the entire exec path had none.**
  `process_exec_echo`, `process_exec_large_output` (228,894 bytes of stdout,
  past the 64 KiB pipe buffer, which is what the round-robin drain exists for)
  and `process_exec_confined`. Before them, every benchmark in the suite was
  in-process — `sandbox_full_lifecycle` uses `Backend.NOOP` and execs nothing —
  so `confine_capture`, the drain loop, the deadline, `process_exec` and
  `oci_exec` were unmeasured. **That is why the regression above shipped through
  four releases**: 3.11.3 to 3.11.6 rewrote that code and none of them recorded
  a benchmark row, and a row would not have caught it anyway.

  `large_output` was wrong on its first attempt and reported 20 µs — faster than
  `echo`, because `_split_command` splits on whitespace only, so
  `sh -c "a | b"` became the tokens `"a`, `|`, `b` and nothing ran. A benchmark
  that runs nothing looks like a fast benchmark. It uses `seq` now, verified at
  228,894 bytes through this API.

### Note on the benchmark history

`benches/bench-history.csv` has **no row for 3.11.6, and none for 3.8.0 through
3.11.6** — the labels jump 3.7.1 → 3.11.7. CLAUDE.md requires a row per release,
so the prior-release comparison it asks for could not be made here. The 3.11.7
row is recorded (22 benchmarks); the gate figures above are a direct
before/after on this change instead, which is the comparison that was actually
available. Backfilling the gap is not attempted — those releases are already
cut and re-running them now would label today's machine with their versions.

## [3.11.6] — 2026-08-04

### Added

- **`persistent_spawn_confined_ns(command, policy, require_ns)` — namespaces on
  the persistent path.** It applied landlock and seccomp and **nothing else**:
  it takes a `SandboxPolicy`, which carries `network_enabled`, and acted on none
  of it. `config_require_namespaces` (3.11.5) is a `SandboxConfig` field and
  never reached here.

  That mattered because the persistent path is the only kavach API with a stdin
  channel, so it is what a consumer needing one must use — agnosai's cx tool
  sandbox among them, where a `.cyx` guest could open a socket despite a policy
  saying otherwise.

  Opt-in and fail-closed, the same shape 3.11.5 gave `process_exec`: the guest
  runs inside the policy's namespaces or exits `SPAWN_EXIT_NS` (123) /
  `SPAWN_EXIT_IDMAP` (118), never with a network its policy denied.
  `persistent_spawn_confined` keeps its signature and behaviour.

  Namespaces are created **after** the pipes are wired and **before** landlock,
  seccomp and `execve` — the pipes first because none of the three affect
  already-open descriptors, which is what lets a confined guest still read its
  stdin.

## [3.11.5] — 2026-08-04

### Added

- **`config_require_namespaces(config, on)` — opt-in, fail-closed namespace
  isolation without a rootfs.** 3.11.3 routed confinement on the policy, which
  made `confine_child` reachable with no rootfs; namespaces were then tied to
  the rootfs path because applying them unconditionally broke payloads on hosts
  that restrict unprivileged user namespaces (Ubuntu 24.04 does). That left a
  rootfs-less sandbox with **no network isolation**, silently.

  It is now sayable. With the flag set, the rootfs-less path requests the
  policy's namespaces and **fails closed** if the host refuses — the payload
  exits `SPAWN_EXIT_NS` (123) or `SPAWN_EXIT_IDMAP` (118) rather than running
  with a network the policy said it would not have. Off by default, so no
  existing caller changes behaviour.

- **`confine_last_stderr()` / `confine_last_stderr_len()`.**

### Fixed

- **The payload's stderr is its own stream.** Both child fds went to one pipe
  and `backend_capture_finish` then hardcoded `ExecResult.stderr` to `""` — so
  a caller was told the payload wrote nothing to stderr, which is a different
  and false claim from "kavach did not keep it". A diagnostic like
  `ls: cannot access ...` vanished entirely.

  Two pipes now, both non-blocking and **drained round-robin**: draining one to
  EOF and then the other deadlocks the moment the undrained pipe fills (64 KiB),
  because the payload blocks writing to it and so never closes the first. The
  regression test is shaped for exactly that — a small stdout and a stderr past
  the buffer — since flooding stdout instead proves nothing, the capture having
  its own cap.

### Changed

- `SandboxConfig` gains `require_ns` (size 80 → 88, appended, no existing field
  offset moves).
- `process_exec` sets `ExecResult.stderr` from the capture on both paths.

## [3.11.4] — 2026-08-04

### Security

- **`SandboxConfig.timeout_ms` is enforced on the process backend.** It was
  accepted, stored, scored, and read by `wasm_exec` alone — 14 of 15 registered
  backends dropped it. Measured on 3.11.2: a config with `timeout_ms = 1000`
  running `/bin/sleep 8` took **8001 ms** and reported `timed_out = 0`. A
  sandboxed payload that never exits hung its caller forever, and the flag said
  otherwise.

  `confine_capture` takes a deadline: the capture pipe goes non-blocking, the
  drain loop checks the clock between reads and sleeps 5 ms when idle, and on
  expiry the payload is SIGKILLed — kill first, so its pipe end closes and the
  loop is not left waiting on an EOF that is never coming — then reaped.
  `confine_last_timed_out()` reports it and `process_exec` sets
  `ExecResult.timed_out` from it.

  The idle sleep is not a nicety: polling a non-blocking pipe without one burns
  a full core for as long as the payload runs.

### Fixed

- **The process backend reports the payload's real exit code on every path.**
  The unconfined path used the stdlib's `exec_capture`, which waits on the child
  and discards the status, and `backend_capture_finish` hardcodes 0 — so
  `/bin/false` (real exit 1) and `/bin/ls` on a missing path (real exit 2) both
  came back **0**, and a failing payload was indistinguishable from a successful
  one. 3.11.3 fixed it only for policies that request confinement.

  Both paths now go through `confine_capture`, which already decoded the status
  correctly; the unconfined one passes `do_confine = 0` for a plain
  fork/exec/capture. One capture, so the two cannot drift apart again — and the
  deadline above applies to both for the same reason.

### Added

- `confine_last_timed_out()` — whether the most recent `confine_capture` killed
  its payload on the deadline.
- `kv_sleep_ms(ms)` — the drain loop's idle wait.

### Changed

- `confine_capture` takes `timeout_ms` and `do_confine`. Both are new trailing
  parameters; `process_exec` is the only in-tree caller.

## [3.11.3] — 2026-08-04

### Security

- **Neither exec path applied seccomp or landlock without a rootfs.**
  `process_exec` reached the confined capture only under `rootfs != 0`, so a
  policy carrying `seccomp_enabled = 1` ran its payload through a plain
  fork/exec with the caller's full ambient authority. The flag was stored,
  scored by `score_backend`, and never applied — a `policy_strict()` sandbox
  with no rootfs read an arbitrary host file and reported success.

  Found and measured by agnosai while porting its cx tool sandbox, whose
  [ADR-006](https://github.com/MacCracken/agnosai) makes kavach's seccomp +
  landlock the *entire* security boundary for untrusted bytecode: a `.cyx`
  calling `open("/etc/passwd")` succeeded through `persistent_spawn`.

  Routing is now on the **policy** (`policy_wants_confinement`) rather than on
  the rootfs. `_spawn_enter_rootfs(0)` already returned 0 and `_spawn_ns_flags`
  already accounted for a null rootfs, so the confined path needed no rootfs to
  work — only to be reached. A policy that asks for seccomp and cannot get a
  filter now **fails closed** instead of falling through to an unconfined exec.

- **Landlock rules could not be expressed, so landlock was applied by nothing.**
  `SandboxPolicy.landlock_rules_len` was a bare counter with no list behind it,
  and `confine_child` called `security_apply_landlock(0, 0)` — a null list with
  a zero count, which returns `Ok(0)` immediately. Both shipped presets carried
  a count of 0. The machinery underneath was complete and has handled all
  thirteen ABI v1 rights since 3.11.1; only the path from a policy to it was
  missing.

  New: `policy_landlock_add(policy, path, access)` accumulating a real rule
  list, `policy_landlock_deny_all(policy)` for a ruleset that permits nothing,
  and `policy_landlock_rules(policy)` to read it back. `confine_child` passes
  the policy's actual rules.

- **`persistent_spawn` applied no confinement and took no policy.** It is the
  only kavach API offering a stdin channel, so it is what a consumer needing one
  reaches for — and it forked and `execve`d with nothing applied.
  `persistent_spawn_confined(command, policy)` installs landlock and seccomp in
  the child, after the pipes are wired and before `execve`: landlock does not
  affect already-open descriptors, which is what lets a confined guest still
  read its stdin. `persistent_spawn` keeps its signature and behaviour for
  callers who genuinely want an unconfined child, and now says so.

### Fixed

- **Namespaces are applied on the rootfs path, and only there.** Routing
  confinement on the policy meant `confine_child` was suddenly reached without
  a rootfs — and `config_new` defaults to `policy_basic()`, whose
  `network_enabled = 0` makes `_spawn_ns_flags` request a network namespace,
  which unprivileged requires a **user** namespace to obtain. Ubuntu 24.04
  restricts unprivileged user namespaces, so on a stock CI runner the child
  died at `SPAWN_EXIT_NS` and a payload that previously ran unconfined stopped
  running at all. Caught by CI, not locally, because the developer host permits
  them.

  `confine_child` and `confine_capture` take a **`want_ns`** parameter. It is 1
  for every caller that predates 3.11.3, so their behaviour is untouched — in
  particular `sandbox_spawn`, which has a fail-closed namespace contract with a
  test asserting a payload exits 123/118 rather than running less isolated than
  its policy promised. It is 0 for exactly one caller: the rootfs-less capture
  3.11.3 added. That path previously applied **nothing**, so seccomp + landlock
  is a strict gain, and it claims no network isolation it did not get — a caller
  wanting that guarantee uses a rootfs-bearing sandbox or `sandbox_spawn`.

  A first attempt gated namespaces inside `confine_child` for every caller. That
  silently broke `sandbox_spawn`'s fail-closed contract, and the resulting
  assertion failure surfaced as a **SIGSEGV** rather than a message, because
  `spawn_exit_name` returns 0 for a non-confinement code and the test handed
  that straight to `streq`. The test now null-checks first, so an unexpected
  code fails with a sentence instead of a signal.

- `security_apply_landlock` walked `count` entries of `rules` without bounding
  by the list, so a deny-all request (a non-zero count over an empty list) would
  have indexed past the end. The walk is now bounded by both; `count == 0` still
  means "no landlock at all", which is a different request.

### Added

- `policy_wants_confinement(policy)` — whether a policy requires the child-side
  seam. The routing predicate for `process_exec`, and the answer to "will this
  sandbox actually confine anything".

## [3.11.2] — 2026-08-03

### Added — `SandboxConfig.externalization`: a sandbox can carry its own gate policy

**Reported by agnosai**, porting `sandbox/kavach_bridge`. The Rust kavach lets a
caller attach an `ExternalizationPolicy` to a config, and agnosai's Rust builds
every config with `.externalization(ExternalizationPolicy::default())`
unconditionally. The Cyrius `struct SandboxConfig` had nine fields and no such
slot, so that line had **no counterpart to port** — and the consumer's
`build_config_enables_externalization` test had nothing to assert against.

`config_externalization(c, p)` now sets it, alongside the existing
`config_rootfs` / `config_agent_id` / `config_network`.

⚠ **The default is 0, not `ext_policy_default()`, and that is deliberate for a
patch release.** Defaulting to an active policy would start scanning output for
every existing consumer that never asked for it — a behaviour change dressed as
a new capability. A fresh config behaves exactly as it did in 3.11.1.

⭐ **Carrying the policy is all this does; nothing applies it for you.** The
lifecycle does not run the gate, so a caller still passes the policy to
`gate_apply` where it wants output scanned. What the field buys is that two
sandboxes running under different trust levels stop looking identical to
anything reading their configs — which is exactly agnosai's case, where
`policy_for_trust` maps a crew's trust level to one of three policies.

`SANDBOX_CONFIG_SIZE` grows **72 → 80**. ABI-safe on the same reasoning bote
used when `dispatcher_new` grew 72 → 88 at 3.3.0: `config_new` is the only
constructor, the size is not documented to callers, and every field is read at a
fixed offset.

### Verified

**590 assertions pass, 0 fail** (was 575 at 3.11.1). Both halves
mutation-verified, and the first mutation is the one worth stating: **growing
the struct while forgetting to bump `SANDBOX_CONFIG_SIZE`** puts the new field
outside the allocation, and `test_config_externalization_defaults_off` catches
it reading garbage (`got 1, expected 0`) rather than letting it corrupt the next
heap object silently. Defaulting the field ON is caught by the same assertion.
`test_config_struct_growth_is_abi_safe` round-trips all nine pre-existing fields
after the tenth was appended.

## [3.11.1] — 2026-08-03

### Security — Landlock handled only 3 of 13 filesystem rights, so a confined process could delete any file on the host

⛔ **`security_apply_landlock` named three rights in `handled_access_fs` —
`READ_FILE`, `WRITE_FILE`, `READ_DIR` — and Landlock permits every right it is
not told to handle.** A process confined by this library, including through
`confine_child` (the path every sandboxed spawn takes), could therefore still
`unlink` any file on the system, `rmdir` any directory, `mkdir` anywhere, and
`execve` any binary. Only reading and writing *contents* were confined.

⚠ **The failure mode is the reason this sat undetected.** The obvious smoke test
— and the exact escape test a downstream ADR specifies — is "a confined process
cannot read `/etc/passwd`". That **passed**, because reading was one of the
three rights that *were* handled. The sandbox looked correct while deletion was
wide open.

**Reported by agnosai**, with a runnable probe, while planning its M7 sandbox
milestone against an ADR that makes kavach's seccomp + Landlock the *entire*
security boundary for untrusted tool code. Measured before the fix, on
kavach 3.11.0 / cyrius 6.5.6 / Linux 7.1.5 — a process confined read-only to one
scratch directory:

```
  open(/etc/passwd, O_RDONLY)   REFUSED   [READ_FILE handled]
  open(victim, O_WRONLY)        REFUSED   [WRITE_FILE handled]
  mkdir(/tmp/agnosai_ll_newdir) ALLOWED   [MAKE_DIR NOT handled]
  unlink(victim.txt)            ALLOWED   [REMOVE_FILE NOT handled]
  rmdir(victimdir)              ALLOWED   [REMOVE_DIR NOT handled]
```

…and afterwards the victim file and directory were **gone from disk**.

**The fix.** All thirteen ABI v1 rights are now declared and named in
`handled_access_fs`, plus `REFER` (ABI v2) and `TRUNCATE` (ABI v3) where the
running kernel knows them.

⭐ **The ABI query is not optional and is the subtle part.**
`landlock_create_ruleset` fails **EINVAL** if `handled_access_fs` names a right
the running ABI does not know, so naming `REFER` or `TRUNCATE` unconditionally
would convert a working sandbox into a hard error on any kernel older than 6.2.
New `security_landlock_abi_version()` queries the version
(`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`) and
`_landlock_handled_access(abi)` masks **down** to it. An unknown newer ABI is
clamped to the known set rather than trusted.

⚠ **`EXECUTE` is granted inside read-only paths, deliberately, and this is the
one place the fix is less strict than it could be.** Before 3.11.1 exec was
permitted *everywhere* because the right was unhandled; a sandbox that
read-only-mounts `/usr` in order to run `/usr/bin/python3` is the ordinary case.
Withholding it would have turned a security fix into a breaking change for every
such consumer. Granting it only within allowed paths is strictly tighter than
3.11.0 while keeping that case working.

`FS_READ_WRITE` grants the full mutation set — create, delete, truncate, and on
ABI v2+ rename across two of the caller's own allowed directories — so a
sandboxed process keeps full control of its writable area. **Outside those paths
all of it is now denied, which is the actual fix.**

**One correction to the original report, because the narrower version is the
true one:** `O_CREAT` of a *regular file* was never a way in — it requires
`WRITE_FILE`, which was already handled, so file creation was refused even in
3.11.0. The real holes were directory creation, and deletion of both files and
directories.

### Verified

Host build green. **575 assertions pass, 0 fail** (was 540 + 12 at 3.11.0;
+33 mask assertions and a fork-based end-to-end test).

⭐ **The end-to-end test is the one that regresses**, and it is
mutation-verified against the real bug: reverting `handled_access` to the
3.11.0 three-right mask makes `test_landlock_denies_mutation_outside_allowed_path`
fail with `got 1, expected 0` (the child's unlink succeeded) **and** `the victim
file survived the confined child — got 0, expected 1`. The pure-arithmetic mask
tests cannot catch a mask that is correct but never reaches the kernel, which is
why the fork-and-confine test exists alongside them.

On a kernel without Landlock the test reports "inconclusive" rather than
passing vacuously.

## [3.11.0] — 2026-08-02

### Added — `kv_getgid` / `kv_lstat` / `kv_fork` / `kv_dup2` / `kv_execve` / `kv_setsid`

⛔ **3.10.0 DID NOT ACTUALLY UNBLOCK ITS OWN HEADLINE CONSUMER.** That release guarded the
Linux-only confinement primitives to fail closed on agnos and reported the aethersafha compositor
fixed. It was not: `cyrius build --agnos` still stopped with *"refusing to emit binary with 3
reachable undefined function(s)"* — `sys_getgid`, `sys_execve`, `sys_lstat`.

⛔ **The reason is the one thing 3.10.0 got structurally wrong, and it is worth stating plainly: an
`#ifdef` early-return does not remove the rest of the function from the build.**
`spawn_namespaces_available` opens with `#ifdef CYRIUS_TARGET_AGNOS return 0; #endif` and then
referenced `sys_getgid` twenty lines further down. The guard is a *runtime* branch — every statement
after it is still compiled, and every symbol it names must still resolve at link time. So the six
guarded functions changed what happens when the code *runs* on agnos and changed nothing about
whether it *builds* there. Only a shim, whose two arms are selected at compile time, keeps an
undefined name out of the object. 3.10.0 already knew this — it is exactly why `kv_unlink` /
`kv_rmdir` / `kv_waitpid` exist — and then guarded the remaining call sites the other way.

**The six new shims, and what each answers on agnos:**

- **`kv_getgid()` → -1, never 0.** agnos defines `sys_getuid` and has no `sys_getgid` at all: there
  is no group model in the kernel, so there is no honest number. ⚠ It answers **-1 = unknown**
  because every consumer here (the `uid_map`/`gid_map` writer, the OCI `gidMappings` field) treats
  the value as a real credential, and **0 is the id of root**. A shim that quietly reports root on a
  platform with no groups is the kind of lie that reads as a working sandbox.
- **`kv_lstat(path, statbuf)` → -1.** ⛔ Deliberately **not** emulated with agnos's `sys_stat`, even
  though one exists. The single call site (`_oci_dir_is_ours`) uses lstat precisely to refuse a path
  whose last component is a symlink — an attacker aiming the OCI state root at a directory they
  control is the case it exists to catch — and agnos's `sys_stat` **follows** links, so the
  substitution would convert a security check into its own bypass while the caller still read
  `0 = verified ours`. ⚠ It would also hand back the wrong struct: agnos's stat buffer carries no
  `st_uid`, and the caller reads the owner from `+24 >> 32`.
- **`kv_fork` / `kv_dup2` / `kv_execve` / `kv_setsid` → -1.** agnos has no fork/exec model: all four
  syscalls are absent, and process creation is the **fused** `sys_spawn_path(path, len)` #43 — load
  an ELF and run it, with no separately-addressable child in between at which stdio could be
  redirected or an image replaced. ⚠ `kv_dup2` is **not** emulated with agnos's `sys_dup`: dup picks
  the lowest free descriptor while dup2 forces a *specific* one, and every call here targets fd
  0/1/2, so a `sys_dup`-based shim would report success while the child's output went somewhere the
  parent never reads.

⭐ **The refusal is the error path that was already written, not a new one.** Every fork site in this
repo reads `var pid = kv_fork(); if (pid < 0) { ...cleanup...; return -1; }`, so -1 walks straight
into the handling the Linux path uses when `fork` itself fails. No caller needs a target check, no
sandbox reports success it did not deliver, and the `if (pid == 0)` child block becomes unreachable
by construction rather than by guard.

⚠ **`fork` / `dup2` / `setsid` were shimmed even though only `execve` was tripping the build.** The
compiler errors on undefined symbols it can prove reachable and merely *warns* on the rest; those
three sit in the same child blocks, are equally undefined, and would have errored the moment
reachability analysis, an inliner, or one new caller shifted. Leaving three of a family of four
un-shimmed leaves a build break armed for whoever touches this next — which is precisely how the
2026-08-01 compositor stop happened.

### Verified

Host **and `--agnos`** builds green. Test suites **540 + 12 pass, 0 fail**. Downstream:
**aethersafha `--agnos` now builds for the first time since 2026-07-25** (15,499,624 B, static
x86-64 ELF64 — the shape `agnos/scripts/burn/stage-tools.sh` requires), with its own 20 suites green
on the host.

## [3.10.0] - 2026-08-02

### Added — `kv_unlink` / `kv_rmdir` / `kv_waitpid`: portable shims for the syscalls whose SHAPE differs by target

⛔ **kavach did not build `--agnos` at all, and that broke every consumer, not just the backends.**
`cyrius build` auto-prepends every `[deps.*]` module into the compilation unit, so a project
declaring `[deps.kavach]` and building `--agnos` failed even if it only ever touched `sandbox_*`.
That is how it surfaced: it broke the aethersafha compositor, which never sandboxes anything.

The syscall wrappers genuinely differ by target: Linux `sys_unlink(path)` / `sys_rmdir(path)` take
one argument, agnos takes `(path, pathlen)`. 25 call sites across 8 files used the Linux form with
no guard. Cyrius used to **warn** on an arity mismatch and compile anyway; **6.5.1 made it a hard
error**, which turned latent wrongness into a build stop — the correct direction.

⚠ **`kv_waitpid` is a MODEL adapter, not an arity adapter, and conflating the two would be silently
wrong.** Linux writes a packed wait-STATUS word (low 7 bits signal, bits 8-15 exit code). agnos
`sys_waitpid(pid)` takes one argument and returns the **exit code directly** — cyrius's own
`syscalls_x86_64_agnos.cyr` says so where it defines the agnos `W*` decoders. Every caller in this
repo decodes `(status >> 8) & 255`, so handing them a bare code would put it in the **signal**
field: a child exiting 11 would read as *killed by SIGSEGV*, and a clean exit 0 as *killed by signal
0*. The agnos arm synthesises the packed word.

### Changed — the Linux-only confinement primitives now FAIL CLOSED on agnos instead of failing to compile

Guarded: `_spawn_enter_rootfs`, `confine_child`, `spawn_namespaces_available`,
`spawn_seccomp_available`, `confine_capture`, `_oci_run`.

⛔ **Not one of them returns success on agnos, and that is the whole point.** agnos has no mount
namespaces, no `chroot`, no `prctl`, no cgroups, no landlock, no seccomp — `SYS_CHDIR` and
`SYS_PRCTL` are not even in its syscall enum. A guard that returned 0 would report *"the payload is
confined"* on a platform where not one primitive ran: a sandbox that is silently not a sandbox,
which is the worst failure mode this file could have. agnos sandboxing goes through
`backend_sy_agnos`, not here.

### Known — `--agnos` is CLOSER but still does not build, and the remainder needs a decision, not another sweep pass

Three reachable undefined symbols remain: `sys_fork` (`src/persistent.cyr:69`, `src/spawn.cyr:139`),
`sys_dup2` (`_spawn_redirect_stdio` and the fork children), and `json_v_parse_str` — which is **not
kavach's**, it is a bayan symbol.

⭐ **The regression has a date, and it reframes the work.** `src/confine.cyr` is new in **3.9.1
(2026-07-25)**, and aethersafha's last working `--agnos` binary is dated 2026-07-25 11:24. agnos did
not newly LOSE anything — `sys_fork` was always absent there. What 3.9.1 changed is that the fork
path became **REACHABLE** from the compilation unit, and cyrius only refuses to emit on *reachable*
undefined functions. So the remaining fix is guarding entry points, not porting a process model.

⛔ **Do not reach for `--allow-undef`.** It emits a binary containing undefined functions, which is
exactly the class of silent wrongness this ecosystem pays for in hardware burns.

Full analysis, including the consumer-side pin failure that let this land unnoticed:
`docs/development/issues/2026-08-01-linux-only-backends-break-every-agnos-consumer.md`.

### Changed — cyrius pin 6.4.69 -> 6.5.5; sigil 3.12.2, ai-hwaccel 2.3.16

### Verification

Host build green; **554 tests pass** (540 + 12 + 2), unchanged from before these edits.
⚠ The `--agnos` build is still red by design of what remains — see Known above.


## [3.9.3] — 2026-07-26

### Fixed — the OCI scratch directory and files were open to a local symlink attack
Found by adversarial review of the 3.9.2 changes above, which introduced the scratch files.

`_oci_state_root` built a fully predictable path — `/tmp/kavach-runc-<uid>` — called `sys_mkdir`
and **discarded the result** ("EEXIST is fine"), then trusted whatever was there. On a shared host
another user can create that directory (or symlink it) before the victim's first OCI exec and
thereafter own runc's entire `--root` state plus both new scratch files. `EEXIST` says nothing
about what is actually at the path.

It is now validated: a real **directory** (`lstat`, so a symlink reports `S_IFLNK` rather than its
target's type — `stat` would happily accept a link to a valid 0700 dir), **owned by us**, with **no
group or other permission bits**. Any failure returns 0 and every caller refuses rather than
proceeding into someone else's directory; `oci_exec` reports why.

Two more holes in the same area:
- **The scratch files were opened `O_APPEND` and followed symlinks.** `SPAWN_LOG_FLAGS` is
  `O_WRONLY|O_CREAT|O_APPEND`, so a leftover file made a run's stderr the *concatenation* of the
  previous run's and this one's, and a planted symlink redirected the write. Now
  `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`.
- **`_oci_take_file` read with no `O_NOFOLLOW`**, so winning the race on that predictable path
  turned the read into an arbitrary-file read whose contents became the container's reported
  stderr. Now `O_RDONLY|O_NOFOLLOW`.

**`O_EXCL` alone would have made things worse**, which is worth recording: it makes the child's
open *fail* on a leftover, so stderr goes to the inherited fd 2 and the read-back returns purely
the stale contents. The parent now unlinks both paths before forking — that also removes a planted
symlink (unlink removes the link, not its target), and the state-root validation is what makes the
unlink safe, since nobody else can be racing inside a 0700 directory we own. **532 → 540
assertions.**

## [3.9.2] — 2026-07-26

### Fixed — the OCI backend never reported the container's exit code, so every run looked like success
`oci_exec` reported **`exit_code = 0` for every container that ran**, whatever the payload actually
did. A container that exited 7, died on a signal, or never started at all was indistinguishable
from one that succeeded.

This is the **same defect 3.9.1 fixed for the PROCESS backend** — that release added
`ExecResult_set_exit_code(rr, confine_last_exit())` to `process_exec` and its entry below records
"a failed `execve` no longer reports exit 0". The fix reached one backend of two, and the one it
missed is the backend that gets *selected* whenever `runc` or `crun` is installed, i.e. on most
real hosts.

Three links produced it, all in `src/backend_oci.cyr`:

1. `_oci_run` called the stdlib's `exec_capture`, which returns a **byte count**. runc's wait status
   was never retrieved and is not recoverable from that return value.
2. `oci_exec` passed that byte count straight to `backend_capture_finish`.
3. `backend_capture_finish` sets `exit_code = 0` on every `n >= 0` path.

So the reported exit code was a property of *whether the capture read bytes*, not of the container.

`_oci_run` now forks, execs, and decodes `waitpid` itself, recording the result in
`oci_last_exit()` — `128 + signal` for a signalled child, matching `confine_capture`'s convention
so an exit code means the same thing on both backends. `oci_exec` applies it on the success path
only; when the capture itself failed, `backend_capture_finish`'s own `(1, fail_msg)` pair is still
the truth.

**stderr is now captured too**, which is the other half of the same defect. `exec_capture` `dup2`s
`/dev/null` onto the child's fd 2, so runc's own diagnostics were discarded — `_oci_state_root`'s
comment already records being bitten by exactly that ("mkdir /run/runc: permission denied" going to
a discarded stderr, so "the whole container silently produced nothing and reported success"). That
instance was worked around by passing `--root`; the general case needed the message.

It also closes a quieter hole: because stderr went to `/dev/null`, **anything a container wrote to
stderr bypassed the externalization gate entirely.** A secret echoed to stderr was never scanned.
It is now.

**stdout comes back over a pipe, stderr into a temp file, and the asymmetry is deliberate.**
Draining two pipes from one thread deadlocks the moment either fills: a child writing 64 KiB to
stderr before its first stdout byte blocks forever against a parent reading stdout. A regular file
never blocks its writer, so this needs no concurrent drain, no `poll`/`epoll`, and no
arch-conditional event-struct layout — `epoll_event` is packed differently on x86_64 and aarch64
and the AGNOS wrappers take a different arity again. `test_oci_run_large_stderr_does_not_deadlock`
pushes ~82 KiB of stderr ahead of stdout; it hangs rather than fails if this regresses, which is
the honest signal.

### Fixed — runc's own diagnostics no longer reach the externalization gate
Two further defects surfaced while verifying the above, both instances of one mistake: **kavach was
letting its own secret scanner censor its own error messages.**

`code_scan` rates a runtime diagnostic such as
`runc run failed: ... exec: "/app/x": stat /app/x: no such file or directory` a **HIGH** finding.
The gate turns HIGH into QUARANTINE and `sandbox_exec` turns QUARANTINE into a hard failure, so
every runtime error presented as `externalization blocked: quarantined` — the scanner meant to
police the payload suppressing precisely the message needed to diagnose the failure.

Two changes, because it arrived by two routes:

- **`runc --log <file>`** now sends runc's structured log to its own file rather than onto the
  container's stderr. A non-empty log means the RUNTIME failed and the payload never ran, which is
  reported as a backend error carrying runc's message. This also resolves what would otherwise be
  an unfixable ambiguity: `runc run` exits with the CONTAINER's status on success but its own
  non-zero status on its own failure, so the exit code alone cannot say which happened — the log
  file can. The container's stderr, which *does* belong to the payload, is still gated.
- **`sandbox_exec` no longer gates a diagnostic result at all.** `backend_error_result` and
  `backend_guard_result` now mark themselves via `backend_result_is_diagnostic()`, which
  `backend_capture_finish` clears. The gate's contract is "scan what the payload is about to
  externalize"; a diagnostic is kavach explaining why there was no payload. The result still flows
  back with its non-zero exit code and its reason attached, which is what callers had before this
  path started producing messages long enough to trip the scanner.

Net effect for a consumer: `stiva run <image> /nope` used to print `exit_code=0`. It now reports
exit 1 with `stat /nope: no such file or directory`.

**Residual ambiguity, stated rather than papered over:** for a container that genuinely ran, a
non-zero exit code is the payload's. runc's own failures are separated by the log file, not by the
code — a runtime whose log stays empty while it fails would still be attributed to the payload.

Consumer impact (stiva, whose `exec_container` reads `ExecResult_exit_code` verbatim): `stiva wait`
always yielded 0, `state.json`'s `exit_status` was wrong and stayed wrong across restarts, and
`on-failure` restart policies could never observe a failure. Found while verifying stiva's
`stiva build`, where `stiva run <image> /definitely-not-here` reported exit 0.

Filed as `docs/development/issues/2026-07-26-oci-backend-never-reports-the-container-exit-code.md`.
**494 → 532 assertions.**

## [3.9.1] — 2026-07-25

### Fixed — a sandbox could not say WHICH filesystem to run in, so every payload ran on the host
`SandboxConfig` had no rootfs field. A container runtime consuming this API could unpack an image,
materialize a rootfs, and hand kavach a command — and kavach would `execve` it **on the host
filesystem**. A payload that exists only in the image simply did not run; one that happens to exist
on the host (`/bin/sh`, `/bin/true`) ran the HOST copy. Reported by stiva, where
`stiva run <image> /bin/ticker` exited 0 having executed nothing.

- **`config_rootfs(cfg, path)`** — `SandboxConfig.rootfs`, appended at offset 64 so no existing
  field offset moves. 0 keeps the previous behaviour.
- **`src/confine.cyr`** (new) — the child-side confinement sequence, shared by every backend that
  forks. Extracted from `spawn.cyr` because `backend_process.cyr` is included *before* it, and
  without the split only DETACHED containers would have entered their rootfs — a stranger bug than
  the one being fixed.
- Both paths now enter the rootfs: `sandbox_spawn`'s child, and a new `confine_capture` for the
  blocking path (the stdlib's `exec_capture` forks and execs on the host with no child-side seam).

Entry is `unshare(CLONE_NEWUSER|CLONE_NEWNS)` → uid/gid map → `mount(/, MS_REC|MS_PRIVATE)` →
`chroot` → `chdir("/")`. Ordering is load-bearing: rootfs entry precedes **landlock** (whose path
rules resolve against the current root) and **seccomp** (which denies `mount`/`chroot` to the
payload — correctly, but it would also deny this).

Uses `chroot(2)`, not `pivot_root(2)`. chroot is escapable by a process holding CAP_SYS_CHROOT
*and* a directory fd outside the new root — which is why inherited descriptors are closed first and
why the payload is left with no capability to re-chroot. **pivot_root is the stronger primitive and
is the next increment**; it wants the rootfs to be a mount point of its own, which is a behaviour
change rather than a silent upgrade.

Unprivileged callers get the mount namespace via a user namespace, the same pairing 3.9.0 added
for the network namespace. Without the uid/gid map every file reads as owned by `nobody`, so
anything expecting uid 0 fails in a way that looks like a corrupt image.

### Fixed — the OCI backend ran every container in an empty throwaway rootfs
`oci_prepare_bundle` created a fresh EMPTY directory under `/tmp` and pointed `config.json` at it
(`"root":{"path":"rootfs"}`), ignoring the sandbox entirely. On any host with `runc`/`crun`
installed — where `backend_is_available(OCI)` selects this backend over PROCESS — a container ran
with no filesystem at all. Four defects had to fall for a payload to actually run, each hidden
behind the last:

1. **`root.path` now points at the sandbox's rootfs** (absolute; runc accepts that, so no bind
   mount), and the throwaway directory is only staged when no rootfs is configured.
2. **A minimal `mounts` list.** Without `/proc` runc panics inside its own init ("at least one
   candidate /proc/thread-self path should work"); without a `/dev` tmpfs it fails setting up the
   standard `/dev` symlinks. An image rootfs supplies neither. The previous spec emitted no mounts
   at all, survivable only because it also pointed at an empty rootfs and never got that far.
3. **Rootless support.** An unprivileged runc refuses outright — *"rootless container requires
   user namespaces"* — unless the spec declares a user namespace **and** uid/gid mappings. Emitted
   now when `getuid() != 0`.
4. **`process.args` is real argv, not `/bin/sh -c <string>`**, when the sandbox names a rootfs.
   The shell wrapper made every container depend on the IMAGE shipping `/bin/sh`, so a distroless
   or scratch image — or a single static binary — could not run. `_split_command` moved to
   `util.cyr` so the spec generator and the process backend share one splitter.

Plus: **`runc` is invoked with an explicit `--root`**. The child is exec'd with an empty
environment (deliberate — kavach does not leak the caller's env into a sandbox), and an
unprivileged runc with no `XDG_RUNTIME_DIR` defaults its state root to `/run/runc` and dies with
`mkdir /run/runc: permission denied`. That went to stderr, which the capture sends to `/dev/null`,
so the container produced nothing and reported success.

### Added — confinement failures are diagnosable, and the tests no longer depend on the host
`spawn_exit_name(code)` turns a child's confinement exit code into a sentence. "The container
exited 123" tells a caller nothing; *"cannot create namespaces (unprivileged user namespaces may
be disabled on this host)"* tells them exactly what their kernel is refusing.
`spawn_namespaces_available(flags)` probes, in a forked child, whether the host will actually grant
the namespaces a policy implies — `unshare(2)` mutates the caller, so there is no way to ask
without doing it. It exercises the id-mapping write too, not just the namespace creation: those are
different privileges, and a runner already inside a restricted user namespace grants the first and
refuses the second, so probing only the first certifies a spawn that still dies.

Creating a namespace and mapping ids into it accordingly have **separate exit codes**
(`SPAWN_EXIT_NS` 123 / `SPAWN_EXIT_IDMAP` 118). Sharing one made the two indistinguishable —
which is the exact opacity the per-step codes exist to remove, and it cost a second CI round to
find.

Both exist because the spawn tests were **host-dependent and failed in CI while passing locally**.
They used the default policy, whose zero-filled `network_enabled = 0` reads as "isolate the
network" — which unprivileged Linux grants only inside a USER namespace, and CI runners commonly
deny those. Nine tests died with child exit 123 and no explanation.

The tests now request no namespace where the namespace is not what is under test (spawn/wait/kill/
log mechanics), and a separate environment-aware test asserts the **fail-closed refusal** when the
host denies them — rather than skipping and pretending the path is covered. Verified by stubbing
`security_create_namespace` to fail: the old tests reproduce all nine CI failures exactly, the new
ones pass.

`spawn_seccomp_available()` is the same probe for the seccomp step, added after an audit showed the
identical trap one confinement step further along: `_spawn_running_sandbox` overrode only
`network_enabled`, while `policy_basic()` also sets `seccomp_enabled = 1`, so every spawn child
still loaded a filter. On a host that refuses seccomp that is 11 failures with an opaque exit 125.

The suite is now verified against four simulated hosts — all capabilities, namespaces denied,
uid_map denied, seccomp denied — by stubbing each primitive to fail and rerunning. All four green.

### Fixed — harness include sets
`tests/kavach.bcyr` (and `tests/kavach.tcyr`) include `backend_process.cyr`, which now calls into
`confine.cyr` and `security.cyr`; neither was in their include list, so both failed to compile
with undefined `confine_capture` / `security_create_exec_seccomp_filter`. A `.tcyr`/`.bcyr` file
carries its own include set rather than inheriting `src/lib.cyr`'s, so any module a backend starts
depending on has to be added to every harness that includes that backend.

### Fixed — a failed `execve` was swallowed into exit 0
The blocking capture path reported success for a command that never ran, which is a large part of
why the missing-rootfs bug stayed invisible. `confine_capture` records the child's real status and
`process_exec` surfaces it, so a missing binary now reports **127**.

## [3.9.0] — 2026-07-25

### Security — seccomp filters were never actually applied
`security_bpf_write_insn` built each BPF instruction through a typed
`bpf_insn` struct local (`var insn: bpf_insn = buf + offset; insn.code = …`).
Under this toolchain that compiled to a **no-op**: every field write was
dropped. `security_create_basic_seccomp_filter` therefore returned 184
**zero** bytes, and `security_load_seccomp` failed with `EINVAL` on every call
it has ever received — so **no consumer of this library has ever had a seccomp
filter installed**, while the API reported a policy that requested one.

Nothing failed loudly. The function returned 0, the filter had the right
length, the struct had the right shape, and the only observable symptom was a
`Result` error at load time that no caller was checking closely. Found while
building `sandbox_spawn`, when a child that should have exec'd kept dying at
the confinement step.

Fixed by writing the instruction bytes explicitly. The regression test asserts
the **produced bytes** against the kernel's `struct sock_filter` layout, and a
second test loads a filter in a forked child and confirms the kernel accepts it
and that `execve` still runs — because "the call returned 0" is exactly the
check that passed for the entire time this was broken.

### Added — `sandbox_spawn`: policy-threaded detached spawn
`sandbox_exec` runs to completion and captures output; `persistent_spawn` keeps
a guest on pipes but takes no `Sandbox`, so it threads **no** policy — no
cgroup, no namespaces, no landlock, no seccomp. Neither serves a daemon
container. The named consumer is stiva's `run -d`, which has been blocked on
this symbol existing.

- `sandbox_spawn(sandbox, command, log_path)` → `SpawnedProcess*`
- `spawned_pid` / `_alive` / `_exit_code` / `_try_wait` / `_wait` / `_kill`
- `spawned_terminate(sp, grace_ms)` — SIGTERM, grace, then SIGKILL and reap;
  the escalation a container `stop` needs, where getting it wrong means either
  lost data or leaked processes.

**The policy contract is all-or-nothing.** A detached spawn that quietly drops
half the policy is worse than none, because the caller cannot tell. Every
confinement step either applies or the child `_exit`s with a **distinct code**
(120 stdio · 121 cgroup · 122 no_new_privs · 123 namespaces · 124 landlock ·
125 seccomp) rather than falling through to `execve` unconfined — so a dead
container says *which* primitive was unavailable.

Child ordering, which is security-relevant: `setsid` (or a Ctrl-C in the
launching shell kills the "detached" job) → stdio redirect → close inherited
fds (the CVE-2024-21626 class) → cgroup join → `NO_NEW_PRIVS` → namespaces →
landlock → **seccomp last**, since it would otherwise filter the confinement
steps above it.

### Added — `security_create_exec_seccomp_filter`
A seccomp profile that can be installed **before** `execve`.
`security_create_basic_seccomp_filter`'s 20-syscall allowlist does not include
`execve`, so loading it on any spawn path kills the child on the very syscall
that starts it. The new profile is a **deny-list (default allow)** covering the
~20 syscalls that appear in container-escape chains — `mount`, `pivot_root`,
`setns`, `unshare`, `ptrace`, `process_vm_readv/writev`, module loading,
`kexec_load`, `bpf`, `perf_event_open`, `userfaultfd` and friends.

That is explicitly weaker than a default-deny allowlist, and the comment says
so: a usable default-deny profile needs `execve` plus the whole dynamic-loader
surface — in practice the ~300-entry OCI default list, which is a policy
artifact rather than something this function should invent.

### Fixed — unprivileged network isolation was unobtainable
`_spawn_ns_flags` pairs `NS_USER` with `NS_NETWORK` when not running as root.
`unshare(CLONE_NEWNET)` alone is `EPERM` for an unprivileged process; a network
namespace is only obtainable as part of a new **user** namespace, which is how
rootless containers get one.

## [3.8.3] — 2026-07-22

**samay + ai-hwaccel are now `optional` — consumers stop paying for a bridge kavach
does not ship.** 3.8.0 added `[deps.samay]` (which pulls `[deps.ai-hwaccel]`) as
always-on dependencies. cyrius auto-includes every **active** `[deps.*]` module into
every compilation unit, so every downstream consumer linked ~279 KB of scheduler and
accelerator symbols — for a bridge that is deliberately excluded from `[lib].modules`:
`src/samay_bridge.cyr` is test-only, and `grep samay dist/kavach.cyr` returns nothing.

That cost was not theoretical. In stiva it pushed `tests/stiva.tcyr` past cycc's
identifier cap — `identifier buffer full (261893/262144)`, a hard compile error — and
dragged in ai-hwaccel's `backend_name`, which collided with kavach's own (fixed in
3.8.2 by renaming ours to `os_backend_name`).

- Changed: `[deps.samay]` and `[deps.ai-hwaccel]` are `optional = true`, activated by a
  new default-on `scheduler` feature (`[features] default = ["scheduler"]`). kavach's own
  build and tests are unaffected — `tests/samay_integration.tcyr` still compiles and runs.
  **Consumers are no longer given either bundle**: transitive `[features]` tables are not
  parsed, so an optional dep stays inactive downstream — no clone, no module copy, no
  auto-include. A consumer that genuinely wants samay now declares it directly and on its
  own terms. Same lever libro uses for `sigil-tpm` and mehman for `kavach`.
- No source change; `dist/kavach.cyr` is unchanged apart from its version header.
- Full suite (436 assertions) green.

## [3.8.2] — 2026-07-22

**`backend_name` → `os_backend_name` — symbol-hygiene fix for a silent
last-def-wins collision.** Since 3.8.0 pulled `[deps.samay]`, consumers also
receive samay's transitive `[deps.ai-hwaccel]`, which defines its **own**
`backend_name(b)` over an unrelated enum (`BACKEND_CUDA`..`BACKEND_WINDOWS`,
17 hardware-detection backends). Both enums start at `0`, cycc resolves
duplicate fns last-definition-wins, and ai-hwaccel sorts after kavach — so in
any consumer pulling both, kavach's OS-backend namer was silently replaced by
the hardware one: `backend_name(Backend.OCI)` returned `"intel-npu"`, and
`backend_name(Backend.PROCESS)` returned `"cuda"`. Reproduced end-to-end in
stiva, whose `stiva info` logged `computing security strength score: intel-npu`
instead of `oci`.

The collision also corrupted kavach's **own** error paths — `lifecycle.cyr:165`
and `backend_dispatch.cyr:48` both pass the result to
`kavach_err_print(KAVACH_ERR_BACKEND_UNAVAILABLE, …)` — so a consumer-side
workaround was not possible; the rename had to land here.

`os_` marks this as the OS/isolation-backend namer and leaves the bare
`backend_name` to ai-hwaccel. Same class and resolution as samay's 1.0.1
`uuid_v4` → `samay_uuid_v4` fix, and shipped the same way, as a patch.

**Breaking for direct callers** (one line each): `stiva/src/runtime.cyr:841,955`
and `mehman/src/sandbox.cyr:88`. `backend_parse`, `backend_is_available`, and
`score_backend` are unchanged.

- Changed: `src/backend.cyr:26` `backend_name` → `os_backend_name`; internal
  callers updated at `src/lifecycle.cyr:165`, `src/backend_dispatch.cyr:48`,
  `src/main.cyr:66`. `dist/kavach.cyr` regenerated.
- Note: kavach's 3.8.0 claim "No symbol collisions with kavach's 442-fn surface
  (verified)" was true of kavach vs samay, but did not cover the **transitive**
  closure a consumer actually links. `backend_name` and `path_exists` both
  collide with ai-hwaccel; `path_exists` is benign (identical 1/0 semantics).
- Full suite (436 assertions) green.

## [3.8.1] — 2026-07-21

**samay dep `1.0.0` → `1.0.1`.** Picks up samay's symbol-hygiene fix (its `uuid_v4` was
renamed to `samay_uuid_v4` to avoid a last-def-wins collision with libro's incompatible
`uuid_v4(buf)`). No effect on kavach's `samay_bridge` surface — the rename is internal to
samay's task construction. Full suite (436 assertions) green against the updated dist.

## [3.8.0] — 2026-07-21

**samay integration — size sandboxes from scheduler placements.** kavach now
consumes samay (`[deps.samay]`, `dist/samay.cyr`), realising the AGNOS split
"samay decides placement, kavach executes": a task's samay `ResourceReq`
(cpu_cores / memory_mb / network) maps onto the sandbox's `SandboxPolicy`
cgroup limits, layered on the hardened strict baseline.

### Added

- `src/samay_bridge.cyr` — `sandbox_policy_from_samay_req(req)` /
  `sandbox_policy_from_samay_task(task)`: map a samay `ResourceReq` →
  `SandboxPolicy` (f64 cpu_cores → cpu_limit_tenths with a 1-tenth floor,
  memory_mb → memory_limit_mb, network → the network namespace gate). The
  module is **excluded from `[lib].modules`**, so kavach's own dist bundle
  does not force samay + its transitive deps (ai-hwaccel/bayan/math) on
  downstream consumers of kavach.
- `tests/samay_integration.tcyr` — 12 assertions building against the vendored
  samay dist (real `resource_req_new` / `scheduled_task_new`), covering the
  resource mapping, fractional-cpu rounding, the cpu floor, and the task path.

### Changed

- **Cyrius pin `6.4.62` → `6.4.69`** — samay's `#derive(Serialize)` f64 codec
  requires it (6.4.69 Grisu2). Full suite verified green (**436 assertions**).
- `[deps]`: added `math`, `sakshi`, `atomic` (samay's stdlib closure) and the
  first-party deps `[deps.samay]` (0.7.0) + `[deps.ai-hwaccel]` (2.3.15). No
  symbol collisions with kavach's 442-fn surface (verified).

## [3.7.1] — 2026-07-13

Toolchain + dependency refresh. Pin cyrius `6.3.40` → `6.4.62` and sigil
`3.9.8` → `3.11.1`, both to the current ecosystem. **No source or API change**:
the `dist/kavach.cyr` consumable surface is byte-identical apart from the
version-header restamp, so downstream consumers (mehman) are unaffected.
Build + the full **422-assertion** suite verified green under cc `6.4.62`.

### Changed

- **Cyrius pin `6.3.40` → `6.4.62`.** Clean pin move — all 33 kavach-declared
  `[deps].stdlib` modules exist unchanged in the 6.4.62 snapshot (no rename /
  retirement this move, unlike the 6.1 → 6.2 `json`→`bayan` / `bigint`-drop
  reshuffle). Re-vendored via `rm -f lib/*.cyr cyrius.lock && cyrius deps`
  (65 deps locked, 1 commit-pinned = sakshi transitively via sigil);
  `cyrius deps --verify` green (65 verified, 0 failed).
- **sigil `3.9.8` → `3.11.1`** (latest). Consumed as the committed
  `dist/sigil.cyr` bundle. The benign `sys_error`/`sys_util` symbol overlap
  (`duplicate fn 'err_*' / 'agnosys_*' / 'syserr_*'`, `last definition wins`)
  is unchanged from 3.9.8 — documented in [ADR-006](docs/adr/006-library-surface-and-bundle-generation.md)
  §4 and the README integration caveats. `thread_local` stays declared in
  `[deps]` (opt-in module preceding sigil in the auto-include order; its
  absence SIGILLs at first crypto use).
- Validated the pin move with the CLAUDE.md pipeline: `deps → build → lint
  (0 warnings) → vet (42 deps, 0 untrusted, 0 missing) → test (422/422) →
  bench (22 recorded)`.

### Performance

- 22 benchmarks recorded for 3.7.1 in `benches/bench-history.csv`. The prior
  recorded baseline is **3.4.2** (cc 6.2.11) — releases 3.5.0–3.7.0 shipped
  without a bench row (a process gap, now re-established). Source is unchanged
  from 3.7.0 (the 422 assertions are identical), so the deltas below are
  toolchain/dependency-driven, not algorithmic. CPU-bound micro-ops improved
  substantially under the newer toolchain:
  `config_builder_full` 268 → 158 ns (**−41%**),
  `policy_strict_create` 140 → 87 ns (**−38%**),
  `http_path_extract` 154 → 99 ns (**−36%**),
  `cgroup_wrap_argv` 738 → 478 ns (**−35%**),
  `http_allowlist_hit` 82 → 63 ns (**−23%**),
  `score_backend_process_strict` 37 → 33 ns (**−11%**). The syscall/IO-bound
  benches (`health_check_noop`, `secrets_redact`, `sandbox_full_lifecycle`)
  move within their usual ±10–20% run-to-run noise (µs/ms-scale).

### Docs

- **`agnosys (agnodrm)` naming.** The internalized Linux security backends are
  now written as `agnosys (agnodrm)` at their identity / dependency sites
  (`cyrius.cyml` `[lib]` + `[deps]` comments, `src/main.cyr`, `src/lib.cyr`) —
  their post-decomposition home is agnodrm, not agnosys. The `agnosys →
  agnodrm` arrow (naming the split itself) and the historical v3.5.0 release
  notes are left unchanged.
- Swept stale toolchain/dependency version references (last refreshed at
  v3.4.2) across `README.md`, `docs/architecture/overview.md`,
  `docs/guides/getting-started.md`, `docs/development/roadmap.md`,
  `docs/doc-health.md`, `CLAUDE.md`, and the `cyrius.cyml` comment blocks —
  many still read cc `6.2.11` / sigil `3.7.14` / agnosys `1.4.3` (an external
  dep dropped at v3.5.0) and now carry cc `6.4.62` / sigil `3.11.1`.

## [3.7.0] — 2026-07-03

### Added
- **Persistent guest execution** (`src/persistent.cyr`) — a sandboxed guest that
  stays alive with **live stdin/stdout pipes**, so a host can stream input to a
  running guest and read its output over time (the execution primitive the
  swallow stage's protocol shim delivers events over). API: `persistent_spawn`
  (fork + dup2 + execve with two pipes, after the same `is_safe_argument` +
  `check_command` runtime-guard checks the one-shot path enforces),
  `persistent_send` / `persistent_read` / `persistent_terminate` (SIGKILL +
  `waitpid` reap) + `persistent_pid` / `persistent_alive`. Verified end-to-end
  with a `/bin/cat` round-trip (send bytes → read the echo back); **422-assertion
  suite green**.
- **Security note**: the persistent path applies the pre-exec command-safety
  checks but **not** the externalization gate (which scans a full captured buffer
  — meaningless for an open-ended stream), so persistent-guest stdout is raw. It
  is for trusted-shape guests behind the consumer's capability contract. SIGPIPE
  on writing to a self-exited guest is a documented limitation (send guards on the
  alive flag).

## [3.6.1] — 2026-07-03

### Changed
- Toolchain pin `6.3.15` → `6.3.40`, catching kavach up to the current ecosystem
  (aethersafha / mehman are on 6.3.40). Purely a maintenance bump: no source or
  API change — build + the full **413-assertion** suite verified green under
  6.3.40, and the `dist/kavach.cyr` consumable surface is unchanged, so downstream
  consumers (mehman) are unaffected.

## [3.6.0] — 2026-07-02

Kavach becomes **consumable as a Cyrius source-level library**. Downstream
first-party projects — first up, **mehman**'s M1 sandbox host
(`mehman_sandbox_run_guest`) — can now depend on kavach the same way the
tree consumes sigil/patra/bhumi: a single committed `dist/kavach.cyr`
bundle declared with `[deps.kavach] modules = ["dist/kavach.cyr"]`, which
`cyrius deps` materializes into the consumer's `lib/kavach.cyr`. Purely
additive: no runtime code path changed, so the 413-assertion suite and the
benchmark surface are unchanged by construction (this release ships no new
benchmarkable code).

### Added

- **`[lib]` profile + `src/lib.cyr` aggregation header.** `src/lib.cyr` is
  the public library entry point — the domain `src/*.cyr` modules in
  dependency order (mirroring `src/main.cyr`'s include block) **without**
  the program surface (`main()`, the end-to-end demo, the top-level
  `syscall(SYS_EXIT)`). `[lib].modules` in `cyrius.cyml` lists those 41
  modules in the same order and is the single source of truth `cyrius
  distlib` reads. `src/main.cyr` stays the in-tree smoke/demo entry and is
  deliberately excluded from `[lib]` (bundling it would inline a `main()`
  and duplicate every module body into consumers — the lesson
  bhumi/agnosys already recorded).
- **Committed `dist/kavach.cyr` single-file bundle** (41 modules) +
  **`dist/kavach.deps` sidecar**, generated by **`cyrius distlib`** — the
  same standard first-party dist flow sigil/patra/bhumi use. distlib
  computes the sidecar by symbol analysis, recording only the **10** stdlib
  leaves the bundle's unresolved symbols actually need (`string, fmt,
  alloc, vec, tagged, syscalls, hashmap, str, net, process`); the
  consumer's `cyrius deps` supplies them, and each transitive dep (sigil,
  sandhi, sakshi) carries its own sidecar, so kavach's lists only kavach's
  direct leaves. The transitive sigil dep resolves from this repo's
  `[deps.sigil]`.
- **CI freshness gate** (`.github/workflows/ci.yml`, "Verify dist bundle
  fresh"): regenerates the bundle with `cyrius distlib` and fails if the
  committed `dist/` differs — the same gate sigil/bhumi use.
  `scripts/version-bump.sh` also re-runs distlib so a bump restamps the
  bundle header. See
  [ADR-006](docs/adr/006-library-surface-and-bundle-generation.md).

### Notes

- **Consumer stdlib contract.** `cyrius distlib` records only kavach's 10
  **direct** stdlib leaves in `dist/kavach.deps`; the bundle also pulls
  sigil (crypto: `ct`/`keccak`/`thread`/`thread_local`) and the
  credential-HTTP proxy (`sandhi` → `tls`, `bayan`). Per the Cyrius model
  (distlib prints *"stdlib is supplied by the consumer's `[deps]` stdlib
  list"*), the **consumer declares stdlib** — a consumer with only a
  minimal `[deps].stdlib` fails to *link* (undefined `thread_local_*` /
  `sandhi_server_*` / `TLS_BACKEND_LIBSSL`). A consumer must mirror
  kavach's transitive stdlib (same as kavach declares sigil's opt-in
  modules); the README "Consume kavach as a library" section lists the
  exact set.
- **Verified end-to-end**: a consumer declaring `[deps.kavach]` **and**
  kavach's transitive stdlib resolved via `cyrius deps`, compiled, linked,
  and **ran** the full M1 flow — `kavach_init` → `config_new` →
  `config_backend(PROCESS)` → `sandbox_create` →
  `sandbox_transition(RUNNING)` → `sandbox_exec` → `resolve_best_backend`
  → `sandbox_destroy` — to a clean exit 0. The sigil-backed HMAC audit
  path (`hmac_sha256` / `sha256_global_init`) linked and executed.
- **Known integration clashes** (documented in README + ADR-006 §4):
  - *Benign* — `duplicate fn 'err_*' / 'agnosys_*' / 'syserr_*'` (`last
    definition wins`), the kavach⇄sigil `sys_error`/`sys_util` overlap that
    kavach's own build already emits.
  - *Resolved* — the former `ERR_UNKNOWN` value collision is fixed at the
    source. sakshi (via sigil) mints a generic `ERR_UNKNOWN = 1`; kavach's
    `SysErrorKind` members are now namespaced `KAVACH_ERR_*`
    (`KAVACH_ERR_UNKNOWN = 7`, `KAVACH_ERR_SYSCALL_FAILED = 1`, …), so they
    can no longer collide with any dep's generic `ERR_*` under
    last-def-wins. The rename is confined to `src/sys_error.cyr` (the enum,
    the `err_*`/`syserr_*` constructors, and the `syserr_print` match arms
    — the constructor/accessor **function** names are unchanged, so callers
    are untouched), keeps behavior identical (413 assertions green;
    create-then-read classification still round-trips), and a consumer probe
    confirms `KAVACH_ERR_UNKNOWN` (7) and sakshi's `ERR_UNKNOWN` (1) now
    coexist as distinct values.
  - *Resolved* — the **`KavachError`** enum (`src/error.cyr`) got the same
    treatment. Its members were bare generic names (`OK`, `TIMEOUT`,
    `IO_ERROR`, `OTHER`, …); a two-enum consumer probe under cc 6.3.35
    confirmed the latent hazard was real and — unlike `SysErrorKind` —
    **not** mitigated by kavach's own `KavachError.X` qualified access:
    that access is only sugar for the hoisted global, so `KavachError.OK`
    silently resolved to a later dep's generic `OK` (probe printed `100`,
    not `0`), and the pollution ran **both** directions (kavach's bundle
    last also overwrote a well-behaved dep's `OK`→0/`TIMEOUT`→4). Members
    are now namespaced `KAVACH_ERR_*` (`KAVACH_ERR_OK = 0`,
    `KAVACH_ERR_TIMEOUT = 4`, `KAVACH_ERR_IO_ERROR = 9`, …) and every
    call site (`src/` + `tests/`) uses the bare prefixed name, matching the
    `SysErrorKind` convention. Values, ordering, and `kavach_err_name`
    output are unchanged (413 assertions green), `dist/kavach.cyr` was
    regenerated, and the post-fix probe confirms `KAVACH_ERR_*` and a
    foreign dep's generic `OK`/`TIMEOUT`/`IO_ERROR`/`OTHER` now coexist as
    distinct values in either include order.
  - Consumers also inherit the ~13 MB static scan tables (`CYRIUS_DCE=1`
    drops the unreachable surface).

## [3.5.4] — 2026-06-30

Tier-4 (consumer) step of the coordinated base-security-stack migration
to cyrius **6.3.15**. Toolchain pin + sigil refresh, plus one var-bomb
fix the 6.3.13 stack-locals change turns from latent to fatal. All 413
assertions pass on the new stack.

### Changed

- **Cyrius toolchain pin: 6.2.36 → 6.3.15.**
- **Dependency**: sigil **3.9.8** (was 3.8.1).

### Fixed

- **Landlock ruleset-attr stack smash** (`src/security.cyr`,
  non-agnos path). `var attr[1]` is a **1-byte** function-local (cyrius
  6.3.13 moved these to the guard-paged thread stack, where a local
  `var X[N]` allocates N bytes), but the code does `store64(&attr,
  handled_access)` — an 8-byte write — and passes `&attr, 8` to
  `SYS_LANDLOCK_CREATE_RULESET`. Benign before (scribbled an adjacent
  local), a hard fault under 6.3.13+. Sized to `var attr[8]` to hold the
  u64 `LandlockRulesetAttr`.

## [3.5.3] — 2026-06-29

### Fixed

- **AGNOS build — gate `kernel_audit.cyr`'s raw netlink/`syscall()` paths behind
  `#ifdef CYRIUS_TARGET_AGNOS`** (the same `err_not_supported` pattern `security.cyr`
  already uses for LANDLOCK/SECCOMP/NAMESPACES). The 3.5.1 CHANGELOG *claimed*
  `kernel_audit.cyr` already used this gating — it did not; only `security.cyr` was
  gated. `kernel_audit.cyr`'s `audit_open` / `audit_send_raw` / `audit_recv_raw` /
  `audit_agnos_log` issued **raw Linux x86_64 syscall numbers** (`socket=41`,
  `bind=49`, `sendto=44`, `recvfrom=45`, plus `SYS_AGNOS_AUDIT_LOG=520`) that are
  **catastrophically aliased** on agnos's own 0-62 table — `#41=sleep_ms`,
  `#44=unassigned`, `#45=getrandom`, `#49=sock_recv`, `#272`/`#520` out of range. On
  an agnos build a `syscall(49, fd, sockaddr, 12)` would invoke **`sock_recv` with a
  sockaddr pointer as a destination buffer** — silently memory-unsafe, not merely
  unsupported. The four entry points now return `err_not_supported("NETLINK_AUDIT" |
  "SYS_AGNOS_AUDIT_LOG")` on agnos and never reach the aliased numbers; the Linux
  bodies are unchanged under `#ifndef CYRIUS_TARGET_AGNOS`. The sovereign audit path
  on agnos is the HMAC-SHA256 hash chain in `audit.cyr` (pure-userspace), not netlink.
- **`sys_security_syscalls.cyr` — correct the dangerously-misleading header comment.**
  It described these as "the agnos-only x86_64 syscall numbers"; they are plain
  **Linux x86_64** numbers, and that mislabel is precisely the confusion that bred
  the aliasing hazard. The comment now states they are Linux-host numbers, documents
  the per-number agnos aliasing, and records the invariant: every consumer must
  reference them **only** inside `#ifndef CYRIUS_TARGET_AGNOS`.

### Notes

- Host build + 413/413 tests green. The `--agnos` build still has a **separate,
  pre-existing** blocker — `file_append_locked` / `sys_access` resolve in the vendored
  `lib/io.cyr` only on Linux/macOS/aarch64 syscall layers, not the agnos target (a
  cyrius-stdlib surface gap under the installed 6.3.5 vs pin 6.2.36). That is a
  cyrius-side concern, unrelated to this fix, which removes the syscall-aliasing
  hazard regardless. On agnos, sandbox confinement remains the capability layer's job.

### Changed

- **cyrius toolchain pin `6.2.11` → `6.2.36`** — aligns with the latest cyrius. Host +
  `--agnos` builds re-verified clean (the 3.5.1 Linux-MAC agnos gating holds at 6.2.36).

## [3.5.1] — 2026-06-22

### Changed

- **AGNOS build support — gate the Linux MAC stack behind `err_not_supported`** (`src/security.cyr`).
  AGNOS has none of **Landlock** (FS-confinement), **seccomp-BPF** (syscall-surface
  filtering), or **namespaces/`unshare`** (isolation), and the unconditional
  `SYS_LANDLOCK_*` / `SYS_PRCTL` / `SYS_UNSHARE` references made an agnos build fail to
  even **link**. Each of the three is now `#ifdef CYRIUS_TARGET_AGNOS`-gated to return a
  structured `err_not_supported("LANDLOCK" | "SECCOMP" | "NAMESPACES")` — the same pattern
  `mac.cyr` (SELinux/AppArmor) and `kernel_audit.cyr` (NETLINK_AUDIT) already use — so the
  agnos build **compiles** and the system process gets a clear "this Linux MAC mechanism is
  unavailable here" signal instead of a build break or a silent `Ok(0)` no-op that would
  falsely imply confinement was applied. On AGNOS, sandbox confinement is the **capability
  layer's** responsibility. **Transitional** until AGNOS ships native confinement primitives
  (tracked in the agnos kernel roadmap's *Deferred* table). Linux behaviour is byte-unchanged
  (each body lives under `#ifndef CYRIUS_TARGET_AGNOS`). kavach now builds clean for both host
  and `--agnos`.

## [3.5.0] — 2026-06-19

**Internalizes the Linux security backends — kavach drops its agnosys dependency.**
Part of the `agnosys → agnodrm` ecosystem decomposition (agnosys narrows to the
device model; its subsystems fold to their proper homes). kavach was the heavy
consumer of agnosys's Landlock/seccomp, MAC, and Linux-audit code (landlock 37×,
mac 21×, audit 24×) — it now owns those backends directly.

### Changed

- **Internalized agnosys's security backends**: `security.cyr` (Landlock/seccomp/
  namespaces), `mac.cyr` (SELinux/AppArmor), `kernel_audit.cyr` (Linux audit) +
  their `sys_error.cyr`/`sys_util.cyr` support, plus `sys_security_syscalls.cyr` —
  the 6 agnos-only syscall numbers (`SYS_UNSHARE`, the `*_NR` socket nums,
  `SYS_AGNOS_AUDIT_LOG`). The landlock/prctl/close numbers come from cyrius's
  `lib/syscalls`, so the full per-arch syscall layer is **not** duplicated.
- **Dropped `[deps.agnosys]`** (was bundling the entire agnosys distribution).
- **`[deps.sigil]` 3.7.14 → 3.8.1** — picks up sigil's own agnosys drop, which
  clears the transitive agnosys that collided with the internalized `sys_error`.

### Notes

- The advisory `log_warn` in `kernel_audit.cyr` (agnosys logging) was dropped —
  rewire to kavach's logger when one is wired (logging folds to sakshi separately).
- Verified: `cyrius build src/main.cyr` clean (no duplicate-fn/undefined in the
  aggregated build).

## [3.4.2] — 2026-06-15

Toolchain bump to cyrius `6.2.11` and dependency refresh (sigil `3.7.8 →
3.7.14`, agnosys `1.4.1 → 1.4.3`). The 6.1 → 6.2 stdlib reshuffle retires the
standalone `json` and `bigint` modules, so the vendored `[deps]` set is
re-pointed accordingly. 413 tests pass; lint 0 warnings; vet clean. No
benchmark regressions across the pin move.

### Changed
- **Cyrius pin `6.1.24 → 6.2.11`** (`cyrius.cyml`, CLAUDE.md). Validated by a
  clean `deps → build → lint → vet → test → bench` run on the new toolchain.
- **sigil `3.7.8 → 3.7.14`** (latest) and **agnosys `1.4.1 → 1.4.3`** (latest).
  sigil 3.7.14 keeps `dist/sigil.cyr` self-contained (the SHA-NI / AES-NI banks
  are inlined, as of 3.7.12) and its `crypto_scratch` exercises the
  thread-local TLS path — see the SIGILL note below.
- **Stdlib `[deps]` re-pointed for the 6.2 consolidation.** The pre-6.1
  standalone `json` and `base64` modules were folded into the consolidated
  **`bayan`** data module and no longer ship as separate files; `json` is
  replaced by `bayan` in the vendored set. kavach does not parse JSON or decode
  base64 directly — `oci_json_escape` is hand-rolled (`src/oci_spec.cyr`) — but
  `bayan` is kept declared so `cyrius deps` resolves the union the vendored
  sandhi/sigil bundles forward-reference under the single-pass loader.
- **`fmt` reflow under 6.2.x** — 13 source/test files reindented. cyrius 6.2's
  formatter flattens multi-line call-continuation arguments from paren-aligned
  indentation to a single 4-space level under the statement. Whitespace-only;
  behavior-preserving (rebuilt + 413 tests re-run clean after the reflow).

### Removed
- **`bigint` stdlib `[deps]` entry dropped.** The pre-6.1 `bigint` module is
  retired — sigil 3.x bundles its own `u256`/`u384` inline and kavach has no
  direct big-integer use, so the entry was dead. (`ganita` in 6.2.x is an
  unrelated linear-algebra module, not a `bigint` successor.)

### Notes
- **`thread_local` stays load-bearing.** It must remain declared in `[deps]`
  (preceding sigil in the auto-include order): sigil 3.7.14's `crypto_scratch`
  exercises the TLS path, so without `thread_local` storage the binary links
  clean but SIGILLs (exit 132) at first crypto use. This was latent through
  sigil ≤3.7.12 and is the same class of bug fixed at 3.4.1 — the entry added
  then is what keeps 3.4.2 safe under the 3.7.14 bump.
- **Benchmark** (`bench-history.csv`, `3.4.1 → 3.4.2`): flat within measurement
  noise across all 22 benchmarks (±a few ns / single-digit µs). The toolchain
  and dependency refresh carries no codegen regression on the hot paths
  (scoring, scanning, audit-chain, credential proxy).

## [3.4.1] — 2026-06-10

Toolchain bump to cyrius `6.1.24` and dependency refresh (sigil `3.5.9 →
3.7.8`, agnosys `1.3.0 → 1.4.1`). 413 tests pass; lint 0 warnings. The pin
move surfaced — and this release fixes — a latent opt-in-stdlib gap that
SIGILLs under cyrius 6.1.x.

### Changed
- **Cyrius pin `6.0.43 → 6.1.24`** (`cyrius.cyml`, CLAUDE.md). Validated by a
  clean `deps → build → lint → test → bench` run on the new toolchain.
- **sigil `3.5.9 → 3.7.8`** (latest) and **agnosys `1.3.0 → 1.4.1`** (latest).
  sigil 3.7.8 brings ML-DSA-65 PQC default-on, the ECDSA verify scalar-mult
  speedup, and Solinas field reduction for P-256/P-384.

### Fixed
- **Audit-chain HMAC SIGILL (exit 132) under cyrius 6.1.x.** Since sigil 3.6,
  four stdlib modules are **opt-in** — they are *not* in the cyrius
  auto-prepend union and the `dist/sigil.cyr` bundle does not carry them
  (sigil README §Usage). kavach already vendored `ct`, `keccak`, and `thread`,
  but **`thread_local` was missing from the `[deps]` list**, so it was never
  resolved into `lib/`. Under 6.1.x cyrius only *warns* on the undefined
  `thread_local_init/get/set` and compiles the call site to a `ud2` trap; the
  binary builds, then SIGILLs the moment a crypto path touches it — here, the
  first `audit_chain_record` HMAC. Adding `thread_local` to the vendored
  stdlib closes it. (sigil's own fix for the same class of bug is its 3.7.8
  release.)
- **Latent `async` `ud2` on the HTTP credential-proxy path.** The refreshed
  dependency set pulls a sandhi whose HTTP path references `async_*`; the
  `async` stdlib module was likewise absent from `[deps]`, leaving another
  trap one code path away. Added `async` to the vendored stdlib — the build is
  now free of undefined-function warnings.

### Notes
- Root cause was **vendoring**, not asm-offsets. The prior manifest comments
  framed sigil pin moves as an NI-asm-offset hazard (a cc 5.10.x-era concern);
  the real 6.1.x requirement is declaring the opt-in stdlib modules. Comments
  in `cyrius.cyml` updated to reflect this.
- **Benchmark** (`bench-history.csv`, `3.4.0 → 3.4.1`): the 6.1.24 codegen is a
  net win on real workloads — `code_scan_large_naive` 6.60 → 5.57 ms (−15.6%),
  `score_all_backends_strict` 455 → 338 ns (−25.7%), `gate_clean_output` 370 →
  331 µs (−10.5%), `backend_parse` 193 → 154 ns (−20.2%). A handful of
  sub-microsecond micro-benchmarks moved the other way (`cgroup_wrap_argv` 545
  → 740 ns, `config_builder_full` 194 → 264 ns, `policy_strict_create` 113 →
  137 ns) — codegen variance at the few-hundred-nanosecond floor, not a real
  regression; the larger the workload, the cleaner the win.

## [3.4.0] — 2026-06-02

Aho-Corasick multi-pattern matching for the code scanner — the post-3.3.0
audit's P2 perf finding. 413 tests pass (+7); lint 0 warnings; vet 35 deps, 0
untrusted/missing; pin stays `6.0.43`.

### Added
- **`src/aho_corasick.cyr`** — a reusable Aho-Corasick automaton: trie + BFS
  failure links + dict (output) links, with a single-pass `ac_search` that
  fills a per-pattern first-match-position hit table. Built once over a static
  pattern set and cached (build cost amortized to zero); only the O(n) search
  runs per scan. Public surface: `ac_build(patterns) → ac`, `ac_hits_new(ac)`,
  `ac_search(ac, text, n, hits)`, `ac_num_pats(ac)`.

### Changed
- **Code scanner runs one Aho-Corasick pass instead of ~109 per-pattern
  re-scans.** Each of the 26 pattern groups in `scanning_code.cyr` previously
  called `cstr_contains(lower, LIT)` per literal — O(patterns × n × m), i.e.
  ~109 full walks of the (pre-lowered) artifact. `code_scan` now runs a single
  O(n) AC pass over `lower` and the groups query a cheap per-pattern hit table
  via `_cg_hit()`. Behavior is identical (same groups, order, one-finding-per-
  group, severity/category/name, evidence) — verified by the full existing
  scanner test suite. A literal not in the master pattern list falls back to a
  direct `cstr_contains` scan, so a drifted list can only cost speed, never
  correctness.

  **Benchmark** (new `code_scan_large_*`, ~16 KB benign artifact — worst case
  for the old path since every `cstr_contains` runs to completion):
  - `code_scan_large_naive` (old, 109 scans): **6.60 ms**
  - `code_scan_large_ac` (new, one pass): **0.54 ms** → **~12× faster**

  The win grows with artifact size: naive is O(patterns × n), AC is O(n) plus a
  constant per-pattern lookup, so on multi-MiB artifacts the ratio approaches
  the pattern count (~100×).

### Notes
- Scan context (the cached automaton, the per-scan hit table, and the lowered
  buffer for fallback) lives in `scanning_code.cyr` module globals set at the
  top of `code_scan`. kavach's scan path is synchronous (ADR-004 §1 — no
  async/threads), so this is safe; it is not reentrant.
- The **data** and **phylax** scanners still use per-pattern `cstr_contains` —
  they can adopt the same AC engine next (the engine is scanner-agnostic);
  tracked as follow-up.

## [3.3.4] — 2026-06-02

Final cc 6.0 modernization-arc item: bounds-checked slice reads on the
untrusted-input validation path. Closes the v3.3.x arc. 406 tests pass (+4);
lint 0 warnings; vet 34 deps, 0 untrusted/missing; pin stays `6.0.43`.

### Changed
- **`is_safe_text` / `is_safe_argument` read untrusted input through a
  bounds-checked slice.** These screen command strings for control-char
  injection before tokenize/exec (ADR-005 §H3). The per-byte `load8(s + i)` is
  now `sl[i]` over a `[u8]` slice, which lowers to the stdlib
  `_slice_idx_get_1` — out-of-range traps (`slice bounds violation`, exit 134)
  instead of reading attacker-influenced memory. Behavior is unchanged for
  valid input; this is defense-in-depth against a future off-by-one on a
  security-relevant path. Read-only, cold path — no measurable cost (benches
  flat).

### Added
- **Regression test `is_safe_text`** (plain/tab-newline-CR/empty/ESC cases).

### Notes — typed-slice adoption scope (arc close-out)
The broader "typed `Str`/`slice` everywhere" idea from the arc plan was
evaluated against the real cc 6.0.43 API and deliberately **bounded** to the
above rather than swept across the codebase:
- Slice subscripting is **read-only** — there is no `_slice_idx_set_W`, so
  write loops (e.g. `hex_encode_bytes`' `dst[i*2] = …`) can't use it.
- Field dot-syntax (`s.len`/`s.ptr`) is **not yet wired** in 6.0.43; the
  `slice_len()` / `slice_ptr()` accessors are required.
- kavach's pointer loops are already correctly bounded (`while i < n`), so
  subscripting is future-proofing, not a live bug fix; and the highest-volume
  reads live in the hot scanner paths, where a per-element bounds check would
  regress throughput for little safety gain.
The slice idiom is now established on the most appropriate surface (untrusted
input) and can be adopted further opportunistically. The one *real* deferred
perf finding from the post-3.3.0 audit — the scanners re-scanning the full
buffer per pattern (O(patterns × n × m); a kavach-side Aho-Corasick would
collapse it) — remains the higher-value next investment, tracked for a future
cut.

## [3.3.3] — 2026-06-02

Toolchain patch refresh + the next cc 6.0 stdlib adoption (Result `_r` on the
secure-write path). 402 tests pass (+5); lint 0 warnings; vet 34 deps, 0
untrusted/missing; benchmarks flat within noise.

### Changed
- **Cyrius pin `6.0.40` → `6.0.43`.** Patch-level toolchain refresh within the
  cc 6.0 line, re-validated with a clean `deps → build → lint → vet → test →
  bench` run. The manifest-vs-`cycc` drift warning that had been informational
  since 3.3.0 now clears (pin matches the installed `cycc 6.0.43`).
- **Hardened secure write now carries a distinguishable error.** Added
  `file_write_secure_r` (`util.cyr`) — a `Result`-returning write with the same
  `O_EXCL|O_NOFOLLOW`, mode-0600 guarantee as `file_write_secure`, built on the
  stdlib `_r` primitives (`file_open_r`/`file_write_r`/`file_close_r`) so a
  failure surfaces a typed `IoError` (`IoNotFound`/`IoAccessDenied`/…) instead
  of a bare `-1`. `file_write_secure` is now a thin int wrapper over it, so all
  existing callers are unchanged. The stdlib `file_write_all_r` is deliberately
  **not** used — it opens `O_WRONLY|O_CREAT|O_TRUNC` without the
  `O_EXCL|O_NOFOLLOW` hardening (ADR-005 §C4).
- **Quarantine writes log *why* they fail.** `quarantine_store` now uses
  `file_write_secure_r` and emits a structured error line naming the `IoError`
  (`io_error_name`) when the artifact or metadata write fails — a failed
  quarantine is a security-relevant event, and the trail now distinguishes
  "access denied" / "not found" / staged-symlink from an opaque `-1`
  (satisfies the "structured logging on every external operation" principle).

### Added
- **`file_write_secure_r` + `io_error_name`** in `util.cyr` (the `_r` write
  pattern, available for future leaf-by-leaf migration of other write paths).
- **Regression test `file_write_secure_r`** — `Ok(len)` on a fresh write,
  `Err(IoNotFound)` on a missing parent directory, and the int wrapper still
  returning `-1` on the same failure.

### Notes
- The audit-chain append (`audit.cyr`) stays on `file_append_locked` (flock +
  append; no stdlib `_r` equivalent) — out of scope for this cut. Other secure
  writes (oci_spec / credential / sgx / firecracker) remain on the back-compat
  `file_write_secure` int wrapper; they can adopt `_r` if/when they grow
  error-specific handling.

## [3.3.2] — 2026-06-02

Continues the cc 6.0 stdlib-adoption arc. Cyrius pin stays at `6.0.40`. 397
tests pass (+3); lint 0 warnings; vet 34 deps, 0 untrusted/missing.

### Changed
- **Container-ID entropy now uses the kernel CSPRNG via `getrandom(2)`** (stdlib
  `random.cyr`'s `random_bytes`) instead of hand-rolled `/dev/urandom`
  open/read/close. `util.cyr`'s `read_urandom` is replaced by `fill_random`
  (same contract: bytes filled, or -1); `rand_hex_id` / `rand_u64` /
  `rand_uuid_hex` are unchanged at the call site. Benefits for a sandbox tool:
  no fd lifecycle, one syscall instead of three, and it works where
  `/dev/urandom` isn't mounted (chroot, landlocked, minimal mount namespace) —
  strengthening the unpredictable-id security property (ADR-005 §C3). Uses
  `flags = 0` (blocks only until the pool is seeded); never `GRND_INSECURE`.
  `sandbox_full_lifecycle` bench 9µs → 7µs (fewer syscalls in id generation;
  other benches flat).

### Added
- **`random` added to `[deps] stdlib`** in `cyrius.cyml` (resolved into `lib/`
  by `cyrius deps`).
- **Regression test `fill_random_entropy`** — asserts the full byte count is
  filled and that `rand_u64` draws are nonzero and distinct.

## [3.3.1] — 2026-06-02

Memory-safety + hardening patch from the post-3.3.0 source audit, plus the
first cc 6.0 stdlib adoptions. 394 tests pass (+10 regression cases); lint 0
warnings; vet 34 deps, 0 untrusted/missing. Benchmarks vs 3.3.0 are flat
within measurement noise (e.g. `ct_streq_64` 227→217ns, `audit_chain_record`
13→12µs) — the added bounds checks and clamps carry no measurable cost.

### Security
- **Heap overflow in every exec-capture backend (M1).** `exec_capture`
  (`lib/process.cyr`) fills until `total >= buflen` and can return exactly
  `out_cap`; the per-backend `store8(out_buf + n, 0)` then wrote a NUL one
  byte past `alloc(out_cap)` on attacker-influenced subprocess output. Fixed
  once in the new shared `backend_capture_finish` (see R1) by clamping `n`
  into `[0, out_cap - 1]` before the terminator. Affected all nine capture
  backends (process / gvisor / oci / wasm / sgx / sev / tdx / sy-agnos /
  firecracker).
- **Off-by-one in the three `/proc` integrity readers (M2).** `_integrity_check_{pid,mount,user}_ns`
  in `scanning_runtime.cyr` read the full buffer length then NUL-terminated at
  `buf + n` — OOB when the read filled the buffer. Now read `size - 1`,
  matching `cgroup_supported`.
- **Predictable `/tmp` workdir + symlink TOCTOU in SGX & Firecracker (SEC1).**
  `/tmp/kavach-{sgx,fc}-<epoch_secs>` was a guessable path written via plain
  `file_write_all`. Now uses an unpredictable `rand_hex_id()` name, mode-0700
  `mkdir` with abort-on-`EEXIST`, and `file_write_secure` (`O_EXCL|O_NOFOLLOW`)
  — matching the hardening already on the OCI/quarantine paths (ADR-005 §C3/§C4).
- **Out-of-range backend id → wild fn-pointer (SEC3).** `backend_dispatch_*`
  now route through a bounds-checked `_backend_fp(bid, offset)`; an id outside
  `[0, BACKEND_COUNT)` reads as unregistered instead of indexing
  `_backend_table[320]` out of bounds.
- **cgroup controller false-positive (SEC2).** `cgroup_supported` matched
  `"cpu"` as a substring of `cpuset`. New `_cgroup_has_controller` does a
  whole-token match over `cgroup.subtree_control`.
- **Overflow-checked stdin credential payload (M3).** `credential_proxy_stdin_payload`
  now accumulates lengths via `checked_add` and allocates via `alloc_checked`.

### Fixed
- **Data-scanner evidence pointed at the wrong bytes (P1).** The structural PII
  matchers emitted a single stand-in char (`"4"`/`"0"`/…) as the match pattern,
  so evidence extraction re-scanned the whole (up to 50 MiB) artifact and
  snipped around the first stray digit. New `code_emit_at` /
  `code_extract_evidence_at` take the known `(start, len)` directly — correct
  snippet, no per-finding re-scan.
- **OCI `pids` limit buffer under-allocation (C1).** `oci_generate_spec` sized
  the resources buffer as `alloc(64 + mem_len)`, ignoring `pids_len`; a large
  `max_pids` overflowed it. Now sized with `checked_sum4`/`alloc_checked` over
  both rendered ints.
- **`quarantine_store` / `quarantine_update_status` now null-check `_qpath`**
  before writing (C2).

### Changed
- **R1 — shared exec-backend epilogue.** Extracted `backend_error_result`,
  `backend_guard_result`, and `backend_capture_finish` into `backend.cyr`; all
  nine capture backends route through them. The ~40-line-per-backend duplication
  (which is why M1 lived in nine places at once) is gone, so the overflow fix
  and future changes land in one place.
- **Raw syscalls replaced with stdlib wrappers (S2/S3).** `path_exists` now uses
  `sys_access`; `kavach_err_print` and the `main.cyr` banner use `sys_write` —
  dropping bare `syscall(21,…)` / `syscall(1,…)` and their magic numbers.
- **`mono_now_ns` is now a thin alias over `chrono.clock_now_ns`** (S1) — it was
  a byte-for-byte duplicate of the stdlib monotonic clock; chrono was already a
  dep.

### Added
- **wasm backend resolves `$HOME/.cargo/bin/wasmtime` via stdlib `getenv`** —
  closes the long-standing `# no getenv yet` placeholder now that `getenv`
  ships in `lib/io.cyr`. Probed at config time only (getenv allocates and is
  not async-signal-safe).
- **10 regression assertions** (`tests/kavach.tcyr`): `backend_capture_finish`
  clamp on a full buffer, cgroup controller whole-token match, dispatch-id
  bounds, and position-based evidence extraction.
- **`benches/bench-history.csv`** row for `3.3.1`.

## [3.3.0] — 2026-06-02

Major toolchain + dependency jump to the Cyrius 6.0 line, plus the
release-benchmark discipline now baked into the dev loop. The first-party
tree has moved off the 5.10.x sigil-NI asm-offset bisect gate; validation
is now a clean `deps → build → lint → vet → test → bench` run on the
pinned toolchain. All 384 tests pass; lint is 0 warnings; vet reports 34
deps, 0 untrusted, 0 missing.

### Changed
- **Cyrius pin** — `cyrius.cyml` bumped `5.10.44` → `6.0.40`. `README.md`,
  `CLAUDE.md`, and the `docs/` set updated to match. The DO-NOT rule
  against bumping the pin now references the build/test/bench validation
  path instead of the retired 5.10.x asm-offset bisect. (Local `cycc` may
  sit a patch ahead at 6.0.41 — the manifest pins 6.0.40 and fmt writes
  are skipped locally to avoid minor-version drift against CI.)
- **sigil pin** — `2.9.0` → `3.5.9` (latest). The cc 5.10.x bisect that
  capped sigil at 2.9.0 (2.9.1 → 3.0.1 SIGILL on the ed25519-NI path,
  3.1.0 on aes-gcm-NI) no longer applies under cc 6.0.40 — the NI-path
  offsets are stable across the sigil 3.x line, validated by a clean
  build/test/bench at this pin.
- **`scripts/bench-history.sh`** — ported off the Rust-era
  `cargo bench --manifest-path Cargo.toml` (the stale `Cargo.toml` is
  long gone) to `cyrius bench tests/kavach.bcyr`. Parser rewritten for the
  `name: <avg><unit> avg (...)` format; unit→ns normalization moved from
  `bc` (not installed here) to `awk` so the `time_ns` column is correctly
  comparable across ns/us/ms rows. Seeds `benches/bench-history.csv` (new).

### Added
- **`[deps.agnosys]` transitive override (`1.3.0`)** — sigil 3.5.9 pins
  agnosys `1.2.7` (authored for cc 6.0.1), which fails to compile under
  cc 6.0.40 (the 6.0 line tightened slice-subscript codegen to require the
  `lib/slice.cyr` helpers). agnosys `1.3.0` (cc 6.0.24) is the latest and
  builds clean; override drops once sigil bumps its own agnosys pin
  upstream.
- **Stdlib modules `ct`, `json`, `keccak`, `slice`, `thread`** added to
  `[deps] stdlib`. The cc 6.0 stdlib absorbed constant-time compare into
  `ct.cyr` (which is why sigil retired its own `ct.cyr`), and the sigil
  3.5.9 dist transitively references `json`/`keccak`/`thread`; `slice`
  satisfies the new slice-subscript helper requirement.
- **`benches/bench-history.csv`** — first per-release benchmark baseline,
  labeled `3.3.0` (20 benchmarks). Selected medians at this cut:
  `state_valid_transition_check` 7ns, `cgroup_policy_has_limits` 10ns,
  `score_backend_process_strict` 37ns, `http_allowlist_hit` 74ns,
  `policy_strict_create` 100ns, `ct_streq_64` 227ns,
  `score_all_backends_strict` 365ns, `cgroup_wrap_argv` 545ns,
  `sandbox_full_lifecycle` 9µs, `audit_chain_record_to_tmpfs` 13µs,
  `credential_env_vars_100` 18µs. This is the reference row future
  releases diff against.

### Migration
- **sigil `ct_eq` retired → stdlib `ct_eq_bytes_lens`.** sigil removed
  `src/ct.cyr` and the public `ct_eq` / `ct_eq_32` symbols from
  `dist/sigil.cyr` in the 3.x line in favor of the cyrius stdlib
  `ct_eq_bytes_lens` (identical semantics, one identifier rename).
  `src/util.cyr::ct_streq` migrated accordingly — the audit-chain
  constant-time HMAC compare (ADR-005 §C1) is unchanged in behavior.
- **Renamed kavach helpers that newly collided with cc 6.0 stdlib / sigil
  symbols** (the cc 6.0 stdlib grew `str_contains`/`str_index_of`/`now_ns`
  and sigil's dist now exports `integrity_report_new`, all with
  signatures incompatible with kavach's same-named helpers):
  - `now_ns` → `mono_now_ns` (kavach's CLOCK_MONOTONIC timer; the stdlib
    `bench.cyr` now ships a CLOCK_MONOTONIC_RAW `now_ns`).
  - `str_contains` → `cstr_contains`, `str_index_of` → `cstr_index_of`
    (kavach's cstr-pointer substring helpers; the stdlib's are `Str`-typed
    and char-based — passing a cstr to the stdlib version SIGSEGVs).
  - `integrity_report_new` → `runtime_integrity_report_new` (kavach's
    runtime-scanner report, distinct from sigil's integrity type).
  These were applied across `src/` **and** `tests/kavach.tcyr`.
- **`backend_wasm.cyr`** — removed a dead `syscall(0 - 1, 0)` placeholder
  (unused `home`, flagged by cc 6.0's stricter syscall-arity check); the
  `$HOME/.cargo/bin` probe lands when stdlib `getenv` is available.

## [3.2.1] — 2026-05-11

Toolchain pin refresh — Cyrius 5.10.34 → 5.10.44 across the first-party
tree (majra / nein / agnosys / kavach), re-validated against the
sigil-NI asm-offset bisect. No source changes; CI fmt baseline now
runs at 5.10.44.

### Changed
- **Cyrius pin** — `cyrius.cyml` bumped from `5.10.34` to `5.10.44`.
  `README.md`, `CLAUDE.md`, and `docs/architecture/overview.md` updated
  to match. The DO-NOT rule against running `cyrius fmt` with a
  non-pinned local toolchain now references 5.10.44 as the in-tree
  baseline.

## [3.2.0] — 2026-05-10

Two new feature modules from the v3.2 Ready queue. Both are unblocked
at cc 5.10.34 + sigil 2.9.0 — no upstream wait. The third Ready
feature (Landlock hooks) deferred to v3.3.0 because it requires a
`sandbox_fork_exec(args, pre_exec_fn)` helper that's better built
jointly with future seccomp support; v3.3.0 will be the final cut of
this work arc.

### Added
- **`src/cgroup.cyr`** — cgroups v2 resource limits. Wires
  `SandboxPolicy.{memory_limit_mb, cpu_limit_tenths, max_pids}` into a
  per-sandbox cgroup at `/sys/fs/cgroup/kavach-<random_u64>/`. Writes
  `memory.max` (bytes), `cpu.max` (quota/period with 100ms period), and
  `pids.max` from the policy. Placement uses the shell-prepend pattern:
  user argv gets wrapped in `["sh", "-c", "echo $$ > <path>/cgroup.procs;
  exec \"$@\"", "--", <user argv>...]` so the shell writes its own PID
  into `cgroup.procs` and `exec "$@"` replaces the shell with the user
  command — same PID, same cgroup placement, **no shell re-interpretation
  of the user's argv** (variables and metachars in user args don't
  expand because they pass through `"$@"` positionally, not through
  `<command>` substitution). Graceful no-op when /sys/fs/cgroup isn't
  writable. Public surface: `cgroup_supported()`,
  `cgroup_policy_has_limits(policy)`, `cgroup_setup(policy) → path`,
  `cgroup_wrap_argv(path, user_argv) → wrapped_argv`,
  `cgroup_teardown(path)`. Wired into `backend_process.cyr::process_exec`;
  the OCI backend handles cgroup limits via the OCI runtime spec
  (future enhancement; current `oci_spec.cyr` minimal spec is unchanged
  in this cut).
- **`src/credential_http.cyr`** — closes ADR-004 §4. Sandhi-backed
  HTTP server on `127.0.0.1:<port>` (loopback only — never binds
  `INADDR_ANY`) that serves `GET /v1/secret/<name>` from the existing
  in-memory `CredentialProxy`. Per-instance allowlist gates which names
  this proxy serves; allowlist-miss returns 403 without consulting the
  proxy (no oracle for "does this name exist?"). Every served fetch +
  every 403/404 hits the audit chain when one is wired. Pairs with the
  v3.0 env/file/stdin injection methods — HTTP is the "no secret on
  disk" alternative. Public surface:
  `credential_http_proxy_new(proxy, allowed_vec, audit) → handle`,
  `credential_http_proxy_listen(http, port) → 0|-1`,
  `credential_http_proxy_serve_one(http)`,
  `credential_http_proxy_serve(http, max_requests)`,
  `credential_http_proxy_close(http)`.
- **`file_write_secure_modal` precedent reuse** — the cgroup module's
  `_cgroup_write_int` / `_cgroup_write_str` use plain `file_write_all`
  rather than the secure variant; cgroup files are owned by root and
  the kernel manages their attributes — the precautions
  `file_write_secure` adds (O_EXCL, O_NOFOLLOW, mode 0600) don't
  apply to /sys/fs/cgroup writes.
- **stdlib surface added** to `cyrius.cyml [deps] stdlib`:
  `dynlib`, `fdlopen`, `fs`, `hashmap_fast`, `mmap`, `net`, `result`,
  `sandhi`, `tls` — most are transitive pulls from sandhi's TLS / HTTP
  surface. `net` + `sandhi` are the direct dependencies of the HTTP
  credential proxy.
- **28 new tests** (358 → 386). Coverage:
  - cgroup: `policy_has_limits` shape, `wrap_argv` shape (argv layout +
    body content), `supported()` graceful return, `setup()` no-op when
    unsupported (the common CI environment).
  - credential_http: handle shape, allowlist hit/miss/empty, path
    extraction (valid / wrong-prefix / empty-suffix / nested-path
    rejected), listen+close lifecycle.
- **5 new benches** (15 → 20):
  - `cgroup_wrap_argv` — 498ns (alloc + vec_push of 4 strings)
  - `cgroup_policy_has_limits` — 9ns (3 field reads + compares)
  - `http_path_extract` — 111ns (prefix check + traversal check + alloc)
  - `http_allowlist_hit` — 69ns (linear scan + streq)
  - `http_allowlist_miss` — 81ns (linear scan, no early termination)

### Changed
- **`src/backend_process.cyr::process_exec`** — when the sandbox's
  policy has any cgroup-controlled limit set, the user argv is wrapped
  via `cgroup_wrap_argv()` before being passed to `exec_capture()`.
  The wrap is conditional — sandboxes with no resource limits avoid
  the `sh` dependency entirely. Cgroup teardown via `cgroup_teardown()`
  runs unconditionally after exec (no-op when no setup happened).
  Runtime guard check runs against the *original* command (not the
  wrapped one), so the sh-prepend doesn't bypass argument-smuggling
  detection.
- **`src/main.cyr`** banner string `v3.0.0` → `v3.2.0` (the v3.1.x
  patches didn't touch the banner; this cut brings it current).
- **CI **lint gate** stays hard-fail** (set in v3.1.1); the two new
  modules + bench-file edits ship lint-clean against cc 5.10.34.

### Internal — known upstream gap
- **sandhi 1.3.3 hashmap_ vs map_ naming inconsistency.** sandhi's
  TLS session cache references `hashmap_new_a` / `hashmap_get` /
  `hashmap_set_a` / `hashmap_len` while the stdlib `hashmap` module
  exports the same shape under `map_*` names. The HTTP credential
  proxy is loopback-only and never reaches sandhi's TLS code, but the
  linker still resolves the symbols. Worked around with 4-line shim
  wrappers in `credential_http.cyr` that route `hashmap_*` → `map_*`.
  Tracked: needs an upstream sandhi filing — fold the shims back to
  bare imports when sandhi resolves the naming.

### Race-tolerance note for cgroups v2
Per the 3.1.2 scoping discussion: cgroups v2 placement is done via
the shell-prepend pattern, which introduces a small bounded window
between `fork()` and the shell writing its own PID to `cgroup.procs`
in the new process. During that window the process is NOT in the
target cgroup; its scheduling / accounting falls under whatever
cgroup `kavach` itself sits in (typically the agnos service slice,
fine). Functional impact: resource accounting from the first ~few
syscalls of `sh` startup is attributed to kavach's parent cgroup,
not the sandbox's. This is the standard race-tolerant model used by
container runtimes that don't have a custom fork+pre_exec helper
available. v3.3.0 + the `sandbox_fork_exec` helper will close this
window for the configurations that need exact accounting from the
first instruction; today's pattern is correct for the 99% case
where cgroup limits exist to constrain steady-state, not to bound
microsecond-scale startup costs.

### Deferred to v3.3.0 (final cut of this work arc)
- **Landlock hooks** — needs the `sandbox_fork_exec(args, pre_exec_fn)`
  helper to install the ruleset post-fork in the child.
- **`sandbox_fork_exec` helper itself** — same infrastructure that
  future seccomp (waiting on the upstream cyrius `sys_prctl` /
  `sys_seccomp` wrappers) will slot into.
- **OCI backend cgroup integration** — populate the `resources` section
  of the OCI runtime spec so `runc` / `crun` set up cgroups directly.
  Independent of the fork-infra; deferred only to keep this cut tight.

### Still deferred (unchanged)
- **`cyrius fmt` drift** across 7 src/ files + 2 tests/ files. Local
  cyrius is 5.10.44; pin is 5.10.34. Awaiting 5.10.34 toolchain to
  clear safely. CI fmt step remains `::warning::` informational.

## [3.1.2] — 2026-05-10

Closes out the 3.1.x arc by filing the v3.2 Blocked-queue items
upstream as P1 issues in the projects that own them. No source /
behavior changes in kavach; this is documentation work that
externalises kavach's wait-list so upstream maintainers can plan.

The three v3.2 "Ready" feature items that the cc-5.10.34 verify pass
unblocked (Landlock hooks, cgroups v2, HTTP credential proxy) are
**deliberately deferred to 3.2.0** — each is a new module plus
post-fork wiring, which is minor-sized work, not patch-sized.

### Added (upstream filings)
- **[`cyrius/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md`](https://github.com/MacCracken/cyrius/blob/main/docs/development/issues/2026-05-10-kavach-sandbox-syscall-wrappers.md)**
  — single coordinated filing covering the six sandbox-runtime
  syscall wrappers kavach v3.2 features will use: `sys_prctl`
  (157), `sys_seccomp` (317), `sys_setresuid` (117),
  `sys_setresgid` (119), `sys_execveat` (322), `sys_fchmod`
  (91). Per-wrapper detail: numbers (x86_64 + aarch64), the
  kavach feature it gates, the async-signal-safe post-fork
  context, the workaround-via-raw-syscall pattern (kavach 3.1.1
  ships `SYS_FCHMOD` this way as the precedent), and a
  suggested landing order. Filed P1 with explicit "severity
  rationale" letting an upstream maintainer re-rate to P2 if
  scheduling pressure is elsewhere (workaround exists in-tree).
- **[`sigil/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md`](https://github.com/MacCracken/sigil/blob/main/docs/development/issues/2026-05-10-kavach-sgx-sev-tdx-attestation-modules.md)**
  — single coordinated filing covering the TEE attestation +
  sealing surface for kavach's SGX / SEV-SNP / TDX backends.
  Calls out: SGX quote parser + IAS/DCAP cert chain; SEV-SNP
  guest attestation parser (VCEK chain); TDX TD-quote parser;
  SGX sealing (key derivation against MRSIGNER + ISVSVN).
  Notes which crypto primitives sigil 2.9.0 already ships
  (sha256 / hmac / ct / hkdf / ed25519 / verify) and what's
  missing (ECDSA P-256, minimal X.509 cert-chain primitives,
  quote-format parsers). Suggested placement: sigil 3.2-or-later
  (sigil 3.1 alloc-free verify rewrite shouldn't be displaced).
  Filed P1 with explicit "severity rationale" letting an upstream
  maintainer re-rate to P3 (enhancement; kavach ships fine
  today without quote verify — the backends start the runtime
  but don't attest its identity).
- **Stiva OCI backend** — no upstream filing. There's no stiva
  Cyrius port repo today; the blocker resolves when one ships,
  and will be revisited then.

### Changed
- **`docs/development/roadmap.md` § v3.2 Blocked rows** — each
  blocker row now cross-links to its upstream filing under the
  "Who owns it" line. SGX / SEV / TDX rows merged into a single
  unified row (they share the upstream filing). Meta block updated
  with a summary of the upstream-filing work landed in this patch.

### Deferred to 3.2.0 (deliberately)
The three v3.2-Ready feature items unblocked at cc 5.10.34 are
**not** in this patch — each is new-module work that belongs in a
minor cut, not a patch:
- **Landlock hooks** — new `src/landlock.cyr` + post-fork hooks in
  `backend_process` / `backend_oci`.
- **cgroups v2 resource limits** — new `src/cgroup.cyr` + pre-exec
  hook in `sandbox_exec.cyr`.
- **HTTP credential proxy** — new `src/credential_http.cyr` using
  sandhi + tls from stdlib.

### Still deferred (unchanged from 3.1.1)
- **`cyrius fmt` drift** across `src/{audit,backend_sy_agnos,composite,credential,quarantine,scanning_gate,scanning_secrets}.cyr`
  + `tests/kavach.{tcyr,bcyr}`. Local toolchain is 5.10.44; pin is
  5.10.34. Awaiting a 5.10.34-toolchain install to clear safely.

## [3.1.1] — 2026-05-10

Post-3.1.0 patch cut. Drains the doc-sweep queue the v3.1.0
`doc-health.md` left open, plus three concrete v3.2-Ready items:
lint clean, `FileInjection.mode` honoring helper, and the
`rust-old/` removal. Also a verify-pass against cc 5.10.34
that reclassifies three "Blocked" items as Ready and rewrites
the v3.2 Blocked table with full per-item context. No
behavior changes to the sandbox runtime, scanners, audit
chain, or threat classifier.

### Added
- **`credential_inject_files(injections)`** in
  [`src/credential.cyr`](src/credential.cyr) — closes
  [ADR-005](docs/adr/005-v2-hardening-pass.md) §M2. Iterates the
  FileInjection vec, writes each via the new
  `file_write_secure_modal(path, buf, len, mode)` helper, returns
  the count of successful writes (or `-(n+1)` on first failure).
- **`file_write_secure_modal(path, buf, len, mode)`** in
  [`src/util.cyr`](src/util.cyr) — variant of `file_write_secure`
  that holds the fd across an fchmod-to-caller-mode before close.
  Closes the TOCTOU window between write and chmod that
  `file_write_secure` + post-close `sys_chmod` would re-open.
  Raw `syscall(91, fd, mode, 0)` since stdlib has no
  `sys_fchmod` wrapper at cc 5.10.34 — folded back to a wrapper
  when upstream ships one. SAFETY-commented per the raw-syscall
  convention.
- **5 new tests** in `tests/kavach.tcyr` covering
  `credential_inject_files`: empty vec, single file with mode
  honoring, two-file batch, O_EXCL refuses preexisting target,
  failure return-code shape (`-(written + 1)`). Test count:
  349 → 358.

### Changed
- **`cyrius lint` clean across `src/`** — 37 long-line warnings
  (inherited from the v3.0 cut, chiefly in the scanner pattern
  lists) cleared by rewrapping call sites. Affected files:
  `scanning_code.cyr` (16 `code_emit` call sites rewrapped to
  two-line form, plus all sibling sites in the same module for
  style consistency); `scanning_data.cyr` (16 `_dg_emit` sites,
  same treatment); `backend_sgx.cyr` (3 long string literals
  split into `p1a`/`p1b`, `p2a`/`p2b`, `p3a`-`p3f` with adjacent
  `memcpy` calls — same bytes emitted, smaller per-line
  surface); `oci_spec.cyr` (1 string-literal split via `mid1a` /
  `mid1b`); `scanning_runtime.cyr` (1 multi-arg `vec_push` call
  rewrapped). No semantic change. CI lint gate flipped from
  `::warning::` informational to hard-fail.
- **CHANGELOG `[Unreleased]` block from 3.1.0 → `[3.1.1]`** —
  the post-cut doc sweep (README, CLAUDE.md, getting-started,
  rust-old-removal) is now dated. See the rolled-in detail below.
- **`docs/development/roadmap.md` § v3.2** — rewritten. Three
  items reclassified out of "Blocked — awaiting upstream" after
  a cc-5.10.34 verify pass:
  - **Landlock hooks** — `sys_landlock_create_ruleset`,
    `sys_landlock_add_rule`, `sys_landlock_restrict_self` ship
    in stdlib (`syscalls_x86_64_linux.cyr` L614-630 + aarch64
    peer). Moved to Ready.
  - **HTTP credential proxy** — `sandhi` (HTTP server/client),
    `tls`, `net` all ship in stdlib at 5.10.34. Moved to Ready.
  - **cgroups v2** — never actually needed a stdlib wrapper;
    `/sys/fs/cgroup/<scope>/{memory.max,cpu.max,pids.max}`
    writes work via plain `fs.cyr`. Mis-classified in v3.0;
    moved to Ready.

  Remaining "Blocked — actually awaiting upstream" rows each
  carry **what it means** (concrete kavach-side surface that
  gates on the missing piece), **who owns the upstream work**,
  and **trigger condition** (what has to ship): seccomp hooks,
  Firecracker jailer/vsock/snapshot, H4 binary-path TOCTOU
  (residual from ADR-005 §H4), SGX attestation + sealing,
  SEV/TDX attestation, Stiva OCI backend.

### Removed
- **`rust-old/` tree** (1.4 MB, 25,935 lines of Rust). Parity
  audit re-verified 2026-05-10 — every public Rust API has a
  Cyrius equivalent per
  [`docs/development/rust-old-removal.md`](docs/development/rust-old-removal.md).
  Heritage `# Ported from rust-old/src/...` header comments
  in `src/` preserved as breadcrumbs to git history; the source
  tree itself is reachable via git history pre-3.1.1. Suggest
  tagging `kavach-pre-rust-removal` at the parent commit for
  easy rollback / archaeology. `.gitignore` `rust-old/target/`
  line dropped (parent directory no longer exists).

### Doc sweep (rolled in from the pre-3.1.1 [Unreleased] block)
- **`README.md`** — Cyrius floor bumped to 5.10.34 with the
  pin-lock rationale (sigil-NI asm-offset bisect); `cyrius
  deps` step added to the build instructions; `cyrius.toml`
  → `cyrius.cyml`; v3.0 status block split into v3.1
  modernization arc + v3.0 port summary; dep list updated
  against `[deps] stdlib` + sigil 2.9.0; `doc-health.md`
  cross-link added.
- **`CLAUDE.md`** — Rust-era `MSRV: 1.89` line dropped;
  Version bumped to v3.1.0 (now → v3.1.1); new `Language:
  Cyrius (pinned at 5.10.34 …)` line carrying the pin-lock
  rationale. Cleanliness Check lines swapped from `cargo *`
  → `cyrius *`. Key Principles translated from Rust-attribute
  idioms to Cyrius-shaped equivalents. DO-NOT list rewritten
  with the pin-bump prohibition + `cyrius fmt` on
  non-pinned-toolchain prohibition + `lib/`/`build/`
  gitignore reminders. `Cargo.lock` reference dropped.
- **`docs/guides/getting-started.md`** — § 1 "Build +
  install" rewritten: `cyrius deps` step added; toolchain
  line bumped to 5.10.34; dep list aligned to `[deps]
  stdlib`; sigil pin updated 2.1.2 → 2.9.0; `lib/`
  gitignored model documented.
- **`docs/development/rust-old-removal.md`** — sed recipe
  `cyrius.toml` → `cyrius.cyml`; commit message bumped v3.0
  → v3.x; pre-removal checklist gains the
  cyrius.cyml-migration-prereq row.
- **`docs/doc-health.md`** — bucket counts walked after the
  sweep: Fresh 5 → 9, Stale 3 → 1, Read-through 2 → 0.
  Per-row Last touched / Status / Notes refreshed.

### Still queued (carried into v3.2 backlog)
- **`cyrius fmt` drift** across `src/{audit,backend_sy_agnos,composite,credential,quarantine,scanning_gate,scanning_secrets}.cyr`
  + `tests/kavach.{tcyr,bcyr}`. (Shorter list than v3.1.0
  documented — the lint-cleanup pass incidentally restyled
  `scanning_code.cyr` and `scanning_data.cyr`.) Needs a clean
  run against the cc 5.10.34 toolchain; CI fmt step remains
  `::warning::` informational until cleared.

## [3.1.0] — 2026-05-10

**Modernization arc.** Brings the kavach build / dependency / CI / release
surface into line with majra and nein. No behavior changes to the sandbox
runtime; the v3.0.0 surface (10 backends, 3-scanner pipeline, HMAC audit
chain, threat classifier, hardening pass) is unchanged. The previously
queued "v3.1 — unblocking queue" backlog has cascaded to v3.2 — see
[`docs/development/roadmap.md`](docs/development/roadmap.md) for the
new shape.

### Changed
- **Cyrius toolchain pin: 4.5.0 → 5.10.34.** Same floor as majra / nein /
  agnosys post-M6. Picks up the cc5 type-check default-on surface
  (cstring / Str annotations) and the arch-peer include resolution
  under `~/.cyrius/versions/<V>/lib`.
- **Manifest format: `cyrius.toml` → `cyrius.cyml`.** Mirrors the majra
  shape: `version = "${file:VERSION}"` so the `VERSION` file is the
  single source of truth; `[deps] stdlib = [...]` lists the union of
  stdlib modules included across src/, tests/, and fuzz/;
  `[deps.sigil]` switched from path/absolute-path workaround to
  `git = "https://github.com/MacCracken/sigil.git"` + `tag = "2.9.0"`.
- **`lib/` is no longer committed.** Added `/lib/` to `.gitignore`.
  `cyrius deps` is now the source of truth — it populates `lib/` from
  the cc 5.10.34 stdlib snapshot plus the `[deps.sigil]` git tag.
  Mirrors majra / nein post-M6.
- **`.cyrius-toolchain` removed.** The cyrius pin lives in
  `cyrius.cyml`'s `cyrius = "5.10.34"` field — single source of truth.
  CI installers read the pin via a grep on `cyrius.cyml` (same
  pattern as majra / nein).
- **sigil pin: 2.1.2 → 2.9.0.** Same gate the rest of the first-party
  tree is on. 2.9.1 through 3.0.1 SIGILL on the ed25519-NI path under
  cc5 5.10.x; 3.1.0 also breaks aes-gcm-NI. Bump only when sigil
  ships an asm-offset-stable release (tracked upstream).
- **VERSION: 3.0.0 → 3.1.0.**

### Added
- **CI rewrite** (`.github/workflows/ci.yml`). Version-pinned toolchain
  installer (`~/.cyrius/versions/<V>/{bin,lib}` + `~/.cyrius/{bin,lib}`
  symlinks), source-archive fetch for the stdlib snapshot (release
  tarball ships `bin/` + `deps/` only under 5.10.x), `cyrius deps` +
  lockfile hash verification, `cyrius fmt / lint / vet` gates,
  build / smoke / test / bench / fuzz pipeline, security scan
  (raw-execve allowlist + `/etc` writes guard), docs presence +
  version-consistency + CHANGELOG-date currency gates. Pattern lifted
  from majra / nein / agnosys.
- **Release rewrite** (`.github/workflows/release.yml`). Same installer
  + deps flow, version verify (semver shape + VERSION-vs-tag match +
  `${file:VERSION}` literal check on `cyrius.cyml`), binary +
  source-archive assets, SHA256SUMS, dated CHANGELOG body
  extraction for the release notes. Accepts both `v3.1.0` and
  `3.1.0` tag styles.
- **`docs/doc-health.md`** — initial doc-currency ledger, modeled on
  majra's. Buckets the ~22-file surface into fresh / stale /
  read-through / evergreen / frozen, queues the 3 stale rows
  (`README.md`, `CLAUDE.md`, `benchmarks-rust-v-cyrius.md`) and 2
  read-through rows (`docs/guides/getting-started.md`,
  `docs/development/rust-old-removal.md`) for the 3.1.x follow-up.

### Removed
- **`cyrius.toml`** — replaced by `cyrius.cyml`.
- **`.cyrius-toolchain`** — cyrius pin moved into `cyrius.cyml`.
- **`cyrius.lock`** — will be regenerated by the first `cyrius deps`
  run under the new manifest; stale lockfile from the v3.0 toolchain
  deleted.
- **`lib/` (working tree, 27 vendored stdlib + sigil modules)** —
  resolved by `cyrius deps` from now on. Gitignored.

### Notes for consumers
- SY / stiva / kiran / AgnosAI / hoosh / bote / aethersafta: kavach is
  binary-only at the moment, so consumers don't pull a manifest
  reference. If a consumer starts embedding kavach modules at the
  source level (similar to how majra is consumed), a `[lib]` profile
  and `dist/kavach.cyr` bundle will land in a 3.1.x patch.

## [3.0.0] — 2026-04-13

Complete language migration — **Rust → Cyrius**. First release of kavach in
Cyrius; supersedes the Rust v2.0.0 line. Major version bump reflects the
language/ABI change and the intentional API refinements (async → sync,
monotonic IDs → UUID-v4-equivalent random, field consolidations). 25,935
lines of Rust → 33 Cyrius modules, ~7K lines. See
[ADR-001](docs/adr/001-cyrius-port-architecture.md) for the port rationale.

The v3.0.0 release bundles three internal waves of work:

1. **Port skeleton** — all 10 backends, scanner pipeline, threat classifier,
   lifecycle FSM, credential proxy, audit chain, quarantine storage.
2. **P(-1) hardening pass** — see [ADR-005](docs/adr/005-v2-hardening-pass.md).
   9 CWE-class findings fixed in-tree (CWE-208, CWE-116, CWE-59, CWE-276,
   CWE-532, CWE-88, CWE-316, CWE-190, CWE-252).
3. **Feature closeout** — UUID v4 IDs, WARN-verdict redaction, OffenderTracker,
   integrity monitoring, composite backend, observability + attestation types.

### Added (gap-close wave)
- **CompositeBackend port** (`src/composite.cyr`) — `merge_policies(base, overlay)` with stricter-wins semantics, `score_composite(outer, inner, policy)` returning the layered score with +5 defense-in-depth bonus, and `composite_exec(...)` for executing through an outer backend with a merged inner policy.
- **Observability types** (`src/observability.cyr`) — `HealthStatus`, `HealthState` enum, `health_probe(sandbox)`, `SandboxMetrics` struct (CPU/memory/PID/IO/wall fields; cgroup-backed populator pending), `sandbox_metrics_from_result`, `SpawnedProcess` handle for fire-and-forget execs.
- **Attestation types** (`src/attestation.cyr`) — `AttestationResult` + `AttestationTrust` enum (Contraindicated < Warning < None < Affirming), `attestation_is_acceptable(result, min_trust)`, `SgxAttestationReport` with `sgx_report_verify_structure` (MRENCLAVE/MRSIGNER hex + IAS signature length check; full cryptographic verify deferred to v3.0 sigil EAR helpers).
- **33 Cyrius modules total** — added composite.cyr + observability.cyr + attestation.cyr.

### Documentation
- **Benchmarks — Rust v2.0 vs Cyrius v3.0** (`benchmarks-rust-v-cyrius.md`) — apples-to-apples per-op comparison with honest commentary on where Cyrius is slower (unoptimized codegen tax) and where it's faster (no tokio startup on sandbox lifecycle).
- **Guides** (`docs/guides/`): getting-started (build → configure → execute), composite-backends (defense-in-depth merge rules), threat-tracking (intent scoring + OffenderTracker + decay tuning).
- **Worked examples** (`docs/examples/`): 4 progressive walkthroughs covering Noop, Process+audit, scanner verdicts with WARN redaction, offender tracking across execs.
- **rust-old removal readiness** (`docs/development/rust-old-removal.md`) — per-symbol audit confirming Cyrius coverage, pre-removal checklist, removal command.
- **Benchmark harness** (`tests/kavach.bcyr`) — 15 benches via `lib/bench.cyr` covering scoring, policy build, credentials, scanners, gate, lifecycle, audit.
- **349 tests** (was 326) — 23 new tests for composite merge + score, health probe, metrics, attestation trust ordering, SGX report structure.

### Feature closeout wave

Drains 5 of the 7 "ready" items from the internal roadmap; leaves
`FileInjection.mode` helper and `cyrius audit` for a future release.

- **UUID v4 IDs** — Sandbox, ScanFinding, and Quarantine entry ids are now 64-bit random values from `/dev/urandom` via new `util.cyr::rand_u64`. Monotonic counters removed. Collision probability across 2^32 entries is ~2^-32.
- **Secret redaction on WARN verdict** — `secrets_redact(text)` walks the text once, rewrites every secret-pattern span to `[REDACTED:CATEGORY]`, returns the cleaned cstr. `gate_apply` now invokes it on `stdout`/`stderr` when the verdict is WARN and `policy.redact_secrets == 1`.
- **OffenderTracker** — `offender_tracker_new/with_config/record/prune/agent_score/should_escalate/count`. Per-agent violation score accumulates with integer-only half-life decay (score × decay_factor^(age / half_window)). Defaults match the Rust original: 1h window, decay 0.5 per half-window, escalation threshold 3.0.
- **Sandbox integrity monitoring** — `check_integrity()` returns an `IntegrityReport{intact, checks[3], checked_at}` verifying PID namespace (`/proc/1/cmdline` not systemd/init), mount namespace (`/proc/mounts` no host `/home` without overlay), and user namespace (`/proc/self/uid_map` populated).
- **Integer-overflow guards completed (M1 closeout)** — new `checked_sum4` + `alloc_checked` wired through audit `_sign_input`/`_entry_to_jsonl`, quarantine `_qpath`/`_meta_jsonl`, and `oci_generate_spec`. Every multi-term allocation refuses negative sizes or anything over 64 MiB per single allocation.

### Changed
- **`QuarantineStorage.next_id` field retained for ABI** but no longer incremented. Entry IDs come from `rand_u64()` per `quarantine_store()` call.
- **349 tests passing, 0 failing**.
- **33 Cyrius modules**.

### Security
- **P(-1) hardening pass completed** — see [ADR-005](docs/adr/005-v2-hardening-pass.md). Fixes applied, with CWE/CVE analogs:
  - **Constant-time HMAC verification** (CWE-208, CVE-2016-2107 class) — `audit_entry_verify` now uses sigil `ct_eq` via new `util.cyr::ct_streq`. HMAC-signing-key extraction via verify-latency oracle is closed.
  - **Full RFC 8259 JSON escape** (CWE-116, CVE-2021-44228 class) — `oci_json_escape` now escapes all control chars 0x00–0x1F as `\uXXXX` with short forms for `\b\f\t\n\r`. Audit JSONL routes `event_type` + `payload` through it; quarantine metadata escapes `sandbox_id`. Log forgery via control chars in user-controlled strings is closed.
  - **Symlink TOCTOU on /tmp** (CWE-59, CVE-2024-21626 class) — container IDs include 16 random hex chars from `/dev/urandom`. `oci_prepare_bundle` uses mode 0700 + checks `sys_mkdir` returns; files via new `file_write_secure()` with `O_CREAT|O_EXCL|O_NOFOLLOW`. Symlink-preseed redirection of config writes is closed.
  - **Sensitive artifacts mode 0600** (CWE-276) — audit log + quarantine `.bin`/`.meta` + OCI/FC/SGX configs now created with mode 0600 (not stdlib default 0644). Audit log additionally `sys_chmod`-tightened after `file_append_locked`.
  - **Secret evidence redaction** (CWE-532) — `_evidence_copy` in scanner now keeps first 4 + `****` + last 4; full secrets never land in findings, audit logs, or quarantine files. Prefix preserves signal (`AKIA****…`) without leaking the secret.
  - **Argument smuggling via control chars** (CWE-88) — `backend_process.cyr::process_exec` rejects commands with any byte < 0x20 except tab. Newline-smuggled second tokens past the runtime guard are closed.
  - **HMAC key lifetime** (CWE-316, CVE-2019-1559 class) — new `audit_chain_close(chain)` calls sigil `zeroize_key` on the key buffer and clears the chain's pointer.
  - **Integer overflow guards** (CWE-190, partial) — new `util.cyr::checked_add` + `checked_mul`. `oci_json_escape` caps input at 1 MiB before the ×6 expansion.
- **32 new hardening-specific tests** added to `tests/kavach.tcyr` (constant-time comparator, JSON control-char escape, argument-smuggling rejection, overflow guards, redacted evidence, key zeroing).

### Added
- **All 10 backends registered** — Noop, Process, gVisor, OCI, WASM, SyAgnos, SGX, SEV, TDX, Firecracker. Dispatch table fully populated; ADR-002's extension pattern is fully demonstrated.
- **SyAgnos backend** (`src/backend_sy_agnos.cyr`) — docker/podman shell-out against the hardened AGNOS container image (`ghcr.io/maccracken/agnos:latest`), with Phylax scanner extending the secrets scanner to detect verity violations, nftables bypass, namespace escape, and mount-escape attempts.
- **SGX backend** (`src/backend_sgx.cyr`) — `gramine-sgx` with an auto-generated Gramine manifest. Requires `/dev/sgx_enclave`.
- **SEV backend** (`src/backend_sev.cyr`) — `qemu-system-x86_64` with SEV-SNP confidential-guest object. Requires `/dev/sev`.
- **TDX backend** (`src/backend_tdx.cyr`) — `qemu-system-x86_64` with tdx-guest object. Requires `/dev/tdx_guest`.
- **Firecracker backend** (`src/backend_firecracker.cyr`) — minimal microVM config.json + `firecracker --no-api --config-file`. Jailer/vsock/snapshot deferred.
- **WASM backend** (`src/backend_wasm.cyr`) — `wasmtime run` shell-out with fuel-based CPU metering (`--fuel`), memory limit (`--max-memory-size`), and directory preopens (`--dir`). Takes a `.wasm` file path as the command. Registers into the dispatch table.
- **OCI backend** (`src/backend_oci.cyr`) — `runc`/`crun` shell-out against the shared OCI bundle. Picks first available runtime from PATH. Same dispatch registration pattern as gVisor.
- **Shared OCI spec module** (`src/oci_spec.cyr`) — extracted from the gVisor backend: container-id generation, JSON escape, minimal runtime spec v1.0.2, bundle mkdir, and cleanup (unlink config.json, rmdir rootfs/, rmdir bundle/). Both gVisor and OCI backends call into this.
- **Bundle cleanup on exit** — `oci_cleanup_bundle(bundle)` called after every exec regardless of outcome. Prevents `/tmp/kavach-gvisor-*` and `/tmp/kavach-oci-*` accumulation.
- **gVisor backend** (`src/backend_gvisor.cyr`) — OCI bundle generation + `runsc run` + auto-cleanup. Registers into the dispatch table via `backend_gvisor_register()`. Proves ADR-002's "3-line extension" pattern: same dispatch slot layout, different `exec_fn`.
- **`path_exists` + `which_exists`** — real implementations via `access(2)` syscall. Enables meaningful `backend_is_available()` probes and `resolve_best_backend()` ranking.

### Fixed
- **`cyrius.toml` sigil path** — switched from `path = "../sigil"` to
  absolute path to work around a `cyrius deps` bug where relative `path`
  entries produce broken symlinks in `lib/`. Symptom was
  `undefined function 'hmac_sha256'` despite successful dep resolution.
  Fix is temporary; file upstream for cyrius 4.4.0.: `error`, `util`, `backend`, `policy`, `scoring`,
  `lifecycle`, `scanning_types/_secrets/_code/_data/_gate/_runtime/_threat`,
  `audit`, `credential`, `quarantine`, `backend_dispatch/_noop/_process`,
  `sandbox_exec`
- **Function-pointer dispatch table** for backends — O(1) lookup, O(3-line)
  extension cost. See [ADR-002](docs/adr/002-backend-dispatch-fnptr-table.md).
- **Fixed-point threat scoring** — intent_score is `_x1000` (0..1000). See
  [ADR-003](docs/adr/003-fixed-point-threat-scoring.md).
- **HMAC-SHA256 audit chain** via [sigil](https://github.com/MacCracken/sigil) ≥ 2.1.2
- **End-to-end demo** (`./build/kavach`): backend dispatch → gate → threat →
  audit, writes `/tmp/kavach-demo.audit` with linked HMAC chain.
- **Architecture docs**: [overview](docs/architecture/overview.md) +
  4 ADRs + README rewrite for the Cyrius edition.
- **Integration tests**: real `/bin/echo` fork+exec via PROCESS backend;
  full scanner pipeline validated with synthetic inputs.

### Changed
- **Language**: Rust 2021 → Cyrius 4.0.0+
- **Async → sync**: all exec paths are synchronous in v3.0. See
  [ADR-004 §1](docs/adr/004-deferred-features.md).
- **Build tool**: `cargo` → `cyrius build`
- **Dependency model**: `Cargo.toml` → `cyrius.toml`; binary deps via sigil
- **Test runner**: `cargo test` → `cyrius test tests/kavach.tcyr`
- **Module layout**: nested `src/<module>/mod.rs` → flat `src/<module>.cyr`

### Deferred — see [ADR-004](docs/adr/004-deferred-features.md)
- 8 of 10 backends (Noop + Process shipped; slots reserved for the other 8)
- Seccomp / Landlock / cgroups kernel-level enforcement hooks
- HTTP credential proxy (direct env/file/stdin injection shipped)
- OffenderTracker (per-exec threat classification shipped)
- Sandbox integrity monitoring (`/proc` readers)
- Secret redaction on WARN verdict
- UUID v4 (monotonic counters shipped — audit HMAC covers trust boundary)
- Full PCRE regex (literal-prefix + char-class matchers shipped for all
  distinctive secret/data patterns)

### Removed
- `rust-old/` contains the entire v1.x Rust source (25,935 lines) preserved
  for reference. Will be deleted in v3.0 once port reaches feature parity.
- Cargo workspace, Makefile, `deny.toml`, `rust-toolchain.toml` —
  replaced by `cyrius.toml`.

---

## [2.0.0] — 2026-04-02 (Rust, superseded by 3.0.0 Cyrius port)

### Added
- **Firewall types in agnosys** — `TrafficDirection`, `Protocol`, `FirewallAction` enums, `FirewallRule` and `FirewallPolicy` structs with constructors, `apply_firewall_rules()` function, nftables ruleset rendering
- **`sandbox_core` module enabled** — unblocked by agnosys firewall API; `#[cfg(feature = "agnostik")]` now compiles and links
- **Delegation depth limit** — capability token delegation chains capped at 5 levels to prevent unbounded chains
- **Process substitution detection** — `<(` and `>(` patterns added to code scanner shell metacharacter group
- **`shell_words()` validation** — now returns `Result` and rejects unclosed quotes instead of silently accepting malformed input
- **Namespace check fail-safe** — `is_in_separate_namespace()` returns `true` (assume isolated) when namespace inodes are unreadable, preventing false-negative escape verdicts
- **Exec timeout enforcement** — `child.wait()` now bounded by remaining timeout budget; prevents zombie processes hanging indefinitely after I/O completes
- 5 new tests: unclosed quote rejection, process substitution detection, delegation depth, cascade revocation, namespace fail-safe

### Changed
- **Dependencies updated** — hmac 0.12→0.13, sha2 0.10→0.11, nix 0.29→0.31, seccompiler 0.4→0.5, oci-spec 0.7→0.9, wasmtime 42→43, criterion 0.5→0.8, libc 0.2.183→0.2.184
- **HMAC `KeyInit` import** — adapted `scanning::audit` for hmac 0.13 API change
- **`deny.toml`** — added `GPL-3.0-only` and `CDLA-Permissive-2.0` to license allowlist
- **agnos-common workspace license** — corrected from deprecated `GPL-3.0` to `GPL-3.0-only`
- Dependency count reduced from 513 to 448 crates

### Fixed
- 6 collapsible-if clippy warnings in `v2.rs` and `credential_proxy.rs`
- 2 collapsible-if clippy warnings in `sandbox_core.rs` teardown

### Security
- P(-1) scaffold hardening audit completed — 13 findings across security, correctness, and performance
- 872 tests passing (up from 561 at v1.0.0)

## [1.0.0] — 2026-03-25

### Added
- **TDX backend** (`Backend::Tdx`) — Intel Trust Domain Extensions, 10th backend variant (strength 85)
- **Backend auto-selection** — `Backend::resolve_best()` ranks by strength; `resolve_min_strength()` filters by minimum
- **`SandboxPool`** — pre-warmed sandbox pool with `claim()`/`replenish()` for fast startup
- **`CompositeBackend`** — stack isolation layers with policy merging (stricter-wins, intersected allowlists, +5 scoring bonus)
- **`Backend::FromStr`** — parse backend names case-insensitively, returns `KavachError`
- **`SandboxPolicy::from_preset()`** — parse policy preset by name
- **Code scanner** (`scanning::code`) — 25 pattern groups: command injection, exfiltration, privilege escalation, supply chain, obfuscation, filesystem abuse, crypto misuse
- **Data scanner** (`scanning::data`) — PII (Visa/MC/Amex/IBAN, phone, IPv4) and compliance (HIPAA, GDPR, PCI-DSS, SOC2)
- **Threat classifier** (`scanning::threat`) — intent scoring (0.0-1.0), 7 kill-chain stages, co-occurrence amplification, 4-tier escalation
- **Repeat offender tracker** — rolling window + time decay + per-agent scoring
- **Quarantine storage** (`scanning::quarantine`) — file-based with metadata sidecar, approval/reject workflow
- **Audit chain** (`scanning::audit`) — HMAC-SHA256 append-only log with chain verification and tamper detection
- **Runtime guards** (`scanning::runtime`) — fork bomb detection, 15-path sensitive blocklist, 26-command blocklist, shell metacharacter detection, time anomaly checks
- **Sandbox integrity monitoring** — PID/mount/user namespace isolation verification
- **Entropy-based secret detection** — Shannon entropy > 4.5 on unrecognized high-entropy strings
- **Multi-scanner gate** — ExternalizationGate runs secrets + code + data scanners on every exec
- **HTTP credential proxy** (`credential::http_proxy`) — transparent proxy on 127.0.0.1, Authorization header injection, CONNECT tunneling, host allowlist
- **SEV attestation** — `SevAttestationReport`, `SevAttestationPolicy`, `SevGuestPolicy` with composable bit flags
- **SGX attestation** — `SgxAttestationReport`, `SgxAttestationPolicy`, sealed data API (`SealedData`, `SealKeyPolicy`)
- **Unified attestation** (`backend::attestation`) — `Attestable` trait, `AttestationResult`, EAR conversion for Veraison/IETF RATS
- **Phylax scanner** (SyAgnos) — verity violation + nftables bypass + namespace/mount escape detection
- **Image managers** — `SyAgnosImageManager` and `OciImageManager` for pull/build/list
- **Firecracker** — vsock communication, snapshot/restore, network TAP with iptables isolation
- **Dependencies** — `hmac` v0.12, `sha2` v0.10, `ear` v0.5 (optional), `sigstore` v0.13 (optional)
- **Infrastructure** — `scripts/bench-history.sh`, `make semver`, overhead benchmark, `.cargo/audit.toml`

### Changed
- **Seccomp blocklist** expanded from 14 to 17 entries (added `io_uring_setup`, `io_uring_enter`, `io_uring_register`)
- **Audit chain** upgraded from SipHash to cryptographic HMAC-SHA256
- **`AttestationTrust` ordering** — now `Contraindicated < Warning < None < Affirming` (higher = more trusted)

### Fixed
- Zombie process leak on I/O error path in `execute_with_timeout`
- `eprintln!` in pre_exec replaced with `libc::write(2)` for async-signal-safety
- All `tracing::*` calls removed from post-fork path (namespaces, landlock, capabilities)
- iptables rule ordering — ACCEPT ESTABLISHED before DROP in TAP config
- IP overflow in `TapConfig::for_vm()` for > 60 VMs
- Gate stdout/stderr boundary — newline separator prevents false positives
- SGX seal/unseal — direct tool invocation instead of shell command
- Vsock CONNECT response validation
- Audit chain — `sorted_json` propagates errors instead of swallowing
- HTTP proxy — CRLF sanitization, 8 KiB request line cap, exact/suffix host matching
- Composite network allowlists intersected (not unioned)
- `cgroups.rs` — `.unwrap()` replaced with `.unwrap_or()`

### Performance
- Seccomp BPF cache — 61-71x faster filter retrieval via `LazyLock`
- Capabilities cache — `OnceLock` eliminates 5 `/proc` reads per exec
- UTF-8 zero-copy — `lossy_utf8()` avoids 1 MiB copy for valid output
- Cow redact — `SecretsScanner::redact()` returns `Cow<str>`, zero-copy when clean
- Gate caching — `ExternalizationGate` created once per sandbox
- Policy clone optimization — `LandlockParams` extracts only needed fields; rlimits use raw scalars
- Code scanner patterns pre-lowercased, no per-match allocation
- `resolve_min_strength` scores each backend once via `filter_map`

### Security
- `#[non_exhaustive]` on all 18 public enums and key structs
- `#[must_use]` on ~35 pure functions
- `#[inline]` on ~12 hot-path functions
- `// SAFETY:` comments on all 4 unsafe blocks
- All public items documented (0 `missing_docs` warnings)
- 561 tests across 35 source files

## [0.22.3] — 2026-03-22

### Changed
- Version bump for stiva 0.22.3 ecosystem release

## [0.21.4] — 2026-03-21

### Fixed
- aarch64 Linux build — legacy syscalls mapped to modern equivalents via `#[cfg(target_arch)]`
- cargo-deny license failure — added `MPL-2.0` for `sized-chunks` (wasmtime)
- Release workflow packages platform binaries as `kavach-{version}-{arch}.tar.gz`

## [0.21.3] — 2026-03-21

### Added
- `#[derive(Debug)]` on all backend structs
- `#[must_use]` on `Backend::is_available()` and `Backend::available()`
- 39 tests (error.rs, gVisor, OCI, exec_util)
- Benchmark history log

### Changed
- Extracted `execute_with_timeout()` — eliminated ~250 lines of duplication across 7 backends
- `which_first()` returns `&str` instead of allocating

### Fixed
- OCI backend missing `#[derive(Debug)]` with `--features full`

### Performance
- `secrets_redact` 2.4x faster (single-pass replacement)
- LazyLock regex caching
- `shell_words()` pre-allocates capacity

## [0.21.2] — 2026-03-21

### Added
- Benchmark suite — 23 benchmarks
- Adversarial integration tests — 30 tests

## [0.21.1] — 2026-03-21

### Added
- gVisor and OCI backends
- Health monitoring, sandbox metrics, OCI spec generation, Firecracker config

## [0.21.0] — 2026-03-21

### Added
- Initial release — Backend trait, 7 backends, strength scoring, policy engine, credential proxy, secrets scanner, externalization gate, lifecycle FSM
