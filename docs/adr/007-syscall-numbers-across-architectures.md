# ADR-007 — Syscall numbers across architectures

**Status**: Accepted
**Date**: 2026-09-25
**Version**: v3.12.8

## Context

cyrius spells syscall numbers in x86-64 terms. Its aarch64 backend renumbers the ones it knows at
every `syscall()` site, through a sequential chain of translation rows (`ESYSXLAT`,
`src/backend/aarch64/emit.cyr`). A number with no row goes to `svc` unchanged, so it is not an
error on aarch64. It is a different, valid syscall. That split puts kavach's numbers in two places
that behave differently:

- **A number at a `syscall()` site is renumbered, or not.** Through 3.12.7, kavach issued x86-64
  `unshare` (272) and `chroot` (161), which have no row. Under `qemu-aarch64 -strace`, 272 runs
  `kcmp` and 161 runs `sethostname`, with the rootfs path as the name.
- **A number inside a seccomp filter is data.** The kernel compares it with `seccomp_data.nr`, in
  the numbering of the ABI that made the call, and nothing renumbers it. kavach's filters held
  x86-64 numbers and never read `seccomp_data.arch`.

Measured on x86-64 against the 3.12.7 exec filter, built from the tag on a kernel with IA32
emulation and x32 enabled:

- a native `umount2` was killed;
- the same `umount2`, entered through the i386 gate (`int 0x80`, i386 number 52, which x86-64 reads
  as `getpeername`), ran and returned `ENOENT`;
- an x32 `getpid` ran, and so did an i386 `getpid`.

On aarch64, where the filter compared the same x86-64 numbers, it killed `nanosleep` (x86-64
`ptrace` is 101) and let the real `ptrace` (117), `mount` (40) and `unshare` (97) through. That
part is read from the tables, not run: qemu-user refuses to load seccomp filters.

`seccomp(2)` warns about exactly this: syscall numbers differ between ABIs, one process can use
more than one, so a filter must check `arch`.

## Decision

### 1. A filter admits one ABI: the one kavach was built for

Every filter starts with the same check:

```
0  LD   seccomp_data.arch
1  JEQ  <AUDIT_ARCH of this build>, skip 1
2  RET  KILL_PROCESS
3  LD   seccomp_data.nr
4  JGE  X32_SYSCALL_BIT -> KILL          (x86-64 only)
```

Rejected alternatives:

- **A table per ABI**, dispatching on `arch` the way libseccomp can. kavach would keep three x86
  tables correct (x86-64, i386, x32) for payloads no consumer runs.
- **`ERRNO` for a foreign ABI instead of `KILL`.** The rest of the filter kills, and a payload
  reaching for the i386 gate is not a case to keep alive.

`systemd.exec(5)` recommends the same restriction (`SystemCallArchitectures=native`) "so that
secondary ABIs may not be used to circumvent the restrictions applied to the native ABI".

### 2. Filter tables hold native numbers, one column per architecture

Each row gives both numbers side by side (`_seccomp_push(v, x86_64, aarch64)`), from
`asm/unistd_64.h` and `asm-generic/unistd.h`, with -1 where an architecture has no such call. The
stdlib's `SYS_*` names are deliberately not used here. The aarch64 peer spells some calls with x86
numbers that are renumbered only at a `syscall()` site, and filter data never passes through one.
The tests restate the pairs instead of reading the tables, so a wrong entry cannot agree with
itself.

### 3. At a `syscall()` site: a stdlib name, an x86-only declaration, or a refusal

1. **The stdlib's `sys_*` / `SYS_*`**, which carries each architecture's number. 3.12.8 moved the
   netlink socket calls and `kv_sleep_ms` onto them.
2. **Where the stdlib has no name** (`unshare`, `chroot` at cyrius 6.6.6): kavach declares the
   x86-64 number under `#ifdef CYRIUS_ARCH_X86` only, so an aarch64 use does not compile. The
   aarch64 path refuses (fails closed) until the stdlib names the call. Requested upstream in
   `cyrius/docs/development/issues/2026-09-25-kavach-unshare-chroot-unnamed-aarch64-chroot-unreachable.md`.
3. **Never the aarch64-native number under an aarch64 `#ifdef`.** This is rule 3 of the cyrius
   guide. The chain matches numbers, not intent, so a row added later takes the call over. Both
   halves were measured in 3.12.8:
   - aarch64 `chroot` (51) is already unreachable, because the getsockname row turns 51 into 204;
   - takumi's native `ppoll` (73) runs as `flock` since cyrius 6.6.4 added a `73→32` row.

**Inline-asm `svc` was also considered.** The stdlib's `thread.cyr` issues `clone` that way, and it
bypasses the chain. But it needs hand-encoded instructions and a frame slot for the result. A slip
there reports a failed `unshare` as success (fail open), on a platform kavach does not yet claim.
The upstream name is the smaller and safer fix.

### Enforcement

CI (3.12.8) enforces this in two places:

- **The aarch64 job**: an aarch64 cross-build, an agnos build, and the test suite under
  qemu-aarch64. An informational native `ubuntu-24.04-arm` job runs the same binary on hardware.
- **The security scan**: it fails on any `syscall(<digit>` in `src/`, and on a `SYS_*` number
  declared outside `src/sys_security_syscalls.cyr` and `src/kernel_audit.cyr`.

## Consequences

**Positive**

- A kavach filter no longer has a second door. The i386 gate and x32 calls die at the arch check
  on x86-64, and AArch32 calls die the same way on aarch64.
- On aarch64 the filters deny what they name.
- An x86-only number used on aarch64 is now a build failure, not a different syscall at run time.

**Negative**

- A 32-bit payload (i386 on x86-64, AArch32 on aarch64) is killed at its first syscall under any
  kavach filter. Running one needs a policy with `seccomp_enabled = 0`.
- aarch64 has no namespaces and no rootfs entry until the stdlib names `unshare` and `chroot`.
  `security_create_namespace` returns not-supported there, and `_spawn_enter_rootfs` returns -1.
  A confined child that needs either exits 123, as it already did through 3.12.7 when `kcmp`
  failed. The difference is that the refusal is now deliberate and named.
  With those two exceptions, aarch64 is recorded as supported from 3.13.0. The evidence is the
  `aarch64 (native)` CI job on GitHub's arm64 runner, blocking since 3.12.9: 853 of 853 with
  seccomp loaded on the 3.12.9 run (docs/architecture/overview.md, Platforms).

**Neutral**

- The x86-64 filter grows from 23 to 27 instructions (25 on aarch64). That is four more BPF
  instructions on each syscall of a confined child on x86-64 (three on aarch64), and no
  measurable change in `process_exec_confined` (CHANGELOG 3.12.8).

## References

- `seccomp(2)`: the `SECCOMP_SET_MODE_FILTER` caveat on checking `arch`.
- `linux/seccomp.h`: `struct seccomp_data` (`nr` at +0, `arch` at +4).
- `linux/audit.h`: `AUDIT_ARCH_X86_64` = `0xC000003E`, `AUDIT_ARCH_AARCH64` = `0xC00000B7`.
- `asm/unistd.h` (x86-64): `__X32_SYSCALL_BIT` = `0x40000000`.
- `systemd.exec(5)`: `SystemCallArchitectures=`.
- The cyrius guide, "A raw syscall number is the single most portable-looking thing that is not
  portable", rules 1–3.
