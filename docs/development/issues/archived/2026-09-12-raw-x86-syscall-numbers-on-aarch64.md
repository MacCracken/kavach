# `file_write_secure_modal` and `kv_sleep_ms` pass raw x86 syscall numbers and flags that aarch64 Linux executes as something else — RESOLVED

**Status:** ✅ **RESOLVED in kavach 3.12.6** (cyrius pin 6.6.6). Each fix was checked on aarch64 by
cross-building with `cyrius build --aarch64` and running under `qemu-aarch64 -strace`.

- **Defect 1 (requested mode never applied).** `sys_fchmod(fd, mode)` replaces `syscall(91, …)`.
  Its result is now checked, so a failed chmod fails the write. aarch64 issues `fchmod(3,0644) = 0`,
  and the file lands at 0644 (it stayed 0600 before). agnos has no fchmod — 91 there is
  `gpu_blit_bb` — so no chmod is issued on that target.
- **Defect 2 (`O_NOFOLLOW` dropped).** `kv_o_nofollow()` returns the stdlib's per-arch `O_NOFOLLOW`
  on Linux, and `131072` on agnos, where the `file_open` bridge maps it to `AO_NOFOLLOW`. The x86
  literal was at **four** sites, not only the one filed here: both secure writes in `src/util.cyr`,
  and both OCI scratch-file opens in `src/backend_oci.cyr`. At `_oci_take_file` the flag is the only
  guard (there is no `O_EXCL`). Under the old build, aarch64 read a planted symlink's target through
  the link; it now gets `ELOOP`.
- **Defect 3 (no sleep).** Fixed by the pin, with no kavach change: cyrius 6.6.5 translates raw x86
  `35` to aarch64 `nanosleep`.
- **Tests.** `credential_inject_files` now asserts the resulting mode, and
  `oci_take_file_refuses_a_symlink` is new. Each fails against a mutant of its fix.

Originally filed from the cyrius 6.6.2 ecosystem-sweep close-out (2026-09-12), kavach 3.12.5 at
cyrius pin 6.6.2. Every behaviour below was traced under `qemu-aarch64 -strace` with a cyrius 6.6.3
aarch64 build.

**Severity:** Medium. Nothing here is exploitable at the final path component, and every wrong syscall fails
rather than corrupting anything. But two of the three defects sit in the **credential-write path**
(requested permissions silently never applied; `O_NOFOLLOW` silently dropped), and the third turns
`confine_capture`'s idle sleep back into a full-core busy loop on aarch64.

## What happens on aarch64 Linux

All three are raw x86_64 values in arch-neutral code. cyrius renumbers x86 **syscall numbers** for aarch64
through its ESYSXLAT table, but has no entry for 35 or 91, and it never translates **open flag values**.

### 1. `file_write_secure_modal` never applies the requested mode — `src/util.cyr:359`

```cyrius
syscall(91, fd, mode, 0);          # x86_64 fchmod
```

aarch64 runs syscall 91, which is `capset`:

```
capset((nil),(nil)) = -1 errno=14 (Bad address)
```

The return value is ignored, so the write reports success with the file still at `sys_open`'s create mode
(`384` = 0600, before umask). The only caller is `credential_inject_files` (`src/credential.cyr:146`), so on
aarch64 **every credential file injection ignores `FileInjection_mode`**. The file ends up 0600 no matter
what the caller asked for.

### 2. `file_write_secure_modal` drops `O_NOFOLLOW` — `src/util.cyr:350`

```cyrius
var flags = 1 + 64 + 512 + 128 + 131072;   # O_WRONLY|O_CREAT|O_TRUNC|O_EXCL|O_NOFOLLOW (x86_64 values)
```

131072 (`0x20000`) is `O_NOFOLLOW` on x86_64, but on aarch64 it is `O_LARGEFILE` (aarch64 `O_NOFOLLOW` is
`0x8000`):

```
openat(AT_FDCWD,"<path>",O_WRONLY|O_CREAT|O_EXCL|O_LARGEFILE|O_TRUNC,0600) = 3
```

**Not exploitable at the final component:** `O_CREAT|O_EXCL` already refuses a symlink there with `EEXIST`.
What is lost is the defence-in-depth the flag was written to provide.

### 3. `kv_sleep_ms` does not sleep — `src/util.cyr:521`

```cyrius
return syscall(35, &ts, 0);        # x86_64 nanosleep (inside #ifndef CYRIUS_TARGET_AGNOS)
```

aarch64 runs syscall 35, which is `unlinkat`:

```
unlinkat(-14728480,NULL,0) = -1 errno=14 (Bad address)
```

It returns immediately. The caller is the drain loop in `confine_capture_input_env_wd`
(`src/confine.cyr:637-638`), which 3.11.4 gave an idle sleep because without one it "burns a full core for as
long as the payload runs" (agnosai measured 100% CPU). **On aarch64 that fix is void and the spin is back.**
`unlinkat` is also a delete-class syscall; it fails here only because the path argument happens to be NULL.

## Reproduction

```sh
# in a cyrius checkout: an x86-hosted compiler that emits aarch64
cat src/main_aarch64.cyr | ./build/cycc > /tmp/cc_a64 && chmod +x /tmp/cc_a64
/tmp/cc_a64 < probe.cyr > probe && chmod +x probe
qemu-aarch64 -strace ./probe 2>&1 | grep -vE 'brk|mmap|rt_sig|prlimit|set_tid'
```

`probe.cyr` is `include "lib/syscalls.cyr"` plus the exact call under test, e.g.
`var ts[16]; store64(&ts, 0); store64(&ts + 8, 0); var r = syscall(35, &ts, 0);`. Run the `open` / `fchmod`
probes against a scratch file, never a real path.

## Proposed fix

1. **Mode → `sys_fchmod(fd, mode)`, and check its return.** The util.cyr comment says raw 91 was needed
   because the stdlib had no `sys_fchmod` "at cc 5.10.34". It has one now: `lib/syscalls_linux_common.cyr`,
   backed by a per-target `SYS_FCHMOD` (x86_64 91, aarch64 52). **Verified on aarch64:** traced
   `fchmod(3,0600) = 0`, and the file's mode changed from 644 to 600. A failed chmod on a credential file
   should fail the write rather than be ignored.
2. **`O_NOFOLLOW` → a per-target value.** The cyrius stdlib defines no `O_NOFOLLOW` constant today, which is
   why this is a literal (patra hardcodes the same x86 value). Until cyrius ships one, select it per arch
   (`CYRIUS_ARCH_AARCH64` → `0x8000`).
3. **Sleep → poll-as-sleep.** There is no `sys_nanosleep` or `SYS_NANOSLEEP` in the stdlib.
   `syscall(7, 0, 0, ms)` (x86 `poll` with no fds) *is* translated on aarch64 — traced as `ppoll` — and is what
   yantra already uses (`lib/yantra.cyr:107`).
4. Add a test that runs on real aarch64 hardware. These all compile cleanly; only execution shows the defect.

## Scope and consumers

- **Untested:** macOS / Mach-O (BSD numbering differs) and Windows. `sys_fchmod` is Linux-only, so a macOS
  build still needs its own answer for (1).
- **Vendored by** aethersafha, agnosai, agnostic, mehman and stiva (`lib/kavach.cyr`). Fix it here and
  re-vendor; patching the vendored copies evaporates on the next `cyrius deps`.

## Related

- cyrius `docs/development/issues/2026-09-12-raw-x86-syscall-numbers-fdlopen-dynlib-aarch64.md` — the same
  class inside the cyrius stdlib (`fdlopen` / `dynlib`), with the full trace of which raw numbers aarch64
  translates.
