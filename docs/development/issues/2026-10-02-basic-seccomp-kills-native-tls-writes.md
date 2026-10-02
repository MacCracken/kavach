# 2026-10-02 — the `basic` seccomp profile kills a sandboxed native-TLS writer: cyrius 6.6.14 writes sockets with `sendto`

**Status:** 🟡 **OPEN** — filed from cyrius **6.6.14** (the TLS follow-ups; CVE-66).
**Checked against:** kavach **3.13.1** — `src/security.cyr` (`_seccomp_allow_list` ~544, `security_create_basic_seccomp_filter`
~743, miss action `SECCOMP_RET_KILL_PROCESS`), `src/policy.cyr` (`policy_basic` :46).
**Severity:** a crash (SIGSYS) of a sandboxed process that does TLS over a socket it inherited. Read from the
source, not traced.

## What changed in cyrius

cyrius 6.6.14 fixed CVE-66: a TLS write to a peer that had reset the connection raised SIGPIPE and killed the
process. The native TLS default transport now writes a socket with `send(fd, buf, n, MSG_NOSIGNAL)` —
**`sendto(2)`, 44 on x86_64, 206 on aarch64** — instead of `write(2)` (`write` remains only for an fd that is
not a socket). On macOS each connection adds one `setsockopt(SO_NOSIGPIPE)` (no seccomp there).

Since cyrius 6.6.13, a native TLS read or write under a caller deadline (`tls_set_deadline` /
`tls_native_set_deadline`) also uses `fcntl(F_GETFL/F_SETFL, O_NONBLOCK)` and `poll` (7 on x86_64; `ppoll` 73 on
aarch64).

## What happens in kavach

The `basic` profile is an ALLOWLIST of ~20 syscalls (read, write, close, fstat, mmap, mprotect, munmap, brk,
rt_sigreturn, exit, sigaltstack, arch_prctl, gettid, futex, set_tid_address, exit_group, set_robust_list,
getrandom, clock_gettime, rseq) and kills the process on a miss. It has no `sendto`, `poll`/`ppoll` or `fcntl`.
So a process under `basic` that runs native TLS over an inherited socket:

- from cyrius 6.6.14 is killed (SIGSYS) on its first TLS record write;
- from cyrius 6.6.13 was already killed whenever it set a TLS deadline.

The profile has no `socket`/`connect`/`openat`, so only an inherited fd can reach this — a narrow case, but a
silent process kill when it happens.

## The decision (kavach's)

- **Allow it, constrained:** add `sendto` with the destination pinned to none (seccomp arg checks:
  `dest_addr == NULL`, `addrlen == 0` — on a connected socket that is exactly `write`, so the sandbox gains no
  new reach), and, if deadlines are in scope, `poll`/`ppoll` and `fcntl` restricted to `F_GETFL`/`F_SETFL`.
- **Or declare it out of scope:** document that `basic` is a compute-only profile and that TLS (cyrius ≥ 6.6.14)
  or any deadline-bounded socket I/O needs `strict` or a custom profile — and say so where `basic` is chosen
  (`scoring.cyr` picks `basic` for scores < 50).

## Acceptance

- Whichever is chosen, a test that runs a cyrius ≥ 6.6.14 native TLS client under `basic` over an inherited
  socketpair: it either completes a record write (allowed) or the documentation names the profile it needs
  (declared out of scope), and the choice is pinned so a future cyrius transport change is caught here.
