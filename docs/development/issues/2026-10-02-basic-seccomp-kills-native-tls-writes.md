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

## Update 2026-10-05 — from cyrius 6.6.16 a PLAIN-socket writer is killed too (recorded by cyrius)

⛔ This concerns a cyrius 6.6.16 lib change. Nothing reaches kavach until a process is built against cyrius
≥ 6.6.16 (not yet tagged at this writing); kavach is not a gate on that release.

**What changed in cyrius.** 6.6.16 (cyrius CVE-74) stops a reset peer from killing a PLAIN-socket writer with
SIGPIPE: every `lib/net.cyr` socket write (`sock_send`, `sock_send_all`, `sock_send_a` — and so `lib/http.cyr`,
`lib/ws.cyr`, `lib/ws_server.cyr`, yantra and sandhi's client paths) and the async `async_send` /
`async_relay_once` writers now issue `sendto(fd, buf, n, MSG_NOSIGNAL, NULL, 0)` on Linux (44 x86_64 / 206
aarch64) instead of `write(2)`. `write(2)` remains only for an fd that is not a socket. So the trigger is no
longer only native TLS (6.6.14) or a TLS deadline (6.6.13): from 6.6.16 a process that loads `basic` on itself
dies of SIGSYS on its first `sock_send_all`.

**Measured** 2026-10-04 with the cyrius 6.6.16 lane tree (x86_64; a forked child holding an inherited AF_UNIX
socketpair, filter loaded with `PR_SET_NO_NEW_PRIVS` + `PR_SET_SECCOMP`):

| child does | 3.13.2 basic, cyrius 6.6.15 lib | 3.13.2 basic, cyrius 6.6.16 lib | proposed basic (below), 6.6.16 lib |
|---|---|---|---|
| `sock_send_all(fd, "abc", 3)` | lives (write) | **SIGSYS (sig 31)** | lives |
| native TLS 1.3 client: handshake + 40000-byte echo + close, under a deadline | SIGSYS (since 6.6.14) | SIGSYS | lives, echo byte-exact |
| `sendto` WITH a destination (`sockaddr_in`, 16) | SIGSYS | SIGSYS | SIGSYS (still refused) |
| `fcntl(fd, F_DUPFD, 10)` | SIGSYS | SIGSYS | SIGSYS (still refused) |

The probe is checked in as `repros/2026-10-05-basic-seccomp-sendto-probe.cyr` (built against the cyrius tree's
`lib/`; `argv[1]` mode 0 = 3.13.2's filter layout byte for byte, 1 = the proposal; `argv[2]` probe 0..3 =
TLS / `sock_send_all` / sendto-with-dest / `F_DUPFD`).

**Reach — a correction to this issue's framing.** The `basic` POLICY never selects this filter: every spawn path
loads `security_create_exec_seccomp_filter` (the deny-list, which allows `sendto` / `poll` / `fcntl`) —
`src/spawn.cyr:121`, `src/backend_process.cyr:113`, `src/persistent.cyr:89`, `src/confine.cyr:480`,
`src/backend_wasm.cyr:185` — and the policy's `seccomp_profile` string is never read to pick a filter. So
sandboxed spawns are NOT affected. The kill reaches direct callers of the public
`security_create_basic_seccomp_filter()` + `security_load_seccomp` (self-confinement); a `grep -rl` over
`~/Repos/*/src`, programs and tests found none outside kavach, and the vendored `lib/kavach.cyr` copies
(aethersafha, agnosai, agnostic, mehman) do not call it either. (Whether `seccomp_profile` *should* select the
filter is a separate question for kavach.)

### SUGGESTION — an argument-pinned allowlist (measured; the design is kavach's call)

Keep the miss action `SECCOMP_RET_KILL_PROCESS`; admit only the write-equivalent shapes, pinned on their
arguments:

1. `enum BpfConst` (`src/security.cyr:336`): `SECCOMP_DATA_ARG1_LO = 24`, `SECCOMP_DATA_ARG4_LO = 48`,
   `SECCOMP_DATA_ARG4_HI = 52`, `SECCOMP_DATA_ARG5_LO = 56` (`struct seccomp_data.args[6]` at +16, 8 bytes each,
   little-endian on x86_64 and aarch64); `F_GETFL = 3`, `F_SETFL = 4`.
2. `_seccomp_allow_list` (`:544`): `_seccomp_push(v, 7, 0 - 1)` (poll, x86_64 only) and
   `_seccomp_push(v, 271, 73)` (ppoll) — unconditional: poll only reads and writes the caller's own pollfd array.
3. A basic builder (or a `_seccomp_build` variant taking a tail writer) that after the plain JEQs emits:
   - `c0: JEQ sendto(44 / 206) -> s0, else c1`
   - `c1: JEQ fcntl(72 / 25) -> f0, else KILL`
   - `s0: LD arg4.lo; JEQ 0 -> next, else KILL` / `LD arg4.hi; JEQ 0 -> next, else KILL` (a NULL `dest_addr`
     must be checked on BOTH halves) / `LD arg5.lo; JEQ 0 -> ALLOW, else KILL` (`addrlen` is an int)
   - `f0: LD arg1.lo; JEQ 3 -> ALLOW; JEQ 4 -> ALLOW, else KILL` (the cmd is an unsigned int)
   - then `RET KILL; RET ALLOW`.

   11 conditional instructions; totals x86_64 5 + 22 + 11 + 2 = **40**, aarch64 4 + 20 + 11 + 2 = **37**; every
   jt / jf well under 255; the prologue's x32 `JGE` must target the new KILL index. Pinning `sendto` to a NULL
   destination makes it exactly `write(2)` on a connected socket and also closes `MSG_FASTOPEN` (needs an
   address) and unconnected-datagram sends; `sendto`'s flags stay unconstrained (`MSG_NOSIGNAL`,
   `MSG_DONTWAIT`, `MSG_OOB` give no new reach).
4. Tests: `test_basic_seccomp_filter_shape` (`tests/kavach.tcyr:3788`) pinned to 40 / 37 and every jump target;
   a live row per shape (sendto NULL dest == 3 and alive; sendto with `&sockaddr, 16` SIGSYS; `F_GETFL` /
   `F_SETFL | O_NONBLOCK` ok; `F_DUPFD` SIGSYS; poll / ppoll for POLLOUT; **`sock_send_all(sv, "abc", 3) == 3`**
   — the row that pins the cyrius 6.6.16 transport); and this issue's own acceptance (a native TLS client under
   `basic` over an inherited socketpair completing a record write).
5. CI needs no new job (x86_64 ubuntu-latest and aarch64-native ubuntu-24.04-arm load filters; qemu takes the
   fail-closed skip). The `sock_send_all` row passes at kavach's current cyrius pin (write) and at ≥ 6.6.16
   (sendto), so it needs no pin bump to land.

The "declare it out of scope" option above stays open; if chosen, the documentation should now say that any
socket write through the cyrius stdlib (not only TLS) needs a profile other than `basic` from cyrius 6.6.16.
