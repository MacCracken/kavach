# 2026-11-07 — a policy denying network is enforced only with a namespace, which most hosts refuse — RESOLVED (3.14.8)

**Discovered:** 2026-11-07, by agnosai, confining its process and Python tool tiers with `confine_child_caps`
(agnosai ADR 031).
**Severity:** Low as a defect, as kavach claims nothing it does not apply: `score_backend` has given the process
backend no network credit since 3.14.7. It is a missing capability, and its absence decides what a consumer can offer.
**Affects:** kavach 3.14.7: `_spawn_ns_flags` (`network_enabled = 0` becomes `NS_NETWORK`, plus `NS_USER`
unprivileged), and `security_apply_landlock_scoped`, which writes `handled_access_net` as 0 (`src/security.cyr`, the
`attr` block).
**Status:** ✅ **RESOLVED in kavach 3.14.8**: both halves, the TCP rule and UDP, and the port list. See the resolution at
the end.

## What happens

A policy with `network_enabled = 0` is enforced by a network namespace, and only that. Unprivileged, a network namespace
needs a new user namespace, and these hosts refuse one:

- Ubuntu 24.04 and later (`kernel.apparmor_restrict_unprivileged_userns = 1`).
- docker's default seccomp profile, which refuses `unshare` without CAP_SYS_ADMIN.
- GitHub's Ubuntu runners, which ship the same AppArmor restriction.

So a consumer chooses between failing closed, which stops every confined run on those hosts, and not isolating the
network at all. agnosai's cx tier fails closed (`persistent_spawn_confined_ns`, require_ns = 1) and does not run on
them. Its process and Python tiers, which carry every Python tool, cannot afford that, so on 2.3.4 they keep the server's
network.

## Proposed fix

**Landlock ABI 4 (Linux 6.7) restricts TCP with no namespace and no privilege.** A ruleset whose `handled_access_net`
holds `LANDLOCK_ACCESS_NET_BIND_TCP` (1) and `LANDLOCK_ACCESS_NET_CONNECT_TCP` (2), with no `LANDLOCK_RULE_NET_PORT`
rule, refuses every TCP bind and connect from the payload with EACCES. It applies in a container and on a host that
refuses user namespaces, as landlock does.

- In `security_apply_landlock_scoped`, when the policy has `network_enabled = 0` and the ABI is 4 or more, set
  `handled_access_net` to both rights, and pass the 16-byte `attr` (the 24-byte one with a scope).
- Allowed ports could follow as `LANDLOCK_RULE_NET_PORT` rules, if a consumer wants "only 443".
- Below ABI 4, nothing changes.

**What it does not cover.** UDP, raw sockets and unix sockets are not landlock network rights, so a payload could still
send a DNS query or reach a local daemon's socket. A seccomp rule on `socket(2)`'s domain argument (refuse `AF_INET` and
`AF_INET6` for `SOCK_DGRAM` and `SOCK_RAW`) closes UDP, and kavach's filter already tests arguments for `clone`. That
half is a second ask, and the TCP half is worth having on its own.

Scoring could then give the process backend its network credit back where the ABI allows it.

## What agnosai does meanwhile

Nothing to work around: its tiers keep the network, its threat model says so, and kavach's score already agrees.
agnosai's confinement sets `network_enabled = 1` on the policy it builds, saying what it applies, so a kavach that
enforces this changes nothing for agnosai until agnosai asks. Its half, when this lands: set `network_enabled` from its
own policy (its process policy denies network, and its Python sandbox would take a setting), and say so in its CHANGELOG
as the behaviour change it is.

## Resolution (3.14.8)

**As proposed, for the TCP half, and the second ask with it.** Every confined process-path payload denied network
(`network_enabled = 0`), with no network namespace of its own and on a kernel with landlock ABI v4, gets two things,
both or neither (`_spawn_net_alone`):

- **Landlock's TCP rights** in its domain (`security_apply_landlock_domain`): `handled_access_net` holds BIND_TCP and
  CONNECT_TCP, and the 16-byte `attr` (24 with a scope) is passed. Every TCP bind and connect reads EACCES.
- **A network filter** of its own (`security_net_seccomp_filter`), loaded beside any other: `socket(2)` is allowed for
  AF_UNIX and AF_NETLINK, and for AF_INET and AF_INET6 only as a TCP stream (protocol 0 or IPPROTO_TCP), and reads EACCES
  for anything else; `io_uring_setup` reads ENOSYS. It is loaded whether or not the policy enables seccomp: measured with
  landlock holding TCP on 7.2.14 (ABI 10), **an MPTCP socket connected to a refused port and an SCTP connect went out**, so
  landlock's TCP rights are plain TCP's and the rest needs the filter.

**Allowed ports, as "could follow": `policy_network_allow_tcp(p, port, access)`**, `KAVACH_TCP_BIND` and
`KAVACH_TCP_CONNECT`, as NET_PORT rules. This is also the roadmap's unpinned "Landlock TCP port rules" item: the two
counts the policy carried now follow lists. A policy naming a port gets no network namespace, which would leave nothing
to reach, and a port list is a request for confinement on its own (`policy_wants_confinement`). Merged, a port is allowed
where both sides allow it, as the network is. UDP stays refused, so a name to resolve needs DNS over TCP or an address.

Measured from inside the payload on Linux 7.2.14, rootless, no rootfs, no namespace, through `sandbox_exec`, under
`policy_basic()` and `policy_strict()` alike. The 3.14.7 column is a driver built from 3.14.7's `src/` running the same
payload:

| Payload with `network_enabled = 0` | 3.14.7 | 3.14.8 |
|---|---|---|
| TCP connect to a listener, TCP bind, TCP Fast Open (`sendto` with MSG_FASTOPEN) | **connect**, each | EACCES, each |
| MPTCP connect to a listener | **connects** | EACCES |
| SCTP connect | **goes out** (ECONNREFUSED: no SCTP listener) | EACCES |
| UDP and UDP over IPv6 socket | **open** | EACCES |
| raw and packet socket | EPERM: no CAP_NET_RAW, rootless | EACCES, before the capability is asked |
| `io_uring_setup` | **a ring** | ENOSYS |
| AF_UNIX, AF_NETLINK, a TCP socket before its connect | open | open |
| with `policy_network_allow_tcp(p, P, KAVACH_TCP_CONNECT)`: connect to P / to another port | no such call | connects / EACCES |

`policy_new()`, and any policy with `network_enabled = 1`, read the 3.14.7 column on both builds.

**Which payloads.** The issue's proposal reads the policy, and so does the fix: a confined payload denied network has it
denied. `policy_new()` asks for no confinement, and its payload still runs unconfined with the network, as through 3.14.7,
which the maintainer's choice for the issue's Ask 3 kept. `policy_basic()` and `policy_strict()` set `network_enabled = 0`
and confine, so their payloads with no rootfs lose the network on a kernel with ABI v4: the CHANGELOG lists it under
behaviour changes. agnosai sets `network_enabled = 1` and is unaffected. A payload in its own network namespace (a rootfs,
`config_require_namespaces`) keeps the namespace as its isolation and gets neither. Below ABI v4 nothing changes, and
nothing is scored.

**Scoring, as "could then give the network credit back".** `score_config` gives the process backend 5 for `network_enabled =
0` where the path applies it: a namespace, or landlock and the filter on a confined payload with ABI v4. A port list scores 3
there instead, where 3.13.1 gave 3 to bare counts nothing applied.

Tests: `test_network_denied_without_a_namespace`, rootless and in CI's root job, and `test_network_port_rules`.

**agnosai's half**, as the issue says: set `network_enabled` from its own policy, and say so in its CHANGELOG. Its process
and Python tiers call `confine_child_caps`, which now denies the network as above where the policy does.
