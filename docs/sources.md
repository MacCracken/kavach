# Sources

External specifications, algorithms and measured behaviour that kavach's code relies on, with
where each is used. Started at v3.14.2, when kavach began evaluating Intel's attestation
collateral itself; earlier citations live beside the code they justify (`# SAFETY:` notes,
kernel header references in `src/security.cyr`, ADR-005 and ADR-007).

## TEE attestation (`src/attestation.cyr`, `src/attest_collateral.cyr`)

| Source | What kavach takes from it |
|---|---|
| Intel, *SGX ECDSA Quote Library API* (DCAP), quote format v3 | The SGX quote layout. sigil parses it; kavach reads the QE report fields (MISCSELECT +16, ATTRIBUTES +48, MRSIGNER +128, ISVPRODID +256, ISVSVN +258). |
| Intel, *TDX DCAP Quoting Library API*, quote format v4 | The TDX quote layout, including QE report certification data (type 6) around the PCK chain (type 5), which kavach unwraps because sigil 3.13.15 does not (`_attest_tdx_parse`; docs/development/issues/2026-11-02-sigil-tdx-quote-type6-wrapper.md). TD report body offsets: TEE_TCB_SVN +0, MRSIGNERSEAM +64, SEAMATTRIBUTES +112, TD_ATTRIBUTES +120, MRTD +136, RTMR0–3 +328…, REPORTDATA +520. |
| Intel, *Provisioning Certification Service (PCS) API* v4 — TCB Info v3, Enclave Identity v2 | The collateral formats: `tcbLevels` (`sgxtcbcomponents`, `pcesvn`, `tdxtcbcomponents`, `tcbStatus`), `tdxModule` / `tdxModuleIdentities`, the QE identity's masked MISCSELECT and ATTRIBUTES, MRSIGNER, ISVPRODID and ISVSVN levels, `issueDate` / `nextUpdate`, and the signature over the exact bytes of the signed member. |
| Intel, *SGX PCK Certificate and CRL Profile* | The SGX extension, OID 1.2.840.113741.1.13.1: PPID (.1), TCB (.2, components .2.1–.2.16, PCESVN .2.17, CPUSVN .2.18), PCE-ID (.3), FMSPC (.4), SGX Type (.5). The PCK CRL's issuer is the PCK Platform/Processor CA; the root CA CRL's is the root. |
| Intel SGX DCAP Quote Verification Library (QVL), `TcbLevelCheck` / `QuoteVerifier` | The order of the checks and the TCB level match: the first level the platform meets, with TDX components compared from index 2 when TEE_TCB_SVN[1] (the module's major version) is above 0, and the module identity `TDX_<major as two hex digits>`. |
| google/go-tdx-guest, `verify` and `pcs` | The same rules, cross-checked; the QE identity's MISCSELECT and ATTRIBUTES compared bytewise under their masks; the signed member taken as the raw bytes of the JSON value. |
| Intel, *TDX Virtual Firmware Design Guide* §11 (measurement) | What TDVF extends into each RTMR: RTMR0 the TD configuration (TD HOB, ACPI tables, boot variables), RTMR1 the OS loader and kernel, RTMR2 the command line and initrd; RTMR3 the guest's (`policy_attest_rtmr`). |
| RFC 5280 §4.1, §5.1 | Certificate and CRL structure that kavach walks in DER (serial, issuer, subject, extensions; `tbsCertList`, `revokedCertificates`), and the UTCTime century rule (§4.1.2.5.1). |
| Phala-Network/dcap-qvl `sample/` at `9cfb908c4ad81314d773f61f65f3654c1e3e747c` (MIT) | Real SGX and TDX quotes with Intel's collateral, the test data in `tests/data/dcap-qvl/` (provenance and checksums in `tests/data/README.md`). |
| Intel SGX Root CA, `certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer` | The real root for `tests/data/intel/`, SHA-256 `44a0196b…74d3`. |

## Algorithms

| Algorithm | Source | Used in |
|---|---|---|
| Days from a proleptic Gregorian date (`days_from_civil`) | Howard Hinnant, *chrono-Compatible Low-Level Date Algorithms* (howardhinnant.github.io/date_algorithms.html) | `_kc_days`, for the collateral's ISO 8601 dates and the CRLs' X.509 times |
| Aho-Corasick multi-pattern matching | Aho & Corasick, *Efficient string matching: an aid to bibliographic search*, CACM 18(6), 1975 | `src/aho_corasick.cyr` (since v3.4.0) |

## Runtime behaviour (`src/backend_gvisor.cyr`, `src/backend_sy_agnos.cyr`)

| Source | What kavach takes from it |
|---|---|
| gVisor `runsc/cmd/util/util.go` (`Errorf`, `Fatalf`) | runsc's own failures go to stderr and, as a JSON line `{"msg":…,"level":"error"}`, to the `--log` file; `Fatalf` exits 128. |
| gVisor `runsc/cli/cli.go` | `--log` opens the error logger; internal logs go to a discarding emitter unless `--debug-log` or `--alsologtostderr` is set. So a non-empty `--log` file means runsc failed. |
| docker 29.9.2, measured on this machine (CHANGELOG 3.14.2) | `docker run` prints its own errors on the container's stderr and exits 125/126/127; `create` / `start -a -i` / `inspect --format {{.State.Error}}` separate them: a container that never started leaves `.State.Error` set, a payload's own exit 127 leaves it empty. |

## OCI seccomp and capabilities (`src/oci_spec.cyr`)

- **OCI runtime spec**, `linux.seccomp` and `process.capabilities`:
  [config-linux.md](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md),
  [config.md](https://github.com/opencontainers/runtime-spec/blob/main/config.md). `SCMP_CMP_MASKED_EQ` compares
  `arg & value` with `valueTwo`, which is why `_oci_seccomp_json` writes one `clone` rule per namespace flag.
- **runc 1.5.2 with libseccomp 2.6.0**, measured in 3.14.4, not read: a name libseccomp does not know is skipped
  with nothing logged (`open_tree_attr`); a capability the kernel lacks is logged at `level=warning` into `--log`
  and ignored; a spec with no `process.capabilities` drops none.
- **`runc spec` 1.5.2**, run in 3.14.5: `linux.maskedPaths` and `linux.readonlyPaths` are its output, and it lists
  three capabilities. **runc 1.5.2, 1.4.0 and 1.3.4**, measured in 3.14.5 rootless and as root: all three apply
  both lists and skip a path that does not exist, logging nothing. With no `linux.resources.devices`, runc 1.5.2
  as root opened a device node of `c 1 3` and refused `c 1 11`.
- **pivot_root(2)** (man-pages), read for 3.14.6: `chdir(new_root); pivot_root(".", "."); umount2(".", MNT_DETACH)` needs
  no temporary directory, because the call stacks the old root on top of the new one and `.` resolves up that stack. It
  also says the initial ramfs cannot be pivoted, which was read and not run. **runc's `pivotRoot`**
  (`libcontainer/rootfs_linux.go`), read for the same sequence, and for the `chdir("/")` that follows it.
- **capabilities(7)**, read for 3.14.6: at `execve` a process's inheritable set survives for a uid 0 program whatever the
  bounding set holds, which is why the bound clears it. Measured by `test_bound_clears_inheritable_and_ambient`.
- **Docker 29.9.3's default capability set**, measured in 3.14.5: `CapEff` reads `00000000a80425fb`, which is the
  twelve kavach writes plus CAP_NET_RAW and CAP_MKNOD.
- **Linux capability numbers and first versions**: `capabilities(7)`, and `include/uapi/linux/capability.h`, whose
  numbers order `_oci_capability_names`.
- **Linux `fs/proc/proc_sysctl.c` and `net/sysctl_net.c`**, read in 3.14.5 to explain a measurement: `sysctl_perm`
  goes through `test_perm`, which compares against the global root, and `net_ctl_permissions` gives root's bits only
  to a holder of CAP_NET_ADMIN. Measured: a rootless payload's open of a net sysctl to write reads EACCES without that
  capability and EROFS with it.
- **runsc**, read from its source, since no runsc was at hand: `runsc/specutils/seccomp/seccomp.go` (`convertAction`
  has no `SCMP_ACT_KILL_PROCESS`), `runsc/config/flags.go` (`--oci-seccomp`), `runsc/boot/loader.go`
  (`noNewPrivileges`). In 3.14.5, `runsc/specutils/specutils.go`: `Capabilities` returns an empty set for a spec with
  no list, and `capsFromNames` refuses a name it does not know; `MaskedPaths` and `ReadonlyPaths` are only cleared for
  logging, and `runsc/boot` does not read them.
- **wasmtime 50.0.1**: `wasmtime run -W help`, for the option names in `_wasm_append_limits`; each was run.

## A caller's `/proc` and `/sys` in a process-path rootfs (`src/confine.cyr`, 3.14.7)

These are cited as documented and were not re-read for 3.14.7, where no man pages or kernel tree were at hand.
Each behaviour the code depends on was measured, as each entry says.

- **`runc spec` 1.5.2's `linux.maskedPaths` and `linux.readonlyPaths`**, as in 3.14.5, now the table in
  `src/security.cyr`. **runc's `maskPath` and `readonlyPath`** (`libcontainer/rootfs_linux.go`), for the order
  (read-only paths, then masks), the bind of `/dev/null` over a file and an empty read-only tmpfs over a directory, the
  skip of a missing path, and the remount carrying the mount's existing flags.
- **CVE-2025-31133** (runc): a masked path bound from a container's own `/dev/null`, which an
  image can replace with a symlink. Why kavach binds the host's `/dev/null`, after checking that it is a character
  device.
- **mount_namespaces(7)**, "Restrictions on mount namespaces": mounts copied into a namespace owned by a less
  privileged user namespace are locked together, and their flags (`MS_RDONLY`, `MS_NOSUID`, `MS_NODEV`, `MS_NOEXEC`, the
  atime flags) cannot be cleared. Measured in 3.14.7: rootless, a remount without the mount's own nosuid, nodev and
  noexec reads EPERM, a bind of a path holding a locked mount without `MS_REC` reads EINVAL, and a nested user namespace's
  `umount2` of the masks reads EINVAL.
- **statfs(2)**: `f_flags` reports the mount's flags as `ST_*` bits, which share `MS_*`'s values except
  `ST_RELATIME` (4096) for `MS_RELATIME` (`1 << 21`). The 64-bit Linux `struct statfs` puts `f_type` at 0 and
  `f_flags` at 80, on x86-64 and aarch64 alike (`include/uapi/asm-generic/statfs.h`); measured the same on both under
  qemu. `PROC_SUPER_MAGIC` and `SYSFS_MAGIC` from `include/uapi/linux/magic.h`.
- **mount(2)**: a bind's source must be on a mount in the caller's namespace, which is why the guard runs before
  the pivot detaches the old root, and `MS_REMOUNT | MS_BIND` changes one mount's flags, not its superblock's.
- **binfmt_misc** (`Documentation/admin-guide/binfmt-misc.rst`): a handler registered through `register` runs for
  every matching exec on the host, and the `F` flag opens its interpreter at registration, in the registrar's root.
  Measured in 3.14.7: through an rbind of a `/proc` carrying it, a payload opened `register` to write on 3.14.6.
- **ptrace(2)**, "Ptrace access mode checking", for `/proc/<pid>/root`: a caller passes the check for a target
  with the same uid whose permitted capabilities are a subset of its own. Measured in 3.14.7: a sibling sandbox holding
  the same twelve is reachable, the host's init and kavach's own process read EACCES. **landlock(7)**, not measured: a
  sandboxed process cannot ptrace one outside its domain, one way that would close it.


## `/dev`, other processes and the network on the process path, and an OCI spawn (`src/confine.cyr`, `src/security.cyr`, `src/backend_oci.cyr`, 3.14.8)

Cited as documented; no man pages or kernel tree were at hand, so each behaviour the code depends on was measured, as
each entry says. Linux 7.2.14, landlock ABI 10, runc 1.5.2.

- **landlock(7)** and `Documentation/userspace-api/landlock.rst`, "Ptrace restrictions": a process inside a landlock
  domain may ptrace only a process in its own domain or one nested in it. `/proc/<pid>/root`, `cwd` and `environ` take
  that check (`ptrace_may_access`, mode READ_FSCREDS). Measured in 3.14.8: a confined payload reads EACCES opening
  kavach's `/proc/<pid>/root` and `environ`, rootless, and as root a sibling sandbox's root, where 3.14.7 read the file.
- **landlock(7)**, "Scope flags" (ABI v6, Linux 6.12): `LANDLOCK_SCOPE_SIGNAL` lets a process signal only inside its
  domain. Measured: `kill(ppid, 0)` reads EPERM from a confined payload. `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` as in 3.13.2.
- **landlock_create_ruleset(2)**: a ruleset handling no access right is refused (ENOMSG), which is why a domain with
  nothing else to handle handles `LANDLOCK_ACCESS_FS_MAKE_BLOCK` and allows it beneath `/`. Not reached on ABI 10, where
  the signal scope makes every domain: see the CHANGELOG's mutant list.
- **landlock(7)**, "Network flags" (ABI v4, Linux 6.7): `LANDLOCK_ACCESS_NET_BIND_TCP` and `LANDLOCK_ACCESS_NET_CONNECT_TCP`
  in `handled_access_net`, and `LANDLOCK_RULE_NET_PORT` with `struct landlock_net_port_attr { __u64 allowed_access; __u64
  port; }`. Measured: with both handled and no rule, a TCP connect, a bind and a Fast Open `sendto(MSG_FASTOPEN)` read
  EACCES; with a rule for one port, a connect there succeeds and to another reads EACCES. **Not covered, measured:** an
  MPTCP socket (`IPPROTO_MPTCP`, 262) connected to a refused port, and an SCTP connect went out (ECONNREFUSED from no
  listener), with landlock alone. landlock's network rights are TCP's, as the documentation says, and do not reach MPTCP.
- **socket(2)**, **ip(7)**, **udp(7)**: the families (AF_UNIX 1, AF_INET 2, AF_INET6 10, AF_NETLINK 16), `SOCK_STREAM` (1)
  and the type mask (`SOCK_TYPE_MASK`, 0xf, `include/linux/net.h`), and IPPROTO_TCP (6), the values the network filter
  compares, the same on x86-64 and aarch64. **io_uring_setup(2)**: a ring opens sockets (`IORING_OP_SOCKET`, Linux 5.19)
  with no `socket(2)` call for a filter to test; docker's default profile refuses `io_uring_setup` for the same reason.
- **seccomp(2)**: filters stack, every one is evaluated, and the most restrictive action wins, which is what loading the
  network filter beside the exec filter relies on.
- **runc's `setupDev`, `createDevices` and `setupDevSymlinks`** (`libcontainer/rootfs_linux.go`, read as documented):
  a tmpfs over `/dev` (`mode=755,size=65536k`), the default devices bound from the host rootless and created as root (kavach
  binds both), a devpts with `newinstance,ptmxmode=0666,mode=0620,gid=5`, a tmpfs `/dev/shm` (`mode=1777,size=65536k`),
  and the links `fd`, `stdin`, `stdout`, `stderr` and `ptmx`. kavach mounts no `/dev/mqueue`, which needs an IPC namespace.
- **devpts.rst** (`Documentation/filesystems/devpts.rst`): a `newinstance` mount is a private instance, mountable in a user
  namespace. Measured: rootless, in kavach's user namespace, it mounts without `gid=5`, which that namespace does not map.
- **pid_namespaces(7)**: a namespace's init receives only signals it has a handler for, from inside the namespace or an
  ancestor, except SIGKILL and SIGSTOP from an ancestor. Measured: a sleeping payload under `runc run` outlives a forwarded
  SIGTERM, and `spawned_terminate` ends it with SIGKILL after the grace period, exit 137.
- **runc run** (`runc run --help`, and `signals.go`'s handler): in the foreground runc forwards the signals it receives to
  the container's init and exits with its status, and a SIGKILL to runc reaches only runc. Measured with runc 1.5.2,
  rootless and as root: exit 7 comes back as 7, `runc kill <id> KILL` ends the container with 137, and `runc delete --force`
  after runc is reaped leaves no state directory.
- **capabilities(7)**, "Effect of user ID changes on capabilities" and "Capabilities and execution of programs by root":
  only uid 0 takes the bounding set into its permitted set at `execve`; under `no_new_privs` a file's capabilities and a
  set-id bit grant nothing. Why a caller that is not uid 0 and holds no CAP_SETPCAP is bounded without dropping its bounding
  set. Measured as root: a confined payload with no rootfs reads `CapEff 00000000a00405fb`.
