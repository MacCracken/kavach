//! Seccomp-BPF filter construction and application.
//!
//! Builds BPF programs from named profiles using the `seccompiler` crate.
//! Filters are pre-compiled before spawn and applied in `pre_exec`.

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use libc;
#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

/// Allowed syscalls — 87 entries matching SecureYeoman's baseline.
/// Used for reference and validation. The actual filter uses a denylist approach.
pub const ALLOWED_SYSCALLS_BASIC: &[&str] = &[
    "read",
    "write",
    "open",
    "close",
    "stat",
    "fstat",
    "lstat",
    "poll",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "ioctl",
    "access",
    "pipe",
    "select",
    "sched_yield",
    "mremap",
    "msync",
    "mincore",
    "madvise",
    "dup",
    "dup2",
    "pause",
    "nanosleep",
    "getpid",
    "sendfile",
    "socket",
    "connect",
    "accept",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    "clone",
    "fork",
    "vfork",
    "execve",
    "exit",
    "wait4",
    "uname",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    "getdents",
    "getcwd",
    "chdir",
    "rename",
    "mkdir",
    "rmdir",
    "link",
    "unlink",
    "symlink",
    "readlink",
    "chmod",
    "chown",
    "umask",
    "gettimeofday",
    "getrlimit",
    "getrusage",
    "sysinfo",
    "times",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "getppid",
    "getpgrp",
    "setsid",
    "setpgid",
    "sigaltstack",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "clock_gettime",
    "clock_nanosleep",
    "exit_group",
    "epoll_create",
    "epoll_ctl",
    "epoll_wait",
    "futex",
    "set_tid_address",
];

/// Blocked syscalls — 17 entries.
///
/// Includes io_uring syscalls which can bypass seccomp-bpf filters
/// (io_uring operations are not subject to seccomp checks).
pub const BLOCKED_SYSCALLS: &[&str] = &[
    "ptrace",
    "mount",
    "umount2",
    "reboot",
    "kexec_load",
    "init_module",
    "delete_module",
    "pivot_root",
    "swapon",
    "swapoff",
    "acct",
    "settimeofday",
    "sethostname",
    "setdomainname",
    // io_uring — blocks seccomp bypass via async I/O
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];

/// Strict profile — minimal set for non-interactive commands.
pub const ALLOWED_SYSCALLS_STRICT: &[&str] = &[
    "read",
    "write",
    "open",
    "close",
    "stat",
    "fstat",
    "lstat",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "access",
    "pipe",
    "dup",
    "dup2",
    "nanosleep",
    "getpid",
    "execve",
    "exit",
    "wait4",
    "uname",
    "fcntl",
    "fsync",
    "getdents",
    "getcwd",
    "chdir",
    "readlink",
    "umask",
    "gettimeofday",
    "getrlimit",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "getppid",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "clock_gettime",
    "exit_group",
    "futex",
    "set_tid_address",
];

/// Resolve a profile name to a syscall allowlist.
#[must_use]
pub fn resolve_profile(name: &str) -> &'static [&'static str] {
    match name {
        "strict" => ALLOWED_SYSCALLS_STRICT,
        _ => ALLOWED_SYSCALLS_BASIC,
    }
}

/// Check if a syscall name is in the basic allowlist.
#[inline]
#[must_use]
pub fn is_syscall_allowed(name: &str) -> bool {
    ALLOWED_SYSCALLS_BASIC.contains(&name)
}

/// Map a syscall name to its number on this architecture.
/// Returns None if the name is not recognized or not available on the current arch.
///
/// On aarch64, many legacy syscalls (open, stat, etc.) do not exist.
/// We map those names to their modern equivalents (openat, newfstatat, etc.)
/// so that profile definitions work consistently across architectures.
#[cfg(target_os = "linux")]
pub fn syscall_number(name: &str) -> Option<i64> {
    Some(match name {
        // Universal syscalls (available on both x86_64 and aarch64)
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "close" => libc::SYS_close,
        "fstat" => libc::SYS_fstat,
        "lseek" => libc::SYS_lseek,
        "mmap" => libc::SYS_mmap,
        "mprotect" => libc::SYS_mprotect,
        "munmap" => libc::SYS_munmap,
        "brk" => libc::SYS_brk,
        "ioctl" => libc::SYS_ioctl,
        "sched_yield" => libc::SYS_sched_yield,
        "mremap" => libc::SYS_mremap,
        "msync" => libc::SYS_msync,
        "mincore" => libc::SYS_mincore,
        "madvise" => libc::SYS_madvise,
        "dup" => libc::SYS_dup,
        "nanosleep" => libc::SYS_nanosleep,
        "getpid" => libc::SYS_getpid,
        #[cfg(target_arch = "x86_64")]
        "sendfile" => libc::SYS_sendfile,
        #[cfg(target_arch = "aarch64")]
        "sendfile" => 71, // sendfile on aarch64 (not defined in libc crate)
        "socket" => libc::SYS_socket,
        "connect" => libc::SYS_connect,
        "accept" => libc::SYS_accept,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "sendmsg" => libc::SYS_sendmsg,
        "recvmsg" => libc::SYS_recvmsg,
        "shutdown" => libc::SYS_shutdown,
        "bind" => libc::SYS_bind,
        "listen" => libc::SYS_listen,
        "getsockname" => libc::SYS_getsockname,
        "getpeername" => libc::SYS_getpeername,
        "setsockopt" => libc::SYS_setsockopt,
        "getsockopt" => libc::SYS_getsockopt,
        "clone" => libc::SYS_clone,
        "execve" => libc::SYS_execve,
        "exit" => libc::SYS_exit,
        "wait4" => libc::SYS_wait4,
        "uname" => libc::SYS_uname,
        "fcntl" => libc::SYS_fcntl,
        "flock" => libc::SYS_flock,
        "fsync" => libc::SYS_fsync,
        "fdatasync" => libc::SYS_fdatasync,
        "truncate" => libc::SYS_truncate,
        "ftruncate" => libc::SYS_ftruncate,
        "getcwd" => libc::SYS_getcwd,
        "chdir" => libc::SYS_chdir,
        "umask" => libc::SYS_umask,
        "gettimeofday" => libc::SYS_gettimeofday,
        "getrusage" => libc::SYS_getrusage,
        "sysinfo" => libc::SYS_sysinfo,
        "times" => libc::SYS_times,
        "getuid" => libc::SYS_getuid,
        "getgid" => libc::SYS_getgid,
        "geteuid" => libc::SYS_geteuid,
        "getegid" => libc::SYS_getegid,
        "getppid" => libc::SYS_getppid,
        "setsid" => libc::SYS_setsid,
        "setpgid" => libc::SYS_setpgid,
        "sigaltstack" => libc::SYS_sigaltstack,
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "clock_gettime" => libc::SYS_clock_gettime,
        "clock_nanosleep" => libc::SYS_clock_nanosleep,
        "exit_group" => libc::SYS_exit_group,
        "epoll_ctl" => libc::SYS_epoll_ctl,
        "futex" => libc::SYS_futex,
        "set_tid_address" => libc::SYS_set_tid_address,

        // Syscalls that exist on x86_64 but not aarch64.
        // On aarch64, map to modern equivalents.
        #[cfg(target_arch = "x86_64")]
        "open" => libc::SYS_open,
        #[cfg(not(target_arch = "x86_64"))]
        "open" => libc::SYS_openat,

        #[cfg(target_arch = "x86_64")]
        "stat" => libc::SYS_stat,
        #[cfg(not(target_arch = "x86_64"))]
        "stat" => libc::SYS_newfstatat,

        #[cfg(target_arch = "x86_64")]
        "lstat" => libc::SYS_lstat,
        #[cfg(not(target_arch = "x86_64"))]
        "lstat" => libc::SYS_newfstatat,

        #[cfg(target_arch = "x86_64")]
        "poll" => libc::SYS_poll,
        #[cfg(not(target_arch = "x86_64"))]
        "poll" => libc::SYS_ppoll,

        #[cfg(target_arch = "x86_64")]
        "access" => libc::SYS_access,
        #[cfg(not(target_arch = "x86_64"))]
        "access" => libc::SYS_faccessat,

        #[cfg(target_arch = "x86_64")]
        "pipe" => libc::SYS_pipe,
        #[cfg(not(target_arch = "x86_64"))]
        "pipe" => libc::SYS_pipe2,

        #[cfg(target_arch = "x86_64")]
        "select" => libc::SYS_select,
        #[cfg(not(target_arch = "x86_64"))]
        "select" => libc::SYS_pselect6,

        #[cfg(target_arch = "x86_64")]
        "dup2" => libc::SYS_dup2,
        #[cfg(not(target_arch = "x86_64"))]
        "dup2" => libc::SYS_dup3,

        #[cfg(target_arch = "x86_64")]
        "pause" => libc::SYS_pause,
        #[cfg(not(target_arch = "x86_64"))]
        "pause" => return None, // no equivalent on aarch64

        #[cfg(target_arch = "x86_64")]
        "fork" => libc::SYS_fork,
        #[cfg(not(target_arch = "x86_64"))]
        "fork" => libc::SYS_clone,

        #[cfg(target_arch = "x86_64")]
        "vfork" => libc::SYS_vfork,
        #[cfg(not(target_arch = "x86_64"))]
        "vfork" => libc::SYS_clone,

        #[cfg(target_arch = "x86_64")]
        "getdents" => libc::SYS_getdents,
        #[cfg(not(target_arch = "x86_64"))]
        "getdents" => libc::SYS_getdents64,

        #[cfg(target_arch = "x86_64")]
        "rename" => libc::SYS_rename,
        #[cfg(not(target_arch = "x86_64"))]
        "rename" => libc::SYS_renameat,

        #[cfg(target_arch = "x86_64")]
        "mkdir" => libc::SYS_mkdir,
        #[cfg(not(target_arch = "x86_64"))]
        "mkdir" => libc::SYS_mkdirat,

        #[cfg(target_arch = "x86_64")]
        "rmdir" => libc::SYS_rmdir,
        #[cfg(not(target_arch = "x86_64"))]
        "rmdir" => libc::SYS_unlinkat,

        #[cfg(target_arch = "x86_64")]
        "link" => libc::SYS_link,
        #[cfg(not(target_arch = "x86_64"))]
        "link" => libc::SYS_linkat,

        #[cfg(target_arch = "x86_64")]
        "unlink" => libc::SYS_unlink,
        #[cfg(not(target_arch = "x86_64"))]
        "unlink" => libc::SYS_unlinkat,

        #[cfg(target_arch = "x86_64")]
        "symlink" => libc::SYS_symlink,
        #[cfg(not(target_arch = "x86_64"))]
        "symlink" => libc::SYS_symlinkat,

        #[cfg(target_arch = "x86_64")]
        "readlink" => libc::SYS_readlink,
        #[cfg(not(target_arch = "x86_64"))]
        "readlink" => libc::SYS_readlinkat,

        #[cfg(target_arch = "x86_64")]
        "chmod" => libc::SYS_chmod,
        #[cfg(not(target_arch = "x86_64"))]
        "chmod" => libc::SYS_fchmodat,

        #[cfg(target_arch = "x86_64")]
        "chown" => libc::SYS_chown,
        #[cfg(not(target_arch = "x86_64"))]
        "chown" => libc::SYS_fchownat,

        #[cfg(target_arch = "x86_64")]
        "getrlimit" => libc::SYS_getrlimit,
        #[cfg(not(target_arch = "x86_64"))]
        "getrlimit" => libc::SYS_prlimit64,

        #[cfg(target_arch = "x86_64")]
        "getpgrp" => libc::SYS_getpgrp,
        #[cfg(not(target_arch = "x86_64"))]
        "getpgrp" => return None, // not available on aarch64

        #[cfg(target_arch = "x86_64")]
        "epoll_create" => libc::SYS_epoll_create,
        #[cfg(not(target_arch = "x86_64"))]
        "epoll_create" => libc::SYS_epoll_create1,

        #[cfg(target_arch = "x86_64")]
        "epoll_wait" => libc::SYS_epoll_wait,
        #[cfg(not(target_arch = "x86_64"))]
        "epoll_wait" => libc::SYS_epoll_pwait,

        // Blocked syscalls
        "ptrace" => libc::SYS_ptrace,
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "reboot" => libc::SYS_reboot,
        #[cfg(target_arch = "x86_64")]
        "kexec_load" => libc::SYS_kexec_load,
        #[cfg(not(target_arch = "x86_64"))]
        "kexec_load" => libc::SYS_kexec_load,
        "init_module" => libc::SYS_init_module,
        "delete_module" => libc::SYS_delete_module,
        "pivot_root" => libc::SYS_pivot_root,
        "swapon" => libc::SYS_swapon,
        "swapoff" => libc::SYS_swapoff,
        "acct" => libc::SYS_acct,
        "settimeofday" => libc::SYS_settimeofday,
        "sethostname" => libc::SYS_sethostname,
        "setdomainname" => libc::SYS_setdomainname,
        // io_uring — block to prevent seccomp bypass
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        _ => return None,
    })
}

/// Cached BPF programs by profile name. Compiled once, reused on every exec.
#[cfg(target_os = "linux")]
static CACHED_FILTERS: std::sync::LazyLock<std::collections::HashMap<&'static str, BpfProgram>> =
    std::sync::LazyLock::new(|| {
        let mut cache = std::collections::HashMap::new();
        for profile in &["basic", "strict"] {
            if let Ok(program) = build_filter_uncached(profile) {
                cache.insert(*profile, program);
            }
        }
        cache
    });

/// Get a cached BPF program for the given profile, or compile on cache miss.
#[cfg(target_os = "linux")]
pub fn build_filter(profile_name: &str) -> crate::Result<BpfProgram> {
    // Check cache first (covers "basic" and "strict")
    if let Some(program) = CACHED_FILTERS.get(profile_name) {
        return Ok(program.clone());
    }
    // Unknown profile name — compile fresh (falls back to basic)
    build_filter_uncached(profile_name)
}

/// Build a BPF program for the given profile (uncached).
///
/// Uses a **denylist approach**: default action is Allow, matched (dangerous)
/// syscalls return EPERM. This avoids breaking programs that use modern
/// syscalls (openat, newfstatat, rseq, etc.) not in our legacy allowlist.
///
/// For "strict" profile, uses an allowlist approach instead.
#[cfg(target_os = "linux")]
fn build_filter_uncached(profile_name: &str) -> crate::Result<BpfProgram> {
    let (rules, default_action, match_action) = if profile_name == "strict" {
        // Strict: allowlist approach — only permit known-safe syscalls
        let allowed = resolve_profile("strict");
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for name in allowed {
            if let Some(nr) = syscall_number(name) {
                rules.insert(nr, vec![]);
            }
        }
        (
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
        )
    } else {
        // Basic/default: denylist approach — block dangerous syscalls, allow rest
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for name in BLOCKED_SYSCALLS {
            if let Some(nr) = syscall_number(name) {
                rules.insert(nr, vec![]);
            }
        }
        (
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
        )
    };

    let filter = SeccompFilter::new(
        rules,
        default_action,
        match_action,
        std::env::consts::ARCH.try_into().map_err(|e| {
            crate::KavachError::ExecFailed(format!("unsupported arch for seccomp: {e}"))
        })?,
    )
    .map_err(|e| crate::KavachError::ExecFailed(format!("seccomp filter error: {e}")))?;

    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| crate::KavachError::ExecFailed(format!("seccomp compile error: {e}")))?;

    Ok(program)
}

/// Apply a pre-compiled BPF program to the current thread.
/// Must be called in a `pre_exec` context (after fork, before exec).
#[cfg(target_os = "linux")]
pub fn apply_filter(program: &BpfProgram) -> crate::Result<()> {
    seccompiler::apply_filter(program)
        .map_err(|e| crate::KavachError::ExecFailed(format!("seccomp apply error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_resolution() {
        assert_eq!(resolve_profile("basic").len(), ALLOWED_SYSCALLS_BASIC.len());
        assert_eq!(
            resolve_profile("strict").len(),
            ALLOWED_SYSCALLS_STRICT.len()
        );
        // Unknown defaults to basic
        assert_eq!(
            resolve_profile("unknown").len(),
            ALLOWED_SYSCALLS_BASIC.len()
        );
    }

    #[test]
    fn syscall_allowed_check() {
        assert!(is_syscall_allowed("read"));
        assert!(is_syscall_allowed("write"));
        assert!(is_syscall_allowed("mmap"));
        assert!(!is_syscall_allowed("ptrace"));
        assert!(!is_syscall_allowed("mount"));
        assert!(!is_syscall_allowed("nonexistent"));
    }

    #[test]
    fn no_overlap_between_allowed_and_blocked() {
        for blocked in BLOCKED_SYSCALLS {
            assert!(
                !ALLOWED_SYSCALLS_BASIC.contains(blocked),
                "{blocked} is in both allowed and blocked lists"
            );
        }
    }

    #[test]
    fn strict_is_subset_of_basic() {
        for syscall in ALLOWED_SYSCALLS_STRICT {
            assert!(
                ALLOWED_SYSCALLS_BASIC.contains(syscall),
                "{syscall} is in strict but not basic"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syscall_numbers_resolve() {
        // All allowed syscalls should have known numbers
        for name in ALLOWED_SYSCALLS_BASIC {
            assert!(
                syscall_number(name).is_some(),
                "no syscall number for {name}"
            );
        }
        for name in BLOCKED_SYSCALLS {
            assert!(
                syscall_number(name).is_some(),
                "no syscall number for {name}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_filter_basic() {
        let program = build_filter("basic").unwrap();
        assert!(!program.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_filter_strict() {
        let program = build_filter("strict").unwrap();
        assert!(!program.is_empty());
    }
}
