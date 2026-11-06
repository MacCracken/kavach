/* The payload half of 2026-11-06-process-backend-capabilities.cyr. Static C, not
 * Cyrius, because a Cyrius binary reads its argv from /proc/self/cmdline and a
 * process-backend rootfs has no /proc. x86-64.
 *
 *   gcc -static -O1 -o probe 2026-11-06-process-backend-capabilities.c
 *
 * `pv` and `rosys` are the fix candidates, run on their own, with no kavach: they
 * stand where confine_child's chroot would, then `drop` does the rest.
 *
 * ⛔ It OPENS and never WRITES. As real root /proc/sys is the host's: no O_TRUNC,
 * no O_CREAT on a host path, and /proc/kcore is read for one byte. `dev` makes two
 * nodes in the rootfs, opens one, and removes both.
 * ⛔ PR_SET_DUMPABLE 0 comes first: a seccomp kill is a core dump, and a core dump
 * runs the host's core_pattern.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define CAPS_LAST 63

static long res(long r) { return r < 0 ? -errno : r; }

static void creds(void) {
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2];
    unsigned long long eff, prm, bnd = 0;
    int i;

    dprintf(1, "uid %d\npid %d\n", getuid(), getpid());
    memset(d, 0, sizeof d);
    if (syscall(SYS_capget, &h, d) != 0) {
        dprintf(1, "capget %ld\n", (long)-errno);
        return;
    }
    eff = d[0].effective | ((unsigned long long)d[1].effective << 32);
    prm = d[0].permitted | ((unsigned long long)d[1].permitted << 32);
    dprintf(1, "capget-eff %016llx\ncapget-prm %016llx\n", eff, prm);
    for (i = 0; i <= CAPS_LAST; i++) {
        int c = prctl(PR_CAPBSET_READ, i, 0, 0, 0);
        if (c < 0) break;
        if (c == 1) bnd |= 1ULL << i;
    }
    dprintf(1, "prctl-bnd %016llx\n", bnd);
    dprintf(1, "nnp %d\nseccomp %d\n", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
            prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
}

static void status(void) {
    char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        dprintf(1, "status %ld\n", (long)-errno);
        return;
    }
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "CapEff:", 7) || !strncmp(line, "CapPrm:", 7) ||
            !strncmp(line, "CapBnd:", 7) || !strncmp(line, "NoNewPrivs:", 11) ||
            !strncmp(line, "Seccomp:\t", 9))
            dprintf(1, "status-%s", line);
    }
    fclose(f);
}

static void ns(const char *name, const char *path) {
    char b[64];
    long r = readlink(path, b, sizeof b - 1);
    if (r > 0) {
        b[r] = 0;
        dprintf(1, "%s %s\n", name, b);
    } else {
        dprintf(1, "%s %ld\n", name, (long)-errno);
    }
}

static void wopen(const char *label, const char *path) {
    int fd = open(path, O_WRONLY); /* no O_TRUNC: an open changes nothing */
    if (fd >= 0) {
        close(fd);
        dprintf(1, "%s OPENED\n", label);
    } else {
        dprintf(1, "%s %ld\n", label, (long)-errno);
    }
}

static void rbyte(const char *label, const char *path) {
    char b;
    long r;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        dprintf(1, "%s %ld\n", label, (long)-errno);
        return;
    }
    r = read(fd, &b, 1);
    close(fd);
    if (r == 1)
        dprintf(1, "%s READ1\n", label);
    else
        dprintf(1, "%s %ld\n", label, res(r));
}

static void base(void) {
    creds();
    status();
    ns("ns-mnt", "/proc/self/ns/mnt");
    ns("ns-net", "/proc/self/ns/net");
    ns("ns-pid", "/proc/self/ns/pid");
    wopen("core_pattern", "/proc/sys/kernel/core_pattern");
    wopen("sysrq", "/proc/sysrq-trigger");
    rbyte("kcore", "/proc/kcore");
    wopen("etc-passwd", "/etc/passwd");
}

/* A proc of the payload's own, in its private mount namespace. */
static void mountproc(void) {
    long r = res(mount("proc", "/proc", "proc", 0, 0));
    dprintf(1, "mount-proc %ld\n", r);
    if (r == 0) base();
}

/* The classic: a chroot below the cwd leaves the cwd outside the root, and `..`
 * from there walks past the old root to the top of the mount namespace. */
static void escape(const char *marker) {
    long r;
    int i, fd;

    dprintf(1, "marker-before %ld\n", res(open(marker, O_RDONLY)));
    r = res(chroot("/sub"));
    dprintf(1, "chroot-sub %ld\n", r);
    if (r != 0) return;
    for (i = 0; i < 64; i++)
        if (chdir("..") != 0) break;
    r = res(chroot("."));
    dprintf(1, "chroot-dot %ld\n", r);
    if (chdir("/") != 0) dprintf(1, "chdir %ld\n", (long)-errno);
    fd = open(marker, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        dprintf(1, "marker-after ESCAPED\n");
    } else {
        dprintf(1, "marker-after %ld\n", (long)-errno);
    }
    base();
}

/* 1:3 is /dev/null's number, 1:11 /dev/kmsg's. Open only, then unlink. */
static void dev(void) {
    long r = res(mknod("/kv-n1", S_IFCHR | 0600, makedev(1, 3)));
    int fd;

    dprintf(1, "mknod-null %ld\n", r);
    if (r == 0) unlink("/kv-n1");
    r = res(mknod("/kv-n2", S_IFCHR | 0600, makedev(1, 11)));
    dprintf(1, "mknod-kmsg %ld\n", r);
    if (r == 0) {
        fd = open("/kv-n2", O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            close(fd);
            dprintf(1, "open-kmsg OPENED\n");
        } else {
            dprintf(1, "open-kmsg %ld\n", (long)-errno);
        }
        unlink("/kv-n2");
    }
}

/* The gate on open_by_handle_at is CAP_DAC_READ_SEARCH, and a handle names an
 * inode with no path, so a chroot does not bound it. EPERM is the gate and
 * anything else got past it. `extra`, when given, is a handle the driver took
 * outside the rootfs. */
static void handle(const char *extra) {
    union {
        struct file_handle h;
        char b[256];
    } u;
    int mid, fd;
    long r;

    memset(&u, 0, sizeof u);
    u.h.handle_bytes = 128;
    r = res(name_to_handle_at(AT_FDCWD, "/probe", &u.h, &mid, 0));
    dprintf(1, "name-to-handle %ld\n", r);
    if (r == 0) {
        fd = open_by_handle_at(AT_FDCWD, &u.h, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            dprintf(1, "open-by-handle OPENED\n");
        } else {
            dprintf(1, "open-by-handle %ld\n", (long)-errno);
        }
    }
    if (extra) {
        char m[256];
        int mf = open(extra, O_RDONLY);
        long n = mf >= 0 ? read(mf, m, sizeof m) : -1;
        if (mf >= 0) close(mf);
        if (n > 0) {
            memcpy(&u, m, n);
            fd = open_by_handle_at(AT_FDCWD, &u.h, O_RDONLY);
            if (fd >= 0) {
                char c;
                long g = read(fd, &c, 1);
                close(fd);
                dprintf(1, "open-outside-by-handle ESCAPED read=%ld\n", g);
            } else {
                dprintf(1, "open-outside-by-handle %ld\n", (long)-errno);
            }
        } else {
            dprintf(1, "no handle file %s\n", extra);
        }
    }
}

/* What a bound set in confine_child would give a payload: the same calls, made
 * here, then an exec, which is where a set takes effect for root. */
static void drop(unsigned long long mask, char *self, char *mode, char *extra) {
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2];
    char *av[5] = {self, "--payload", mode, extra, 0};
    char *ev[1] = {0};
    int i;

    for (i = 0; i <= CAPS_LAST; i++) {
        if (!((mask >> i) & 1))
            if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0) < 0) break;
    }
    memset(d, 0, sizeof d);
    d[0].effective = d[0].permitted = (unsigned)mask;
    d[1].effective = d[1].permitted = (unsigned)(mask >> 32);
    dprintf(1, "capset %ld\n", res(syscall(SYS_capset, &h, d)));
    execve(self, av, ev);
    dprintf(1, "execve %ld\n", (long)-errno);
}

/* A nested user namespace, the way past a bounded set: every capability again,
 * held in the new namespace. The kernel refuses one to a chrooted caller. */
static void nest(const char *marker) {
    long r = res(unshare(CLONE_NEWUSER | CLONE_NEWNS));
    dprintf(1, "nest %ld\n", r);
    if (r != 0) return;
    dprintf(1, "nest-mount-proc %ld\n", res(mount("proc", "/proc", "proc", 0, 0)));
    escape(marker);
}

/* The same from a nested user namespace, where every capability is back. */
static void nestum(void) {
    long r = res(unshare(CLONE_NEWUSER | CLONE_NEWNS));
    dprintf(1, "nest %ld\n", r);
    if (r != 0) return;
    dprintf(1, "umount-sys %ld\n", res(umount2("/proc/sys", MNT_DETACH)));
    dprintf(1, "umount-kcore %ld\n", res(umount2("/proc/kcore", MNT_DETACH)));
    wopen("core_pattern", "/proc/sys/kernel/core_pattern");
    rbyte("kcore", "/proc/kcore");
}

/* Whether a read-only /proc/sys comes off again. */
static void um(void) {
    dprintf(1, "umount-sys %ld\n", res(umount2("/proc/sys", MNT_DETACH)));
    dprintf(1, "umount-kcore %ld\n", res(umount2("/proc/kcore", MNT_DETACH)));
    base();
}

static void must(const char *what, long r) {
    if (r != 0) {
        dprintf(1, "prototype %s %ld\n", what, (long)-errno);
        exit(3);
    }
}

/* The candidate for the rootfs path, standing where confine_child's chroot does.
 * pivot_root(".", ".") stacks the old root under the new, and the detach removes
 * it: runc's sequence, so nothing is left to walk up to. */
static void pv(char *root, unsigned long long mask, char *mode, char *extra) {
    must("unshare", unshare(CLONE_NEWNS));
    must("private", mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    must("bind", mount(root, root, NULL, MS_BIND | MS_REC, NULL));
    must("chdir", chdir(root));
    must("pivot_root", syscall(SYS_pivot_root, ".", "."));
    must("detach", umount2(".", MNT_DETACH));
    must("chdir", chdir("/"));
    must("nnp", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    drop(mask, "/probe", mode, extra);
}

static void bind_ro(const char *path) {
    must("bind", mount(path, path, NULL, MS_BIND | MS_REC, NULL));
    must("remount", mount(NULL, path, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL));
}

/* The candidate for the path with no rootfs: what runc gives /proc, in a mount
 * namespace of the payload's own. */
static void rosys(char *self, unsigned long long mask, char *mode, char *extra) {
    must("unshare", unshare(CLONE_NEWNS));
    must("private", mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    bind_ro("/proc/sys");
    bind_ro("/proc/sysrq-trigger");
    must("mask", mount("/dev/null", "/proc/kcore", NULL, MS_BIND, NULL));
    must("nnp", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    drop(mask, self, mode, extra);
}

int main(int argc, char **argv) {
    char *mode, *extra;

    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (argc < 3 || strcmp(argv[1], "--payload") != 0) {
        dprintf(1, "usage\n");
        return 2;
    }
    mode = argv[2];
    extra = argc > 3 ? argv[3] : 0;
    if (!strcmp(mode, "base")) base();
    else if (!strcmp(mode, "cred")) creds();
    else if (!strcmp(mode, "mp")) mountproc();
    else if (!strcmp(mode, "esc")) escape(extra);
    else if (!strcmp(mode, "dev")) dev();
    else if (!strcmp(mode, "fh")) handle(extra);
    else if (!strcmp(mode, "nest")) nest(extra);
    else if (!strcmp(mode, "um")) um();
    else if (!strcmp(mode, "nestum")) nestum();
    else if (!strcmp(mode, "pv") && argc > 5)
        pv(argv[3], strtoull(argv[4], 0, 16), argv[5], argc > 6 ? argv[6] : 0);
    else if (!strcmp(mode, "rosys") && argc > 4)
        rosys(argv[0], strtoull(argv[3], 0, 16), argv[4], argc > 5 ? argv[5] : 0);
    else if (!strcmp(mode, "drop") && argc > 4)
        drop(strtoull(argv[3], 0, 16), argv[0], argv[4], argc > 5 ? argv[5] : 0);
    else {
        dprintf(1, "unknown mode\n");
        return 2;
    }
    return 0;
}
