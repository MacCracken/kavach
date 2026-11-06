#!/bin/bash
# The root half of 2026-11-06-process-backend-capabilities. PID 1 of a throwaway
# privileged container, with the two built binaries in a directory bound at /rig:
#
#   docker run --rm --privileged --cidfile <file> -v <dir>:/rig:ro archlinux:latest \
#     bash /rig/2026-11-06-process-backend-capabilities.sh
#
# Every step is bounded, because no signal from outside stops PID 1 here, and the
# probes open and never write: /proc/sys in a privileged container is the host's.
# ⛔ Stop it by the id in that file. Other work shares a Docker host.
echo "--- rig"
uname -r
echo "uid=$(id -u) uid_map: $(cat /proc/self/uid_map)"
grep -E '^Cap(Eff|Bnd)|^NoNewPrivs|^Seccomp:' /proc/self/status
timeout -k 5 150 pacman -Sy --noconfirm --needed runc >/tmp/pacman.log 2>&1
echo "pacman rc=$?"
timeout 10 runc --version | head -1
ulimit -c 0
PROBE=/rig/capprobe-payload

one() {   # one <work dir>: the whole matrix there
  W=$1
  mkdir -p "$W/rfsproc/proc" "$W/rfsproc/dev" "$W/rfsproc/sub"
  cp "$PROBE" "$W/rfsproc/probe"; chmod 755 "$W/rfsproc/probe"
  timeout 10 mount -t proc proc "$W/rfsproc/proc"
  echo "fs=$(stat -f -c %T "$W") caller-proc-mount rc=$?"
  timeout -k 5 100 /rig/capprobe-driver --drive "$W" "$PROBE" > "$W.out" 2>"$W.err"
  echo "driver rc=$?"
  timeout 10 umount "$W/rfsproc/proc"
}

one /tmp/kvw
mkdir -p /tmp/kvt
timeout 10 mount -t tmpfs -o size=64m tmpfs /tmp/kvt
one /tmp/kvt

echo "--- candidates, outside kavach, no filter"
R=/tmp/kvt/rfs
M=/tmp/kvt/outside-marker
T=a00405fb
c() { echo "=== candidate $*"; timeout -k 5 20 "$@"; echo "exit $?"; }
{
  # pivot_root and the twelve, each chain
  c "$PROBE" --payload pv "$R" $T base
  c "$PROBE" --payload pv "$R" $T esc "$M"
  c "$PROBE" --payload pv "$R" $T dev
  c "$PROBE" --payload pv "$R" $T nest "$M"
  c "$PROBE" --payload pv "$R" $T mp
  # a read-only /proc/sys in a mount namespace of its own, with no rootfs
  c "$PROBE" --payload rosys $T base
  c "$PROBE" --payload rosys 0 base
  c "$PROBE" --payload rosys $T um
  c "$PROBE" --payload rosys $T nestum
  # the same mounts with no bound: what the mask is worth alone
  c "$PROBE" --payload rosys 1ffffffffff um
  # and no rootfs, no bound worth having: zero capabilities, root's files
  c "$PROBE" --payload drop 0 base
} > /tmp/cand.out 2>&1
echo "candidates done"

echo "--- raw overlay"
cat /tmp/kvw.out
echo "--- raw tmpfs"
cat /tmp/kvt.out
echo "--- raw candidates"
cat /tmp/cand.out
echo "--- stderr"
head -20 /tmp/kvw.err /tmp/kvt.err
echo "--- end"
