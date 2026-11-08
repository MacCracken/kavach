#!/bin/bash
# The root half of 2026-11-07-process-rootfs-caller-proc. PID 1 of a throwaway privileged
# container, with rig-before, rig-after and a `docker export` of postgres:16-alpine as
# pg.tar in a directory bound at /rig:
#
#   docker run --rm --privileged -v <dir>:/rig:ro ubuntu:24.04 bash /rig/2026-11-07-process-rootfs-caller-proc.sh
#
# /proc/sys in a privileged container is the host's, and so is binfmt_misc: every probe
# opens and never writes. Every step is bounded.
ulimit -c 0
echo "--- rig"; uname -r; echo "uid=$(id -u)"
timeout 10 mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc; echo "binfmt mount rc=$?"
for V in before after; do
  echo "##### $V"
  D=/rig/rig-$V
  rm -rf /tmp/rigA /tmp/rigB /tmp/rigC
  mkdir -p /tmp/rigA /tmp/rigB/proc /tmp/rigB/sys /tmp/rigC/proc
  for R in A B C; do cp $D /tmp/rig$R/payload; chmod 755 /tmp/rig$R/payload; done
  echo a > /tmp/rigA/marker-a
  timeout 10 mount -t proc proc /tmp/rigB/proc
  timeout 10 mount -t sysfs sysfs /tmp/rigB/sys
  timeout 10 mount --rbind /proc /tmp/rigC/proc
  for P in basic new; do timeout -k 5 120 $D --drive $P; echo "drive rc=$?"; done
  timeout 10 umount -R /tmp/rigC/proc; timeout 10 umount /tmp/rigB/sys; timeout 10 umount /tmp/rigB/proc
  rm -rf /tmp/pg; mkdir /tmp/pg; tar -xf /rig/pg.tar -C /tmp/pg
  mkdir -p /tmp/pg/dev /tmp/pg/proc
  timeout 10 mount --rbind /dev /tmp/pg/dev; timeout 10 mount -t proc proc /tmp/pg/proc
  rm -f /tmp/pg.log
  timeout -k 5 150 $D --pg /tmp/pg; echo "pg rc=$?"
  echo "--- pg log tail"; tail -4 /tmp/pg.log
  timeout 10 umount -R /tmp/pg/dev; timeout 10 umount /tmp/pg/proc
done
# A caller's /dev, an rbind of the host's: open the first block device read-only.
ulimit -c 0
B=$(ls /sys/block | grep -v -E '^(loop|ram|zram)' | head -1); echo "block device: $B"
mkdir -p /tmp/rigD/dev /tmp/rigD/proc; cp /rig/rig-after /tmp/rigD/payload; chmod 755 /tmp/rigD/payload
timeout 10 mount --rbind /dev /tmp/rigD/dev; timeout 10 mount -t proc proc /tmp/rigD/proc
for P in basic new; do timeout -k 5 60 /rig/rig-after --devdrive $P /dev/$B; done
timeout 10 umount -R /tmp/rigD/dev; timeout 10 umount /tmp/rigD/proc
timeout 10 umount /proc/sys/fs/binfmt_misc
echo "--- end"
