#!/bin/bash
# The root half of 2026-11-07-consumer-images-on-3.14.8. PID 1 of a throwaway privileged
# container, with rig-before, rig-after and `docker export`s of postgres:16-alpine and
# nginx:alpine, as pg.tar and nginx.tar, in a directory bound at /rig:
#
#   docker run --rm --privileged -v <dir>:/rig:ro ubuntu:24.04 bash /rig/2026-11-07-consumer-images-on-3.14.8.sh
#
# The process path's half. The OCI half needs runc, which ubuntu:24.04 lacks: the same
# script with OCI=1, run in a chroot of a host root that has runc (see ADR-011). Every
# step is bounded; a block device is opened read-only and closed.
ulimit -c 0
echo "--- rig"; uname -r; echo "uid=$(id -u)"
B=$(ls /sys/block | grep -v -E '^(loop|ram|zram)' | head -1); echo "block device: $B"
for V in before after; do
  echo "##### $V"
  D=/rig/rig-$V
  if [ "$OCI" = 1 ]; then
    rm -rf /tmp/ngx; mkdir /tmp/ngx; tar -xf /rig/nginx.tar -C /tmp/ngx; mkdir -p /tmp/ngx/dev /tmp/ngx/proc
    rm -f /tmp/nginx.log; timeout -k 5 90 $D --oci-nginx /tmp/ngx on; echo "--- nginx log"; tail -3 /tmp/nginx.log
    continue
  fi
  rm -rf /tmp/pg; mkdir /tmp/pg; tar -xf /rig/pg.tar -C /tmp/pg; mkdir -p /tmp/pg/dev /tmp/pg/proc
  echo "--- postgres, the caller's /dev and /proc"
  timeout 10 mount --rbind /dev /tmp/pg/dev; timeout 10 mount -t proc proc /tmp/pg/proc
  rm -f /tmp/pg.log; timeout -k 5 150 $D --pg /tmp/pg; echo "--- pg log"; tail -3 /tmp/pg.log
  echo "--- the host's disk through the caller's /dev"
  cp $D /tmp/pg/payload; chmod 755 /tmp/pg/payload
  timeout -k 5 60 $D --dev /tmp/pg /dev/$B
  timeout 10 umount -R /tmp/pg/dev; timeout 10 umount /tmp/pg/proc
  pkill -9 postgres; sleep 1
  rm -rf /tmp/pg; mkdir /tmp/pg; tar -xf /rig/pg.tar -C /tmp/pg; mkdir -p /tmp/pg/dev /tmp/pg/proc
  echo "--- postgres, the caller's /proc only"
  timeout 10 mount -t proc proc /tmp/pg/proc
  rm -f /tmp/pg.log; timeout -k 5 150 $D --pg /tmp/pg; echo "--- pg log"; tail -3 /tmp/pg.log
  timeout 10 umount /tmp/pg/proc
  pkill -9 postgres; sleep 1
  echo "--- no rootfs: the payload's capabilities"
  timeout -k 5 30 $D --caps $D
  echo "--- a sibling sandbox, through a caller's /proc"
  rm -rf /tmp/sibA /tmp/sibB; mkdir -p /tmp/sibA/proc /tmp/sibB/proc
  cp $D /tmp/sibA/payload; cp $D /tmp/sibB/payload; chmod 755 /tmp/sibA/payload /tmp/sibB/payload
  echo b > /tmp/sibB/marker-b
  timeout 10 mount -t proc proc /tmp/sibA/proc; timeout 10 mount -t proc proc /tmp/sibB/proc
  for P in basic new; do timeout -k 5 60 $D --sibling /tmp/sibA /tmp/sibB $P; done
  timeout 10 umount /tmp/sibA/proc; timeout 10 umount /tmp/sibB/proc
  echo "--- nginx, as kavach leaves the rootfs"
  rm -rf /tmp/ngx; mkdir /tmp/ngx; tar -xf /rig/nginx.tar -C /tmp/ngx; mkdir -p /tmp/ngx/dev /tmp/ngx/proc
  for N in on port off; do rm -f /tmp/nginx.log; timeout -k 5 60 $D --nginx /tmp/ngx $N; echo "--- nginx log"; tail -2 /tmp/nginx.log; done
done
echo "--- end"
