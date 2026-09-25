;; kavach — the WASI probe that WASM_FS_PROBE_HEX in tests/kavach.tcyr carries.
;;
;; For each preopen, fds 3 to 16, it prints
;;   P <the preopen's guest path>
;;   R <probe.txt's content>    or  R E<errno> when it cannot be read
;;   W ok                       or  W E<errno> for creating created.txt and
;;                                  writing one byte to it
;; and exits 0. It takes no argument and imports six WASI preview1 functions.
;; WASI errno 2 is EACCES and 44 is ENOENT.
;;
;; The suite carries the module as binary, assembled from this text by hand like
;; the suite's other modules, so the tests need no WAT support. The 818 bytes
;; were checked under wasmtime 49 against this text: the output is the same,
;; error branches included (R E44 for a missing file, W E2 for a write that
;; landlock refuses). wasmtime runs this file directly:
;;   wasmtime run --dir <dir> tests/wasm_fs_probe.wat
(module
  (import "wasi_snapshot_preview1" "fd_prestat_get" (func $prestat_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_prestat_dir_name" (func $prestat_dir_name (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $fd_close (param i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 100) "probe.txt")
  (data (i32.const 120) "created.txt")
  (data (i32.const 140) "P ")
  (data (i32.const 144) "R ")
  (data (i32.const 148) "W ")
  (data (i32.const 152) "\n")
  (data (i32.const 156) "E")
  (data (i32.const 160) "ok")
  (data (i32.const 164) "x")
  (func $out (param $p i32) (param $n i32)
    (i32.store (i32.const 0) (local.get $p))
    (i32.store (i32.const 4) (local.get $n))
    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 24))))
  (func $num (param $v i32)
    (local $i i32)
    (local.set $i (i32.const 63))
    (loop $l
      (i32.store8 (local.get $i) (i32.add (i32.const 48) (i32.rem_u (local.get $v) (i32.const 10))))
      (local.set $v (i32.div_u (local.get $v) (i32.const 10)))
      (local.set $i (i32.sub (local.get $i) (i32.const 1)))
      (br_if $l (i32.ne (local.get $v) (i32.const 0))))
    (call $out (i32.add (local.get $i) (i32.const 1)) (i32.sub (i32.const 63) (local.get $i))))
  (func $err (param $e i32)
    (call $out (i32.const 156) (i32.const 1))
    (call $num (local.get $e)))
  (func (export "_start")
    (local $fd i32) (local $e i32) (local $nfd i32) (local $len i32)
    (local.set $fd (i32.const 3))
    (block $done
      (loop $each
        (br_if $done (i32.gt_u (local.get $fd) (i32.const 16)))
        (local.set $e (call $prestat_get (local.get $fd) (i32.const 16)))
        (if (i32.eqz (local.get $e))
          (then
            (local.set $len (i32.load (i32.const 20)))
            (drop (call $prestat_dir_name (local.get $fd) (i32.const 512) (local.get $len)))
            (call $out (i32.const 140) (i32.const 2))
            (call $out (i32.const 512) (local.get $len))
            (call $out (i32.const 152) (i32.const 1))
            (call $out (i32.const 144) (i32.const 2))
            (local.set $e (call $path_open (local.get $fd) (i32.const 1) (i32.const 100) (i32.const 9)
              (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 24)))
            (if (i32.eqz (local.get $e))
              (then
                (local.set $nfd (i32.load (i32.const 24)))
                (i32.store (i32.const 8) (i32.const 1024))
                (i32.store (i32.const 12) (i32.const 1000))
                (local.set $e (call $fd_read (local.get $nfd) (i32.const 8) (i32.const 1) (i32.const 28)))
                (if (i32.eqz (local.get $e))
                  (then (call $out (i32.const 1024) (i32.load (i32.const 28))))
                  (else (call $err (local.get $e)) (call $out (i32.const 152) (i32.const 1))))
                (drop (call $fd_close (local.get $nfd))))
              (else (call $err (local.get $e)) (call $out (i32.const 152) (i32.const 1))))
            (call $out (i32.const 148) (i32.const 2))
            (local.set $e (call $path_open (local.get $fd) (i32.const 1) (i32.const 120) (i32.const 11)
              (i32.const 9) (i64.const 64) (i64.const 0) (i32.const 0) (i32.const 24)))
            (if (i32.eqz (local.get $e))
              (then
                (local.set $nfd (i32.load (i32.const 24)))
                (i32.store (i32.const 8) (i32.const 164))
                (i32.store (i32.const 12) (i32.const 1))
                (local.set $e (call $fd_write (local.get $nfd) (i32.const 8) (i32.const 1) (i32.const 28)))
                (if (i32.eqz (local.get $e))
                  (then (call $out (i32.const 160) (i32.const 2)))
                  (else (call $err (local.get $e))))
                (drop (call $fd_close (local.get $nfd))))
              (else (call $err (local.get $e))))
            (call $out (i32.const 152) (i32.const 1))))
        (local.set $fd (i32.add (local.get $fd) (i32.const 1)))
        (br $each))))
)
