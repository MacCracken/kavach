;; kavach — the WASI probe that WASM_STATUS_PROBE_HEX in tests/kavach.tcyr carries.
;;
;; It opens `status` in its first preopen (fd 3), prints what one read of it
;; returns, and exits 0; with no preopen it prints nothing. Run under
;; `--dir /proc/self`, the preopen is wasmtime's own /proc/<pid>, so the output
;; is wasmtime's status: its `Seccomp:` and `NoNewPrivs:` lines say how kavach
;; confined it. It imports three WASI preview1 functions.
;;
;; The suite carries the module as binary, assembled from this text by hand like
;; the suite's other modules, so the tests need no WAT support. The 274 bytes
;; were checked under wasmtime 49 against this text: the output is the same but
;; for the lines that change from run to run (pids, memory use, context
;; switches). wasmtime runs this file directly:
;;   wasmtime run --dir /proc/self tests/wasm_status_probe.wat
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "status")
  (func (export "_start")
    (local $fd i32)
    ;; path_open(fd 3, SYMLINK_FOLLOW, "status", no oflags, FD_READ) -> fd at 32
    (if (i32.ne (call $path_open (i32.const 3) (i32.const 1) (i32.const 16) (i32.const 6)
                  (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 32))
                (i32.const 0))
      (then (return)))
    (local.set $fd (i32.load (i32.const 32)))
    ;; one iovec at 48: 4096 bytes at 1024
    (i32.store (i32.const 48) (i32.const 1024))
    (i32.store (i32.const 52) (i32.const 4096))
    (drop (call $fd_read (local.get $fd) (i32.const 48) (i32.const 1) (i32.const 56)))
    ;; write back what was read
    (i32.store (i32.const 52) (i32.load (i32.const 56)))
    (drop (call $fd_write (i32.const 1) (i32.const 48) (i32.const 1) (i32.const 56)))))
