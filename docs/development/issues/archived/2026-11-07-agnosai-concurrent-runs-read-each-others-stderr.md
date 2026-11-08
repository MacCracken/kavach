# 2026-11-07 — two runs at once read each other's stderr: a run's result is process-wide — RESOLVED (3.14.8)

**Discovered:** 2026-11-07, by agnosai, while choosing how to confine its process and Python tool tiers (agnosai ADR
031). agnosai runs tool calls on several threads at once.
**Severity:** Medium. One run's stderr reaches another run's caller, which in a multi-tenant consumer is another
tenant's. A consumer that decides anything from stderr decides it from the wrong run.
**Affects:** kavach 3.14.7, every backend whose exec reads a result back from `confine.cyr`'s globals after the
capture: `backend_process.cyr:159-163` and `:183-186`, `backend_wasm.cyr:380-381`, `backend_oci.cyr:188`, and
`backend.cyr:320-358` (`backend_set_capture_stderr`). Through `sandbox_exec`.
**Status:** ✅ **RESOLVED in kavach 3.14.8**, as proposed, and wider than filed. See the resolution at the end.

## What happens

`confine_capture_run` writes the payload's stderr into one static buffer as it arrives, `_confine_err_buf[65536]`
(`src/confine.cyr:1356`, written at `:1183`), and leaves the length, the exit code and the timeout flag in
`_confine_err_len`, `_confine_last_exit` and `_confine_last_timed_out` (`:1239-1251`). Each backend then reads them back
with `confine_last_stderr()`, `confine_last_exit()` and `confine_last_timed_out()`. Two captures on two threads write the
same buffer at once, and each reads back whatever is there when it finishes.

**Measured**, on x86-64 (Arch, Linux 7.2.14), kavach 3.14.7, with the repro below. Two threads, one running `/bin/ls` and
one `/bin/cat` on a missing path, 100 runs each through `sandbox_exec` on the process backend:

| Run | Runs whose stderr was not their own |
|---|---|
| 1 | 116 of 200 |
| 2 | 125 of 200 |
| 3 | 100 of 200 |

What came back was the other program's stderr, or the two spliced, as the second write lands over the first:

```
ls's caller got  [cat: /nonexistent-bravo: No such file or directory\n No such file or directory\n]
cat's caller got [ls: cannot access '/nonexistent-alpha-alpha-alpha':]
```

No exit code swapped in 600 runs, as that window is a load straight after a store, but nothing keeps it shut. The same
holds for `_backend_diag_only` (`src/backend.cyr:175`), which `sandbox_exec` reads to skip the gate, and
`_last_scan_result`. ⚠ **And for `_kv_exec_keep_fd`**, which a caller sets to its pin before the fork, so a second thread
pinning between one thread's pin and its fork leaves that child sparing the wrong descriptor and closing its own pin.

## Repro

Built inside agnosai's tree for its includes, kavach's API only:

```cyr
var _wrong = 0;
var _runs = 0;

fn _run(cmd) {
    var cfg = config_new();
    config_backend(cfg, KavachBackend.PROCESS);
    config_timeout_ms(cfg, 5000);
    config_stdin(cfg, "", 0);
    var sb = sandbox_create(cfg);
    sandbox_transition(sb, SandboxState.RUNNING);
    var r = sandbox_exec(sb, cmd);
    sandbox_transition(sb, SandboxState.STOPPED);
    sandbox_transition(sb, SandboxState.DESTROYED);
    return r;
}

fn _worker(which) {
    var cmd = "/bin/ls /nonexistent-alpha-alpha-alpha";
    var want = "ls: cannot access '/nonexistent-alpha-alpha-alpha': No such file or directory\n";
    if (which == 1) {
        cmd = "/bin/cat /nonexistent-bravo";
        want = "cat: /nonexistent-bravo: No such file or directory\n";
    }
    for (var i = 0; i < 100; i = i + 1) {
        var r = _run(cmd);
        atomic_fetch_add(&_runs, 1);
        if (r == 0) { continue; }
        if (streq(ExecResult_stderr(r), want) == 0) { atomic_fetch_add(&_wrong, 1); }
    }
    return 0;
}

fn main() {
    alloc_init();
    kavach_init();
    var a = thread_create(&_worker, 0);
    var b = thread_create(&_worker, 1);
    thread_join(a);
    thread_join(b);
    print_num(_wrong); print(" of ", 4); print_num(_runs); println(" runs read a stderr that was not their own");
    return 0;
}
```

Each run alone, on one thread, returns its own stderr, 63 and 51 bytes. Only concurrency mixes them.

## What agnosai does meanwhile

agnosai 2.3.4 confines its process and Python tiers in its own spawner, calling `confine_child_caps` in the child and
capturing per call, so those tiers do not go through any of this (ADR 031). Its WASM tier does, through `sandbox_exec`:
it returns no stderr to a caller, but reads it to tell a module over the store limits from a guest that failed, so a
concurrent call can be misclassified either way. agnosai has no workaround short of serializing every WASM call behind
one lock, which would let one 30 s guest hold up the rest, so it waits on this.

## Proposed fix

**Keep a capture's result in the capture.** `ConfineCapture` already carries the run's inputs (`src/confine.cyr:943`).
Giving it the stderr buffer, its length, the exit code and the timeout flag, and having each backend read them from the
capture it ran, makes two runs independent. The stderr buffer can come from `backend_capture_buf`, as stdout's does since
3.14.7, so it costs what the payload wrote. `confine_last_*` can stay for a single-threaded caller, reading the last
capture this thread ran.

`_backend_diag_only` and `_last_scan_result` want the same: carried on the `ExecResult`, or per thread.

`_kv_exec_keep_fd` wants to be a parameter of `confine_child*`, or a field of the capture, rather than a global set
before the fork. A consumer with its own spawner then has no global to set: agnosai lifts its pin and its error pipe
above `SPAWN_MAX_FD` instead, which works where the hard open-file limit allows it.

## Resolution (3.14.8)

**As proposed: a capture's result is the capture's.** `ConfineCapture` gained `total`, `exit`, `timed_out`, `err` and
`err_len`. Each capture's stderr goes into a buffer of its own, `backend_capture_buf(CONFINE_ERR_MAX)`, which costs the pages
the payload writes and goes back with `confine_capture_release`. Every backend reads the capture it ran: the process
backend's two paths, WASM, OCI, gVisor and SY-agnos, through `backend_capture_result` and `backend_run_start`.
`confine_last_*`, `backend_set_capture_stderr`, `backend_run_capture`, `backend_run_finish`, `oci_last_exit` and `_oci_run`
stay, copied from the capture when it finishes, for a caller on one thread.

**`_backend_diag_only` and `_last_scan_result`, as proposed, and the rest of `sandbox_exec`'s state with them.** The
result carries the diagnostic flag (`ExecResult_diagnostic`, `exec_result_is_diagnostic`), and `sandbox_exec` reads it there.
The sandbox carries its last scan, assessment and attestation (`sandbox_last_scan_result`, `sandbox_last_assessment`,
`sandbox_last_attestation`), and the nonce and quote of its exec in flight (`backend_sandbox_nonce`,
`backend_sandbox_attach_quote`). The process-wide `sandbox_exec_last_*` still read the most recent.

**Found on the way, the same class, all fixed:**

- **The code scanner's hit table and lowered text were two module globals**, on the premise that the scan path is
  synchronous. A gate scanning on two threads read another scan's hits.
- **The audit chain had no lock.** Two records at once read the same head, and took one serial and one `prev_hmac`, so the
  log stopped verifying as a chain. `audit_chain_record` now holds a per-chain mutex (`kavach_lock_cell`).
- **A payload inherited another thread's capture pipes.** They are not close-on-exec, and the unconfined capture and
  `kv_exec_capture` closed nothing in the child, so a capture waited for its EOF until the other thread's payload exited.
  Every capture child now closes what it inherited, as the confined path has since 3.9.1.
- **An attesting exec's nonce was cleared by any other exec**, which reset the process-wide pair before and after every
  dispatch. An attesting exec now holds a lock across it, and nothing else touches the pair. Quote verification shares one
  arena, so it holds a lock as well.
- **`oci_container_id`'s counter and the audit netlink sequence** were a read and a write. Both are atomic now. The syscall name
  map was published empty and then filled in place. It is now filled first and published last, and `kavach_init` builds
  the shared caches before a consumer starts a thread.

**One claim does not hold: `_kv_exec_keep_fd` is not racy.** Every site sets it in the child, after `fork`
(`confine.cyr`, `spawn.cyr`, `persistent.cyr`, and now `util.cyr` and `oci_spawn`), where it is the child's own copy. A
consumer with its own spawner sets it the same way, after its `fork`, and no other thread sees it. It stays a global.

**Measured** with the issue's shape: four threads, `/bin/ls` and `/bin/cat` on missing paths, under `policy_new()` and
`policy_basic()`, 30 runs each through `sandbox_exec`, every result compared with what that command and policy give on one
thread. The two scanner and audit rows are this release's additions to the group. Built from 3.14.7's `src/` with the same
test, three runs:

| | 3.14.7 | 3.14.8 |
|---|---|---|
| runs whose stderr was not their own, of 120 | 64 to 80 | 0 |
| runs whose exit code was not their own, of 120 | 0 | 0 |
| code scans on two threads finding another scan's findings, of 800 | 552 to 600 | 0 |
| audit records on two threads, 80 written: entries counted | 42 to 43 | 81 (with the genesis) |
| …records that took another's serial | 38 to 39 | 0 |

Tests: `test_concurrent_runs_keep_their_own_results` and `test_results_carry_their_own_state`, and
`test_attest_verifies_on_two_threads`. A mutation pass reverting each part fails the suite: see the CHANGELOG.

**agnosai's half.** Its WASM tier can run calls on several threads through `sandbox_exec` once it pins 3.14.8, and read each
call's stderr from its own result. It need not serialize them.
