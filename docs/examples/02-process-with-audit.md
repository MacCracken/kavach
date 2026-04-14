# Example 2: Process backend + HMAC audit chain

Runs a real `/bin/echo` through the Process backend, signs every exec event
into a tamper-evident HMAC-SHA256 chain, and demonstrates verify-on-read.

## Code

```cyrius
include "src/main.cyr"

fn main() {
    kavach_init();

    var chain = audit_chain_open("/tmp/example-02.audit", "demo-hmac-key", 13);
    sandbox_exec_set_audit_chain(chain);

    var cfg = config_new();
    config_backend(cfg, Backend.PROCESS);
    config_policy(cfg, policy_strict());

    var sb = sandbox_create(cfg);
    sandbox_transition(sb, SandboxState.RUNNING);

    var r = sandbox_exec(sb, "/bin/echo hello_from_kavach");
    if (r != 0) {
        syscall(1, 1, "output: ", 8);
        var out = ExecResult_stdout(r);
        syscall(1, 1, out, strlen(out));
    }

    sandbox_destroy(sb);

    # Chain now has: genesis + exec_begin + exec_complete.
    println("audit entries:");
    print_num(audit_chain_len(chain));
    syscall(1, 1, "\n", 1);

    audit_chain_close(chain);    # zeroes the HMAC key in memory
    return 0;
}

var r = main();
syscall(60, r);
```

## Audit file format

The file at `/tmp/example-02.audit` is JSONL — one entry per line:

```json
{"serial":0,"event_type":"genesis","payload":"audit chain initialized","timestamp":"1744531200","hmac":"4a05...","prev_hmac":""}
{"serial":1,"event_type":"exec_begin","payload":"/bin/echo hello_from_kavach","timestamp":"1744531201","hmac":"fb5b...","prev_hmac":"4a05..."}
{"serial":2,"event_type":"exec_complete","payload":"pass","timestamp":"1744531201","hmac":"04e7...","prev_hmac":"fb5b..."}
```

Every entry's `hmac` field is
`HMAC-SHA256(key, "serial:event_type:payload:timestamp:prev_hmac")`. The
`prev_hmac` field chains the entries — modifying any entry invalidates all
subsequent ones.

## Verify the chain

```cyrius
# Load an entry (in production — via a JSONL parser); demonstrated here
# by keeping the returned `e` from audit_chain_record:
var e = audit_chain_record(chain, "test", "payload");
if (audit_entry_verify(e, "demo-hmac-key", 13) == 1) {
    println("entry is authentic");
}
```

`audit_entry_verify` uses `ct_streq` (constant-time comparison) — timing
analysis can't recover the HMAC one byte at a time.

## Sensitive hygiene

- The audit log file is created at mode 0600 (tightened after first write).
- `audit_chain_close(chain)` zeroes the HMAC key buffer via sigil's
  compiler-barrier-protected `zeroize_key` — critical to call before process
  exit if a core dump could leak the key.
- User-controlled payload/event_type values are JSON-escaped through
  `oci_json_escape` before being written, closing the log-forgery vector.

## Next

[Example 3: gVisor with per-policy redaction](03-gvisor-redact.md)
