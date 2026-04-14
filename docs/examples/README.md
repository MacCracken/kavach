# Worked examples

Hands-on walkthroughs of the kavach API. Each example builds on the previous
one and is tested against the in-tree test suite.

| # | Example | Skills |
|---|---------|--------|
| 1 | [Hello, Noop](01-hello-noop.md) | `config_new` → `sandbox_create` → `sandbox_exec` |
| 2 | [Process backend + HMAC audit chain](02-process-with-audit.md) | `audit_chain_open`, `audit_entry_verify`, `audit_chain_close` |
| 3 | [Scanner verdicts + redaction](03-scanner-verdicts.md) | `gate_apply`, verdict routing, WARN-verdict in-place redaction |
| 4 | [Offender tracking across execs](04-offender-tracking.md) | `offender_tracker_record`, `should_escalate`, decay tuning |

## Running examples

Examples are Cyrius source files that use the kavach public API:

```sh
cd kavach
cyrius build path/to/example.cyr build/example
./build/example
```

Or embed in your own project by importing the kavach module via
`include "src/main.cyr"` — this brings in all 31 modules.

## See also

- [Getting started guide](../guides/getting-started.md)
- [Composite backends guide](../guides/composite-backends.md)
- [Threat tracking guide](../guides/threat-tracking.md)
- [Architecture overview](../architecture/overview.md)
