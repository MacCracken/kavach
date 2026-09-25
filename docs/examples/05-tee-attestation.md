# Example 5: TEE attestation — verify a quote, gate an exec

kavach 3.13.0 verifies SGX and TDX quotes with sigil, and `sandbox_exec`
releases a TEE guest's output only if its quote passes the sandbox policy.
kavach's own SGX and TDX launchers cannot fetch a quote yet, so this example
uses sigil's test quote twice: once verified directly, and once handed to the
gate by a stand-in backend, the way a launcher that can fetch one would.

## Code

Built from the repo root, against the library bundle and the test vectors:

```cyrius
include "dist/kavach.cyr"
include "tests/attest_vectors.cyr"

# Stands in for a TEE launcher that can fetch a quote: it would have the guest
# put `backend_attest_nonce()` in the quote's report data, then hand the quote
# back. This one returns sigil's SGX test quote, whose report data is cc*64.
fn demo_sgx_exec(sandbox, command) {
    backend_attach_quote(hex_decode(ATT_SGX_HEX, 2 * ATT_SGX_LEN), ATT_SGX_LEN);
    var r = exec_result_new();
    ExecResult_set_exit_code(r, 0);
    ExecResult_set_stdout(r, "enclave output");
    ExecResult_set_stdout_len(r, 14);
    return r;
}

fn show(label, ar) {
    var d = AttestationResult_details(ar);
    var t = attestation_trust_name(AttestationResult_trust(ar));
    sys_write(1, label, strlen(label));
    sys_write(1, t, strlen(t));
    sys_write(1, " — ", strlen(" — "));
    sys_write(1, d, strlen(d));
    sys_write(1, "\n", 1);
    return 0;
}

fn main() {
    kavach_init();

    # 1. A policy that requires attestation: a root to verify against, and the
    #    measurements it allows. The root here is sigil's test root; in
    #    production it is Intel's SGX root CA, DER, which TDX quotes chain to.
    var p = policy_new();
    policy_attest_root(p, hex_decode(ATT_ROOT_HEX, 2 * ATT_ROOT_LEN), ATT_ROOT_LEN);
    policy_attest_allow(p, ATT_SGX_MRENCLAVE);

    # 2. Verify a quote directly.
    var nonce = alloc(32);
    memset(nonce, 0xcc, 32);
    var quote = hex_decode(ATT_SGX_HEX, 2 * ATT_SGX_LEN);
    show("direct:   ", kavach_attest_sgx_quote(quote, ATT_SGX_LEN, p, nonce, 32, ATT_NOW));

    # 3. The gate. The fixture's certificates expire, so verify as of a fixed
    #    time; production leaves the clock alone.
    sandbox_exec_set_attest_time(ATT_NOW);
    backend_register_exec(KavachBackend.SGX, &demo_sgx_exec);
    var cfg = config_new();
    config_backend(cfg, KavachBackend.SGX);
    config_policy(cfg, p);
    var sb = alloc(SANDBOX_SIZE);       # sandbox_create refuses SGX without /dev/sgx_enclave
    Sandbox_set_config(sb, cfg);
    Sandbox_set_state(sb, SandboxState.RUNNING);

    sandbox_exec_set_attest_nonce(nonce, 32);    # a relying party's challenge, used once
    var r = sandbox_exec(sb, "run");
    show("fresh:    ", sandbox_exec_last_attestation());
    if (r != 0) { println(ExecResult_stdout(r)); }

    r = sandbox_exec(sb, "run");                 # kavach draws a random nonce
    show("replayed: ", sandbox_exec_last_attestation());
    if (r == 0) { println("output withheld"); }
    return 0;
}

var r = main();
sys_exit(r);
```

```sh
cyrius build path/to/example-05.cyr build/ex05 && ./build/ex05
```

## Output

```
direct:   affirming — verified; TCB, QE identity and revocation not evaluated
fresh:    affirming — verified; TCB, QE identity and revocation not evaluated
enclave output
kavach: policy violation: the report data does not carry the nonce
replayed: contraindicated — the report data does not carry the nonce
output withheld
```

The second exec gets the same quote back. kavach drew a new nonce for it, the
quote does not carry that nonce, and the output is withheld.

## What the result means

`kavach_attest_quote` (and the SGX and TDX functions under it) checks, in order:
the policy names a root and a measurement; the quote parses; it verifies to the
root (the PCK chain with its validity dates, the PCK's signature over the Quoting
Enclave's report, that report's binding of the attestation key, and the key's
signature over the quote); the guest is not a debug guest unless the policy
allows one; the report data starts with the nonce; and the measurement
(MRENCLAVE for SGX, MRTD for TDX) is on the allowlist. The first failure makes
the result `contraindicated`, with the reason in `details`. A pass is
`affirming`, or `warning` for a debug guest the policy allowed.

Not evaluated: Intel's TCB level, QE identity and revocation collateral, and for
TDX the RTMRs. `details` says so on every pass.

## Writing a launcher that attests

A backend at the SGX or TDX slot reads `backend_attest_nonce()` and
`backend_attest_nonce_len()` before it starts the guest (a length of 0 means the
policy did not ask), has the guest put the nonce at the start of its quote's
report data, and hands the quote back with `backend_attach_quote(buf, len)`. It
does not verify the quote itself; `sandbox_exec` does, after the backend
returns. `sandbox_spawn`, persistent guests and `composite_exec` refuse a policy
that requires attestation, since nothing on those paths checks a quote.
