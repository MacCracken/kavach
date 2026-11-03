# Example 5: TEE attestation — verify a quote, gate an exec

kavach verifies SGX and TDX quotes (3.13.0) and, since 3.14.2, Intel's
collateral for the platform that made them: its TCB level, the Quoting
Enclave's identity, and revocation. `sandbox_exec` releases a TEE guest's output
only if its quote passes the sandbox policy. kavach's own SGX and TDX launchers
cannot fetch a quote yet, so this example uses the generated test set
(`tests/attest_collateral_vectors.cyr`): quotes in Intel's layout under a test
root, with their collateral. It verifies two quotes directly, then hands one to
the gate through a stand-in backend, the way a launcher that can fetch one would.

## Code

Built from the repo root, against the library bundle and the test vectors:

```cyrius
include "dist/kavach.cyr"
include "tests/attest_collateral_vectors.cyr"

fn bytes(hex, len) { return hex_decode(hex, 2 * len); }

# Stands in for a TEE launcher that can fetch a quote: it would have the guest
# put `backend_attest_nonce()` in the quote's report data, then hand the quote
# back. This one returns the generated SGX quote, whose report data is cc*64.
fn demo_sgx_exec(sandbox, command) {
    backend_attach_quote(bytes(KC_SGX_HEX, KC_SGX_LEN), KC_SGX_LEN);
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

    # 1. A policy that requires attestation: the root to verify against, the
    #    measurements it allows, and Intel's collateral for the platform. The
    #    root and collateral here are the generated test set; in production the
    #    root is Intel's SGX root CA, DER, and the collateral comes from Intel's
    #    PCS (or a PCCS) exactly as served.
    var p = policy_new();
    policy_attest_root(p, bytes(KC_ROOT_HEX, KC_ROOT_LEN), KC_ROOT_LEN);
    policy_attest_allow(p, KC_MRENCLAVE);
    var c = kavach_collateral_new();
    kavach_collateral_tcb_info(c, bytes(KC_SGX_TCB_INFO_HEX, KC_SGX_TCB_INFO_LEN), KC_SGX_TCB_INFO_LEN);
    kavach_collateral_qe_identity(c, bytes(KC_QE_IDENTITY_HEX, KC_QE_IDENTITY_LEN), KC_QE_IDENTITY_LEN);
    kavach_collateral_signer_chain(c, bytes(KC_SIGNER_CHAIN_HEX, KC_SIGNER_CHAIN_LEN), KC_SIGNER_CHAIN_LEN);
    kavach_collateral_pck_crl(c, bytes(KC_PCK_CRL_HEX, KC_PCK_CRL_LEN), KC_PCK_CRL_LEN);
    kavach_collateral_root_crl(c, bytes(KC_ROOT_CRL_HEX, KC_ROOT_CRL_LEN), KC_ROOT_CRL_LEN);
    policy_attest_collateral(p, c);

    # 2. Verify quotes directly: a current platform, and one Intel's TCB info
    #    rates OutOfDate.
    var nonce = alloc(64);
    memset(nonce, 0xcc, 64);
    show("direct:   ", kavach_attest_sgx_quote(bytes(KC_SGX_HEX, KC_SGX_LEN), KC_SGX_LEN, p, nonce, 64, KC_NOW));
    show("outdated: ", kavach_attest_sgx_quote(bytes(KC_SGX_OLD_HEX, KC_SGX_OLD_LEN), KC_SGX_OLD_LEN, p, nonce, 64, KC_NOW));

    # 3. The gate. The collateral expires, so verify as of a fixed time inside
    #    its window; production leaves the clock alone.
    sandbox_exec_set_attest_time(KC_NOW);
    backend_register_exec(KavachBackend.SGX, &demo_sgx_exec);
    var cfg = config_new();
    config_backend(cfg, KavachBackend.SGX);
    config_policy(cfg, p);
    var sb = alloc(SANDBOX_SIZE);       # sandbox_create refuses SGX without /dev/sgx_enclave
    Sandbox_set_config(sb, cfg);
    Sandbox_set_state(sb, SandboxState.RUNNING);

    sandbox_exec_set_attest_nonce(nonce, 64);    # a relying party's challenge, used once
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
direct:   affirming — verified; TCB UpToDate, QE UpToDate
outdated: contraindicated — the platform's TCB status is not accepted
fresh:    affirming — verified; TCB UpToDate, QE UpToDate
enclave output
kavach: policy violation: the report data does not carry the nonce
replayed: contraindicated — the report data does not carry the nonce
output withheld
```

The second quote is genuine, from a platform Intel's TCB info rates OutOfDate,
and the policy accepts only UpToDate. The second exec gets the same quote back
as the first. kavach drew a new nonce for it, the quote does not carry that
nonce, and the output is withheld.

## What the result means

`kavach_attest_quote` (and the SGX and TDX functions under it) checks, in order:

1. the policy names a root, a measurement and its collateral (for TDX also
   RTMR0 to RTMR2);
2. the quote parses (a TDX quote in Intel's layout, with type-6 certification
   data, is unwrapped first);
3. it verifies to the root: the PCK chain with its validity dates, the PCK's
   signature over the Quoting Enclave's report, that report's binding of the
   attestation key, and the key's signature over the quote;
4. the collateral clears the platform: the TCB info and QE identity are signed
   under the root and current, no CRL lists the PCK certificate, its CA or the
   TCB Signing certificate, and the platform's, TDX module's and QE's statuses
   are ones the policy accepts (`policy_attest_accept_tcb`; UpToDate only by
   default, Revoked never);
5. the guest is not a debug guest unless the policy allows one;
6. the report data starts with the nonce;
7. the measurement (MRENCLAVE for SGX, MRTD for TDX) is on the allowlist, and
   for TDX each pinned RTMR is on its list.

The first failure makes the result `contraindicated`, with the reason in
`details`. A pass is `affirming`, or `warning` for a debug guest the policy
allowed, and `details` names the statuses. `AttestationResult_tcb_status` is the
platform's status as a `KAVACH_TCB_*` bit.

In production the collateral comes from Intel's PCS
(`api.trustedservices.intel.com`, the v4 `tcb`, `qe/identity` and `pckcrl`
endpoints under `/sgx/` or `/tdx/`) or a PCCS, passed as served. It expires
about 30 days after issue, and kavach refuses any part past its `nextUpdate`.
`test_attest_real_intel_quotes` in `tests/kavach.tcyr` runs the same calls on
real quotes with Intel's own collateral (`tests/data/`).

## Writing a launcher that attests

A backend at the SGX or TDX slot reads `backend_attest_nonce()` and
`backend_attest_nonce_len()` before it starts the guest (a length of 0 means the
policy did not ask), has the guest put the nonce at the start of its quote's
report data, and hands the quote back with `backend_attach_quote(buf, len)`. It
does not verify the quote itself; `sandbox_exec` does, after the backend
returns. `sandbox_spawn`, persistent guests and `composite_exec` refuse a policy
that requires attestation, since nothing on those paths checks a quote.
