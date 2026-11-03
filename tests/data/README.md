# Test data

## `dcap-qvl/` — real Intel DCAP quotes and collateral

Copied unchanged from [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl)
`sample/` at commit `9cfb908c4ad81314d773f61f65f3654c1e3e747c` (2026-10-10), under its MIT
licence (`dcap-qvl/LICENSE`). The quotes come from real SGX and TDX platforms. The collateral is
Intel's, as its PCS served it: the TCB info and QE identity are signed by Intel's TCB Signing
key, and the CRLs by the PCK Platform/Processor CA and the Intel SGX Root CA.

| File | What it holds | Used by |
|---|---|---|
| `sgx_quote` | SGX DCAP quote v3, FMSPC `00A067110000` | `test_attest_real_intel_quotes` |
| `sgx_quote_collateral.json` | its collateral, issued 2025-06-19 (TCB level ConfigurationAndSWHardeningNeeded) | same |
| `tdx_quote` | TDX quote v4, FMSPC `B0C06F000000`, TDX module `TDX_01`: 4936 bytes by its own length field, then 70 zero bytes from the buffer it was captured in. Intel's layout puts the PCK chain inside type-6 QE report certification data, which sigil 3.13.15 does not parse (docs/development/issues/2026-11-02-sigil-tdx-quote-type6-wrapper.md) | same |
| `tdx_quote_collateral.json` | its collateral, issued 2025-06-19 (UpToDate throughout) | same |
| `tdx_quote_td15ex_collateral.json` | collateral for the same FMSPC, issued 2026-10-08, by which that platform is OutOfDate (INTEL-SA-01192 and others) | same |
| `tdx_quote_outdated_collateral.json` | collateral for another FMSPC (`90C06F000000`), issued 2026-02-18 | same (FMSPC mismatch) |

The collateral is dcap-qvl's JSON: `tcb_info` and `qe_identity` are the signed members' exact
bytes, `*_signature` their hex signatures, `*_issuer_chain` the PEM chains, and the CRLs hex
DER. The tests rebuild the PCS bodies (`{"tcbInfo":…,"signature":"…"}`) from them.

## `intel/Intel_SGX_Provisioning_Certification_RootCA.cer`

The Intel SGX Root CA, DER, from
<https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer>
(SHA-256 fingerprint `44:A0:19:6B:2B:99:F8:89:B8:E1:49:E9:5B:80:7A:35:0E:74:24:96:43:99:E8:85:A7:CB:B8:CC:FA:B6:74:D3`).

## SHA-256

```
f77e71ba8380d395e78485302cc4beccab400b9a01648e2acaf26085fe65bd7f  dcap-qvl/LICENSE
f8b81014b6e443609746822194910f5dc1c92c322fa0584298d1e33e505ca3b5  dcap-qvl/sgx_quote
bdd694bbe50f3a2a1cfe12f9e2bd83125921107a368edcf10780a5523b8501ce  dcap-qvl/sgx_quote_collateral.json
c42f9164325024bca2757bc8819b11879a0a369132ea4e2b7c85df4805ea72db  dcap-qvl/tdx_quote
b0a5f5fd620a8881b1eda45261fdf30dd930b49aff93231556645c81fcb4c0bc  dcap-qvl/tdx_quote_collateral.json
05e91466e56352166c15a73654147c3d95d6f4ffa62bd150c3c8cbb1d75c3b15  dcap-qvl/tdx_quote_outdated_collateral.json
29e1cb0c2dc98c2cc7f241cc142bdf9d61dee288276d33ae45d5fb2b6b5cc0b0  dcap-qvl/tdx_quote_td15ex_collateral.json
44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3  intel/Intel_SGX_Provisioning_Certification_RootCA.cer
```
