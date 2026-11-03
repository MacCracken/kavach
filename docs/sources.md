# Sources

External specifications, algorithms and measured behaviour that kavach's code relies on, with
where each is used. Started at v3.14.2, when kavach began evaluating Intel's attestation
collateral itself; earlier citations live beside the code they justify (`# SAFETY:` notes,
kernel header references in `src/security.cyr`, ADR-005 and ADR-007).

## TEE attestation (`src/attestation.cyr`, `src/attest_collateral.cyr`)

| Source | What kavach takes from it |
|---|---|
| Intel, *SGX ECDSA Quote Library API* (DCAP), quote format v3 | The SGX quote layout. sigil parses it; kavach reads the QE report fields (MISCSELECT +16, ATTRIBUTES +48, MRSIGNER +128, ISVPRODID +256, ISVSVN +258). |
| Intel, *TDX DCAP Quoting Library API*, quote format v4 | The TDX quote layout, including QE report certification data (type 6) around the PCK chain (type 5), which kavach unwraps because sigil 3.13.15 does not (`_attest_tdx_parse`; docs/development/issues/2026-11-02-sigil-tdx-quote-type6-wrapper.md). TD report body offsets: TEE_TCB_SVN +0, MRSIGNERSEAM +64, SEAMATTRIBUTES +112, TD_ATTRIBUTES +120, MRTD +136, RTMR0–3 +328…, REPORTDATA +520. |
| Intel, *Provisioning Certification Service (PCS) API* v4 — TCB Info v3, Enclave Identity v2 | The collateral formats: `tcbLevels` (`sgxtcbcomponents`, `pcesvn`, `tdxtcbcomponents`, `tcbStatus`), `tdxModule` / `tdxModuleIdentities`, the QE identity's masked MISCSELECT and ATTRIBUTES, MRSIGNER, ISVPRODID and ISVSVN levels, `issueDate` / `nextUpdate`, and the signature over the exact bytes of the signed member. |
| Intel, *SGX PCK Certificate and CRL Profile* | The SGX extension, OID 1.2.840.113741.1.13.1: PPID (.1), TCB (.2, components .2.1–.2.16, PCESVN .2.17, CPUSVN .2.18), PCE-ID (.3), FMSPC (.4), SGX Type (.5). The PCK CRL's issuer is the PCK Platform/Processor CA; the root CA CRL's is the root. |
| Intel SGX DCAP Quote Verification Library (QVL), `TcbLevelCheck` / `QuoteVerifier` | The order of the checks and the TCB level match: the first level the platform meets, with TDX components compared from index 2 when TEE_TCB_SVN[1] (the module's major version) is above 0, and the module identity `TDX_<major as two hex digits>`. |
| google/go-tdx-guest, `verify` and `pcs` | The same rules, cross-checked; the QE identity's MISCSELECT and ATTRIBUTES compared bytewise under their masks; the signed member taken as the raw bytes of the JSON value. |
| Intel, *TDX Virtual Firmware Design Guide* §11 (measurement) | What TDVF extends into each RTMR: RTMR0 the TD configuration (TD HOB, ACPI tables, boot variables), RTMR1 the OS loader and kernel, RTMR2 the command line and initrd; RTMR3 the guest's (`policy_attest_rtmr`). |
| RFC 5280 §4.1, §5.1 | Certificate and CRL structure that kavach walks in DER (serial, issuer, subject, extensions; `tbsCertList`, `revokedCertificates`), and the UTCTime century rule (§4.1.2.5.1). |
| Phala-Network/dcap-qvl `sample/` at `9cfb908c4ad81314d773f61f65f3654c1e3e747c` (MIT) | Real SGX and TDX quotes with Intel's collateral, the test data in `tests/data/dcap-qvl/` (provenance and checksums in `tests/data/README.md`). |
| Intel SGX Root CA, `certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer` | The real root for `tests/data/intel/`, SHA-256 `44a0196b…74d3`. |

## Algorithms

| Algorithm | Source | Used in |
|---|---|---|
| Days from a proleptic Gregorian date (`days_from_civil`) | Howard Hinnant, *chrono-Compatible Low-Level Date Algorithms* (howardhinnant.github.io/date_algorithms.html) | `_kc_days`, for the collateral's ISO 8601 dates and the CRLs' X.509 times |
| Aho-Corasick multi-pattern matching | Aho & Corasick, *Efficient string matching: an aid to bibliographic search*, CACM 18(6), 1975 | `src/aho_corasick.cyr` (since v3.4.0) |

## Runtime behaviour (`src/backend_gvisor.cyr`, `src/backend_sy_agnos.cyr`)

| Source | What kavach takes from it |
|---|---|
| gVisor `runsc/cmd/util/util.go` (`Errorf`, `Fatalf`) | runsc's own failures go to stderr and, as a JSON line `{"msg":…,"level":"error"}`, to the `--log` file; `Fatalf` exits 128. |
| gVisor `runsc/cli/cli.go` | `--log` opens the error logger; internal logs go to a discarding emitter unless `--debug-log` or `--alsologtostderr` is set. So a non-empty `--log` file means runsc failed. |
| docker 29.9.2, measured on this machine (CHANGELOG 3.14.2) | `docker run` prints its own errors on the container's stderr and exits 125/126/127; `create` / `start -a -i` / `inspect --format {{.State.Error}}` separate them: a container that never started leaves `.State.Error` set, a payload's own exit 127 leaves it empty. |
