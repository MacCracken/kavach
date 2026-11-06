# 2026-11-02 — sigil's `tdx_quote_parse` refuses every TDX quote a real TD produces: it does not read the type-6 certification data — OPEN (upstream: sigil)

**Status:** open upstream. **Worked around in kavach 3.14.2** (`_attest_tdx_parse`, `src/attestation.cyr`), and
kavach verifies real quotes through it. Rechecked at kavach 3.14.4: unchanged, and not repaired there. The fix
belongs in sigil, whose rules need the maintainer's go-ahead for what ships in it, and it reaches kavach only
when the cyrius pin moves to a snapshot that folds it (CLAUDE.md hazard 4). The workaround stays until then.
**Checked against:** sigil **3.13.15**, the snapshot sigil of the cyrius 6.7.18 pin (CLAUDE.md hazard 4):
`tdx_quote_parse` in `lib/sigil.cyr` (~25463), `tdx_quote_verify_full_into` (~25698).
**Severity:** TDX quote verification cannot accept a genuine quote. Measured, not read: an Intel-signed TDX v4
quote from a real platform (Phala-Network/dcap-qvl `sample/tdx_quote`, now `tests/data/dcap-qvl/tdx_quote`)
returns 0 from `tdx_quote_parse`. The same quote verifies under Intel's QVL, dcap-qvl and kavach's reference
evaluator.

## The layout

Intel TDX DCAP Quoting Library API, quote format v4, the signature data after the TD report body:

| Field | Size |
|---|---|
| ECDSA signature over header and body | 64 (P-256) |
| ECDSA attestation key | 64 |
| Certification data type | 2 — **6**, "QE report certification data" |
| Certification data size | 4 |
| — QE report | 384 |
| — QE report signature | 64 |
| — QE authentication data size, data | 2 + n |
| — PCK certification data type | 2 — 5, the PEM PCK chain |
| — PCK certification data size, data | 4 + m |

sigil reads the QE report straight after the attestation key (`store64(out + 80, cur)` with `cur` at
`sig_data_off + sig_w + ak_w`). For a real quote it takes the type-6 header and the start of the QE report as
the QE report, and the parse then fails the "certification data ends at the end of the signature section"
check. sigil's own TDX fixtures (`tests/tcyr/tdx_verify_full.tcyr`, copied into kavach's
`tests/attest_vectors.cyr`) are synthesized without the type-6 header, so its tests pass.

SGX v3 quotes have no such wrapper: the QE report follows the attestation key directly, and sigil parses and
verifies a real one (measured on dcap-qvl's `sample/sgx_quote`).

## Measured

```
sgx_quote_parse(real SGX v3 quote)            = 1
sgx_quote_verify_full(…, Intel SGX Root CA)   = 1
tdx_quote_parse(real TDX v4 quote)            = 0
```

With the 6-byte header removed (and `signature_data_len` reduced by 6), the same quote parses, and
`tdx_quote_verify_full_into` verifies it to the Intel SGX Root CA at 2025-06-20: the PCK chain, the PCK's
signature over the QE report, the attestation key's binding and its signature over the header and body. No
signature covers the removed bytes.

A second, separate point: the sample file is 5006 bytes, the quote 4936 by its own `signature_data_len`; the
rest is zero padding from the buffer it was captured in. sigil refuses the trailing bytes (since 3.13.1), which is
right; kavach's test passes the quote's own length.

## Asked of sigil

- Parse certification data type 6 in `tdx_quote_parse`: the QE report, its signature and the QE auth data
  inside it, then the nested type-5 PCK chain, keeping the "ends exactly at the end" checks at both levels.
- Keep the flat layout only if something produces it; nothing in Intel's stack does.
- Add a real quote to the TDX fixtures. dcap-qvl's samples are MIT-licensed and carry Intel's collateral.
- Quote format v5 (`version == 5`, a body type and size before the TD report, TD 1.5 bodies of 648 bytes) is
  also refused; dcap-qvl's `tdx_quote_outdated` and `tdx_quote_td15ex` are v5. Not needed by kavach today, and
  worth a separate item.

## kavach's workaround

`_attest_tdx_parse` tries `tdx_quote_parse` first. When that fails, the quote is v4, the certification data
after the attestation key is type 6, and its size runs exactly to the end, kavach parses a copy without the
6-byte header. Anything else is refused as before. The workaround goes when sigil parses the wrapper.
