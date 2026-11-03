#!/usr/bin/env python3
# Generate tests/attest_collateral_vectors.cyr: SGX DCAP v3 and TDX v4 quotes in
# Intel's layout, with the collateral kavach evaluates since 3.14.2 (TCB info v3,
# QE identity v2, the PCK and root CRLs), all chaining to a test root made here.
#
# The real-data vectors (Intel-signed quotes and collateral, from dcap-qvl) cover
# the formats; these cover the branches real data cannot reach: a revoked PCK
# certificate, a revoked PCK CA, each TCB status, a TDX module identity that is
# missing, a QE whose ISVSVN is out of date, an RTMR off the allowlist. Keys are
# fresh on every run, so the file changes on every run; nothing depends on the
# bytes, only on what they mean.
#
# Formats: Intel SGX ECDSA Quote Library API (quote v3); Intel TDX DCAP Quoting
# Library API (quote v4, QE report certification data type 6 around the PCK
# chain, type 5); Intel PCS API v4 (TCB info v3, enclave identity v2); Intel SGX
# PCK Certificate and CRL Profile (the SGX extension, 1.2.840.113741.1.13.1).
#
# Usage: python3 scripts/gen-collateral-vectors.py > tests/attest_collateral_vectors.cyr
# Needs the `cryptography` package.
import datetime
import hashlib
import json
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

UTC = datetime.timezone.utc
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=UTC)
ISSUE = datetime.datetime(2026, 6, 1, tzinfo=UTC)
NEXT = datetime.datetime(2026, 7, 1, tzinfo=UTC)
NOW = datetime.datetime(2026, 6, 15, tzinfo=UTC)
FMSPC = bytes.fromhex("00906ED50000")
PCEID = bytes.fromhex("0000")
QE_MRSIGNER = bytes.fromhex("8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF")
QE_VENDOR = bytes.fromhex("939A7233F79C4CA9940A0DB3957F0607")
MRENCLAVE = bytes([0xA1]) * 32
MRSIGNER = bytes([0xB2]) * 32
MRTD = bytes([0xC3]) * 48
RTMR = [bytes([0xD0 + i]) * 48 for i in range(4)]
NONCE = bytes([0xCC]) * 64
SGX_OID = "1.2.840.113741.1.13.1"
SGX_OID_DER = bytes.fromhex("2A864886F84D010D01")


def key():
    return ec.generate_private_key(ec.SECP256R1())


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kavach Test"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, subject_key, issuer, issuer_key, ca, pathlen=None, extra=None):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
    if extra is not None:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(SGX_OID), extra), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def der(tag, body):
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(nb)]) + nb + body


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return der(0x02, b)


def sgx_ext(comps, pcesvn):
    # The PCK certificate's SGX extension: PPID, TCB (16 components, PCESVN,
    # CPUSVN), PCE-ID, FMSPC, SGX Type.
    def entry(suffix, value):
        return der(0x30, der(0x06, SGX_OID_DER + bytes(suffix)) + value)
    tcb = b"".join(entry([2, i + 1], der_int(c)) for i, c in enumerate(comps))
    tcb += entry([2, 17], der_int(pcesvn)) + entry([2, 18], der(0x04, bytes(comps)))
    return der(0x30, entry([1], der(0x04, bytes(16))) + entry([2], der(0x30, tcb))
               + entry([3], der(0x04, PCEID)) + entry([4], der(0x04, FMSPC))
               + entry([5], der(0x0A, b"\x00")))


def sign_raw(k, data):
    r, s = utils.decode_dss_signature(k.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]


def pem(*certs):
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def report_body(attributes, mrenclave, mrsigner, prodid, isvsvn, report_data, misc=0):
    b = bytearray(384)
    struct.pack_into("<I", b, 16, misc)
    b[48:64] = attributes
    b[64:96] = mrenclave
    b[128:160] = mrsigner
    struct.pack_into("<HH", b, 256, prodid, isvsvn)
    b[320:384] = report_data
    return bytes(b)


def qe_part(pck_key, ak, qe_prodid, qe_isvsvn, chain):
    auth = bytes(range(32))
    qe_rd = hashlib.sha256(raw_pub(ak) + auth).digest() + bytes(32)
    qe_attr = bytes.fromhex("11000000000000000000000000000000")
    qe = report_body(qe_attr, bytes([0x5E]) * 32, QE_MRSIGNER, qe_prodid, qe_isvsvn, qe_rd)
    return (qe + sign_raw(pck_key, qe) + struct.pack("<H", len(auth)) + auth
            + struct.pack("<HI", 5, len(chain)) + chain)


def sgx_quote(pck_key, chain, debug=False, qe_isvsvn=8):
    ak = key()
    header = struct.pack("<HHIHH", 3, 2, 0, 8, 13) + QE_VENDOR + bytes(20)
    attr = bytes([0x07 if debug else 0x05]) + bytes(7) + bytes([0x03]) + bytes(7)
    body = report_body(attr, MRENCLAVE, MRSIGNER, 42, 7, NONCE)
    sig = sign_raw(ak, header + body)
    sigdata = sig + raw_pub(ak) + qe_part(pck_key, ak, 1, qe_isvsvn, chain)
    return header + body + struct.pack("<I", len(sigdata)) + sigdata


def tdx_quote(pck_key, chain, tee_tcb_svn, debug=False, qe_isvsvn=8, mrsignerseam=bytes(48)):
    ak = key()
    header = struct.pack("<HHIHH", 4, 2, 0x81, 8, 13) + QE_VENDOR + bytes(20)
    body = bytearray(584)
    body[0:16] = tee_tcb_svn
    body[16:64] = bytes([0x11]) * 48          # MRSEAM
    body[64:112] = mrsignerseam                # MRSIGNERSEAM
    body[112:120] = bytes(8)                   # SEAMATTRIBUTES
    body[120:128] = (bytes([0x01]) if debug else bytes([0x00])) + bytes([0x00, 0x00, 0x10]) + bytes(4)
    body[128:136] = bytes.fromhex("e702060000000000")   # XFAM
    body[136:184] = MRTD
    for i in range(4):
        body[328 + 48 * i:376 + 48 * i] = RTMR[i]
    body[520:584] = NONCE
    body = bytes(body)
    sig = sign_raw(ak, header + body)
    inner = qe_part(pck_key, ak, 2, qe_isvsvn, chain)
    sigdata = sig + raw_pub(ak) + struct.pack("<HI", 6, len(inner)) + inner
    return header + body + struct.pack("<I", len(sigdata)) + sigdata


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def comps_json(svns, with_meta):
    if with_meta:
        return [{"svn": s, "category": "BIOS", "type": "Early Microcode Update"} for s in svns]
    return [{"svn": s} for s in svns]


def signed_body(wrapper_key, member, signer_key):
    raw = json.dumps(member, separators=(",", ":")).encode()
    sig = sign_raw(signer_key, raw).hex()
    return b'{"' + wrapper_key.encode() + b'":' + raw + b',"signature":"' + sig.encode() + b'"}'


SGX_LEVELS = [
    ([5, 5, 2, 2, 4, 1, 0, 5] + [0] * 8, 13, "UpToDate"),
    ([4, 4, 2, 2, 4, 1, 0, 5] + [0] * 8, 11, "SWHardeningNeeded"),
    ([3, 3, 2, 2, 4, 1, 0, 5] + [0] * 8, 10, "OutOfDate"),
    ([1, 1, 1, 1, 1, 1, 0, 1] + [0] * 8, 5, "Revoked"),
]
TDX_COMPS = [3, 0, 3] + [0] * 13
TDX_COMPS_OLD = [3, 0, 2] + [0] * 13


def tcb_info(kind, signer_key, version=3, next_update=NEXT):
    levels = []
    for comps, pcesvn, status in SGX_LEVELS:
        tcb = {"sgxtcbcomponents": comps_json(comps, False), "pcesvn": pcesvn}
        if kind == "TDX":
            tcb["tdxtcbcomponents"] = comps_json(TDX_COMPS if status == "UpToDate" else TDX_COMPS_OLD, False)
        levels.append({"tcb": tcb, "tcbDate": "2026-05-13T00:00:00Z", "tcbStatus": status,
                       "advisoryIDs": [] if status == "UpToDate" else ["INTEL-SA-00000"]})
    if kind == "TDX":
        # The TDX levels: one per SGX level, plus a lower TDX one at each, so
        # TEE_TCB_SVN[2] of 2 is OutOfDate even on an UpToDate SGX platform.
        extra = {"tcb": {"sgxtcbcomponents": comps_json(SGX_LEVELS[0][0], False), "pcesvn": 13,
                         "tdxtcbcomponents": comps_json(TDX_COMPS_OLD, False)},
                 "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "OutOfDate", "advisoryIDs": ["INTEL-SA-00001"]}
        levels.insert(1, extra)
    info = {"id": kind, "version": version, "issueDate": iso(ISSUE), "nextUpdate": iso(next_update),
            "fmspc": FMSPC.hex().upper(), "pceId": PCEID.hex().upper(), "tcbType": 0,
            "tcbEvaluationDataNumber": 17}
    if kind == "TDX":
        info["tdxModule"] = {"mrsigner": "00" * 48, "attributes": "0000000000000000",
                             "attributesMask": "FFFFFFFFFFFFFFFF"}
        info["tdxModuleIdentities"] = [{"id": "TDX_01", "mrsigner": "00" * 48, "attributes": "0000000000000000",
                                        "attributesMask": "FFFFFFFFFFFFFFFF",
                                        "tcbLevels": [{"tcb": {"isvsvn": 3}, "tcbDate": "2026-05-13T00:00:00Z", "tcbStatus": "UpToDate"},
                                                      {"tcb": {"isvsvn": 2}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "OutOfDate"}]}]
    info["tcbLevels"] = levels
    return signed_body("tcbInfo", info, signer_key)


def qe_identity(kind, signer_key, mrsigner=QE_MRSIGNER, next_update=NEXT, attributes="11000000000000000000000000000000"):
    ident = {"id": kind, "version": 2, "issueDate": iso(ISSUE), "nextUpdate": iso(next_update),
             "tcbEvaluationDataNumber": 17, "miscselect": "00000000", "miscselectMask": "FFFFFFFF",
             "attributes": attributes, "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
             "mrsigner": mrsigner.hex().upper(), "isvprodid": 1 if kind == "QE" else 2,
             "tcbLevels": [{"tcb": {"isvsvn": 8}, "tcbDate": "2026-05-13T00:00:00Z", "tcbStatus": "UpToDate"},
                           {"tcb": {"isvsvn": 6}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "OutOfDate"}]}
    return signed_body("enclaveIdentity", ident, signer_key)


def crl(issuer_cert, issuer_key, serials):
    b = (x509.CertificateRevocationListBuilder().issuer_name(issuer_cert.subject)
         .last_update(ISSUE).next_update(NEXT))
    for s in serials:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(s)
                                      .revocation_date(ISSUE).build())
    return b.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def emit(name, data, out):
    out.append("var %s_LEN = %d;" % (name, len(data)))
    out.append('var %s_HEX = "%s";' % (name, data.hex()))


def main():
    root_key, pckca_key, signer_key = key(), key(), key()
    root = cert(name("Kavach Test SGX Root CA"), root_key, name("Kavach Test SGX Root CA"), root_key, True, 1)
    pckca = cert(name("Kavach Test PCK Platform CA"), pckca_key, root.subject, root_key, True, 0)
    signer = cert(name("Kavach Test TCB Signing"), signer_key, root.subject, root_key, False)

    def leaf(comps, pcesvn):
        k = key()
        c = cert(name("Kavach Test PCK Certificate"), k, pckca.subject, pckca_key, False, extra=sgx_ext(comps, pcesvn))
        return k, c, pem(c, pckca, root)

    up_k, up_c, up_chain = leaf(SGX_LEVELS[0][0], 13)
    sw_k, sw_c, sw_chain = leaf(SGX_LEVELS[1][0], 12)
    old_k, old_c, old_chain = leaf(SGX_LEVELS[2][0], 10)
    rv_k, rv_c, rv_chain = leaf(SGX_LEVELS[3][0], 5)
    low_k, low_c, low_chain = leaf([0] * 16, 1)
    gone_k, gone_c, gone_chain = leaf(SGX_LEVELS[0][0], 13)
    # UpToDate components with a PCESVN of 12: the PCE alone drops it a level.
    pce_k, pce_c, pce_chain = leaf(SGX_LEVELS[0][0], 12)

    tee = lambda minor, major, comp2: bytes([minor, major, comp2]) + bytes(13)
    out = []
    out.append("# kavach — generated by scripts/gen-collateral-vectors.py; do not edit by hand.")
    out.append("# SGX v3 and TDX v4 quotes in Intel's layout with their collateral, all under")
    out.append("# \"Kavach Test SGX Root CA\". Certificates 2026-01-01..2036-01-01; collateral and")
    out.append("# CRLs issued 2026-06-01, next update 2026-07-01. See the generator for what")
    out.append("# each quote holds.")
    out.append("var KC_NOW = %d;          # 2026-06-15" % int(NOW.timestamp()))
    out.append("var KC_NOW_STALE = %d;    # 2026-07-02, after every nextUpdate" % int(datetime.datetime(2026, 7, 2, tzinfo=UTC).timestamp()))
    out.append("var KC_NOW_EARLY = %d;    # 2026-05-31, before every issueDate" % int(datetime.datetime(2026, 5, 31, tzinfo=UTC).timestamp()))
    out.append('var KC_MRENCLAVE = "%s";' % MRENCLAVE.hex())
    out.append('var KC_MRTD = "%s";' % MRTD.hex())
    for i in range(4):
        out.append('var KC_RTMR%d = "%s";' % (i, RTMR[i].hex()))
    emit("KC_ROOT", root.public_bytes(serialization.Encoding.DER), out)
    emit("KC_SIGNER_CHAIN", pem(signer, root), out)
    # SGX: one quote per platform TCB, a debug enclave, a QE out of date, a
    # revoked PCK certificate, and a platform below every TCB level.
    emit("KC_SGX", sgx_quote(up_k, up_chain), out)
    emit("KC_SGX_SW", sgx_quote(sw_k, sw_chain), out)
    emit("KC_SGX_OLD", sgx_quote(old_k, old_chain), out)
    emit("KC_SGX_REVOKED_TCB", sgx_quote(rv_k, rv_chain), out)
    emit("KC_SGX_LOW", sgx_quote(low_k, low_chain), out)
    emit("KC_SGX_DEBUG", sgx_quote(up_k, up_chain, debug=True), out)
    emit("KC_SGX_QE_OLD", sgx_quote(up_k, up_chain, qe_isvsvn=6), out)
    emit("KC_SGX_GONE", sgx_quote(gone_k, gone_chain), out)
    emit("KC_SGX_PCESVN_LOW", sgx_quote(pce_k, pce_chain), out)
    # TDX: TEE_TCB_SVN[1] is the module's major version; 1 selects TDX_01.
    emit("KC_TDX", tdx_quote(up_k, up_chain, tee(3, 1, 3)), out)
    emit("KC_TDX_DEBUG", tdx_quote(up_k, up_chain, tee(3, 1, 3), debug=True), out)
    emit("KC_TDX_MODULE_OLD", tdx_quote(up_k, up_chain, tee(2, 1, 3)), out)
    emit("KC_TDX_COMP_OLD", tdx_quote(up_k, up_chain, tee(3, 1, 2)), out)
    emit("KC_TDX_MODULE_0", tdx_quote(up_k, up_chain, tee(3, 0, 3)), out)
    emit("KC_TDX_MODULE_2", tdx_quote(up_k, up_chain, tee(3, 2, 3)), out)
    emit("KC_TDX_SEAM_SIGNER", tdx_quote(up_k, up_chain, tee(3, 1, 3), mrsignerseam=bytes([0x99]) * 48), out)
    emit("KC_SGX_TCB_INFO", tcb_info("SGX", signer_key), out)
    emit("KC_TDX_TCB_INFO", tcb_info("TDX", signer_key), out)
    emit("KC_SGX_TCB_INFO_V2", tcb_info("SGX", signer_key, version=2), out)
    emit("KC_QE_IDENTITY", qe_identity("QE", signer_key), out)
    emit("KC_TD_QE_IDENTITY", qe_identity("TD_QE", signer_key), out)
    emit("KC_QE_IDENTITY_OTHER", qe_identity("QE", signer_key, mrsigner=bytes([0x77]) * 32), out)
    # Attributes the QE does not have: 0x31 sets bit 5 of byte 0, which the
    # mask (0xFB) keeps and the QE's 0x11 lacks.
    emit("KC_QE_IDENTITY_ATTR", qe_identity("QE", signer_key, attributes="31000000000000000000000000000000"), out)
    # Out of date at KC_NOW: next update 2026-06-10.
    stale = datetime.datetime(2026, 6, 10, tzinfo=UTC)
    emit("KC_SGX_TCB_INFO_STALE", tcb_info("SGX", signer_key, next_update=stale), out)
    emit("KC_QE_IDENTITY_STALE", qe_identity("QE", signer_key, next_update=stale), out)
    # A TCB Signing certificate under another root, signing genuine-looking TCB info.
    other_root_key, other_signer_key = key(), key()
    other_root = cert(name("Kavach Test Other Root"), other_root_key, name("Kavach Test Other Root"), other_root_key, True, 1)
    other_signer = cert(name("Kavach Test TCB Signing"), other_signer_key, other_root.subject, other_root_key, False)
    emit("KC_OTHER_SIGNER_CHAIN", pem(other_signer, other_root), out)
    emit("KC_SGX_TCB_INFO_OTHER_SIGNER", tcb_info("SGX", other_signer_key), out)
    # Signed by the PCK CA with a key that is not its own: well-formed, and wrong.
    emit("KC_SGX_TCB_INFO_FORGED", tcb_info("SGX", pckca_key), out)
    emit("KC_PCK_CRL", crl(pckca, pckca_key, [gone_c.serial_number]), out)
    emit("KC_ROOT_CRL", crl(root, root_key, []), out)
    emit("KC_ROOT_CRL_PCKCA", crl(root, root_key, [pckca.serial_number]), out)
    emit("KC_ROOT_CRL_SIGNER", crl(root, root_key, [signer.serial_number]), out)
    emit("KC_PCK_CRL_BY_ROOT", crl(root, root_key, []), out)
    print("\n".join(out))


if __name__ == "__main__":
    main()
