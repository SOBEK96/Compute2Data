"""Intel SGX DCAP attestation fixtures for the Compute2Data test suite.

Two kinds of evidence are produced here, both in Intel's real formats:

1. GENUINE INTEL VECTORS (test/fixtures/intel_sgx/). A real SGX ECDSA v3 quote
   issued on Intel hardware, whose cert_data_type 5 PCK chain terminates at the
   real Intel SGX Root CA, plus the genuine Intel PCS collateral for its FMSPC
   (TCB Info, QE Identity, TCB Signing chain, PCK CRL, Root CA CRL). These
   verify against the contract's DEFAULT deployment, which pins the Intel root.
   See test/fixtures/intel_sgx/README.md for provenance and validity windows.

2. HARNESS-SIGNED EVIDENCE for job-lifecycle tests. A real SGX quote's
   report_data cannot be made to bind a test job, so the harness runs its own
   X.509 PKI in exactly Intel's formats: a root CA, a PCK CA, a PCK leaf that
   carries the Intel SGX extension (OID 1.2.840.113741.1.13.1), a TCB Signing
   certificate, ECDSA-signed X.509 CRLs, TCB Info v3 and QE Identity v2 JSON
   signed the way Intel PCS signs them, and v3 quotes with cert_data_type 5.
   The contract parses these with the same code path as the genuine vectors.
   They verify only when the contract is deployed with the harness root
   (TEST_SGX_ROOT_CA_PUBKEY, via the constructor's test-only argument); the
   production default rejects them (asserted in the regression suite).

LEGACY FORMATS (build_legacy_compact_quote, legacy_simulated_collateral) rebuild
the project-defined compact certificate chain (cert_data_type 0x0101) and the
{fmspc, tcbStatus, signature} collateral that earlier versions of the contract
accepted. They exist only so the regression suite can prove both are rejected.
"""

import datetime as _dt
import hashlib
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID


# =============================================================================
# Genuine Intel vectors
# =============================================================================
INTEL_VECTOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "intel_sgx")
# Inside every validity window of the stored quote and collateral.
INTEL_VECTOR_TIME = "2026-09-23T00:00:00Z"
INTEL_VECTOR_FMSPC = "00a067110000"
INTEL_VECTOR_MRENCLAVE = "33d8736db756ed4997e04ba358d27833188f1932ff7b1d156904d3f560452fbb"
INTEL_VECTOR_MRSIGNER = "815f42f11cf64430c30bab7816ba596a1da0130c3b028b673133a66cf9a3e0e6"
# Platform status for this quote under the stored collateral, as computed
# independently by Phala's dcap-qvl verifier (see the fixture README).
INTEL_VECTOR_TCB_STATUS = "OutOfDateConfigurationNeeded"
INTEL_SGX_ROOT_CA_PUBKEY = (
    "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5"
    "67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394"
)


def _read_vector(name: str) -> str:
    with open(os.path.join(INTEL_VECTOR_DIR, name), "r", encoding="ascii") as handle:
        return handle.read()


def intel_vector_quote_hex() -> str:
    return _read_vector("sgx_quote.hex").strip()


def intel_vector_collateral(tcb_info_file: str = "tcb_info_00a067110000.json") -> dict:
    chain = _read_vector("tcb_signing_issuer_chain.pem")
    return {
        "tcb_info": _read_vector(tcb_info_file),
        "tcb_info_issuer_chain": chain,
        "qe_identity": _read_vector("qe_identity.json"),
        "qe_identity_issuer_chain": chain,
        "pck_crl": _read_vector("pck_crl_processor.der.hex").strip(),
        "root_ca_crl": _read_vector("root_ca_crl.der.hex").strip(),
    }


# =============================================================================
# Harness PKI (deterministic keys; private scalars live only in this file)
# =============================================================================
_ROOT_D = 0xC2D0000000000000000000000000000000000000000000000000000000000001
_TCB_D = 0xC2D0000000000000000000000000000000000000000000000000000000000002
_PCK_CA_D = 0xC2D0000000000000000000000000000000000000000000000000000000000011
_PCK_D = 0xC2D0000000000000000000000000000000000000000000000000000000000012
_ATT_D = 0xC2D0000000000000000000000000000000000000000000000000000000000021
_ROGUE_ROOT_D = 0xC2D00000000000000000000000000000000000000000000000000000000000FF

TEST_SGX_ROOT_CA_PUBKEY = (
    "7904dfa02118e315c4b9576a70ef3e16b7979c9ce47a9c347726f1d196cb65fa"
    "cdbbda90d2d85ed82142ad18ba5872e06ccc679b2e59230d0a8549049c8485ba"
)

DEFAULT_FMSPC = "00906ea10000"
DEFAULT_PCEID = "0000"
# The harness platform's TCB: 16 SGX TCB component SVNs and the PCE SVN.
PLATFORM_TCB_COMPONENTS = [7, 9, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
PLATFORM_PCESVN = 13
# Harness quoting enclave identity.
QE_MRSIGNER = "8c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff"
QE_ISVPRODID = 1
QE_ISVSVN = 8
INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")

# Built at call time: direct mode patches datetime.datetime while a test runs,
# and cryptography type-checks against whichever class is current.
def _utc(*args):
    return _dt.datetime(*args, tzinfo=_dt.timezone.utc)


_VALID_FROM = (2024, 1, 1)
_VALID_UNTIL = (2049, 12, 31, 23, 59, 59)
COLLATERAL_ISSUE_DATE = "2024-01-01T00:00:00Z"
COLLATERAL_NEXT_UPDATE = "2049-12-31T00:00:00Z"


def _priv(d):
    return ec.derive_private_key(d, ec.SECP256R1())


def _pub_xy(priv) -> bytes:
    nums = priv.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _sign_raw(priv, message: bytes) -> bytes:
    """ECDSA P-256 over SHA-256(message) as raw 64-byte r || s (Intel's quote
    and PCS JSON signature encoding)."""
    r, s = decode_dss_signature(priv.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


_ROOT = _priv(_ROOT_D)
_TCB = _priv(_TCB_D)
_PCK_CA = _priv(_PCK_CA_D)
_PCK = _priv(_PCK_D)
_ATT = _priv(_ATT_D)
_ROGUE_ROOT = _priv(_ROGUE_ROOT_D)


def assert_pinned_keys_match():
    """Guard against the harness root drifting away from its published key."""
    assert _pub_xy(_ROOT).hex() == TEST_SGX_ROOT_CA_PUBKEY, "root key drift"


# ---- minimal DER encoder for the Intel SGX PCK certificate extension --------
def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    size = (n.bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + n.to_bytes(size, "big") + body


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(reversed(chunk))
    return _der(0x06, body)


def _der_int(value: int) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return _der(0x02, body)


_SGX = "1.2.840.113741.1.13.1"


def _sgx_extension(fmspc: str, pceid: str, components, pcesvn: int) -> bytes:
    tcb = b""
    for i, svn in enumerate(components):
        tcb += _der(0x30, _der_oid(f"{_SGX}.2.{i + 1}") + _der_int(svn))
    tcb += _der(0x30, _der_oid(f"{_SGX}.2.17") + _der_int(pcesvn))
    tcb += _der(0x30, _der_oid(f"{_SGX}.2.18") + _der(0x04, bytes(components)))
    return _der(
        0x30,
        _der(0x30, _der_oid(f"{_SGX}.1") + _der(0x04, bytes(range(16))))
        + _der(0x30, _der_oid(f"{_SGX}.2") + _der(0x30, tcb))
        + _der(0x30, _der_oid(f"{_SGX}.3") + _der(0x04, bytes.fromhex(pceid)))
        + _der(0x30, _der_oid(f"{_SGX}.4") + _der(0x04, bytes.fromhex(fmspc)))
        + _der(0x30, _der_oid(f"{_SGX}.5") + _der(0x0A, b"\x00")),
    )


# ---- certificates -----------------------------------------------------------
def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Compute2Data Test Harness"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


_ROOT_NAME = _name("C2D Harness SGX Root CA")
_PCK_CA_NAME = _name("C2D Harness SGX PCK Processor CA")


def _certificate(subject, issuer, pub, signer, serial, is_ca, extra=None, valid_until=_VALID_UNTIL):
    usage = x509.KeyUsage(
        digital_signature=not is_ca, content_commitment=not is_ca, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=is_ca, crl_sign=is_ca,
        encipher_only=False, decipher_only=False,
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(serial)
        .not_valid_before(_utc(*_VALID_FROM))
        .not_valid_after(_utc(*valid_until))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(usage, critical=True)
    )
    for ext in extra or []:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(signer, hashes.SHA256())


def _pem(*certs) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs)


_ROOT_CERT = _certificate(_ROOT_NAME, _ROOT_NAME, _ROOT.public_key(), _ROOT, 0x2001, True)
_ROGUE_ROOT_CERT = _certificate(_ROOT_NAME, _ROOT_NAME, _ROGUE_ROOT.public_key(), _ROGUE_ROOT, 0x2002, True)
_PCK_CA_CERT = _certificate(_PCK_CA_NAME, _ROOT_NAME, _PCK_CA.public_key(), _ROOT, 0x2011, True)
_TCB_SIGNING_CERT = _certificate(
    _name("C2D Harness SGX TCB Signing"), _ROOT_NAME, _TCB.public_key(), _ROOT, 0x2021, False
)
PCK_CERT_SERIAL = 0x2031


def _pck_certificate(components=None, pcesvn=PLATFORM_PCESVN, fmspc=DEFAULT_FMSPC, ca_key=_PCK_CA, valid_until=_VALID_UNTIL):
    ext = x509.UnrecognizedExtension(
        x509.ObjectIdentifier(_SGX),
        _sgx_extension(fmspc, DEFAULT_PCEID, components or PLATFORM_TCB_COMPONENTS, pcesvn),
    )
    return _certificate(
        _name("C2D Harness SGX PCK Certificate"), _PCK_CA_NAME, _PCK.public_key(), ca_key,
        PCK_CERT_SERIAL, False, extra=[ext], valid_until=valid_until,
    )


_PCK_CERT = _pck_certificate()


# ---- CRLs ---------------------------------------------------------------------
def _crl(issuer_name, signer, revoked_serials=(), next_update=_VALID_UNTIL) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name)
        .last_update(_utc(*_VALID_FROM))
        .next_update(_utc(*next_update))
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(_utc(*_VALID_FROM)).build()
        )
    return builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def pck_crl_hex(revoked_serials=()) -> str:
    return _crl(_PCK_CA_NAME, _PCK_CA, revoked_serials).hex()


def root_ca_crl_hex(revoked_serials=()) -> str:
    return _crl(_ROOT_NAME, _ROOT, revoked_serials).hex()


def root_ca_crl_pem() -> str:
    der = bytes.fromhex(root_ca_crl_hex())
    crl = x509.load_der_x509_crl(der)
    return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")


# ---- PCS JSON (signed over the exact serialized inner object) ------------------
def _signed_document(member: str, body: dict, signer=_TCB, tamper: bool = False) -> str:
    inner = json.dumps(body, separators=(",", ":"))
    signature = _sign_raw(signer, inner.encode("utf-8")).hex()
    if tamper:
        inner = inner.replace('"UpToDate"', '"UpToDatX"', 1)
    return '{"' + member + '":' + inner + ',"signature":"' + signature + '"}'


def _tcb_level(components, pcesvn, status):
    return {
        "tcb": {"sgxtcbcomponents": [{"svn": svn} for svn in components], "pcesvn": pcesvn},
        "tcbDate": "2023-08-09T00:00:00Z",
        "tcbStatus": status,
    }


def tcb_info_json(
    platform_status: str = "UpToDate",
    fmspc: str = DEFAULT_FMSPC,
    issue_date: str = COLLATERAL_ISSUE_DATE,
    next_update: str = COLLATERAL_NEXT_UPDATE,
    tamper: bool = False,
    signer=_TCB,
) -> str:
    """TCB Info v3. The first level the harness platform satisfies carries
    platform_status; a stricter level above it is never satisfied."""
    above = [svn + 1 for svn in PLATFORM_TCB_COMPONENTS[:2]] + PLATFORM_TCB_COMPONENTS[2:]
    body = {
        "id": "SGX",
        "version": 3,
        "issueDate": issue_date,
        "nextUpdate": next_update,
        "fmspc": fmspc.upper(),
        "pceId": DEFAULT_PCEID,
        "tcbType": 0,
        "tcbEvaluationDataNumber": 17,
        "tcbLevels": [
            _tcb_level(above, PLATFORM_PCESVN, "UpToDate"),
            _tcb_level(PLATFORM_TCB_COMPONENTS, PLATFORM_PCESVN, platform_status),
            _tcb_level([0] * 16, 0, "OutOfDate"),
        ],
    }
    if platform_status == "UpToDate":
        body["tcbLevels"] = body["tcbLevels"][1:]
    return _signed_document("tcbInfo", body, signer=signer, tamper=tamper)


def qe_identity_json(
    qe_status: str = "UpToDate",
    mrsigner: str = QE_MRSIGNER,
    next_update: str = COLLATERAL_NEXT_UPDATE,
) -> str:
    body = {
        "id": "QE",
        "version": 2,
        "issueDate": COLLATERAL_ISSUE_DATE,
        "nextUpdate": next_update,
        "tcbEvaluationDataNumber": 17,
        "miscselect": "00000000",
        "miscselectMask": "FFFFFFFF",
        "attributes": "11000000000000000000000000000000",
        "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
        "mrsigner": mrsigner.upper(),
        "isvprodid": QE_ISVPRODID,
        "tcbLevels": [
            {"tcb": {"isvsvn": QE_ISVSVN}, "tcbDate": "2023-08-09T00:00:00Z", "tcbStatus": qe_status},
            {"tcb": {"isvsvn": 0}, "tcbDate": "2018-08-15T00:00:00Z", "tcbStatus": "OutOfDate"},
        ],
    }
    return _signed_document("enclaveIdentity", body)


def build_collateral(**overrides) -> dict:
    """Harness PCS collateral in the exact Intel PCS v4 shapes."""
    chain = _pem(_TCB_SIGNING_CERT, _ROOT_CERT)
    collateral = {
        "tcb_info": tcb_info_json(),
        "tcb_info_issuer_chain": chain,
        "qe_identity": qe_identity_json(),
        "qe_identity_issuer_chain": chain,
        "pck_crl": pck_crl_hex(),
        "root_ca_crl": root_ca_crl_hex(),
    }
    collateral.update(overrides)
    return collateral


# =============================================================================
# SGX ECDSA quote v3 (cert_data_type 5)
# =============================================================================
_Q_REPORT_LEN = 384


def _report_body(*, mrenclave: bytes, mrsigner: bytes, report_data: bytes, attributes: bytes,
                 isv_prodid: int = 0, isv_svn: int = 3) -> bytes:
    body = bytearray(_Q_REPORT_LEN)
    body[48:64] = attributes
    body[64:96] = mrenclave
    body[128:160] = mrsigner
    body[256:258] = isv_prodid.to_bytes(2, "little")
    body[258:260] = isv_svn.to_bytes(2, "little")
    body[320:384] = report_data
    return bytes(body)


def expected_report_data(dataset_id: str, compute_spec_hash: str, output_data_hash: str) -> bytes:
    """Reproduce the contract's canonical report_data binding byte-for-byte."""
    payload = dataset_id.encode("utf-8") + bytes.fromhex(compute_spec_hash) + bytes.fromhex(output_data_hash)
    return hashlib.sha256(payload).digest() + (b"\x00" * 32)


def _header(vendor_id: bytes = INTEL_QE_VENDOR_ID) -> bytes:
    header = bytearray(48)
    header[0:2] = (3).to_bytes(2, "little")    # version 3
    header[2:4] = (2).to_bytes(2, "little")    # ECDSA-256-with-P-256
    header[8:10] = QE_ISVSVN.to_bytes(2, "little")
    header[10:12] = PLATFORM_PCESVN.to_bytes(2, "little")
    header[12:28] = vendor_id
    return bytes(header)


def _assemble(signed_region: bytes, cert_type: int, cert_data: bytes, *, tamper_signature: bool = False,
              pck_key=_PCK) -> bytes:
    att_pub = _pub_xy(_ATT)
    isv_sig = b"\x00" * 64 if tamper_signature else _sign_raw(_ATT, signed_region)
    qe_auth_data = bytes(range(32))
    qe_report = _report_body(
        mrenclave=b"\xee" * 32,
        mrsigner=bytes.fromhex(QE_MRSIGNER),
        report_data=hashlib.sha256(att_pub + qe_auth_data).digest() + (b"\x00" * 32),
        attributes=bytes.fromhex("15000000000000000700000000000000"),
        isv_prodid=QE_ISVPRODID,
        isv_svn=QE_ISVSVN,
    )
    sig = (
        isv_sig + att_pub + qe_report + _sign_raw(pck_key, qe_report)
        + len(qe_auth_data).to_bytes(2, "little") + qe_auth_data
        + cert_type.to_bytes(2, "little") + len(cert_data).to_bytes(4, "little") + cert_data
    )
    return signed_region + len(sig).to_bytes(4, "little") + sig


def build_binary_quote(
    *,
    mrenclave: str,
    mrsigner: str,
    report_data: bytes,
    tamper_signature: bool = False,
    debug: bool = False,
    pck_chain_pem: str = "",
) -> str:
    """An SGX ECDSA v3 quote whose certification data is a PEM X.509 PCK chain."""
    attributes = bytearray(16)
    attributes[0] = 0x07 if debug else 0x05     # INIT | MODE64BIT (| DEBUG)
    attributes[8] = 0xE7
    report = _report_body(
        mrenclave=bytes.fromhex(mrenclave), mrsigner=bytes.fromhex(mrsigner),
        report_data=report_data, attributes=bytes(attributes),
    )
    chain = pck_chain_pem or _pem(_PCK_CERT, _PCK_CA_CERT, _ROOT_CERT)
    cert_data = chain.encode("ascii") + b"\x00"
    return _assemble(_header() + report, 5, cert_data, tamper_signature=tamper_signature).hex()


def rogue_root_pck_chain_pem() -> str:
    """A structurally perfect PCK chain whose root carries the harness root's
    name but a different key -- i.e. anyone's self-made 'root'."""
    rogue_ca = _certificate(_PCK_CA_NAME, _ROOT_NAME, _PCK_CA.public_key(), _ROGUE_ROOT, 0x2012, True)
    return _pem(_PCK_CERT, rogue_ca, _ROGUE_ROOT_CERT)


def expired_pck_chain_pem() -> str:
    expired_leaf = _pck_certificate(valid_until=(2025, 1, 1))
    return _pem(expired_leaf, _PCK_CA_CERT, _ROOT_CERT)


# =============================================================================
# Legacy (previously accepted, now rejected) formats
# =============================================================================
_LEGACY_CERT_DATA_TYPE_COMPACT = 0x0101


def build_legacy_compact_quote(*, mrenclave: str, mrsigner: str, report_data: bytes,
                               vendor_id: bytes = b"\x00" * 16) -> str:
    """The project-defined compact certificate chain earlier contract versions
    accepted: cert_data_type 0x0101 carrying fmspc || PCK key || CA key ||
    sig(PCK key by CA) || sig(CA key by root), all signed by the harness root.
    vendor_id defaults to the zero bytes those quotes used; pass the Intel QE
    vendor id to isolate the certification-data check."""
    report = _report_body(
        mrenclave=bytes.fromhex(mrenclave), mrsigner=bytes.fromhex(mrsigner),
        report_data=report_data, attributes=bytes.fromhex("05000000000000000700000000000000"),
    )
    pck_pub = _pub_xy(_PCK)
    ca_pub = _pub_xy(_PCK_CA)
    cert_data = (
        bytes.fromhex(DEFAULT_FMSPC) + pck_pub + ca_pub
        + _sign_raw(_PCK_CA, pck_pub) + _sign_raw(_ROOT, ca_pub)
    )
    return _assemble(_header(vendor_id) + report, _LEGACY_CERT_DATA_TYPE_COMPACT, cert_data).hex()


def legacy_simulated_collateral(fmspc: str = DEFAULT_FMSPC, status: str = "UpToDate") -> dict:
    """The project-defined {fmspc, tcbStatus, signature} collateral earlier
    contract versions accepted, signed by the harness TCB key under the old
    'c2d-tcb-collateral-v1' domain tag."""
    message = ("c2d-tcb-collateral-v1|" + fmspc + "|" + status).encode("utf-8")
    return {"fmspc": fmspc, "tcbStatus": status, "signature": _sign_raw(_TCB, message).hex()}
