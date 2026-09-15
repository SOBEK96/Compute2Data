"""Testnet attestation STAND-IN fixtures for the Compute2Data test suite.

These builders emit DCAP-SHAPED binary quotes -- a 48-byte Quote Header, a
384-byte ISV Enclave Report, and an ECDSA signature section -- signed with real
ECDSA P-256 keys. They are NOT genuine Intel-issued DCAP quotes: the
certification section uses the contract's project-defined compact stand-in layout
(not a real X.509 PCK chain), and the collateral uses the project-defined
stand-in JSON (not Intel PCS TCB Info). See contracts/c2d_marketplace.py's module
header and docs/attestation-roadmap.md for the full stand-in vs. production
boundary.

The contract parses the exact same stand-in byte layout and ECDSA-verifies the
signature chain on chain against the deployed root anchor, so a quote built here
either verifies (every link is a valid signature rooted at that anchor) or is
rejected (a link was tampered). Signing runs host-side with the `cryptography`
library; the contract ships its own pure-Python P-256 verifier over the identical
curve, hash, and r||s encoding.

TRUST ANCHOR NOTE: this harness signs under TEST anchors whose PRIVATE halves are
the deterministic scalars below. They are deliberately DIFFERENT from the genuine
Intel roots the contract pins by default, so these harness quotes verify only
when the contract is deployed with the test-only override anchors (see
tests' direct_deploy fixture). assert_pinned_keys_match() fails loudly if the
test public keys ever drift from the vectors below.
"""

import hashlib
import json
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


# =============================================================================
# Deterministic test key material (private scalars live only in the harness).
# =============================================================================
# TEST-only roots. Their public halves are injected into the contract via the
# constructor's test-only override args -- they are NOT the genuine Intel keys
# the contract pins by default.
_ROOT_D = 0xC2D0000000000000000000000000000000000000000000000000000000000001
_TCB_D = 0xC2D0000000000000000000000000000000000000000000000000000000000002
# Per-platform chain below the pinned root (intermediate + PCK leaf) and the
# per-enclave keys (attestation key, quoting-enclave signer). Fixed so quotes are
# reproducible; in production these rotate per platform/enclave.
_INTERMEDIATE_D = 0xC2D0000000000000000000000000000000000000000000000000000000000011
_PCK_D = 0xC2D0000000000000000000000000000000000000000000000000000000000012
_ATT_D = 0xC2D0000000000000000000000000000000000000000000000000000000000021

# TEST-ONLY trust anchors for isolated direct-VM unit testing. Their private
# halves are the _ROOT_D / _TCB_D scalars above and live only in this harness.
# These are NOT Intel keys: the contract's default deployment pins the genuine
# Intel SGX Root CA / TCB Signing keys, and a production-style deployment rejects
# quotes minted under these test anchors (asserted by the production-default
# regression test).
TEST_SGX_ROOT_CA_PUBKEY = (
    "7904dfa02118e315c4b9576a70ef3e16b7979c9ce47a9c347726f1d196cb65fa"
    "cdbbda90d2d85ed82142ad18ba5872e06ccc679b2e59230d0a8549049c8485ba"
)
TEST_TCB_SIGNING_PUBKEY = (
    "e00be39d659c4e447e683160ffc649d58ac7ae502783b9e03649d5c877c7ae0e"
    "103ee3e3dc16ee86d43451d72a08f645ea48290ff22b4dc003aea938744085a2"
)

# Mirrors contracts/c2d_marketplace.py.
TCB_COLLATERAL_DOMAIN = "c2d-tcb-collateral-v1"
DEFAULT_FMSPC = "00906ea10000"


def _priv(d):
    return ec.derive_private_key(d, ec.SECP256R1())


def _pub_xy(priv):
    nums = priv.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _sign(priv, message):
    """ECDSA P-256 over SHA-256(message), returned as raw 64-byte r||s."""
    der = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


_ROOT = _priv(_ROOT_D)
_TCB = _priv(_TCB_D)
_INTERMEDIATE = _priv(_INTERMEDIATE_D)
_PCK = _priv(_PCK_D)
_ATT = _priv(_ATT_D)


def assert_pinned_keys_match():
    """Guard against the test keys drifting away from the test vectors."""
    assert _pub_xy(_ROOT).hex() == TEST_SGX_ROOT_CA_PUBKEY, "root key drift"
    assert _pub_xy(_TCB).hex() == TEST_TCB_SIGNING_PUBKEY, "tcb key drift"


# =============================================================================
# Binary DCAP v3 quote packing (byte layout matches the contract parser).
# =============================================================================
_Q_REPORT_LEN = 384
_R_REPORT_DATA = 320
_CERT_DATA_TYPE_COMPACT = 0x0101


def _report_body(*, mrenclave: bytes, mrsigner: bytes, isv_svn: int, report_data: bytes) -> bytes:
    """Assemble a 384-byte SGX report body with fields at their real offsets."""
    assert len(mrenclave) == 32 and len(mrsigner) == 32 and len(report_data) == 64
    body = bytearray(_Q_REPORT_LEN)
    body[64:96] = mrenclave            # mr_enclave
    body[128:160] = mrsigner           # mr_signer
    body[256:258] = (0).to_bytes(2, "little")        # isv_prod_id
    body[258:260] = isv_svn.to_bytes(2, "little")    # isv_svn
    body[_R_REPORT_DATA:_R_REPORT_DATA + 64] = report_data
    return bytes(body)


def expected_report_data(dataset_id: str, compute_spec_hash: str, output_data_hash: str) -> bytes:
    """Reproduce the contract's canonical report_data binding byte-for-byte."""
    payload = (
        dataset_id.encode("utf-8")
        + bytes.fromhex(compute_spec_hash)
        + bytes.fromhex(output_data_hash)
    )
    return hashlib.sha256(payload).digest() + (b"\x00" * 32)


def _compact_cert_data(fmspc: str) -> bytes:
    """STAND-IN certification data: fmspc + PCK leaf + intermediate, each key
    signed by its issuer so the chain verifies up to the deployed root anchor.
    Not a real X.509 PCK chain (see the module header)."""
    pck_pub = _pub_xy(_PCK)
    inter_pub = _pub_xy(_INTERMEDIATE)
    sig_leaf_by_intermediate = _sign(_INTERMEDIATE, pck_pub)
    sig_intermediate_by_root = _sign(_ROOT, inter_pub)
    return (
        bytes.fromhex(fmspc)
        + pck_pub
        + inter_pub
        + sig_leaf_by_intermediate
        + sig_intermediate_by_root
    )


def build_binary_quote(
    *,
    mrenclave: str,
    mrsigner: str,
    report_data: bytes,
    isv_svn: int = 3,
    fmspc: str = DEFAULT_FMSPC,
    tamper_signature: bool = False,
) -> str:
    """Build a complete binary DCAP v3 quote and return it as a hex string.

    The attestation key signs the header+report; the QE report binds the
    attestation key; the PCK leaf signs the QE report; and the PCK chain is
    signed up to the pinned root. tamper_signature zeroes the ISV report
    signature so the contract's on-chain chain check fails as SIGNATURE_INVALID.
    """
    # Quote Header (48 bytes): v3, ECDSA-256-with-P-256 (att_key_type 2).
    header = bytearray(48)
    header[0:2] = (3).to_bytes(2, "little")   # version
    header[2:4] = (2).to_bytes(2, "little")   # att_key_type
    header[8:10] = (7).to_bytes(2, "little")  # qe_svn
    header[10:12] = (13).to_bytes(2, "little")  # pce_svn

    report = _report_body(
        mrenclave=bytes.fromhex(mrenclave),
        mrsigner=bytes.fromhex(mrsigner),
        isv_svn=isv_svn,
        report_data=report_data,
    )
    signed_region = bytes(header) + report

    att_pub = _pub_xy(_ATT)
    isv_sig = _sign(_ATT, signed_region)
    if tamper_signature:
        isv_sig = b"\x00" * 64

    # QE report binds the attestation key: report_data = sha256(att_pub || auth).
    qe_auth_data = b""
    qe_bind = hashlib.sha256(att_pub + qe_auth_data).digest()
    qe_report = _report_body(
        mrenclave=b"\xee" * 32,
        mrsigner=b"\xff" * 32,
        isv_svn=5,
        report_data=qe_bind + (b"\x00" * 32),
    )
    qe_report_sig = _sign(_PCK, qe_report)

    cert_data = _compact_cert_data(fmspc)

    sig_section = bytearray()
    sig_section += isv_sig
    sig_section += att_pub
    sig_section += qe_report
    sig_section += qe_report_sig
    sig_section += len(qe_auth_data).to_bytes(2, "little")
    sig_section += qe_auth_data
    sig_section += _CERT_DATA_TYPE_COMPACT.to_bytes(2, "little")
    sig_section += len(cert_data).to_bytes(4, "little")
    sig_section += cert_data

    quote = signed_region + len(sig_section).to_bytes(4, "little") + bytes(sig_section)
    return quote.hex()


# =============================================================================
# Intel PCS / DCAP collateral service simulation (signed TCB status).
# =============================================================================
def sign_tcb_collateral(fmspc: str, tcb_status: str) -> str:
    """Produce the hex ECDSA signature the contract verifies against the pinned
    Intel TCB signing key for the collateral response."""
    message = (TCB_COLLATERAL_DOMAIN + "|" + fmspc + "|" + tcb_status).encode("utf-8")
    return _sign(_TCB, message).hex()


def collateral_response(fmspc: str, tcb_status: str = "UpToDate") -> bytes:
    body = {
        "fmspc": fmspc,
        "tcbStatus": tcb_status,
        "signature": sign_tcb_collateral(fmspc, tcb_status),
    }
    return json.dumps(body).encode("utf-8")


def tcb_collateral_handler(data):
    """Live web handler standing in for the Intel PCS TCB collateral service.

    Reads the fmspc query parameter the contract appends and returns a
    test-signed (stand-in) UpToDate TCB status in the gltest live-handler shape.
    This is the project-defined stand-in JSON, not Intel's real PCS TCB Info.
    """
    url = data.get("url", "") if isinstance(data, dict) else ""
    params = parse_qs(urlparse(url).query)
    fmspc = (params.get("fmspc", [DEFAULT_FMSPC]) or [DEFAULT_FMSPC])[0]
    body = collateral_response(fmspc, "UpToDate")
    return {"ok": {"response": {"status": 200, "headers": {}, "body": body}}}
