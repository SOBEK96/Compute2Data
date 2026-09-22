"""Parametrized boundary regression for the Compute2Data domain logic.

This suite locks in every domain-specific threshold and bracket boundary by
calling the contract's module-level pure helper functions directly, WITHOUT a
per-test VM fixture. The helpers under test (_is_hex_of_bytes,
_check_job_binding, _parse_evidence_envelope, _expected_report_data, the DER /
ECDSA / signed-JSON primitives, _validate_production_id) are pure, so
exercising them in-process runs in well under a millisecond each and pins the
exact boundary at which each threshold flips.

End-to-end authenticity (X.509 PCK chain, CRLs, PCS collateral, genuine Intel
vectors) is exercised in test_authentic_attestation.py.

The contract module is imported once (module-scoped fixture) using the same SDK
loader the direct plugin uses; the imported module object is held for the whole
file, so it keeps working even if a sibling VM-based suite evicts SDK modules
from sys.modules during its own teardown.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest


CONTRACT_PATH = "contracts/c2d_marketplace.py"

# Make the primary test/ dir importable so we can reuse the DCAP quote packer.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PRIMARY_TEST_DIR = os.path.join(_ROOT, "test")
if _PRIMARY_TEST_DIR not in sys.path:
    sys.path.insert(0, _PRIMARY_TEST_DIR)

from dcap_fixtures import INTEL_SGX_ROOT_CA_PUBKEY, expected_report_data  # noqa: E402


@pytest.fixture(scope="module")
def c2d():
    """Load the contract module once and expose its pure helpers (no VM).

    The module is loaded through the same SDK loader the direct plugin uses.
    The pure helpers close over the module's own globals (hashlib / json), so
    once imported they keep working without any SDK module remaining in
    sys.modules. On teardown we mirror the VMContext cleanup (path-based SDK
    eviction plus the one-contract registration guard) so this module-scoped
    load never leaks global state into the VM-based sibling suites.
    """
    from gltest.direct.vm import VMContext
    from gltest.direct.loader import load_contract_class
    from gltest.direct import wasi_mock

    vm = VMContext()
    contract_cls = load_contract_class(Path(CONTRACT_PATH), vm)
    module = sys.modules[contract_cls.__module__]

    yield module

    # Replicate VMContext teardown: evict SDK-path modules and the loaded
    # contract module, drop the wasi mock, and remove SDK cache paths so a
    # subsequent direct_deploy re-imports the contract from a clean slate.
    sdk_roots = [p for p in sys.path if "gltest-direct" in p]
    to_remove = []
    for key, mod in sys.modules.items():
        if key.startswith("_contract_") or key.startswith("_deployed_"):
            to_remove.append(key)
            continue
        mod_file = getattr(mod, "__file__", None) or ""
        if any(mod_file.startswith(root) for root in sdk_roots):
            to_remove.append(key)
    for key in to_remove:
        sys.modules.pop(key, None)
    sys.modules.pop("_genlayer_wasi", None)
    sys.path[:] = [p for p in sys.path if "gltest-direct" not in p]
    wasi_mock.clear_vm()


def _spec_commitment(spec: str) -> str:
    return hashlib.sha256(spec.encode("utf-8")).hexdigest()


def _artifact(
    *,
    dataset_commitment="dc",
    input_commitment="ic",
    model_id="mid",
    compute_spec="spec",
    output_commitment="oc",
    result_status="COMPLETED",
    include_compute_spec=True,
):
    artifact = {
        "dataset_commitment": dataset_commitment,
        "input_commitment": input_commitment,
        "model_id": model_id,
        "output_commitment": output_commitment,
        "result_status": result_status,
    }
    if include_compute_spec:
        artifact["compute_spec_commitment"] = _spec_commitment(compute_spec)
    return artifact


def _report_data(*, dataset_id="did", compute_spec="spec", output_commitment="oc", tamper_binding=False):
    """The canonical report_data sha256(dataset_id + compute_spec_hash +
    output_data_hash); tamper_binding binds a different output instead."""
    if tamper_binding:
        output_commitment = output_commitment + "-decoy"
    output_data_hash = hashlib.sha256(output_commitment.encode("utf-8")).hexdigest()
    return expected_report_data(dataset_id, _spec_commitment(compute_spec), output_data_hash)


def _binding(c2d, artifact, report_data, *, dataset_id="did", dataset_commitment="dc",
             input_c="ic", model="mid", spec="spec"):
    return c2d._check_job_binding(
        artifact, report_data, dataset_id, dataset_commitment, input_c, model, _spec_commitment(spec)
    )


# =============================================================================
# _is_hex_of_bytes: exact-length hex bracket
# =============================================================================

@pytest.mark.parametrize(
    "value, byte_length, expected",
    [
        ("ab" * 32, 32, True),        # exact 64 hex chars for 32 bytes
        ("AB" * 32, 32, True),        # uppercase hex is accepted
        ("a" * 63, 32, False),        # one nibble short of the boundary
        ("a" * 65, 32, False),        # one nibble over the boundary
        ("", 32, False),              # empty
        ("zz" * 32, 32, False),       # correct length, non-hex characters
        ("ab", 1, True),              # single-byte boundary
        ("a", 1, False),              # odd length for one byte
        ("abcd", 2, True),            # two-byte boundary
    ],
)
def test_is_hex_of_bytes_boundaries(c2d, value, byte_length, expected):
    assert c2d._is_hex_of_bytes(value, byte_length) is expected


@pytest.mark.parametrize("non_string", [12345, None, b"abcd", ["ab"], {"a": 1}])
def test_is_hex_of_bytes_rejects_non_strings(c2d, non_string):
    assert c2d._is_hex_of_bytes(non_string, 32) is False


# =============================================================================
# _check_job_binding: output_commitment length bracket [1, 256]
# =============================================================================

@pytest.mark.parametrize(
    "length, expect_ok, expect_code",
    [
        (1, True, "NONE"),                          # lower boundary
        (255, True, "NONE"),                        # just inside
        (256, True, "NONE"),                        # exact upper boundary
        (257, False, "OUTPUT_COMMITMENT_INVALID"),  # one over the boundary
    ],
)
def test_output_commitment_length_bracket(c2d, length, expect_ok, expect_code):
    output = "o" * length
    result = _binding(c2d, _artifact(output_commitment=output), _report_data(output_commitment=output))
    assert result["ok"] is expect_ok
    assert result["code"] == expect_code


def test_empty_output_commitment_is_invalid(c2d):
    result = _binding(c2d, _artifact(output_commitment=""), _report_data(output_commitment=""))
    assert result["ok"] is False
    assert result["code"] == "OUTPUT_COMMITMENT_INVALID"


# =============================================================================
# _check_job_binding: deterministic rejection codes for every tampered field
# =============================================================================

@pytest.mark.parametrize(
    "artifact_kwargs, binding_kwargs, on_chain, expect_code",
    [
        # A fully consistent artifact + report_data binds.
        ({}, {}, ("did", "dc", "ic", "mid", "spec"), "NONE"),
        # Each committed artifact field must match the on-chain value.
        ({}, {}, ("did", "OTHER", "ic", "mid", "spec"), "DATASET_MISMATCH"),
        ({}, {}, ("did", "dc", "OTHER", "mid", "spec"), "INPUT_COMMITMENT_MISMATCH"),
        ({}, {}, ("did", "dc", "ic", "OTHER", "spec"), "MODEL_MISMATCH"),
        # An artifact for a different compute spec fails the spec commitment check.
        ({}, {}, ("did", "dc", "ic", "mid", "different-spec"), "COMPUTE_SPEC_MISMATCH"),
        # Omitting the mandatory compute-spec commitment is rejected outright.
        ({"include_compute_spec": False}, {}, ("did", "dc", "ic", "mid", "spec"), "COMPUTE_SPEC_COMMITMENT_INVALID"),
        # report_data sealed over different work is caught by the re-derived binding.
        ({}, {"tamper_binding": True}, ("did", "dc", "ic", "mid", "spec"), "BINDING_MISMATCH"),
        ({}, {"dataset_id": "other-dataset"}, ("did", "dc", "ic", "mid", "spec"), "BINDING_MISMATCH"),
    ],
)
def test_binding_rejection_codes(c2d, artifact_kwargs, binding_kwargs, on_chain, expect_code):
    dataset_id, dataset, input_c, model, spec = on_chain
    result = _binding(
        c2d, _artifact(**artifact_kwargs), _report_data(**binding_kwargs),
        dataset_id=dataset_id, dataset_commitment=dataset, input_c=input_c, model=model, spec=spec,
    )
    assert result["code"] == expect_code
    assert result["ok"] is (expect_code == "NONE")


@pytest.mark.parametrize(
    "malformed",
    ["", "not json", "{", "[]", '"a string"', "42", "null", '{"artifact": {}}', '{"dcap_quote": "00"}'],
)
def test_malformed_envelope_raises_evidence_error(c2d, malformed):
    """A non-object or incomplete envelope is not evidence at all."""
    with pytest.raises(c2d._EvidenceError) as excinfo:
        c2d._parse_evidence_envelope(malformed)
    assert excinfo.value.kind == "ATTESTATION"
    assert excinfo.value.code == "MALFORMED_QUOTE"


# =============================================================================
# _expected_report_data: determinism and full-field coverage
# =============================================================================

def test_expected_report_data_is_deterministic_and_64_bytes(c2d):
    csc = _spec_commitment("spec")
    odh = hashlib.sha256(b"oc").hexdigest()
    a = c2d._expected_report_data("did", csc, odh)
    b = c2d._expected_report_data("did", csc, odh)
    assert a == b
    assert isinstance(a, (bytes, bytearray)) and len(a) == 64
    # The digest occupies the first 32 bytes; the rest is zero padding.
    assert a[32:] == b"\x00" * 32


@pytest.mark.parametrize("field_index", [0, 1, 2])
def test_expected_report_data_changes_when_any_field_changes(c2d, field_index):
    """Every one of the three bound fields (dataset_id, compute_spec_hash,
    output_data_hash) must influence the report_data, so no component of the
    committed work can be swapped without detection."""
    base = ["did", _spec_commitment("spec"), hashlib.sha256(b"oc").hexdigest()]
    mutated = list(base)
    if field_index == 0:
        mutated[0] = base[0] + "-changed"
    else:
        # Perturb a hash field while keeping it valid 32-byte hex.
        mutated[field_index] = hashlib.sha256(base[field_index].encode()).hexdigest()
    assert c2d._expected_report_data(*base) != c2d._expected_report_data(*mutated)


# =============================================================================
# Genuine-format verifier surface: no stand-in path remains
# =============================================================================

def test_only_the_genuine_intel_verifier_is_present(c2d):
    """The compact certificate chain parser, the simulated collateral
    verifier and its domain tag, the placeholder measurements, and the second
    pinned key they relied on are gone. What remains is the X.509 / CRL / PCS
    collateral verifier anchored at the Intel SGX Root CA."""
    for removed in (
        "_parse_dcap_quote",
        "_verify_quote_signature_chain",
        "_verify_tcb_collateral",
        "_inspect_enclave_quote",
        "_CERT_DATA_TYPE_COMPACT",
        "TCB_COLLATERAL_DOMAIN",
        "REPORT_DATA_DOMAIN",
        "DEFAULT_ATTESTATION_ENDPOINT",
        "DEFAULT_ENCLAVE_MEASUREMENT",
        "DEFAULT_ENCLAVE_SIGNER",
        "INTEL_TCB_SIGNING_PUBKEY",
    ):
        assert not hasattr(c2d, removed), removed
    for present in (
        "_verify_sgx_evidence",
        "_parse_sgx_quote",
        "_parse_certificate",
        "_parse_crl",
        "_parse_sgx_extension",
        "_evaluate_tcb_info",
        "_evaluate_qe_identity",
        "_ecdsa_verify",
    ):
        assert hasattr(c2d, present), present
    assert c2d._Q_CERT_DATA_PCK_CHAIN == 5
    assert c2d.INTEL_SGX_ROOT_CA_PUBKEY == INTEL_SGX_ROOT_CA_PUBKEY


# =============================================================================
# DER / ECDSA / signed-JSON strictness
# =============================================================================

@pytest.mark.parametrize(
    "der",
    [
        "30",                  # truncated header
        "3005020101",          # length overruns the buffer
        "30810302010100",      # long-form length for a value < 128 (not minimal)
        "3f0100",              # multi-byte tag
        "308000",              # indefinite length
    ],
)
def test_der_reader_rejects_non_der(c2d, der):
    raw = bytes.fromhex(der)
    with pytest.raises(ValueError):
        c2d._der_items(raw, 0, len(raw))


def test_ecdsa_verify_rejects_out_of_range_and_off_curve_inputs(c2d):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    key = ec.derive_private_key(0x1234, ec.SECP256R1())
    nums = key.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    r, s = decode_dss_signature(key.sign(b"msg", ec.ECDSA(hashes.SHA256())))
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert c2d._ecdsa_verify(pub, b"msg", sig) is True
    assert c2d._ecdsa_verify(pub, b"msh", sig) is False
    assert c2d._ecdsa_verify(pub, b"msg", b"\x00" * 64) is False
    assert c2d._ecdsa_verify(pub, b"msg", c2d._P256_N.to_bytes(32, "big") + sig[32:]) is False
    off_curve = pub[:63] + bytes([pub[63] ^ 1])
    assert c2d._ecdsa_verify(off_curve, b"msg", sig) is False
    assert c2d._ecdsa_verify(pub[:32], b"msg", sig) is False


def test_signed_json_member_is_extracted_verbatim(c2d):
    text = '{"tcbInfo":{"a":"}\\"","b":[1,{"c":2}]} ,"signature":"00"}'
    assert c2d._json_member_text(text, "tcbInfo") == '{"a":"}\\"","b":[1,{"c":2}]}'
    assert c2d._json_member_text(text, "signature") == '"00"'
    with pytest.raises(ValueError):
        c2d._json_member_text(text, "missing")


def test_duplicate_keys_in_pcs_documents_are_rejected(c2d):
    """A document with two tcbInfo members could make the signed text and the
    parsed content diverge, so it is malformed collateral."""
    text = '{"tcbInfo":{"id":"SGX"},"tcbInfo":{"id":"TDX"},"signature":"' + "00" * 64 + '"}'
    with pytest.raises(c2d._EvidenceError) as excinfo:
        c2d._signed_pcs_body(text, "tcbInfo", b"\x00" * 64, "TCB_INFO")
    assert excinfo.value.code == "TCB_INFO_MALFORMED"


# =============================================================================
# _validate_production_id: reserved-prefix bracket
# =============================================================================

def test_reserved_prefix_set_is_lowercase_and_complete(c2d):
    """The isolation check lower-cases input, so every reserved prefix must be
    stored lower-cased for matching to work."""
    prefixes = c2d._RESERVED_ID_PREFIXES
    assert len(prefixes) == 12
    for prefix in prefixes:
        assert prefix == prefix.lower()


@pytest.mark.parametrize("prefix", list(range(12)))
def test_every_reserved_prefix_is_blocked(c2d, prefix):
    bad_id = c2d._RESERVED_ID_PREFIXES[prefix] + "payload"
    with pytest.raises(Exception) as excinfo:
        c2d._validate_production_id(bad_id, "Dataset id")
    assert "reserved prefix" in str(excinfo.value)


@pytest.mark.parametrize(
    "good_id",
    ["mobility-v1", "production-job-1", "urban-forecast", "job-001", "TESTING-but-not-prefix"],
)
def test_legitimate_ids_pass_isolation_check(c2d, good_id):
    # A clean production id returns None (no exception).
    assert c2d._validate_production_id(good_id, "Dataset id") is None


@pytest.mark.parametrize("cased", ["DEMO-x", "Test-Job", "MOCK-set", "Staging-Data"])
def test_reserved_prefix_match_is_case_insensitive(c2d, cased):
    with pytest.raises(Exception) as excinfo:
        c2d._validate_production_id(cased, "Job id")
    assert "reserved prefix" in str(excinfo.value)


# =============================================================================
# Module-level time-window constants
# =============================================================================

def test_time_window_constants(c2d):
    assert c2d.PROOF_WINDOW_SECONDS == 7 * 24 * 60 * 60
    assert c2d.APPEAL_WINDOW_SECONDS == 3 * 24 * 60 * 60
