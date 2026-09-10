"""Parametrized boundary regression for the Compute2Data domain logic.

This suite locks in every domain-specific threshold and bracket boundary by
calling the contract's module-level pure helper functions directly, WITHOUT a
per-test VM fixture. The helpers under test (_is_hex_of_bytes, _parse_dcap_quote,
_expected_report_data, _inspect_enclave_quote, _validate_production_id) depend
only on hashlib / json and never touch VM storage or nondeterminism, so
exercising them in-process runs in well under a millisecond each and pins the
exact boundary at which each threshold flips.

Signature authenticity is NOT decided here: _inspect_enclave_quote performs the
deterministic structural parse + artifact + report_data binding checks; the
ECDSA signature chain is verified separately by _verify_quote_signature_chain
(exercised in test_authentic_attestation.py). Accordingly this suite builds
genuine binary DCAP quotes and asserts that a structurally sound quote with a
correct binding passes inspection regardless of signature verification.

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

from dcap_fixtures import build_binary_quote, expected_report_data  # noqa: E402

# Trusted default measurements provisioned by the contract at deploy time.
MRENCLAVE = "11" * 32
MRSIGNER = "22" * 32


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


def _valid_quote(
    *,
    dataset_id="did",
    dataset_commitment="dc",
    input_commitment="ic",
    model_id="mid",
    compute_spec="spec",
    output_commitment="oc",
    mrenclave=MRENCLAVE,
    mrsigner=MRSIGNER,
    result_status="COMPLETED",
    include_compute_spec=True,
    tamper_binding=False,
    malformed_quote=False,
):
    """Build a genuine binary DCAP quote wrapped with its artifact, as JSON.

    The report_data is the canonical sha256(dataset_id + compute_spec_hash +
    output_data_hash) the contract re-derives, so a boundary result reflects the
    contract logic and not a divergent re-implementation. tamper_binding binds
    report_data to a different output (BINDING_MISMATCH); malformed_quote
    replaces the binary quote with unparseable bytes (MALFORMED_QUOTE).
    """
    compute_spec_commitment = _spec_commitment(compute_spec)
    output_data_hash = hashlib.sha256(output_commitment.encode("utf-8")).hexdigest()
    if tamper_binding:
        decoy = hashlib.sha256((output_commitment + "-decoy").encode("utf-8")).hexdigest()
        report_data = expected_report_data(dataset_id, compute_spec_commitment, decoy)
    else:
        report_data = expected_report_data(dataset_id, compute_spec_commitment, output_data_hash)

    if malformed_quote:
        dcap_quote = "not-a-valid-hex-quote"
    else:
        dcap_quote = build_binary_quote(
            mrenclave=mrenclave, mrsigner=mrsigner, report_data=report_data
        )

    artifact = {
        "dataset_id": dataset_id,
        "dataset_commitment": dataset_commitment,
        "input_commitment": input_commitment,
        "model_id": model_id,
        "output_commitment": output_commitment,
        "output_data_hash": output_data_hash,
        "result_status": result_status,
    }
    if include_compute_spec:
        artifact["compute_spec_commitment"] = compute_spec_commitment
    return json.dumps({"artifact": artifact, "dcap_quote": dcap_quote}, sort_keys=True)


def _inspect(c2d, quote, *, dataset_id="did", dataset_commitment="dc", input_c="ic",
             model="mid", spec="spec"):
    return c2d._inspect_enclave_quote(
        quote, dataset_id, dataset_commitment, input_c, model, _spec_commitment(spec)
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
# _inspect_enclave_quote: output_commitment length bracket [1, 256]
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
    quote = _valid_quote(output_commitment="o" * length)
    result = _inspect(c2d, quote)
    assert result["ok"] is expect_ok
    assert result["code"] == expect_code


def test_empty_output_commitment_is_invalid(c2d):
    quote = _valid_quote(output_commitment="")
    result = _inspect(c2d, quote)
    assert result["ok"] is False
    assert result["code"] == "OUTPUT_COMMITMENT_INVALID"


# =============================================================================
# _inspect_enclave_quote: deterministic rejection codes for every tampered field
# =============================================================================

@pytest.mark.parametrize(
    "quote_kwargs, on_chain, expect_code",
    [
        # A fully consistent quote verifies.
        ({}, ("did", "dc", "ic", "mid", "spec"), "NONE"),
        # Each committed artifact field must match the on-chain value.
        ({}, ("did", "OTHER", "ic", "mid", "spec"), "DATASET_MISMATCH"),
        ({}, ("did", "dc", "OTHER", "mid", "spec"), "INPUT_COMMITMENT_MISMATCH"),
        ({}, ("did", "dc", "ic", "OTHER", "spec"), "MODEL_MISMATCH"),
        # A quote built for a different compute spec fails the spec commitment check.
        ({}, ("did", "dc", "ic", "mid", "different-spec"), "COMPUTE_SPEC_MISMATCH"),
        # Omitting the mandatory compute-spec commitment is rejected outright.
        ({"include_compute_spec": False}, ("did", "dc", "ic", "mid", "spec"), "COMPUTE_SPEC_COMMITMENT_INVALID"),
        # An unparseable binary quote fails the structural check; a forged binding
        # is caught by the re-derived report_data comparison.
        ({"malformed_quote": True}, ("did", "dc", "ic", "mid", "spec"), "MALFORMED_QUOTE"),
        ({"tamper_binding": True}, ("did", "dc", "ic", "mid", "spec"), "BINDING_MISMATCH"),
    ],
)
def test_inspection_rejection_codes(c2d, quote_kwargs, on_chain, expect_code):
    dataset_id, dataset, input_c, model, spec = on_chain
    quote = _valid_quote(**quote_kwargs)
    result = _inspect(
        c2d, quote, dataset_id=dataset_id, dataset_commitment=dataset,
        input_c=input_c, model=model, spec=spec,
    )
    assert result["code"] == expect_code
    assert result["ok"] is (expect_code == "NONE")


@pytest.mark.parametrize("malformed", ["", "not json", "{", "[]", '"a string"', "42", "null"])
def test_malformed_quote_never_verifies(c2d, malformed):
    """A non-object or unparseable quote is rejected deterministically, never raising."""
    result = _inspect(c2d, malformed)
    assert result["ok"] is False
    assert result["code"] == "MALFORMED_QUOTE"


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


def test_inspect_does_not_verify_signature(c2d):
    """_inspect_enclave_quote performs only the deterministic structural + binding
    checks; the ECDSA signature chain is verified separately. A structurally
    sound quote with a correct binding therefore passes inspection, and the
    module exposes no legacy on-chain signature re-derivation helpers."""
    quote = _valid_quote()
    result = _inspect(c2d, quote)
    assert result["ok"] is True
    assert result["code"] == "NONE"
    # The legacy SHA-256 "signature" construction is gone for good.
    assert not hasattr(c2d, "_quote_signature")
    assert not hasattr(c2d, "_binding_digest")
    assert not hasattr(c2d, "_authenticate_quote")
    # Real ECDSA verification and binary DCAP parsing are present instead.
    assert hasattr(c2d, "_ecdsa_verify")
    assert hasattr(c2d, "_parse_dcap_quote")
    assert hasattr(c2d, "_verify_quote_signature_chain")


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
