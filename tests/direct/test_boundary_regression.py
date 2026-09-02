"""Parametrized boundary regression for the Compute2Data domain logic.

This suite locks in every domain-specific threshold and bracket boundary by
calling the contract's module-level pure helper functions directly, WITHOUT a
per-test VM fixture. The helpers under test (_is_hex_of_bytes, _binding_digest,
_quote_signature, _inspect_enclave_quote, _validate_production_id) depend only
on hashlib / json and never touch VM storage or nondeterminism, so exercising
them in-process runs in well under a millisecond each and pins the exact
boundary at which each threshold flips.

The contract module is imported once (module-scoped fixture) using the same SDK
loader the direct plugin uses; the imported module object is held for the whole
file, so it keeps working even if a sibling VM-based suite evicts SDK modules
from sys.modules during its own teardown.
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest


CONTRACT_PATH = "contracts/c2d_marketplace.py"

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


def _valid_quote(
    module,
    *,
    dataset_commitment="dc",
    input_commitment="ic",
    model_id="mid",
    compute_spec="spec",
    output_commitment="oc",
    mrenclave=MRENCLAVE,
    mrsigner=MRSIGNER,
    result_status="COMPLETED",
    include_compute_spec=True,
    tamper_signature=False,
    tamper_binding=False,
):
    """Build a quote JSON string using the module's own digest helpers.

    Reusing the contract's _binding_digest / _quote_signature guarantees the
    fixtures reproduce the exact bytes the contract re-derives, so a boundary
    result reflects the contract logic and not a divergent test re-implementation.
    """
    compute_spec_commitment = hashlib.sha256(compute_spec.encode("utf-8")).hexdigest()
    report_data = module._binding_digest(
        dataset_commitment,
        input_commitment,
        model_id,
        compute_spec_commitment,
        output_commitment,
    )
    if tamper_binding:
        # Well-formed hex that does not equal the canonical five-field binding.
        report_data = module._binding_digest(
            dataset_commitment,
            input_commitment,
            model_id,
            compute_spec_commitment,
            output_commitment + "-decoy",
        )
    signature = module._quote_signature(mrenclave, mrsigner, report_data)
    if tamper_signature:
        signature = "00" * 32
    artifact = {
        "dataset_commitment": dataset_commitment,
        "input_commitment": input_commitment,
        "model_id": model_id,
        "output_commitment": output_commitment,
        "result_status": result_status,
    }
    if include_compute_spec:
        artifact["compute_spec_commitment"] = compute_spec_commitment
    return json.dumps(
        {
            "enclave": {
                "mrenclave": mrenclave,
                "mrsigner": mrsigner,
                "report_data": report_data,
                "quote_signature": signature,
            },
            "artifact": artifact,
        },
        sort_keys=True,
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
    quote = _valid_quote(c2d, output_commitment="o" * length)
    result = c2d._inspect_enclave_quote(quote, "dc", "ic", "mid", _spec_commitment("spec"))
    assert result["ok"] is expect_ok
    assert result["code"] == expect_code


def test_empty_output_commitment_is_invalid(c2d):
    quote = _valid_quote(c2d, output_commitment="")
    result = c2d._inspect_enclave_quote(quote, "dc", "ic", "mid", _spec_commitment("spec"))
    assert result["ok"] is False
    assert result["code"] == "OUTPUT_COMMITMENT_INVALID"


# =============================================================================
# _inspect_enclave_quote: deterministic rejection codes for every tampered field
# =============================================================================

def _spec_commitment(spec: str) -> str:
    return hashlib.sha256(spec.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "quote_kwargs, on_chain, expect_code",
    [
        # A fully consistent quote verifies.
        ({}, ("dc", "ic", "mid", "spec"), "NONE"),
        # Each committed field bound into the quote must match the on-chain value.
        ({}, ("OTHER", "ic", "mid", "spec"), "DATASET_MISMATCH"),
        ({}, ("dc", "OTHER", "mid", "spec"), "INPUT_COMMITMENT_MISMATCH"),
        ({}, ("dc", "ic", "OTHER", "spec"), "MODEL_MISMATCH"),
        # A quote built for a different compute spec fails the spec commitment check.
        ({}, ("dc", "ic", "mid", "different-spec"), "COMPUTE_SPEC_MISMATCH"),
        # Omitting the mandatory compute-spec commitment is rejected outright.
        ({"include_compute_spec": False}, ("dc", "ic", "mid", "spec"), "COMPUTE_SPEC_COMMITMENT_INVALID"),
        # Forged signature and forged binding are each caught.
        ({"tamper_signature": True}, ("dc", "ic", "mid", "spec"), "SIGNATURE_INVALID"),
        ({"tamper_binding": True}, ("dc", "ic", "mid", "spec"), "BINDING_MISMATCH"),
    ],
)
def test_inspection_rejection_codes(c2d, quote_kwargs, on_chain, expect_code):
    dataset, input_c, model, spec = on_chain
    quote = _valid_quote(c2d, **quote_kwargs)
    result = c2d._inspect_enclave_quote(
        quote, dataset, input_c, model, _spec_commitment(spec)
    )
    assert result["code"] == expect_code
    assert result["ok"] is (expect_code == "NONE")


@pytest.mark.parametrize("malformed", ["", "not json", "{", "[]", '"a string"', "42", "null"])
def test_malformed_quote_never_verifies(c2d, malformed):
    """A non-object or unparseable quote is rejected deterministically, never raising."""
    result = c2d._inspect_enclave_quote(malformed, "dc", "ic", "mid", _spec_commitment("spec"))
    assert result["ok"] is False
    assert result["code"] == "MALFORMED_QUOTE"


# =============================================================================
# _binding_digest / _quote_signature: determinism and domain separation
# =============================================================================

def test_binding_digest_is_deterministic_and_hex32(c2d):
    a = c2d._binding_digest("d", "i", "m", "c", "o")
    b = c2d._binding_digest("d", "i", "m", "c", "o")
    assert a == b
    assert c2d._is_hex_of_bytes(a, 32)


@pytest.mark.parametrize("field_index", [0, 1, 2, 3, 4])
def test_binding_digest_changes_when_any_field_changes(c2d, field_index):
    """Every one of the five bound fields must influence the digest, so no
    component of the committed work can be swapped without detection."""
    base = ["d", "i", "m", "c", "o"]
    mutated = list(base)
    mutated[field_index] = base[field_index] + "-changed"
    assert c2d._binding_digest(*base) != c2d._binding_digest(*mutated)


def test_signature_binds_measurements_and_report(c2d):
    report = c2d._binding_digest("d", "i", "m", "c", "o")
    base = c2d._quote_signature(MRENCLAVE, MRSIGNER, report)
    assert base != c2d._quote_signature("99" * 32, MRSIGNER, report)   # mrenclave matters
    assert base != c2d._quote_signature(MRENCLAVE, "99" * 32, report)  # mrsigner matters
    assert base != c2d._quote_signature(MRENCLAVE, MRSIGNER, report[::-1])  # report matters


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
