import datetime as _dt
import hashlib
import json

import pytest

from dcap_fixtures import (
    DEFAULT_FMSPC,
    assert_pinned_keys_match,
    build_binary_quote,
    expected_report_data,
    tcb_collateral_handler,
)


ONE_GEN = 10**18
DATASET_STAKE = 10 * ONE_GEN
JOB_COLLATERAL = 2 * ONE_GEN
JOB_PRICE = 3 * ONE_GEN

# Default measurements provisioned inside contracts/c2d_marketplace.py, mirrored
# here so the fixtures reproduce the exact bytes the contract parses and the
# measurements the contract whitelists.
DEFAULT_ENCLAVE_MEASUREMENT = "11" * 32
DEFAULT_ENCLAVE_SIGNER = "22" * 32

# Must match DEFAULT_ATTESTATION_ENDPOINT in contracts/c2d_marketplace.py.
ATTESTATION_ENDPOINT = "https://api.trustedservices.intel.com/sgx/certification/v4/tcb"

# The dataset_id fund_job registers the job against; the report_data binding is
# sha256(dataset_id + compute_spec_hash + output_data_hash).
DATASET_ID = "mobility-v1"

DATASET_COMMITMENT = "sha256:dataset-commitment-4a1c"
INPUT_COMMITMENT = "sha256:input-commitment-77f0"
MODEL_ID = "mobility-transformer-v4"
# COMPUTE_SPEC must exactly match what fund_job passes to request_compute.
COMPUTE_SPEC = "Train for 12 epochs; report MAE and output artifact commitment."
OUTPUT_COMMITMENT = "sha256:output-artifact-ae92"


def address_hex(address):
    return "0x" + bytes(address).hex()


def future_iso(days: int = 8) -> str:
    """Return an ISO timestamp *days* days ahead of now (UTC, Zulu suffix)."""
    ts = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=days)
    return ts.isoformat().replace("+00:00", "Z")


def warp(direct_vm, iso_ts: str) -> None:
    """Warp the VM clock and propagate the datetime into the live gl.message_raw.

    The test framework's _refresh_gl_message() only updates sender/origin, not
    datetime, so gl.message_raw['datetime'] stays stale after a plain warp()
    call. This helper patches the cached dict directly so that _now_epoch()
    inside the contract reads the warped timestamp on the very next call.
    """
    import sys
    direct_vm.warp(iso_ts)
    if 'genlayer.gl' in sys.modules:
        msg_raw = getattr(sys.modules['genlayer.gl'], 'message_raw', None)
        if isinstance(msg_raw, dict):
            msg_raw['datetime'] = iso_ts


def build_attestation_quote(
    *,
    dataset_id=DATASET_ID,
    dataset_commitment=DATASET_COMMITMENT,
    input_commitment=INPUT_COMMITMENT,
    model_id=MODEL_ID,
    compute_spec=COMPUTE_SPEC,
    output_commitment=OUTPUT_COMMITMENT,
    mrenclave=DEFAULT_ENCLAVE_MEASUREMENT,
    mrsigner=DEFAULT_ENCLAVE_SIGNER,
    result_status="COMPLETED",
    tamper_signature=False,
    drop_compute_spec_commitment=False,
    fmspc=DEFAULT_FMSPC,
):
    """Build a genuine binary DCAP quote wrapped with its artifact, as JSON.

    The measurements and report_data live in the signed binary report body; the
    report_data is the canonical sha256(dataset_id + compute_spec_hash +
    output_data_hash) that the contract re-derives on chain. The quote is signed
    with real ECDSA P-256 keys whose PCK chain terminates at the pinned root.

    tamper_signature=True: zero the ISV report signature (SIGNATURE_INVALID path).
    drop_compute_spec_commitment=True: omit the artifact field
        (COMPUTE_SPEC_COMMITMENT_INVALID path).
    """
    compute_spec_commitment = hashlib.sha256(compute_spec.encode("utf-8")).hexdigest()
    output_data_hash = hashlib.sha256(output_commitment.encode("utf-8")).hexdigest()
    report_data = expected_report_data(dataset_id, compute_spec_commitment, output_data_hash)
    dcap_quote = build_binary_quote(
        mrenclave=mrenclave,
        mrsigner=mrsigner,
        report_data=report_data,
        fmspc=fmspc,
        tamper_signature=tamper_signature,
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
    if not drop_compute_spec_commitment:
        artifact["compute_spec_commitment"] = compute_spec_commitment
    return json.dumps({"artifact": artifact, "dcap_quote": dcap_quote}, sort_keys=True)


def build_attestation_quote_with_binding_mismatch(
    *,
    mrenclave=DEFAULT_ENCLAVE_MEASUREMENT,
    mrsigner=DEFAULT_ENCLAVE_SIGNER,
    output_commitment=OUTPUT_COMMITMENT,
):
    """Quote whose report_data does not match the canonical binding.

    The artifact fields are all correct, but the signed report_data is derived
    from a different output, so the contract's re-derived binding != report_data
    (BINDING_MISMATCH). The DCAP signature chain is internally valid for the
    sealed report_data, so SIGNATURE_INVALID is not reached first.
    """
    compute_spec_commitment = hashlib.sha256(COMPUTE_SPEC.encode("utf-8")).hexdigest()
    output_data_hash = hashlib.sha256(output_commitment.encode("utf-8")).hexdigest()
    decoy_output_hash = hashlib.sha256(b"sha256:binding-mismatch-decoy-output").hexdigest()
    # report_data is bound to the decoy output, but the artifact advertises the
    # real output; the contract binds over the real output and detects the gap.
    report_data = expected_report_data(DATASET_ID, compute_spec_commitment, decoy_output_hash)
    dcap_quote = build_binary_quote(
        mrenclave=mrenclave,
        mrsigner=mrsigner,
        report_data=report_data,
    )
    artifact = {
        "dataset_id": DATASET_ID,
        "dataset_commitment": DATASET_COMMITMENT,
        "input_commitment": INPUT_COMMITMENT,
        "model_id": MODEL_ID,
        "compute_spec_commitment": compute_spec_commitment,
        "output_commitment": output_commitment,
        "output_data_hash": output_data_hash,
        "result_status": "COMPLETED",
    }
    return json.dumps({"artifact": artifact, "dcap_quote": dcap_quote}, sort_keys=True)


def install_attestation_authority(direct_vm):
    """Install the simulated Intel PCS collateral service as the live web handler.

    Every submit_execution_proof / resolve_appeal fetches TCB collateral for the
    quote's FMSPC via gl.nondet.web.get; this handler returns an authentically
    signed UpToDate status. The contract verifies that signature on chain against
    its pinned Intel TCB signing key, so authenticity does not come from the
    endpoint. A test can override the collateral by registering an explicit
    direct_vm.mock_web(...), which takes precedence over this fallback handler.
    """
    direct_vm._live_web_handler = tcb_collateral_handler


@pytest.fixture(autouse=True)
def _attestation_authority_autouse(direct_vm):
    """Make the collateral service reachable for every direct-mode test.

    Installed unconditionally so a test that stands up its own provider (without
    stake_and_register) still reaches a working collateral service. Registering
    an explicit mock_web for the endpoint still overrides this fallback.
    """
    assert_pinned_keys_match()
    install_attestation_authority(direct_vm)
    return direct_vm


def stake_and_register(direct_vm, contract, provider):
    # Make the remote attestation authority reachable for the whole test.
    install_attestation_authority(direct_vm)
    direct_vm.sender = provider
    direct_vm.value = DATASET_STAKE + (2 * JOB_COLLATERAL)
    contract.stake_provider()
    direct_vm.value = 0
    contract.register_dataset(
        "mobility-v1",
        "Urban mobility vectors",
        "Privacy-preserving trajectories for demand forecasting.",
        "Parquet: timestamp, zone_id, speed, occupancy",
        DATASET_COMMITMENT,
        "Approved aggregate forecasting workloads only.",
        JOB_PRICE,
    )


def fund_job(direct_vm, contract, requester, job_id="job-001"):
    direct_vm.sender = requester
    direct_vm.value = JOB_PRICE
    contract.request_compute(
        job_id,
        "mobility-v1",
        MODEL_ID,
        COMPUTE_SPEC,
        INPUT_COMMITMENT,
    )
    direct_vm.value = 0


def valid_assessment():
    return json.dumps(
        {
            "verdict": "VALID",
            "violation_code": "NONE",
            "summary": "The verified enclave report records a completed run for every bound identifier.",
        }
    )


def rejected_assessment():
    return json.dumps(
        {
            "verdict": "INVALID",
            "violation_code": "EXECUTION_FAILED",
            "summary": "The verified enclave report indicates the run failed before completion.",
        }
    )


def inconclusive_assessment():
    return json.dumps(
        {
            "verdict": "INCONCLUSIVE",
            "violation_code": "INSUFFICIENT_EVIDENCE",
            "summary": "The verified enclave report status is pending so completion cannot be established.",
        }
    )
