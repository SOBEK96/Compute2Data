import datetime as _dt
import hashlib
import json

import pytest

from dcap_fixtures import (
    TEST_SGX_ROOT_CA_PUBKEY,
    assert_pinned_keys_match,
    build_binary_quote,
    build_collateral,
    expected_report_data,
)


ONE_GEN = 10**18
DATASET_STAKE = 10 * ONE_GEN
JOB_COLLATERAL = 2 * ONE_GEN
JOB_PRICE = 3 * ONE_GEN

# Harness enclave measurements. The contract's trust registry starts empty; the
# direct_deploy fixture whitelists these as the admin, the way an operator
# whitelists an audited enclave after deployment.
DEFAULT_ENCLAVE_MEASUREMENT = "11" * 32
DEFAULT_ENCLAVE_SIGNER = "22" * 32

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
    for mod_name in ['genlayer.message', 'genlayer']:
        if mod_name in sys.modules:
            mod = sys.modules[mod_name]
            msg_obj = getattr(mod, 'message', mod)
            if hasattr(msg_obj, 'raw') and isinstance(msg_obj.raw, dict):
                msg_obj.raw['datetime'] = iso_ts
            if hasattr(msg_obj, 'datetime'):
                try:
                    setattr(msg_obj, 'datetime', iso_ts)
                except Exception:
                    pass


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
    debug=False,
    collateral=None,
):
    """Build a proof envelope: SGX v3 quote + Intel-format PCS collateral + artifact.

    The measurements and report_data live in the signed report body; report_data
    is the canonical sha256(dataset_id + compute_spec_hash + output_data_hash)
    the contract re-derives on chain. The quote's cert_data_type 5 X.509 PCK
    chain and the collateral are signed by the harness PKI (see dcap_fixtures).

    tamper_signature=True: zero the ISV report signature (reverts, SIGNATURE_INVALID).
    drop_compute_spec_commitment=True: omit the artifact field
        (COMPUTE_SPEC_COMMITMENT_INVALID slash).
    debug=True: set the SGX DEBUG attribute (DEBUG_ENCLAVE slash).
    collateral: override the PCS collateral dict.
    """
    compute_spec_commitment = hashlib.sha256(compute_spec.encode("utf-8")).hexdigest()
    output_data_hash = hashlib.sha256(output_commitment.encode("utf-8")).hexdigest()
    report_data = expected_report_data(dataset_id, compute_spec_commitment, output_data_hash)
    dcap_quote = build_binary_quote(
        mrenclave=mrenclave,
        mrsigner=mrsigner,
        report_data=report_data,
        tamper_signature=tamper_signature,
        debug=debug,
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
    return evidence_envelope(artifact, dcap_quote, build_collateral() if collateral is None else collateral)


def evidence_envelope(artifact, dcap_quote, collateral):
    return json.dumps(
        {"artifact": artifact, "dcap_quote": dcap_quote, "collateral": collateral}, sort_keys=True
    )


def build_attestation_quote_with_binding_mismatch(
    *,
    mrenclave=DEFAULT_ENCLAVE_MEASUREMENT,
    mrsigner=DEFAULT_ENCLAVE_SIGNER,
    output_commitment=OUTPUT_COMMITMENT,
):
    """Quote whose report_data does not match the canonical binding.

    The artifact fields are all correct, but the signed report_data is derived
    from a different output, so the contract's re-derived binding != report_data
    (BINDING_MISMATCH). The quote itself is genuine and fully signed for the
    sealed report_data, so authentication passes and policy slashes it.
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
    return evidence_envelope(artifact, dcap_quote, build_collateral())


def _install_llm_text_shim():
    """Hand exec_prompt(response_format='json') the raw JSON text it decodes.

    genlayer-test 0.30.0rc2's direct-mode LLM mock JSON-parses a mocked reply
    into a dict, but the py-genlayer 5jycge SDK this contract runs on decodes
    the nondet response itself and requires text ("JSON result is not text").
    Return the mocked reply verbatim, as a node delivers raw model output.
    """
    from gltest.direct import wasi_mock

    if getattr(wasi_mock, "_c2d_llm_text_shim", False):
        return
    original = wasi_mock._handle_llm_request

    def handler(vm, data):
        response = vm._match_llm_mock(data.get("prompt", ""))
        if isinstance(response, str):
            return {"ok": response}
        if isinstance(response, (dict, list)):
            return {"ok": json.dumps(response)}
        return original(vm, data)

    wasi_mock._handle_llm_request = handler
    wasi_mock._c2d_llm_text_shim = True


@pytest.fixture(autouse=True)
def _harness_setup(direct_vm):
    assert_pinned_keys_match()
    _install_llm_text_shim()
    return direct_vm


def stake_and_register(direct_vm, contract, provider):
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


@pytest.fixture
def direct_deploy(direct_vm):
    from gltest.direct.pytest_plugin import deploy_contract
    from pathlib import Path

    def _deploy(contract_path: str, *args, sdk_version=None, **kwargs):
        path = Path(contract_path)
        if not path.is_absolute():
            if path.exists():
                path = path.resolve()
            else:
                for base in [
                    Path.cwd(),
                    Path.cwd() / "contracts",
                    Path.cwd() / "intelligent-contracts",
                ]:
                    candidate = base / contract_path
                    if candidate.exists():
                        path = candidate.resolve()
                        break
        if "c2d_marketplace.py" in str(path) and not args:
            # Harness deploy: pin the harness root and, as the admin, whitelist
            # the harness enclave measurements.
            contract = deploy_contract(path, direct_vm, TEST_SGX_ROOT_CA_PUBKEY, sdk_version=sdk_version, **kwargs)
            contract.set_trusted_enclave(DEFAULT_ENCLAVE_MEASUREMENT, True)
            contract.set_trusted_signer(DEFAULT_ENCLAVE_SIGNER, True)
            return contract
        return deploy_contract(path, direct_vm, *args, sdk_version=sdk_version, **kwargs)

    return _deploy
