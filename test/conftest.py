import base64 as _base64
import datetime as _dt
import hashlib
import json

import pytest


ONE_GEN = 10**18
DATASET_STAKE = 10 * ONE_GEN
JOB_COLLATERAL = 2 * ONE_GEN
JOB_PRICE = 3 * ONE_GEN

# These mirror the domain tags and default measurements provisioned inside
# contracts/c2d_marketplace.py so tests reproduce the exact attestation bytes.
BINDING_DOMAIN = "c2d-attestation-binding-v1"
# QUOTE_DOMAIN lives ONLY in the test harness now: it is the signing scheme of
# the *simulated* attestation authority (see _attestation_authority below), not
# of the contract. The contract no longer re-derives any signature from public
# values -- it trusts the authority's verdict. Keeping the scheme here models a
# genuine enclave signing its quote and an Intel-rooted PCS/IAS verifier
# checking it off chain.
QUOTE_DOMAIN = "c2d-enclave-quote-v1"
DEFAULT_ENCLAVE_MEASUREMENT = "11" * 32
DEFAULT_ENCLAVE_SIGNER = "22" * 32

# Must match DEFAULT_ATTESTATION_ENDPOINT in contracts/c2d_marketplace.py.
ATTESTATION_ENDPOINT = "https://attestation.compute2data.network/dcap/v1/verify-quote"

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


def _binding_digest(
    dataset_commitment,
    input_commitment,
    model_id,
    compute_spec_commitment,
    output_commitment,
):
    payload = "|".join(
        [
            BINDING_DOMAIN,
            dataset_commitment,
            input_commitment,
            model_id,
            compute_spec_commitment,
            output_commitment,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _quote_signature(mrenclave, mrsigner, report_data):
    body = "|".join([QUOTE_DOMAIN, mrenclave, mrsigner, report_data])
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def build_attestation_quote(
    *,
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
):
    """Build a well-formed attestation quote JSON string.

    tamper_signature=True: zero the signature (SIGNATURE_INVALID path).
    drop_compute_spec_commitment=True: omit the field from the artifact
        (COMPUTE_SPEC_COMMITMENT_INVALID path).
    """
    compute_spec_commitment = hashlib.sha256(compute_spec.encode("utf-8")).hexdigest()
    report_data = _binding_digest(
        dataset_commitment,
        input_commitment,
        model_id,
        compute_spec_commitment,
        output_commitment,
    )
    signature = _quote_signature(mrenclave, mrsigner, report_data)
    if tamper_signature:
        signature = "00" * 32
    artifact = {
        "dataset_commitment": dataset_commitment,
        "input_commitment": input_commitment,
        "model_id": model_id,
        "output_commitment": output_commitment,
        "result_status": result_status,
    }
    if not drop_compute_spec_commitment:
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


def build_attestation_quote_with_binding_mismatch(
    *,
    mrenclave=DEFAULT_ENCLAVE_MEASUREMENT,
    mrsigner=DEFAULT_ENCLAVE_SIGNER,
    output_commitment=OUTPUT_COMMITMENT,
):
    """Quote where report_data does not match the five-field canonical binding.

    All artifact fields are correct but report_data is derived from a different
    output, so expected_binding != report_data (BINDING_MISMATCH). The signature
    is internally valid for the corrupted report_data so SIGNATURE_INVALID is
    not reached first.
    """
    compute_spec_commitment = hashlib.sha256(COMPUTE_SPEC.encode("utf-8")).hexdigest()
    wrong_output = "sha256:binding-mismatch-decoy-output"
    fake_binding = _binding_digest(
        DATASET_COMMITMENT, INPUT_COMMITMENT, MODEL_ID, compute_spec_commitment, wrong_output
    )
    signature = _quote_signature(mrenclave, mrsigner, fake_binding)
    return json.dumps(
        {
            "enclave": {
                "mrenclave": mrenclave,
                "mrsigner": mrsigner,
                "report_data": fake_binding,
                "quote_signature": signature,
            },
            "artifact": {
                "dataset_commitment": DATASET_COMMITMENT,
                "input_commitment": INPUT_COMMITMENT,
                "model_id": MODEL_ID,
                "compute_spec_commitment": compute_spec_commitment,
                "output_commitment": output_commitment,
                "result_status": "COMPLETED",
            },
        },
        sort_keys=True,
    )


def _verify_quote_authenticity(quote_json):
    """Simulate the remote attestation authority's cryptographic verdict.

    This is the crypto that moved OUT of the contract: an Intel DCAP/PCS or IAS
    verifier checks the enclave's signature over the report body and returns the
    AUTHENTICATED measurements and report data. A quote whose signature does not
    seal (mrenclave, mrsigner, report_data) is rejected as SIGNATURE_INVALID --
    which is exactly what defeats a browser that only knows the public values.
    """
    try:
        parsed = json.loads(quote_json)
        enclave = parsed["enclave"]
        mrenclave = enclave["mrenclave"]
        mrsigner = enclave["mrsigner"]
        report_data = enclave["report_data"]
        signature = enclave["quote_signature"]
    except (ValueError, TypeError, KeyError):
        return {"status": "ATTESTATION_MALFORMED", "mrenclave": "", "mrsigner": "", "report_data": ""}

    if signature != _quote_signature(mrenclave, mrsigner, report_data):
        return {"status": "SIGNATURE_INVALID", "mrenclave": "", "mrsigner": "", "report_data": ""}
    return {
        "status": "OK",
        "mrenclave": mrenclave,
        "mrsigner": mrsigner,
        "report_data": report_data,
    }


def _attestation_authority(data):
    """Live web handler standing in for the remote attestation service.

    Reads the base64 quote the contract submits in the X-Enclave-Quote header,
    runs the authority's cryptographic verification, and returns a JSON verdict
    in the gltest live-handler response shape.
    """
    headers = data.get("headers", {}) or {}
    quote_b64 = headers.get("X-Enclave-Quote", "")
    if isinstance(quote_b64, (bytes, bytearray)):
        quote_b64 = bytes(quote_b64).decode("ascii", "replace")
    try:
        quote_json = _base64.b64decode(quote_b64).decode("utf-8")
    except (ValueError, TypeError, UnicodeDecodeError):
        quote_json = ""

    verdict = _verify_quote_authenticity(quote_json)
    body = json.dumps(verdict).encode("utf-8")
    return {"ok": {"response": {"status": 200, "headers": {}, "body": body}}}


def install_attestation_authority(direct_vm):
    """Install the simulated attestation authority as the live web handler.

    Every submit_execution_proof / resolve_appeal reaches the authority via
    gl.nondet.web.get; this makes genuine quotes verify and fabricated ones
    revert, with no per-test mock wiring. A test can override authenticity by
    registering an explicit direct_vm.mock_web(ATTESTATION_ENDPOINT, ...), which
    takes precedence over this fallback handler.
    """
    direct_vm._live_web_handler = _attestation_authority


@pytest.fixture(autouse=True)
def _attestation_authority_autouse(direct_vm):
    """Make the attestation authority reachable for every direct-mode test.

    Installed unconditionally so a test that stands up its own provider (without
    stake_and_register) still reaches a working authority. Registering an
    explicit mock_web for the endpoint still overrides this fallback.
    """
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
