import hashlib
import json


ONE_GEN = 10**18
DATASET_STAKE = 10 * ONE_GEN
JOB_COLLATERAL = 2 * ONE_GEN
JOB_PRICE = 3 * ONE_GEN

# These mirror the domain tags and default measurements provisioned inside
# contracts/c2d_marketplace.py so tests reproduce the exact attestation bytes.
BINDING_DOMAIN = "c2d-attestation-binding-v1"
QUOTE_DOMAIN = "c2d-enclave-quote-v1"
DEFAULT_ENCLAVE_MEASUREMENT = "11" * 32
DEFAULT_ENCLAVE_SIGNER = "22" * 32

DATASET_COMMITMENT = "sha256:dataset-commitment-4a1c"
INPUT_COMMITMENT = "sha256:input-commitment-77f0"
MODEL_ID = "mobility-transformer-v4"
OUTPUT_COMMITMENT = "sha256:output-artifact-ae92"


def address_hex(address):
    return "0x" + bytes(address).hex()


def _binding_digest(dataset_commitment, input_commitment, model_id, output_commitment):
    payload = "|".join(
        [BINDING_DOMAIN, dataset_commitment, input_commitment, model_id, output_commitment]
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
    output_commitment=OUTPUT_COMMITMENT,
    mrenclave=DEFAULT_ENCLAVE_MEASUREMENT,
    mrsigner=DEFAULT_ENCLAVE_SIGNER,
    result_status="COMPLETED",
    tamper_signature=False,
):
    report_data = _binding_digest(dataset_commitment, input_commitment, model_id, output_commitment)
    signature = _quote_signature(mrenclave, mrsigner, report_data)
    if tamper_signature:
        signature = "00" * 32
    return json.dumps(
        {
            "enclave": {
                "mrenclave": mrenclave,
                "mrsigner": mrsigner,
                "report_data": report_data,
                "quote_signature": signature,
            },
            "artifact": {
                "dataset_commitment": dataset_commitment,
                "input_commitment": input_commitment,
                "model_id": model_id,
                "output_commitment": output_commitment,
                "result_status": result_status,
            },
        },
        sort_keys=True,
    )


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


def fund_job(direct_vm, contract, requester):
    direct_vm.sender = requester
    direct_vm.value = JOB_PRICE
    contract.request_compute(
        "job-001",
        "mobility-v1",
        MODEL_ID,
        "Train for 12 epochs; report MAE and output artifact commitment.",
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
