import json


ONE_GEN = 10**18
DATASET_STAKE = 10 * ONE_GEN
JOB_COLLATERAL = 2 * ONE_GEN
JOB_PRICE = 3 * ONE_GEN


def address_hex(address):
    return "0x" + bytes(address).hex()


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
        "sha256:dataset-commitment-4a1c",
        "Approved aggregate forecasting workloads only.",
        JOB_PRICE,
    )


def fund_job(direct_vm, contract, requester):
    direct_vm.sender = requester
    direct_vm.value = JOB_PRICE
    contract.request_compute(
        "job-001",
        "mobility-v1",
        "mobility-transformer-v4",
        "Train for 12 epochs; report MAE and output artifact commitment.",
        "sha256:input-commitment-77f0",
    )
    direct_vm.value = 0


def valid_assessment():
    return json.dumps(
        {
            "verdict": "VALID",
            "violation_code": "NONE",
            "summary": "The proof matches every committed request field and records completed execution.",
        }
    )


def malicious_assessment():
    return json.dumps(
        {
            "verdict": "INVALID",
            "violation_code": "MODEL_MISMATCH",
            "summary": "The submitted proof names a different model than the funded request.",
        }
    )


def inconclusive_assessment():
    return json.dumps(
        {
            "verdict": "INCONCLUSIVE",
            "violation_code": "INSUFFICIENT_EVIDENCE",
            "summary": "The proof omits the output commitment needed to establish completion.",
        }
    )
