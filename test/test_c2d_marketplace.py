from conftest import (
    DATASET_STAKE,
    JOB_COLLATERAL,
    JOB_PRICE,
    ONE_GEN,
    OUTPUT_COMMITMENT,
    address_hex,
    build_attestation_quote,
    fund_job,
    inconclusive_assessment,
    rejected_assessment,
    stake_and_register,
    valid_assessment,
)


CONTRACT_PATH = "contracts/c2d_marketplace.py"


def test_provider_must_stake_before_registering(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("Available stake is below the dataset bond"):
        contract.register_dataset(
            "unbonded-data",
            "Unbonded data",
            "Dataset without provider collateral.",
            "JSONL",
            "sha256:unbonded",
            "Research use only.",
            JOB_PRICE,
        )


def test_listing_locks_bond_and_blocks_withdrawal(
    direct_vm,
    direct_deploy,
    direct_alice,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    provider = contract.get_provider(address_hex(direct_alice))
    dataset = contract.get_dataset("mobility-v1")
    assert provider["total_stake"] == DATASET_STAKE + (2 * JOB_COLLATERAL)
    assert provider["locked_stake"] == DATASET_STAKE
    assert provider["available_stake"] == 2 * JOB_COLLATERAL
    assert provider["active_datasets"] == 1
    assert dataset["listing_bond"] == DATASET_STAKE

    with direct_vm.expect_revert("Withdrawal exceeds available stake"):
        contract.withdraw_stake((2 * JOB_COLLATERAL) + 1)


def test_default_enclave_registry_is_provisioned(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT_PATH)
    assert contract.is_trusted_enclave("11" * 32) is True
    assert contract.is_trusted_enclave("99" * 32) is False


def test_verified_attestation_releases_escrow_without_slashing(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    direct_vm.check_pickling = True
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(),
        OUTPUT_COMMITMENT,
    )

    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    dataset = contract.get_dataset("mobility-v1")
    stats = contract.get_marketplace_stats()
    assert result["status"] == "VERIFIED"
    assert result["verdict"] == "VALID"
    assert result["attestation_status"] == "ENCLAVE_VERIFIED"
    assert job["verified"] is True
    assert job["attestation_status"] == "ENCLAVE_VERIFIED"
    assert job["slash_amount"] == 0
    assert job["settlement_amount"] == JOB_PRICE
    assert job["output_commitment"] == OUTPUT_COMMITMENT
    assert provider["total_stake"] == DATASET_STAKE + (2 * JOB_COLLATERAL)
    assert provider["locked_stake"] == DATASET_STAKE
    assert provider["slashed_stake"] == 0
    assert dataset["active"] is True
    assert dataset["open_jobs"] == 0
    assert stats["total_escrowed"] == 0
    assert stats["total_slashed"] == 0


def test_forged_model_attestation_is_slashed_deterministically(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # No LLM mock: a mismatched model is rejected by deterministic verification.
    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(model_id="unrelated-model-v9", output_commitment=OUTPUT_COMMITMENT),
        OUTPUT_COMMITMENT,
    )

    expected_slash = DATASET_STAKE + JOB_COLLATERAL
    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    dataset = contract.get_dataset("mobility-v1")
    stats = contract.get_marketplace_stats()
    reputation = contract.get_provider_reputation(address_hex(direct_alice))
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "MODEL_MISMATCH"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"
    assert result["slash_amount"] == expected_slash
    # Requester is refunded the escrow; the slashed collateral is held in treasury.
    assert job["settlement_amount"] == JOB_PRICE
    assert provider["total_stake"] == JOB_COLLATERAL
    assert provider["locked_stake"] == 0
    assert provider["slashed_stake"] == expected_slash
    assert provider["active_datasets"] == 0
    assert dataset["active"] is False
    assert dataset["open_jobs"] == 0
    assert reputation["failed_jobs"] == 1
    assert stats["total_escrowed"] == 0
    assert stats["total_slashed"] == expected_slash


def test_tampered_quote_signature_is_rejected(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(tamper_signature=True),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "SIGNATURE_INVALID"


def test_untrusted_enclave_measurement_is_rejected(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(mrenclave="99" * 32),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "UNTRUSTED_ENCLAVE"


def test_inconclusive_review_keeps_funds_and_collateral_locked(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", inconclusive_assessment())

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(result_status="PENDING"),
        OUTPUT_COMMITMENT,
    )

    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    assert result["status"] == "INCONCLUSIVE"
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["attestation_status"] == "ENCLAVE_VERIFIED"
    assert job["verified"] is False
    assert provider["locked_stake"] == DATASET_STAKE + JOB_COLLATERAL
    assert contract.get_marketplace_stats()["total_escrowed"] == JOB_PRICE


def test_validator_reexecutes_and_compares_decision_fields(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())
    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(),
        OUTPUT_COMMITMENT,
    )

    assert direct_vm.run_validator() is True

    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*security validator settling.*", rejected_assessment())
    assert direct_vm.run_validator() is False


def test_only_provider_can_submit_execution_proof(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
    direct_charlie,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("Only the dataset provider can submit proof"):
        contract.submit_execution_proof(
            "job-001",
            build_attestation_quote(),
            OUTPUT_COMMITMENT,
        )


# =============================================================================
# STATE MACHINE: CANCELLATION, APPEALS, REPUTATION & GLOBAL STATS
# =============================================================================

def test_requester_can_cancel_funded_job_and_receive_refund(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_bob
    contract.cancel_expired_job("job-001")

    job = contract.get_job("job-001")
    dataset = contract.get_dataset("mobility-v1")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    assert job["status"] == "CANCELLED"
    assert dataset["open_jobs"] == 0
    assert provider["locked_stake"] == DATASET_STAKE
    assert stats["total_escrowed"] == 0


def test_unauthorized_address_cannot_cancel_job(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
    direct_charlie,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("Only the requester can cancel this job"):
        contract.cancel_expired_job("job-001")


def test_provider_can_appeal_slashed_job_with_bond(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(model_id="unrelated-model-v9"),
        OUTPUT_COMMITMENT,
    )

    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Hardware enclave attestation shows correct execution despite parsing ambiguity.",
        build_attestation_quote(),
    )
    direct_vm.value = 0

    job = contract.get_job("job-001")
    reputation = contract.get_provider_reputation(address_hex(direct_alice))

    assert job["status"] == "APPEALED"
    assert job["appeal_bond"] == ONE_GEN
    assert "Dispute active" in job["verification_summary"]
    assert reputation["appealed_jobs"] == 1


def test_accepted_appeal_returns_bond_and_reverses_slash(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # Provider is slashed for a malformed quote signature.
    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(tamper_signature=True),
        OUTPUT_COMMITMENT,
    )

    # Provider appeals with a fully valid enclave quote as evidence.
    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Re-submitting a correctly signed enclave quote for the same committed work.",
        build_attestation_quote(),
    )
    direct_vm.value = 0

    result = contract.resolve_appeal("job-001")
    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    assert result["status"] == "APPEAL_ACCEPTED"
    assert result["returned_bond"] == ONE_GEN
    assert job["status"] == "APPEAL_ACCEPTED"
    assert job["slash_amount"] == 0
    assert provider["total_stake"] == DATASET_STAKE + (2 * JOB_COLLATERAL)
    assert provider["slashed_stake"] == 0
    assert stats["total_slashed"] == 0
    assert stats["total_appeal_bonds"] == 0


def test_rejected_appeal_forfeits_bond_to_requester(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(model_id="unrelated-model-v9"),
        OUTPUT_COMMITMENT,
    )

    # Appeal evidence is still invalid, so the appeal must be rejected.
    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Disputing the slash without a valid quote.",
        build_attestation_quote(model_id="unrelated-model-v9"),
    )
    direct_vm.value = 0

    expected_slash = DATASET_STAKE + JOB_COLLATERAL
    result = contract.resolve_appeal("job-001")
    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))

    assert result["status"] == "APPEAL_REJECTED"
    assert result["forfeited_bond"] == ONE_GEN
    assert job["status"] == "APPEAL_REJECTED"
    assert provider["slashed_stake"] == expected_slash
    assert contract.get_marketplace_stats()["total_appeal_bonds"] == 0


def test_provider_reputation_and_marketplace_stats_accuracy(
    direct_vm,
    direct_deploy,
    direct_alice,
    direct_bob,
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(),
        OUTPUT_COMMITMENT,
    )

    reputation = contract.get_provider_reputation(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    assert reputation["successful_jobs"] == 1
    assert reputation["failed_jobs"] == 0
    assert reputation["reputation_score"] == 100
    assert stats["total_datasets"] == 1
    assert stats["total_jobs"] == 1
    assert stats["minimum_appeal_bond"] == ONE_GEN
