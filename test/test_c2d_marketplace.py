import datetime as _dt

from conftest import (
    DATASET_STAKE,
    JOB_COLLATERAL,
    JOB_PRICE,
    ONE_GEN,
    OUTPUT_COMMITMENT,
    address_hex,
    build_attestation_quote,
    fund_job,
    future_iso,
    inconclusive_assessment,
    rejected_assessment,
    stake_and_register,
    valid_assessment,
    warp,
)


CONTRACT_PATH = "contracts/c2d_marketplace.py"


# =============================================================================
# PROVIDER COLLATERAL & DATASET REGISTRATION
# =============================================================================

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


def test_listing_locks_bond_and_blocks_withdrawal(direct_vm, direct_deploy, direct_alice):
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


# =============================================================================
# PRODUCTION ISOLATION
# =============================================================================

def test_reserved_dataset_id_prefix_is_blocked(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_alice
    direct_vm.value = DATASET_STAKE + (2 * JOB_COLLATERAL)
    contract.stake_provider()
    direct_vm.value = 0

    blocked_ids = [
        "demo-mobility",
        "test-dataset-1",
        "mock-data",
        "dev-dataset",
        "staging-v1",
        "_test_corpus",
        "[test]dataset",
        "fake-data",
        "dummy-set",
        "sample-corpus",
    ]
    for bad_id in blocked_ids:
        with direct_vm.expect_revert("reserved prefix"):
            contract.register_dataset(
                bad_id,
                "Blocked dataset",
                "Should not be stored.",
                "JSONL",
                "sha256:placeholder",
                "None.",
                JOB_PRICE,
            )


def test_reserved_job_id_prefix_is_blocked(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    blocked_ids = [
        "test-job-001",
        "demo-run-1",
        "mock-job",
        "staging-compute-1",
        "fake-request",
    ]
    for bad_id in blocked_ids:
        direct_vm.sender = direct_bob
        direct_vm.value = JOB_PRICE
        with direct_vm.expect_revert("reserved prefix"):
            contract.request_compute(
                bad_id,
                "mobility-v1",
                "mobility-transformer-v4",
                "Train for 12 epochs.",
                "sha256:input-abc",
            )
        direct_vm.value = 0


# =============================================================================
# ENCLAVE ATTESTATION — DETERMINISTIC VERIFICATION
# =============================================================================

def test_verified_attestation_releases_escrow_without_slashing(
    direct_vm, direct_deploy, direct_alice, direct_bob
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
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

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
    direct_vm, direct_deploy, direct_alice, direct_bob
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
    direct_vm, direct_deploy, direct_alice, direct_bob
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


def test_compute_spec_mismatch_is_rejected_deterministically(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Providing a quote built for a different compute spec triggers COMPUTE_SPEC_MISMATCH."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(compute_spec="Completely different workload spec."),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "COMPUTE_SPEC_MISMATCH"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_inconclusive_review_keeps_funds_and_collateral_locked(
    direct_vm, direct_deploy, direct_alice, direct_bob
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
    direct_vm, direct_deploy, direct_alice, direct_bob
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
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
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
# CANCELLATION — STRICT DEADLINE GATING
# =============================================================================

def test_nobody_can_cancel_before_proof_deadline(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    """Requester and any third party are both blocked before the deadline passes."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    for sender in (direct_bob, direct_charlie):
        direct_vm.sender = sender
        with direct_vm.expect_revert("deadline has not yet expired"):
            contract.cancel_expired_job("job-001")


def test_anyone_can_cancel_funded_job_after_proof_deadline(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    """Any caller (including a third party) can trigger cancellation once expired."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # Advance the block clock past the 7-day proof window.
    warp(direct_vm, future_iso(days=8))

    direct_vm.sender = direct_charlie
    result = contract.cancel_expired_job("job-001")

    job = contract.get_job("job-001")
    dataset = contract.get_dataset("mobility-v1")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    assert result["status"] == "CANCELLED"
    assert result["refunded_amount"] == JOB_PRICE
    assert job["status"] == "CANCELLED"
    assert dataset["open_jobs"] == 0
    assert provider["locked_stake"] == DATASET_STAKE
    assert stats["total_escrowed"] == 0


def test_requester_can_cancel_funded_job_after_deadline(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Requester is allowed to cancel after the proof deadline — same as any caller."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    warp(direct_vm, future_iso(days=8))

    direct_vm.sender = direct_bob
    contract.cancel_expired_job("job-001")

    job = contract.get_job("job-001")
    assert job["status"] == "CANCELLED"
    assert job["settlement_amount"] == JOB_PRICE


def test_cancel_inconclusive_job_after_appeal_deadline(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """An INCONCLUSIVE job is cancellable only after its appeal_deadline, not before."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", inconclusive_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(result_status="PENDING"),
        OUTPUT_COMMITMENT,
    )

    # The appeal deadline is ~3 days from the proof submission.
    # Without warping, the deadline has not passed.
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("deadline has not yet expired"):
        contract.cancel_expired_job("job-001")

    # After the appeal window closes, cancellation is permitted.
    warp(direct_vm, future_iso(days=4))
    result = contract.cancel_expired_job("job-001")
    assert result["status"] == "CANCELLED"
    assert result["refunded_amount"] == JOB_PRICE

    stats = contract.get_marketplace_stats()
    assert stats["total_escrowed"] == 0


# =============================================================================
# APPEALS — SLASHED ORIGIN
# =============================================================================

def test_provider_can_appeal_slashed_job_with_bond(
    direct_vm, direct_deploy, direct_alice, direct_bob
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
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(tamper_signature=True),
        OUTPUT_COMMITMENT,
    )

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
    direct_vm, direct_deploy, direct_alice, direct_bob
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


# =============================================================================
# APPEALS — INCONCLUSIVE ORIGIN
# =============================================================================

def test_inconclusive_appeal_accepted_settles_payment_to_provider(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """When an INCONCLUSIVE-origin appeal is accepted, the provider receives
    the escrowed job fee, collateral is released, and all balances are clean."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", inconclusive_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(result_status="PENDING"),
        OUTPUT_COMMITMENT,
    )

    # Provider appeals with a fully valid COMPLETED quote as evidence.
    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Submitting a completed-status quote to resolve the inconclusive verdict.",
        build_attestation_quote(result_status="COMPLETED"),
    )
    direct_vm.value = 0

    result = contract.resolve_appeal("job-001")
    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    reputation = contract.get_provider_reputation(address_hex(direct_alice))

    assert result["status"] == "APPEAL_ACCEPTED"
    assert result["returned_bond"] == ONE_GEN
    assert result["settled_payment"] == JOB_PRICE
    assert job["status"] == "APPEAL_ACCEPTED"
    assert job["verified"] is True
    assert job["slash_amount"] == 0
    assert job["settlement_amount"] == JOB_PRICE
    # Collateral released on accepted appeal; provider recovers full stake.
    assert provider["total_stake"] == DATASET_STAKE + (2 * JOB_COLLATERAL)
    assert provider["slashed_stake"] == 0
    assert reputation["successful_jobs"] == 1
    assert reputation["failed_jobs"] == 0
    assert stats["total_escrowed"] == 0
    assert stats["total_appeal_bonds"] == 0


def test_inconclusive_appeal_rejected_slashes_provider_and_refunds_requester(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """When an INCONCLUSIVE-origin appeal is rejected, the job is settled as a
    slash: requester gets the escrow back and provider loses collateral + bond."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", inconclusive_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(result_status="PENDING"),
        OUTPUT_COMMITMENT,
    )

    # Provider appeals with a tampered (invalid) quote — appeal will be rejected.
    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Attempting appeal with invalid evidence.",
        build_attestation_quote(tamper_signature=True),
    )
    direct_vm.value = 0

    result = contract.resolve_appeal("job-001")
    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    expected_slash = DATASET_STAKE + JOB_COLLATERAL

    reputation = contract.get_provider_reputation(address_hex(direct_alice))

    assert result["status"] == "APPEAL_REJECTED"
    assert result["forfeited_bond"] == ONE_GEN
    assert job["status"] == "APPEAL_REJECTED"
    assert job["slash_amount"] == expected_slash
    assert job["settlement_amount"] == JOB_PRICE
    assert provider["slashed_stake"] == expected_slash
    assert reputation["failed_jobs"] == 1
    # Requester was refunded the job price; bond also forfeited to requester.
    assert stats["total_escrowed"] == 0
    assert stats["total_appeal_bonds"] == 0


# =============================================================================
# CLAIM UNRESOLVED APPEAL — LIVENESS GUARD
# =============================================================================

def test_claim_unresolved_appeal_before_adjudication_window_fails(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Provider cannot reclaim the bond while the adjudication window is open."""
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
        "Disputing slash; will claim back bond if not adjudicated.",
        build_attestation_quote(),
    )
    direct_vm.value = 0

    # Adjudication window just opened — cannot claim yet.
    with direct_vm.expect_revert("Appeal adjudication window is still open"):
        contract.claim_unresolved_appeal("job-001")


def test_claim_unresolved_appeal_after_adjudication_window_succeeds(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Provider can reclaim the bond once the adjudication window has closed."""
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
        "Filing appeal; adjudication window is 3 days.",
        build_attestation_quote(),
    )
    direct_vm.value = 0

    # Warp past the 3-day adjudication window.
    warp(direct_vm, future_iso(days=4))

    direct_vm.sender = direct_alice
    result = contract.claim_unresolved_appeal("job-001")
    job = contract.get_job("job-001")

    assert result["status"] == "APPEAL_REJECTED"
    assert result["returned_bond"] == ONE_GEN
    assert job["status"] == "APPEAL_REJECTED"
    assert job["verification_reason"] == "APPEAL_TIMED_OUT"
    assert contract.get_marketplace_stats()["total_appeal_bonds"] == 0


# =============================================================================
# REPUTATION & GLOBAL STATS
# =============================================================================

def test_provider_reputation_and_marketplace_stats_accuracy(
    direct_vm, direct_deploy, direct_alice, direct_bob
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
