"""
Extended direct-mode test suite for C2DMarketplace.

Covers every error branch, access-control guard, attestation error code,
dataset lifecycle path, job creation guard, LLM misbehaviour path, and
reputation edge case not exercised by test_c2d_marketplace.py.
"""

import json

from conftest import (
    DATASET_COMMITMENT,
    DATASET_STAKE,
    INPUT_COMMITMENT,
    JOB_COLLATERAL,
    JOB_PRICE,
    MODEL_ID,
    ONE_GEN,
    OUTPUT_COMMITMENT,
    address_hex,
    build_attestation_quote,
    build_attestation_quote_with_binding_mismatch,
    fund_job,
    future_iso,
    inconclusive_assessment,
    stake_and_register,
    valid_assessment,
    warp,
)


CONTRACT_PATH = "contracts/c2d_marketplace.py"


# =============================================================================
# ADMIN REGISTRY CONTROLS
# =============================================================================

def test_non_admin_cannot_set_trusted_enclave(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Only the admin can manage the enclave registry"):
        contract.set_trusted_enclave("33" * 32, True)


def test_non_admin_cannot_set_trusted_signer(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Only the admin can manage the enclave registry"):
        contract.set_trusted_signer("33" * 32, True)


def test_admin_can_enable_new_enclave_and_it_accepts_proofs(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    """Admin whitelists a new mrenclave; proofs signed by it are then accepted."""
    contract = direct_deploy(CONTRACT_PATH)
    new_mrenclave = "33" * 32

    # Admin enables the new measurement.
    direct_vm.sender = direct_owner
    contract.set_trusted_enclave(new_mrenclave, True)

    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(mrenclave=new_mrenclave),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "VERIFIED"


def test_admin_can_disable_enclave_and_proof_is_then_rejected(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    """Admin revokes the default mrenclave; subsequent proofs are slashed."""
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_owner
    contract.set_trusted_enclave("11" * 32, False)

    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "UNTRUSTED_ENCLAVE"


def test_set_trusted_enclave_rejects_malformed_measurement(
    direct_vm, direct_deploy, direct_owner
):
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_owner
    with direct_vm.expect_revert("Enclave measurement must be 32 bytes of hex"):
        contract.set_trusted_enclave("not-hex", True)


def test_set_trusted_signer_rejects_malformed_measurement(
    direct_vm, direct_deploy, direct_owner
):
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_owner
    with direct_vm.expect_revert("Signer measurement must be 32 bytes of hex"):
        contract.set_trusted_signer("zz" * 32, True)


# =============================================================================
# STAKING GUARDS
# =============================================================================

def test_zero_value_stake_is_rejected(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_alice
    direct_vm.value = 0
    with direct_vm.expect_revert("Stake amount must be greater than zero"):
        contract.stake_provider()


def test_zero_withdrawal_amount_is_rejected(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Withdrawal amount must be greater than zero"):
        contract.withdraw_stake(0)


def test_withdrawal_of_exact_available_balance_succeeds(
    direct_vm, direct_deploy, direct_alice
):
    """Provider can withdraw every unlocked token without error."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    provider = contract.get_provider(address_hex(direct_alice))
    available = provider["available_stake"]
    assert available == 2 * JOB_COLLATERAL

    direct_vm.sender = direct_alice
    contract.withdraw_stake(available)

    provider_after = contract.get_provider(address_hex(direct_alice))
    assert provider_after["available_stake"] == 0
    assert provider_after["locked_stake"] == DATASET_STAKE


# =============================================================================
# DATASET LIFECYCLE
# =============================================================================

def test_duplicate_dataset_id_is_rejected(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Dataset already exists"):
        contract.register_dataset(
            "mobility-v1",
            "Duplicate",
            "Should fail.",
            "CSV",
            "sha256:dup",
            "None.",
            JOB_PRICE,
        )


def test_non_provider_cannot_change_dataset_status(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only the provider can change dataset status"):
        contract.set_dataset_active("mobility-v1", False)


def test_cannot_deactivate_dataset_with_open_jobs(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Dataset has unresolved compute jobs"):
        contract.set_dataset_active("mobility-v1", False)


def test_deactivate_then_reactivate_releases_and_relocks_bond(
    direct_vm, direct_deploy, direct_alice
):
    """Deactivation releases the listing bond; reactivation re-locks it."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_alice
    contract.set_dataset_active("mobility-v1", False)

    provider_after_deactivate = contract.get_provider(address_hex(direct_alice))
    dataset_after_deactivate = contract.get_dataset("mobility-v1")
    assert dataset_after_deactivate["active"] is False
    assert dataset_after_deactivate["listing_bond"] == 0
    assert provider_after_deactivate["locked_stake"] == 0
    assert provider_after_deactivate["active_datasets"] == 0

    contract.set_dataset_active("mobility-v1", True)

    provider_after_reactivate = contract.get_provider(address_hex(direct_alice))
    dataset_after_reactivate = contract.get_dataset("mobility-v1")
    assert dataset_after_reactivate["active"] is True
    assert dataset_after_reactivate["listing_bond"] == DATASET_STAKE
    assert provider_after_reactivate["locked_stake"] == DATASET_STAKE
    assert provider_after_reactivate["active_datasets"] == 1


# =============================================================================
# JOB CREATION GUARDS
# =============================================================================

def test_payment_mismatch_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_bob
    direct_vm.value = JOB_PRICE - 1
    with direct_vm.expect_revert("Payment must match the dataset price"):
        contract.request_compute(
            "job-001", "mobility-v1", MODEL_ID, "Train.", INPUT_COMMITMENT
        )
    direct_vm.value = 0


def test_duplicate_job_id_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_bob
    direct_vm.value = JOB_PRICE
    with direct_vm.expect_revert("Job already exists"):
        contract.request_compute(
            "job-001", "mobility-v1", MODEL_ID, "Again.", INPUT_COMMITMENT
        )
    direct_vm.value = 0


def test_inactive_dataset_blocks_job_creation(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_alice
    contract.set_dataset_active("mobility-v1", False)

    direct_vm.sender = direct_bob
    direct_vm.value = JOB_PRICE
    with direct_vm.expect_revert("Dataset is not accepting jobs"):
        contract.request_compute(
            "job-002", "mobility-v1", MODEL_ID, "Train.", INPUT_COMMITMENT
        )
    direct_vm.value = 0


def test_provider_insufficient_collateral_blocks_job_creation(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Provider staked only enough for the dataset bond; job collateral check fails."""
    contract = direct_deploy(CONTRACT_PATH)

    direct_vm.sender = direct_alice
    direct_vm.value = DATASET_STAKE
    contract.stake_provider()
    direct_vm.value = 0
    contract.register_dataset(
        "lean-data",
        "Lean dataset",
        "No job collateral headroom.",
        "CSV",
        DATASET_COMMITMENT,
        "Research only.",
        JOB_PRICE,
    )

    direct_vm.sender = direct_bob
    direct_vm.value = JOB_PRICE
    with direct_vm.expect_revert("Provider has insufficient job collateral"):
        contract.request_compute(
            "job-lean", "lean-data", MODEL_ID, "Train.", INPUT_COMMITMENT
        )
    direct_vm.value = 0


def test_nonexistent_dataset_blocks_job_creation(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_bob
    direct_vm.value = JOB_PRICE
    with direct_vm.expect_revert("Dataset does not exist"):
        contract.request_compute(
            "job-ghost", "no-such-dataset", MODEL_ID, "Train.", INPUT_COMMITMENT
        )
    direct_vm.value = 0


# =============================================================================
# ATTESTATION ERROR CODES — DETERMINISTIC VERIFICATION
# =============================================================================

def test_dataset_commitment_mismatch_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(dataset_commitment="sha256:wrong-dataset-xyz"),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "DATASET_MISMATCH"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_input_commitment_mismatch_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(input_commitment="sha256:wrong-input-xyz"),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "INPUT_COMMITMENT_MISMATCH"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_untrusted_signer_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A quote from an unregistered mrsigner is slashed as UNTRUSTED_SIGNER."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(mrsigner="aa" * 32),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "UNTRUSTED_SIGNER"


def test_malformed_quote_json_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A quote that is not valid JSON is slashed.

    Note: the contract's post-parse output_commitment cross-check fires before
    any MALFORMED_QUOTE code can be returned (inspection["output_commitment"] is
    "" for failed parses, which never equals the caller's non-empty param). The
    job is still slashed — only the violation_code is caller-side OUTPUT_COMMITMENT_INVALID.
    """
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        "{ this is not valid json !!!",
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"


def test_empty_quote_object_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """An empty JSON object (no enclave/artifact) is slashed for the same reason."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof("job-001", "{}", OUTPUT_COMMITMENT)
    assert result["status"] == "SLASHED"


def test_compute_spec_commitment_missing_from_artifact(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Artifact lacking compute_spec_commitment triggers COMPUTE_SPEC_COMMITMENT_INVALID."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(drop_compute_spec_commitment=True),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "COMPUTE_SPEC_COMMITMENT_INVALID"


def test_binding_mismatch_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """report_data that is valid hex32 but does not match the canonical
    five-field binding triggers BINDING_MISMATCH, not SIGNATURE_INVALID."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote_with_binding_mismatch(),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "BINDING_MISMATCH"


def test_output_commitment_parameter_does_not_match_quote_artifact(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Quote artifact and the output_commitment parameter must agree; a mismatch
    is caught after structural inspection and produces OUTPUT_COMMITMENT_INVALID."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    # Quote is internally valid for OUTPUT_COMMITMENT, but we submit a different param.
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(),
        "sha256:caller-supplied-different-output",
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "OUTPUT_COMMITMENT_INVALID"


# =============================================================================
# PROOF SUBMISSION GUARDS
# =============================================================================

def test_submit_proof_on_inconclusive_job_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
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

    # Job is now INCONCLUSIVE; a second proof submission must be rejected.
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Job is not awaiting proof"):
        contract.submit_execution_proof(
            "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
        )


def test_submit_proof_on_verified_job_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Job is not awaiting proof"):
        contract.submit_execution_proof(
            "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
        )


def test_submit_proof_on_cancelled_job_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    warp(direct_vm, future_iso(days=8))
    direct_vm.sender = direct_bob
    contract.cancel_expired_job("job-001")

    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Job is not awaiting proof"):
        contract.submit_execution_proof(
            "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
        )


# =============================================================================
# CANCEL GUARDS — TERMINAL STATES
# =============================================================================

def test_cancel_verified_job_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    with direct_vm.expect_revert("Job is not in a cancellable state"):
        contract.cancel_expired_job("job-001")


def test_cancel_slashed_job_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(model_id="wrong-model"),
        OUTPUT_COMMITMENT,
    )

    with direct_vm.expect_revert("Job is not in a cancellable state"):
        contract.cancel_expired_job("job-001")


# =============================================================================
# LLM VALIDATOR MISBEHAVIOUR
# =============================================================================

def test_validator_disagreement_on_non_dict_llm_response(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """If the validator's LLM returns a plain string instead of a dict,
    assess_report() raises UserError and the validator returns False."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    direct_vm.clear_mocks()
    # Validator LLM returns a bare string, not a JSON object.
    direct_vm.mock_llm(r".*security validator settling.*", '"just a string"')
    assert direct_vm.run_validator() is False


def test_validator_disagreement_on_unknown_verdict(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """If the validator's LLM returns an unrecognised verdict, assess_report()
    raises UserError (verdict not in allowed set) and the validator returns False."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    direct_vm.clear_mocks()
    bad_verdict = json.dumps({
        "verdict": "UNCERTAIN",
        "violation_code": "NONE",
        "summary": "Unknown verdict string.",
    })
    direct_vm.mock_llm(r".*security validator settling.*", bad_verdict)
    assert direct_vm.run_validator() is False


def test_validator_disagreement_on_wrong_violation_code_for_valid_verdict(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """VALID verdict paired with a non-NONE violation_code is an LLM error;
    assess_report() raises and the validator returns False."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    direct_vm.clear_mocks()
    bad_code = json.dumps({
        "verdict": "VALID",
        "violation_code": "EXECUTION_FAILED",
        "summary": "Contradictory fields.",
    })
    direct_vm.mock_llm(r".*security validator settling.*", bad_code)
    assert direct_vm.run_validator() is False


# =============================================================================
# APPEAL GUARDS
# =============================================================================

def test_appeal_bond_below_minimum_is_rejected(
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
    direct_vm.value = ONE_GEN - 1
    with direct_vm.expect_revert("Appeal bond is below the minimum"):
        contract.appeal_job_verdict(
            "job-001",
            "Disputing with insufficient bond.",
            build_attestation_quote(),
        )
    direct_vm.value = 0


def test_third_party_cannot_appeal_job(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
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

    direct_vm.sender = direct_charlie
    direct_vm.value = ONE_GEN
    with direct_vm.expect_revert("Only the dataset provider can appeal"):
        contract.appeal_job_verdict(
            "job-001",
            "Unauthorised third-party appeal attempt.",
            build_attestation_quote(),
        )
    direct_vm.value = 0


def test_cannot_appeal_verified_job(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    with direct_vm.expect_revert("Only slashed or inconclusive jobs can be appealed"):
        contract.appeal_job_verdict(
            "job-001", "Appealing a settled job.", build_attestation_quote()
        )
    direct_vm.value = 0


def test_appeal_window_expired_before_filing_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The provider's appeal window (3 days post-slash) must not have closed."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(tamper_signature=True),
        OUTPUT_COMMITMENT,
    )

    # Advance past the 3-day appeal window set at slash time.
    warp(direct_vm, future_iso(days=4))

    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    with direct_vm.expect_revert("Appeal window has closed"):
        contract.appeal_job_verdict(
            "job-001",
            "Attempting to file after the window closed.",
            build_attestation_quote(),
        )
    direct_vm.value = 0


def test_resolve_appeal_on_non_appealed_job_is_rejected(
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

    # Job is SLASHED but not APPEALED yet.
    with direct_vm.expect_revert("Job is not under appeal"):
        contract.resolve_appeal("job-001")


def test_claim_unresolved_appeal_by_non_provider_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(model_id="wrong-model"),
        OUTPUT_COMMITMENT,
    )

    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001", "Filing appeal.", build_attestation_quote()
    )
    direct_vm.value = 0

    warp(direct_vm, future_iso(days=4))

    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("Only the provider can reclaim the bond"):
        contract.claim_unresolved_appeal("job-001")


def test_resolve_appeal_checks_result_status_must_be_completed(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """resolve_appeal rejects evidence whose result_status is not COMPLETED."""
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
    # Evidence is otherwise valid but result_status is PENDING, not COMPLETED.
    contract.appeal_job_verdict(
        "job-001",
        "Evidence with non-completed status.",
        build_attestation_quote(result_status="PENDING"),
    )
    direct_vm.value = 0

    result = contract.resolve_appeal("job-001")
    assert result["status"] == "APPEAL_REJECTED"


# =============================================================================
# VIEW GUARDS
# =============================================================================

def test_get_dataset_on_nonexistent_id_raises(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT_PATH)
    with direct_vm.expect_revert("Dataset does not exist"):
        contract.get_dataset("no-such-dataset")


def test_get_job_on_nonexistent_id_raises(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT_PATH)
    with direct_vm.expect_revert("Job does not exist"):
        contract.get_job("no-such-job")


# =============================================================================
# PROVIDER REPUTATION EDGE CASES
# =============================================================================

def test_provider_with_no_completed_jobs_has_perfect_score(
    direct_vm, direct_deploy, direct_alice
):
    """A brand-new provider with zero completed jobs has reputation_score == 100."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    reputation = contract.get_provider_reputation(address_hex(direct_alice))
    assert reputation["successful_jobs"] == 0
    assert reputation["failed_jobs"] == 0
    assert reputation["completed_jobs"] == 0
    assert reputation["reputation_score"] == 100


def test_provider_reputation_reflects_mix_of_successes_and_failures(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """One successful and one slashed job yields reputation_score == 50."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    # Job A: verified successfully; frees the collateral lock before job B.
    fund_job(direct_vm, contract, direct_bob, "job-A")
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())
    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-A", build_attestation_quote(), OUTPUT_COMMITMENT
    )
    direct_vm.clear_mocks()

    # Job B: slashed due to wrong model (dataset is still active after job A).
    fund_job(direct_vm, contract, direct_bob, "job-B")
    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-B",
        build_attestation_quote(model_id="completely-wrong-model"),
        OUTPUT_COMMITMENT,
    )

    reputation = contract.get_provider_reputation(address_hex(direct_alice))
    assert reputation["successful_jobs"] == 1
    assert reputation["failed_jobs"] == 1
    assert reputation["completed_jobs"] == 2
    assert reputation["reputation_score"] == 50


# =============================================================================
# GLOBAL STATS CONSISTENCY
# =============================================================================

def test_marketplace_stats_reflect_multiple_job_lifecycle_events(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Escrowed and slashed totals stay consistent across job state transitions."""
    contract = direct_deploy(CONTRACT_PATH)

    # Need dataset bond + 3 job collaterals worth of stake headroom.
    direct_vm.sender = direct_alice
    direct_vm.value = DATASET_STAKE + (4 * JOB_COLLATERAL)
    contract.stake_provider()
    direct_vm.value = 0
    # Register as "mobility-v1" so fund_job (which hardcodes that dataset id) works.
    contract.register_dataset(
        "mobility-v1",
        "Urban mobility vectors",
        "Three jobs for stats consistency check.",
        "Parquet: timestamp, zone_id, speed, occupancy",
        DATASET_COMMITMENT,
        "Aggregate workloads only.",
        JOB_PRICE,
    )

    # Escrow three jobs.
    for jid in ("stats-job-1", "stats-job-2", "stats-job-3"):
        fund_job(direct_vm, contract, direct_bob, jid)

    stats_after_funding = contract.get_marketplace_stats()
    assert stats_after_funding["total_escrowed"] == 3 * JOB_PRICE
    assert stats_after_funding["total_jobs"] == 3

    # Settle job 1 as verified.
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())
    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "stats-job-1", build_attestation_quote(), OUTPUT_COMMITMENT
    )
    direct_vm.clear_mocks()

    stats_after_verify = contract.get_marketplace_stats()
    assert stats_after_verify["total_escrowed"] == 2 * JOB_PRICE
    assert stats_after_verify["total_slashed"] == 0

    # Settle job 2 via deadline cancellation.
    warp(direct_vm, future_iso(days=8))
    direct_vm.sender = direct_bob
    contract.cancel_expired_job("stats-job-2")

    stats_after_cancel = contract.get_marketplace_stats()
    assert stats_after_cancel["total_escrowed"] == JOB_PRICE

    # Settle job 3 as a slash.
    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "stats-job-3",
        build_attestation_quote(tamper_signature=True),
        OUTPUT_COMMITMENT,
    )

    expected_slash = DATASET_STAKE + JOB_COLLATERAL
    stats_final = contract.get_marketplace_stats()
    assert stats_final["total_escrowed"] == 0
    assert stats_final["total_slashed"] == expected_slash
