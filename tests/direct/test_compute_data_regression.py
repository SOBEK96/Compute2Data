"""Steward remediation regression suite for the Compute2Data marketplace.

This dedicated direct-mode suite pins down the four defects that caused the
prior submission to be rejected, so a regression on any of them fails loudly:

  1. Enclave attestation must reject quotes that omit the mandatory
     compute-spec commitment or carry forged signature / binding bytes, and
     every such rejection must settle funds deterministically with no hanging
     balances.
  2. Cancellation must be strictly deadline-gated: a non-zero deadline must
     elapse before anyone (requester or third party) can cancel, the exact
     boundary second is inclusive, and a zero deadline (consensus clock
     unavailable at creation) is a controlled liveness fallback rather than a
     general bypass.
  3. Every terminal appeal transition (accept, reject, timeout) must move
     escrow, bond, and stake deterministically, for both SLASHED-origin and
     INCONCLUSIVE-origin appeals, leaving no stranded escrow or bond.
  4. Reserved demo / mock / test id prefixes must be blocked from every live
     write path.

The suite runs against contracts/c2d_marketplace.py via genlayer-test in
direct mode: `pytest tests/direct/`.
"""

from regression_helpers import (
    CONTRACT_PATH,
    DATASET_STAKE,
    JOB_COLLATERAL,
    JOB_PRICE,
    ONE_GEN,
    OUTPUT_COMMITMENT,
    address_hex,
    build_attestation_quote,
    build_attestation_quote_with_binding_mismatch,
    clear_clock,
    fund_job,
    future_iso,
    inconclusive_assessment,
    iso_from_epoch,
    stake_and_register,
    valid_assessment,
    warp,
)


# The full slash for a first-time offence is the job collateral plus the
# dataset listing bond, matching contracts/c2d_marketplace.py::_settle_slash.
EXPECTED_SLASH = DATASET_STAKE + JOB_COLLATERAL


# =============================================================================
# 1. ENCLAVE ATTESTATION REJECTION
#    Missing compute-spec commitments and forged client hashes must be
#    rejected deterministically, with escrow and stake fully settled.
# =============================================================================

def test_missing_compute_spec_commitment_is_rejected_and_settled(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A quote whose artifact omits compute_spec_commitment is slashed with a
    clear code, and every balance is resolved (escrow refunded, stake slashed)."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(drop_compute_spec_commitment=True),
        OUTPUT_COMMITMENT,
    )

    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "COMPUTE_SPEC_COMMITMENT_INVALID"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"
    # Funds fully settled: requester refunded escrow, provider stake slashed.
    assert result["slash_amount"] == EXPECTED_SLASH
    assert job["settlement_amount"] == JOB_PRICE
    assert provider["slashed_stake"] == EXPECTED_SLASH
    assert stats["total_escrowed"] == 0
    assert stats["total_slashed"] == EXPECTED_SLASH


def test_forged_signature_hash_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A client-forged (zeroed) signature never matches the enclave re-derived
    signature, so the quote is rejected as SIGNATURE_INVALID."""
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
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_forged_binding_report_data_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """report_data that is well-formed hex but does not equal the canonical
    five-field binding is rejected as BINDING_MISMATCH, proving the binding
    cryptographically incorporates every committed field."""
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


def test_divergent_compute_spec_commitment_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A quote built for a different compute specification produces a commitment
    that does not match the on-chain spec, and is rejected as COMPUTE_SPEC_MISMATCH."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(compute_spec="A completely different workload."),
        OUTPUT_COMMITMENT,
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "COMPUTE_SPEC_MISMATCH"


def test_untrusted_enclave_measurement_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A structurally valid quote from an unregistered mrenclave is rejected."""
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


def test_fully_valid_attestation_is_accepted(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Positive control: a well-formed quote with a trusted measurement and a
    completed run settles the escrow to the provider with no slashing."""
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
    assert result["status"] == "VERIFIED"
    assert result["attestation_status"] == "ENCLAVE_VERIFIED"
    assert result["slash_amount"] == 0
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


# =============================================================================
# 2. DEADLINE-GATED CANCELLATION
#    Zero-deadline fallback and expiry boundary edge cases.
# =============================================================================

def test_cannot_cancel_before_deadline_by_requester_or_third_party(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    """With a live (non-zero) deadline, neither the requester nor an unrelated
    caller may cancel before the proof window elapses."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    for sender in (direct_bob, direct_charlie):
        direct_vm.sender = sender
        with direct_vm.expect_revert("deadline has not yet expired"):
            contract.cancel_expired_job("job-001")


def test_cancel_one_second_before_deadline_reverts(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The instant immediately before the stored deadline is still gated."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    deadline = int(contract.get_job("job-001")["proof_deadline"])
    warp(direct_vm, iso_from_epoch(deadline - 1))

    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("deadline has not yet expired"):
        contract.cancel_expired_job("job-001")


def test_cancel_exactly_at_deadline_boundary_is_permitted(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The boundary second (now == deadline) is inclusive: cancellation is
    permitted and the escrow is refunded to the requester."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    deadline = int(contract.get_job("job-001")["proof_deadline"])
    warp(direct_vm, iso_from_epoch(deadline))

    direct_vm.sender = direct_bob
    result = contract.cancel_expired_job("job-001")

    assert result["status"] == "CANCELLED"
    assert result["refunded_amount"] == JOB_PRICE
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_cancel_after_deadline_settles_all_balances(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    """Any caller can cancel after expiry; escrow returns to the requester and
    the provider collateral lock is released with nothing stranded."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    warp(direct_vm, future_iso(days=8))

    direct_vm.sender = direct_charlie
    result = contract.cancel_expired_job("job-001")

    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    dataset = contract.get_dataset("mobility-v1")

    assert result["status"] == "CANCELLED"
    assert job["settlement_amount"] == JOB_PRICE
    assert provider["locked_stake"] == DATASET_STAKE
    assert dataset["open_jobs"] == 0
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_zero_deadline_is_a_controlled_liveness_fallback(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """When the consensus clock is unavailable at job creation the stored
    deadline is zero. Cancellation is then permitted as a liveness fallback so
    escrow can never be permanently stranded, and the refund still settles."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    clear_clock(direct_vm)
    fund_job(direct_vm, contract, direct_bob)

    job = contract.get_job("job-001")
    assert job["proof_deadline"] == 0

    direct_vm.sender = direct_bob
    result = contract.cancel_expired_job("job-001")

    assert result["status"] == "CANCELLED"
    assert result["refunded_amount"] == JOB_PRICE
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_inconclusive_job_cancellation_is_gated_by_appeal_deadline(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """An INCONCLUSIVE job cannot be cancelled during the provider's appeal
    window, but becomes cancellable once that window closes."""
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

    # Appeal window still open: cancellation is blocked.
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("deadline has not yet expired"):
        contract.cancel_expired_job("job-001")

    # After the appeal window closes: cancellation is permitted.
    warp(direct_vm, future_iso(days=4))
    result = contract.cancel_expired_job("job-001")
    assert result["status"] == "CANCELLED"
    assert result["refunded_amount"] == JOB_PRICE
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_terminal_state_jobs_are_not_cancellable(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A settled (VERIFIED) job cannot be cancelled even after the clock moves."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    warp(direct_vm, future_iso(days=8))
    with direct_vm.expect_revert("Job is not in a cancellable state"):
        contract.cancel_expired_job("job-001")


# =============================================================================
# 3. COMPLETE APPEAL REVERSAL LIFECYCLE
#    Every terminal transition settles escrow, bond, and stake with no
#    hanging balances, for SLASHED-origin and INCONCLUSIVE-origin appeals.
# =============================================================================

def _slash_via_forged_signature(direct_vm, contract, provider):
    """Drive job-001 into SLASHED via a forged-signature attestation."""
    direct_vm.sender = provider
    contract.submit_execution_proof(
        "job-001",
        build_attestation_quote(tamper_signature=True),
        OUTPUT_COMMITMENT,
    )


def test_slashed_appeal_accepted_reverses_slash_and_returns_bond(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Accepting a SLASHED-origin appeal restores the slashed stake from the
    treasury, returns the bond, and leaves no stranded slash or bond."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    _slash_via_forged_signature(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Re-submitting a correctly signed enclave quote for the same work.",
        build_attestation_quote(),
    )
    direct_vm.value = 0

    result = contract.resolve_appeal("job-001")
    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    assert result["status"] == "APPEAL_ACCEPTED"
    assert result["returned_bond"] == ONE_GEN
    assert result["restored_collateral"] == EXPECTED_SLASH
    assert job["slash_amount"] == 0
    # Full stake restored; no slash or bond left hanging in the protocol.
    assert provider["total_stake"] == DATASET_STAKE + (2 * JOB_COLLATERAL)
    assert provider["slashed_stake"] == 0
    assert stats["total_slashed"] == 0
    assert stats["total_appeal_bonds"] == 0


def test_slashed_appeal_rejected_forfeits_bond_and_keeps_slash(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Rejecting a SLASHED-origin appeal keeps the original slash and forfeits
    the bond to the requester, with no bond left escrowed."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    _slash_via_forged_signature(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Disputing the slash with invalid evidence.",
        build_attestation_quote(tamper_signature=True),
    )
    direct_vm.value = 0

    result = contract.resolve_appeal("job-001")
    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    assert result["status"] == "APPEAL_REJECTED"
    assert result["forfeited_bond"] == ONE_GEN
    assert job["slash_amount"] == EXPECTED_SLASH
    assert provider["slashed_stake"] == EXPECTED_SLASH
    assert stats["total_appeal_bonds"] == 0


def test_inconclusive_appeal_accepted_settles_payment_and_releases_collateral(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Accepting an INCONCLUSIVE-origin appeal pays the provider the escrowed
    fee, releases the collateral lock, and returns the bond, clearing escrow."""
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

    assert result["status"] == "APPEAL_ACCEPTED"
    assert result["returned_bond"] == ONE_GEN
    assert result["settled_payment"] == JOB_PRICE
    assert job["verified"] is True
    assert job["slash_amount"] == 0
    assert job["settlement_amount"] == JOB_PRICE
    # Collateral released; provider recovers full stake; escrow cleared.
    assert provider["total_stake"] == DATASET_STAKE + (2 * JOB_COLLATERAL)
    assert provider["slashed_stake"] == 0
    assert stats["total_escrowed"] == 0
    assert stats["total_appeal_bonds"] == 0


def test_inconclusive_appeal_rejected_slashes_and_refunds_requester(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Rejecting an INCONCLUSIVE-origin appeal settles the job as a full slash:
    the requester is refunded, the provider is penalised, and the bond is
    forfeited, leaving no escrow or bond hanging."""
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

    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Appealing with invalid evidence after an inconclusive verdict.",
        build_attestation_quote(tamper_signature=True),
    )
    direct_vm.value = 0

    result = contract.resolve_appeal("job-001")
    job = contract.get_job("job-001")
    provider = contract.get_provider(address_hex(direct_alice))
    stats = contract.get_marketplace_stats()

    assert result["status"] == "APPEAL_REJECTED"
    assert result["forfeited_bond"] == ONE_GEN
    assert job["slash_amount"] == EXPECTED_SLASH
    assert job["settlement_amount"] == JOB_PRICE
    assert provider["slashed_stake"] == EXPECTED_SLASH
    assert stats["total_escrowed"] == 0
    assert stats["total_appeal_bonds"] == 0


def test_unadjudicated_appeal_times_out_and_returns_bond(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """If an appeal is never adjudicated within its window, the provider can
    reclaim the bond and the appeal closes as rejected with nothing stranded."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    _slash_via_forged_signature(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_alice
    direct_vm.value = ONE_GEN
    contract.appeal_job_verdict(
        "job-001",
        "Filing an appeal that will not be adjudicated in time.",
        build_attestation_quote(),
    )
    direct_vm.value = 0

    # Cannot reclaim while the adjudication window is open.
    with direct_vm.expect_revert("Appeal adjudication window is still open"):
        contract.claim_unresolved_appeal("job-001")

    warp(direct_vm, future_iso(days=4))
    direct_vm.sender = direct_alice
    result = contract.claim_unresolved_appeal("job-001")
    job = contract.get_job("job-001")

    assert result["status"] == "APPEAL_REJECTED"
    assert result["returned_bond"] == ONE_GEN
    assert job["verification_reason"] == "APPEAL_TIMED_OUT"
    assert contract.get_marketplace_stats()["total_appeal_bonds"] == 0


# =============================================================================
# 4. PRODUCTION ENVIRONMENT ISOLATION
#    Reserved demo / mock / test id prefixes are blocked from live writes.
# =============================================================================

def test_reserved_dataset_prefixes_are_blocked(
    direct_vm, direct_deploy, direct_alice
):
    """Every reserved id prefix is rejected on dataset registration even after
    the provider has staked, so no demo record can reach production storage."""
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_alice
    direct_vm.value = DATASET_STAKE + (2 * JOB_COLLATERAL)
    contract.stake_provider()
    direct_vm.value = 0

    blocked_ids = [
        "test-mobility",
        "demo-mobility",
        "mock-mobility",
        "dev-mobility",
        "staging-mobility",
        "_test_mobility",
        "[test]mobility",
        "[demo]mobility",
        "[mock]mobility",
        "fake-mobility",
        "dummy-mobility",
        "sample-mobility",
    ]
    for bad_id in blocked_ids:
        with direct_vm.expect_revert("reserved prefix"):
            contract.register_dataset(
                bad_id,
                "Blocked dataset",
                "Must never reach production storage.",
                "JSONL",
                "sha256:placeholder",
                "None.",
                JOB_PRICE,
            )


def test_reserved_dataset_prefix_is_case_insensitive(
    direct_vm, direct_deploy, direct_alice
):
    """Prefix matching is case-insensitive so an upper-cased demo id is blocked."""
    contract = direct_deploy(CONTRACT_PATH)
    direct_vm.sender = direct_alice
    direct_vm.value = DATASET_STAKE + (2 * JOB_COLLATERAL)
    contract.stake_provider()
    direct_vm.value = 0

    with direct_vm.expect_revert("reserved prefix"):
        contract.register_dataset(
            "DEMO-Mobility",
            "Blocked dataset",
            "Upper-cased demo prefix must also be blocked.",
            "JSONL",
            "sha256:placeholder",
            "None.",
            JOB_PRICE,
        )


def test_reserved_job_prefixes_are_blocked(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Reserved id prefixes are rejected on the compute-request write path."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)

    blocked_ids = [
        "test-job-1",
        "demo-job-1",
        "mock-job-1",
        "staging-job-1",
        "fake-job-1",
        "dummy-job-1",
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


def test_legitimate_production_ids_are_accepted(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Positive control: non-reserved ids write to production storage normally."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob, "production-job-1")

    job = contract.get_job("production-job-1")
    assert job["status"] == "FUNDED"
    assert contract.get_dataset("mobility-v1")["open_jobs"] == 1
