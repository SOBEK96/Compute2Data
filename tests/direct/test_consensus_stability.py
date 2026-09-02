"""Validator divergence and consensus-stability regression for Compute2Data.

The contract settles a job through a two-stage flow: deterministic enclave
verification, then a non-deterministic semantic review via
gl.vm.run_nondet_unsafe(assess_report, validate_assessment). Consensus over
that non-deterministic stage is what these tests pin down:

  * Leader-side LLM misbehaviour (unexpected JSON shape, unknown verdict, a
    verdict/code contradiction, a missing summary) must surface the
    "[LLM_ERROR]" prefix and revert, which is the signal that triggers leader
    rotation on chain rather than finalising a malformed settlement.

  * Categorical bucketing must absorb benign variance: the validator compares
    only the discrete (verdict, violation_code) bucket, never the free-text
    summary, so two honest nodes that phrase the same verdict differently still
    agree. Variance that crosses a bucket boundary (a different verdict or a
    different violation code) must instead be detected as divergence so a bad
    settlement can never reach consensus.

NOTE ON SCOPE: this contract performs no HTTP nondeterminism (no get_webpage /
web precompile calls), so there is no external-payload / 429 / "[TRANSIENT]"
surface to pin with direct_vm.mock_web(). The only nondeterministic source is
the LLM review, which is exercised exhaustively here with direct_vm.mock_llm()
and direct_vm.run_validator(). Timeout / expiration edges driven by
direct_vm.warp() are covered in test_compute_data_regression.py.
"""

import json

import pytest

from regression_helpers import (
    CONTRACT_PATH,
    OUTPUT_COMMITMENT,
    build_attestation_quote,
    fund_job,
    rejected_assessment,
    stake_and_register,
    valid_assessment,
)


def _settle_with_leader_llm(direct_vm, contract, provider, leader_response, quote=None):
    """Drive job-001 through a full submit with a pinned leader LLM response.

    The quote passes deterministic stage-1 verification so execution reaches
    the non-deterministic review stage where the pinned response takes effect.
    """
    direct_vm.mock_llm(r".*security validator settling.*", leader_response)
    direct_vm.sender = provider
    return contract.submit_execution_proof(
        "job-001",
        quote if quote is not None else build_attestation_quote(),
        OUTPUT_COMMITMENT,
    )


# =============================================================================
# LEADER-SIDE LLM MISBEHAVIOUR -> [LLM_ERROR] AND REVERT (LEADER ROTATION)
# =============================================================================

@pytest.mark.parametrize(
    "leader_response",
    [
        pytest.param('"just a bare string"', id="non_object"),
        pytest.param("[]", id="json_array"),
        pytest.param(json.dumps({"violation_code": "NONE", "summary": "no verdict"}), id="missing_verdict"),
        pytest.param(json.dumps({"verdict": "MAYBE", "violation_code": "NONE", "summary": "x"}), id="unknown_verdict"),
        pytest.param(json.dumps({"verdict": "VALID", "violation_code": "EXECUTION_FAILED", "summary": "x"}), id="valid_with_bad_code"),
        pytest.param(json.dumps({"verdict": "INCONCLUSIVE", "violation_code": "NOPE", "summary": "x"}), id="inconclusive_bad_code"),
        pytest.param(json.dumps({"verdict": "INVALID", "violation_code": "MADE_UP", "summary": "x"}), id="invalid_disallowed_code"),
        pytest.param(json.dumps({"verdict": "VALID", "violation_code": "NONE", "summary": "   "}), id="empty_summary"),
    ],
)
def test_malformed_leader_llm_raises_llm_error(
    direct_vm, direct_deploy, direct_alice, direct_bob, leader_response
):
    """Every malformed leader assessment reverts with the [LLM_ERROR] prefix."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.mock_llm(r".*security validator settling.*", leader_response)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("[LLM_ERROR]"):
        contract.submit_execution_proof(
            "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
        )


# =============================================================================
# BUCKETING ABSORBS BENIGN VARIANCE
# =============================================================================

def test_validator_absorbs_summary_text_variance(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Leader and validator reach the same (verdict, violation_code) bucket but
    phrase the summary differently. The validator must still agree, proving the
    free-text summary is outside the consensus bucket and cannot cause an
    intermittent divergence."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # Leader settles VALID/NONE with one summary phrasing.
    _settle_with_leader_llm(direct_vm, contract, direct_alice, valid_assessment())

    # Validator re-runs with the same bucket but a completely different summary.
    direct_vm.clear_mocks()
    validator_variant = json.dumps({
        "verdict": "VALID",
        "violation_code": "NONE",
        "summary": "Independent node wording: the bound run reads as complete.",
    })
    direct_vm.mock_llm(r".*security validator settling.*", validator_variant)
    assert direct_vm.run_validator() is True


def test_validator_agrees_on_matching_inconclusive_bucket(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A benign-variance check for the INCONCLUSIVE bucket as well."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    leader = json.dumps({
        "verdict": "INCONCLUSIVE",
        "violation_code": "INSUFFICIENT_EVIDENCE",
        "summary": "Leader: status pending, cannot confirm completion.",
    })
    _settle_with_leader_llm(
        direct_vm, contract, direct_alice, leader,
        quote=build_attestation_quote(result_status="PENDING"),
    )

    direct_vm.clear_mocks()
    validator = json.dumps({
        "verdict": "INCONCLUSIVE",
        "violation_code": "INSUFFICIENT_EVIDENCE",
        "summary": "Validator: evidence is ambiguous, completion not established.",
    })
    direct_vm.mock_llm(r".*security validator settling.*", validator)
    assert direct_vm.run_validator() is True


# =============================================================================
# CROSS-BUCKET VARIANCE IS DETECTED AS DIVERGENCE
# =============================================================================

@pytest.mark.parametrize(
    "validator_response",
    [
        rejected_assessment(),  # VALID (leader) vs INVALID (validator)
        json.dumps({
            "verdict": "INCONCLUSIVE",
            "violation_code": "INSUFFICIENT_EVIDENCE",
            "summary": "Validator saw pending status.",
        }),  # VALID vs INCONCLUSIVE
    ],
)
def test_validator_detects_verdict_divergence(
    direct_vm, direct_deploy, direct_alice, direct_bob, validator_response
):
    """A leader that settled VALID must be rejected by a validator whose own
    review lands in a different verdict bucket."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    _settle_with_leader_llm(direct_vm, contract, direct_alice, valid_assessment())

    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*security validator settling.*", validator_response)
    assert direct_vm.run_validator() is False


def test_validator_detects_violation_code_divergence_within_invalid(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Same INVALID verdict but a different violation_code is still divergence:
    the bucket is (verdict, violation_code), not verdict alone."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # Leader settles INVALID / EXECUTION_FAILED.
    _settle_with_leader_llm(direct_vm, contract, direct_alice, rejected_assessment())

    # Validator reaches INVALID but with a different code.
    direct_vm.clear_mocks()
    other_invalid = json.dumps({
        "verdict": "INVALID",
        "violation_code": "CONTRADICTORY_CLAIMS",
        "summary": "Validator: fields contradict each other.",
    })
    direct_vm.mock_llm(r".*security validator settling.*", other_invalid)
    assert direct_vm.run_validator() is False


# =============================================================================
# VALIDATOR DEFENDS AGAINST A GARBLED OR MALICIOUS LEADER RESULT
# =============================================================================

def test_validator_rejects_non_dict_leader_result(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """If the leader's broadcast result is not a structured object, the
    validator rejects it without even re-running its own LLM."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    _settle_with_leader_llm(direct_vm, contract, direct_alice, valid_assessment())

    # Override the captured leader result with a non-dict payload.
    assert direct_vm.run_validator(leader_result="not-a-structured-result") is False


def test_validator_rejects_leader_result_with_unknown_verdict(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A leader result carrying an out-of-domain verdict is rejected."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    _settle_with_leader_llm(direct_vm, contract, direct_alice, valid_assessment())

    bogus_leader = {"verdict": "DEFINITELY_YES", "violation_code": "NONE"}
    assert direct_vm.run_validator(leader_result=bogus_leader) is False


def test_environment_variance_across_nodes_forces_divergence(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """End-to-end consensus-stability narrative: the leader's environment
    yields a completed reading (VALID) while a validator's environment yields a
    failed reading (INVALID). The mismatch is surfaced as divergence rather than
    silently finalised, which is what protects the escrow settlement."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # Leader node sees a completed run and settles VALID.
    result = _settle_with_leader_llm(direct_vm, contract, direct_alice, valid_assessment())
    assert result["verdict"] == "VALID"

    # A validator node whose environment reports a failure diverges.
    direct_vm.clear_mocks()
    direct_vm.mock_llm(r".*security validator settling.*", rejected_assessment())
    assert direct_vm.run_validator() is False
