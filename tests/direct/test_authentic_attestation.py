"""Authentic on-chain SGX/DCAP attestation regression for Compute2Data.

The contract performs REAL Intel DCAP ECDSA quote verification on chain: it
parses the binary quote, re-derives the report_data binding, verifies the full
ECDSA signature chain up to a PINNED Intel SGX Root CA key, and verifies the TCB
collateral's signature against a PINNED Intel TCB signing key. Nothing is trusted
on the word of an endpoint. These tests pin that path down:

  * A genuine, fully signed quote with authentically signed collateral settles.
  * A quote whose report_data is bound to different work is rejected
    (BINDING_MISMATCH): the enclave did not run this exact workload/output.
  * An unsigned or non-OK collateral response -- from ANY endpoint -- is rejected,
    because the collateral signature is verified on chain against the pinned key.
  * A quote carrying a mismatched enclave identity (MRENCLAVE) is rejected
    deterministically by the trust registry.
  * A browser-fabricated quote signature cannot satisfy the on-chain ECDSA chain.
  * A collateral-service outage fails closed, never silently accepting.
  * The collateral endpoint is admin-configurable; trust does not derive from it.

The simulated Intel PCS collateral service is installed by stake_and_register
(see test/conftest.py::install_attestation_authority). A test can override it for
a specific endpoint with direct_vm.mock_web(), which takes precedence.
"""

import json

from regression_helpers import (
    ATTESTATION_ENDPOINT,
    CONTRACT_PATH,
    JOB_PRICE,
    OUTPUT_COMMITMENT,
    build_attestation_quote,
    build_attestation_quote_with_binding_mismatch,
    fund_job,
    stake_and_register,
    valid_assessment,
)
from dcap_fixtures import DEFAULT_FMSPC, sign_tcb_collateral


# The contract fetches collateral from the Intel PCS host; a substring is enough
# for the mock_web matcher, which regex-searches the request URL.
_ENDPOINT_PATTERN = "trustedservices\\.intel\\.com"


def _browser_fabricated_quote():
    """A structurally perfect quote whose ISV report signature was fabricated.

    The binding is correct and the measurements are trusted, but no genuine
    enclave attestation key signed the report, so the on-chain ECDSA chain fails.
    """
    return build_attestation_quote(tamper_signature=True)


def test_genuine_quote_is_authenticated_on_chain(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Positive control: a genuine quote passes the full on-chain DCAP pipeline
    (signature chain + trust registry + signed collateral) and settles to the
    provider with an ENCLAVE_VERIFIED attestation."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    assert result["status"] == "VERIFIED"
    assert result["attestation_status"] == "ENCLAVE_VERIFIED"
    assert result["slash_amount"] == 0
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_quote_tampered_report_data_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The enclave executed over different code/data, so the quote's report_data
    no longer equals sha256(dataset_id + compute_spec_hash + output_data_hash).
    The contract re-derives the binding and reverts as BINDING_MISMATCH."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote_with_binding_mismatch(), OUTPUT_COMMITMENT
    )

    job = contract.get_job("job-001")
    stats = contract.get_marketplace_stats()

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "BINDING_MISMATCH"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"
    assert job["settlement_amount"] == JOB_PRICE
    assert stats["total_escrowed"] == 0


def test_quote_unsigned_or_invalid_status_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """An unsigned or non-OK TCB collateral response -- from ANY endpoint -- is
    rejected, because the contract verifies the collateral signature on chain
    against its pinned Intel TCB signing key rather than trusting an OK string."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # (a) An "OK" (UpToDate) status with a bogus signature is rejected.
    unsigned_ok = json.dumps(
        {"fmspc": DEFAULT_FMSPC, "tcbStatus": "UpToDate", "signature": "00" * 64}
    )
    direct_vm.mock_web(_ENDPOINT_PATTERN, {"status": 200, "body": unsigned_ok})

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "COLLATERAL_SIGNATURE_INVALID"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_non_ok_tcb_status_with_valid_signature_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Even an authentically signed collateral is rejected when the platform TCB
    status is not acceptable (e.g. OutOfDate), proving the status itself gates
    settlement rather than the mere presence of a signature."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    out_of_date = json.dumps(
        {
            "fmspc": DEFAULT_FMSPC,
            "tcbStatus": "OutOfDate",
            "signature": sign_tcb_collateral(DEFAULT_FMSPC, "OutOfDate"),
        }
    )
    direct_vm.mock_web(_ENDPOINT_PATTERN, {"status": 200, "body": out_of_date})

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "TCB_OUTOFDATE"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_mismatched_mrenclave_measurement(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A quote whose cryptographically recovered MRENCLAVE is not whitelisted is
    rejected deterministically. The signature chain is valid -- the enclave
    identity is simply not trusted -- so this is an identity decision, not a
    signature failure."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(mrenclave="99" * 32), OUTPUT_COMMITMENT
    )

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "UNTRUSTED_ENCLAVE"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_browser_fabricated_signature_fails_on_chain_chain(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A quote signed by a browser from public values cannot satisfy the on-chain
    ECDSA chain rooted at the pinned Intel SGX Root CA, so it is slashed as
    SIGNATURE_INVALID with the escrow refunded."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", _browser_fabricated_quote(), OUTPUT_COMMITMENT
    )

    job = contract.get_job("job-001")
    stats = contract.get_marketplace_stats()

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "SIGNATURE_INVALID"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"
    assert job["settlement_amount"] == JOB_PRICE
    assert stats["total_escrowed"] == 0


def test_collateral_service_unavailable_is_deterministic_slash(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """If the collateral service is unreachable (HTTP 503), verification fails
    closed: the job is slashed with a deterministic transport-failure code rather
    than being accepted on unverified evidence."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    direct_vm.mock_web(_ENDPOINT_PATTERN, {"status": 503, "body": "service unavailable"})

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "ATTESTATION_HTTP_503"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_admin_can_rotate_attestation_endpoint(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    """The collateral endpoint is exposed and admin-configurable; a non-admin
    cannot change it and a non-https endpoint is rejected. Trust is rooted in the
    pinned keys the config also exposes, not in the endpoint."""
    contract = direct_deploy(CONTRACT_PATH)

    config = contract.get_attestation_config()
    assert config["attestation_endpoint"] == ATTESTATION_ENDPOINT
    assert config["attestation_status_ok"] == "UpToDate"
    assert len(config["sgx_root_ca_pubkey"]) == 128
    assert len(config["tcb_signing_pubkey"]) == 128

    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Only the admin can set the attestation endpoint"):
        contract.set_attestation_endpoint("https://pcs.intel.example/verify")

    direct_vm.sender = direct_owner
    with direct_vm.expect_revert("Attestation endpoint must be an https URL"):
        contract.set_attestation_endpoint("http://insecure.example/verify")

    new_endpoint = "https://pcs.intel.example/sgx/certification/v4/tcb"
    contract.set_attestation_endpoint(new_endpoint)
    assert contract.get_attestation_config()["attestation_endpoint"] == new_endpoint


def test_production_default_anchors_to_intel_root_and_rejects_test_keys(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Verify that a default deployment (passing empty test anchors, identical to
    production on-chain deployment) anchors strictly to the official Intel SGX Root CA
    and Intel TCB Signing Key, and unequivocally rejects any quote minted with test keys."""
    # Deploy with empty strings so it falls back to authentic Intel production constants
    contract = direct_deploy(CONTRACT_PATH, "", "")
    config = contract.get_attestation_config()
    assert config["sgx_root_ca_pubkey"] == (
        "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5"
        "67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394"
    )
    assert config["tcb_signing_pubkey"] == (
        "43451bcc73c9d5917caf766e61af3fe98087dd4f13257b261e851897799dd13d"
        "6811fb47713803bb9bae587fccddc2e31be9a28b86962acc6daf96da58eeca96"
    )

    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # Submitting a quote minted with test keys fails because the test certification
    # chain does not terminate at Intel's authentic Root CA.
    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "PCK_CHAIN_INVALID"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"
