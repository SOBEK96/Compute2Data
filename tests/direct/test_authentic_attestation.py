"""Authentic remote TEE attestation regression for Compute2Data.

The contract no longer re-derives an enclave signature from public values on
chain. Authenticity is established by submitting the opaque quote to an
independent remote attestation authority (an Intel DCAP/PCS or IAS verifier)
via gl.nondet.web.get, wrapped in gl.eq_principle.strict_eq so every validator
must agree on the verdict. These tests pin that path down:

  * A genuine quote is authenticated by the authority and settles.
  * A browser that knows only the public MRENCLAVE / MRSIGNER / report_data and
    fabricates a signature cannot pass, because the authority -- not the
    contract -- checks the signature. The rejection is deterministic.
  * A transport failure or a mismatched authenticated identity both revert to a
    deterministic slash, never a silent acceptance.
  * The attestation endpoint is admin-configurable.

The simulated authority is installed by stake_and_register (see
test/conftest.py::install_attestation_authority). A test can override it for a
specific endpoint with direct_vm.mock_web(), which takes precedence.
"""

import hashlib
import json

from regression_helpers import (
    ATTESTATION_ENDPOINT,
    CONTRACT_PATH,
    JOB_PRICE,
    OUTPUT_COMMITMENT,
    build_attestation_quote,
    fund_job,
    stake_and_register,
    valid_assessment,
)


# A substring of the configured endpoint is enough for the mock_web matcher,
# which does a regex search against the request URL.
_ENDPOINT_PATTERN = "attestation\\.compute2data\\.network"


def _browser_fabricated_quote():
    """A structurally perfect quote whose signature was fabricated from public
    values. The binding is correct, so it passes the deterministic stage, but no
    genuine enclave key ever signed it -- only the remote authority can catch it.
    """
    quote = json.loads(build_attestation_quote())
    enclave = quote["enclave"]
    # An attacker can read the public measurements and report_data and hash them,
    # but cannot reproduce the enclave's secret signing scheme.
    forged = hashlib.sha256(
        ("browser-guess|" + enclave["mrenclave"] + enclave["mrsigner"] + enclave["report_data"]).encode("utf-8")
    ).hexdigest()
    enclave["quote_signature"] = forged
    return json.dumps(quote, sort_keys=True)


def test_genuine_quote_is_authenticated_by_remote_authority(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Positive control: a genuine quote is verified by the remote authority and
    the job settles to the provider with an ENCLAVE_VERIFIED attestation."""
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


def test_browser_fabricated_attestation_reverts_deterministically(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A quote signed by a browser from public values is rejected by the remote
    authority as SIGNATURE_INVALID -- not by any on-chain re-derivation -- and
    the job is slashed with the escrow refunded. The verdict comes through
    strict_eq, so every validator reaches the same rejection deterministically."""
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
    # Escrow is refunded to the requester; nothing is left escrowed.
    assert job["settlement_amount"] == JOB_PRICE
    assert stats["total_escrowed"] == 0


def test_attestation_authority_unavailable_is_deterministic_slash(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """If the attestation authority is unreachable (HTTP 503), verification fails
    closed: the job is slashed with a deterministic transport-failure code rather
    than being accepted on unverified evidence."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    # Override the live authority for this endpoint with a 503 outage.
    direct_vm.mock_web(_ENDPOINT_PATTERN, {"status": 503, "body": "service unavailable"})

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "ATTESTATION_HTTP_503"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_authenticated_identity_mismatch_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Even an OK verdict is bound to the exact quote: if the authority returns a
    different authenticated MRENCLAVE than the one the quote claims, the proof is
    rejected as ATTESTATION_REPORT_MISMATCH so an OK verdict for some other quote
    cannot be replayed against this job."""
    contract = direct_deploy(CONTRACT_PATH)
    stake_and_register(direct_vm, contract, direct_alice)
    fund_job(direct_vm, contract, direct_bob)

    spoofed = json.dumps(
        {
            "status": "OK",
            "mrenclave": "ab" * 32,  # not the measurement the quote carries
            "mrsigner": "22" * 32,
            "report_data": "cd" * 32,
        }
    )
    direct_vm.mock_web(_ENDPOINT_PATTERN, {"status": 200, "body": spoofed})

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(), OUTPUT_COMMITMENT
    )

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "ATTESTATION_REPORT_MISMATCH"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_admin_can_rotate_attestation_endpoint(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    """The attestation endpoint is exposed and admin-configurable; a non-admin
    cannot change it and a non-https endpoint is rejected."""
    contract = direct_deploy(CONTRACT_PATH)

    config = contract.get_attestation_config()
    assert config["attestation_endpoint"] == ATTESTATION_ENDPOINT
    assert config["attestation_status_ok"] == "OK"

    # Non-admin cannot repoint the authority.
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Only the admin can set the attestation endpoint"):
        contract.set_attestation_endpoint("https://pcs.intel.example/verify")

    # Admin must supply an https endpoint.
    direct_vm.sender = direct_owner
    with direct_vm.expect_revert("Attestation endpoint must be an https URL"):
        contract.set_attestation_endpoint("http://insecure.example/verify")

    # Admin rotates to a new authority host.
    new_endpoint = "https://pcs.intel.example/dcap/v1/verify-quote"
    contract.set_attestation_endpoint(new_endpoint)
    assert contract.get_attestation_config()["attestation_endpoint"] == new_endpoint
