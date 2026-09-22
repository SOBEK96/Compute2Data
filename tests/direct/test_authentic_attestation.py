"""On-chain Intel SGX DCAP attestation regression for Compute2Data.

The contract verifies Intel SGX ECDSA v3 quotes and Intel PCS collateral
entirely on chain (see contracts/c2d_marketplace.py's module header): the
cert_data_type 5 X.509 PCK chain to the pinned Intel SGX Root CA, the Intel
CRLs, the quote signatures, and the TCB Info / QE Identity signatures. These
tests pin the behaviour down in three groups:

  * GENUINE INTEL VECTORS. A real Intel-issued quote with the real PCS
    collateral for its FMSPC authenticates against the DEFAULT deployment
    (genuine Intel root pinned), and the on-chain TCB evaluation matches an
    independent verifier. Tampering with any genuine byte is rejected.
  * FAIL-CLOSED REJECTION. The project-defined compact certificate chain and
    the simulated {fmspc, tcbStatus, signature} collateral that earlier
    versions accepted now revert with ERR_INVALID_ATTESTATION /
    ERR_INVALID_COLLATERAL, as does a zero-value or undeclared stake.
  * POLICY ON GENUINE EVIDENCE. Authenticated attestations that bind the wrong
    work, come from an untrusted or debug enclave, or report a TCB status the
    operator has not accepted are slashed deterministically.
"""

import datetime
import hashlib
import json

from regression_helpers import (
    CONTRACT_PATH,
    JOB_PRICE,
    OUTPUT_COMMITMENT,
    build_attestation_quote,
    build_attestation_quote_with_binding_mismatch,
    evidence_envelope,
    fund_job,
    stake_and_register,
    valid_assessment,
    warp,
)
from dcap_fixtures import (
    INTEL_SGX_ROOT_CA_PUBKEY,
    INTEL_VECTOR_FMSPC,
    INTEL_VECTOR_MRENCLAVE,
    INTEL_VECTOR_MRSIGNER,
    INTEL_VECTOR_TCB_STATUS,
    INTEL_VECTOR_TIME,
    PCK_CERT_SERIAL,
    build_binary_quote,
    build_collateral,
    build_legacy_compact_quote,
    expected_report_data,
    expired_pck_chain_pem,
    intel_vector_collateral,
    intel_vector_quote_hex,
    legacy_simulated_collateral,
    pck_crl_hex,
    qe_identity_json,
    rogue_root_pck_chain_pem,
    root_ca_crl_pem,
    tcb_info_json,
)
from conftest import (
    COMPUTE_SPEC,
    DATASET_COMMITMENT,
    DATASET_ID,
    DEFAULT_ENCLAVE_MEASUREMENT,
    DEFAULT_ENCLAVE_SIGNER,
    INPUT_COMMITMENT,
    MODEL_ID,
    address_hex,
)


ATTESTATION_REVERT = "ERR_INVALID_ATTESTATION: non-genuine certificate chain rejected"
COLLATERAL_REVERT = "ERR_INVALID_COLLATERAL: simulated collateral format rejected"


def _artifact():
    compute_spec_commitment = hashlib.sha256(COMPUTE_SPEC.encode("utf-8")).hexdigest()
    return {
        "dataset_id": DATASET_ID,
        "dataset_commitment": DATASET_COMMITMENT,
        "input_commitment": INPUT_COMMITMENT,
        "model_id": MODEL_ID,
        "compute_spec_commitment": compute_spec_commitment,
        "output_commitment": OUTPUT_COMMITMENT,
        "result_status": "COMPLETED",
    }


def _job_report_data():
    compute_spec_commitment = hashlib.sha256(COMPUTE_SPEC.encode("utf-8")).hexdigest()
    output_hash = hashlib.sha256(OUTPUT_COMMITMENT.encode("utf-8")).hexdigest()
    return expected_report_data(DATASET_ID, compute_spec_commitment, output_hash)


def _harness_quote(**kwargs):
    return build_binary_quote(
        mrenclave=DEFAULT_ENCLAVE_MEASUREMENT,
        mrsigner=DEFAULT_ENCLAVE_SIGNER,
        report_data=_job_report_data(),
        **kwargs,
    )


def _funded_job(direct_vm, direct_deploy, provider, requester, *deploy_args):
    contract = direct_deploy(CONTRACT_PATH, *deploy_args)
    stake_and_register(direct_vm, contract, provider)
    fund_job(direct_vm, contract, requester)
    return contract


def _assert_still_funded(contract):
    job = contract.get_job("job-001")
    assert job["status"] == "FUNDED"
    assert job["slash_amount"] == 0
    assert contract.get_marketplace_stats()["total_escrowed"] == JOB_PRICE


def _module_globals(contract):
    """Module namespace of the deployed contract, to call its pure verifiers."""
    instance = object.__getattribute__(contract, "_instance")
    return type(instance).__init__.__globals__


# =============================================================================
# 1. GENUINE INTEL VECTORS (production default: Intel SGX Root CA pinned)
# =============================================================================

def test_genuine_intel_quote_verifies_to_pinned_intel_root(direct_vm, direct_deploy):
    """A real Intel-issued SGX quote and the real Intel PCS collateral for its
    FMSPC pass every on-chain authenticity check against the pinned Intel root.
    The resulting TCB status equals what Phala's independent dcap-qvl verifier
    computes for the same quote and collateral."""
    contract = direct_deploy(CONTRACT_PATH, "")
    module = _module_globals(contract)
    now = int(datetime.datetime.fromisoformat(INTEL_VECTOR_TIME.replace("Z", "+00:00")).timestamp())

    evidence = module["_verify_sgx_evidence"](
        intel_vector_quote_hex(), intel_vector_collateral(), INTEL_SGX_ROOT_CA_PUBKEY, now
    )

    assert evidence["fmspc"] == INTEL_VECTOR_FMSPC
    assert evidence["mrenclave"] == INTEL_VECTOR_MRENCLAVE
    assert evidence["mrsigner"] == INTEL_VECTOR_MRSIGNER
    assert evidence["debug"] is False
    assert evidence["report_data"].startswith(b"Hello, world!")
    assert evidence["tcb_status"] == INTEL_VECTOR_TCB_STATUS
    assert evidence["qe_status"] == "UpToDate"


def test_production_deploy_authenticates_genuine_intel_quote_then_applies_policy(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """End to end on a production-default deployment: the genuine Intel quote
    is authenticated (no revert) and then held to policy. With only UpToDate
    accepted, the platform's real TCB status slashes it."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob, "")
    config = contract.get_attestation_config()
    assert config["intel_root_ca_pinned"] is True
    assert config["sgx_root_ca_pubkey"] == INTEL_SGX_ROOT_CA_PUBKEY
    assert config["accepted_tcb_statuses"] == ["UpToDate"]

    warp(direct_vm, INTEL_VECTOR_TIME)
    envelope = evidence_envelope(_artifact(), intel_vector_quote_hex(), intel_vector_collateral())
    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "TCB_" + INTEL_VECTOR_TCB_STATUS.upper()
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_genuine_intel_quote_bound_to_other_work_is_slashed(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    """With the platform status accepted and the enclave whitelisted, the
    genuine Intel quote clears authentication, TCB policy and the trust
    registry -- and is then slashed because its report_data ("Hello, world!")
    does not bind this job's dataset, compute spec, and output."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob, "")
    direct_vm.sender = direct_owner
    contract.set_accepted_tcb_status(INTEL_VECTOR_TCB_STATUS, True)
    contract.set_trusted_enclave(INTEL_VECTOR_MRENCLAVE, True)
    contract.set_trusted_signer(INTEL_VECTOR_MRSIGNER, True)

    warp(direct_vm, INTEL_VECTOR_TIME)
    envelope = evidence_envelope(_artifact(), intel_vector_quote_hex(), intel_vector_collateral())
    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)

    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "BINDING_MISMATCH"
    assert contract.get_job("job-001")["attestation_mrenclave"] == INTEL_VECTOR_MRENCLAVE


def test_tampered_genuine_intel_evidence_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Flipping a single byte of the genuine quote or the genuine TCB Info, or
    pairing the quote with genuine Intel TCB Info for a different FMSPC,
    reverts; the job is untouched."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob, "")
    warp(direct_vm, INTEL_VECTOR_TIME)
    direct_vm.sender = direct_alice

    quote = bytearray(bytes.fromhex(intel_vector_quote_hex()))
    quote[48 + 320] ^= 0x01    # first byte of report_data
    envelope = evidence_envelope(_artifact(), bytes(quote).hex(), intel_vector_collateral())
    with direct_vm.expect_revert(ATTESTATION_REVERT + " (SIGNATURE_INVALID)"):
        contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)

    collateral = intel_vector_collateral()
    collateral["tcb_info"] = collateral["tcb_info"].replace('"svn":', '"svn": ', 1)
    envelope = evidence_envelope(_artifact(), intel_vector_quote_hex(), collateral)
    with direct_vm.expect_revert(COLLATERAL_REVERT + " (TCB_INFO_SIGNATURE_INVALID)"):
        contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)

    collateral = intel_vector_collateral("tcb_info_00906ed50000.json")
    envelope = evidence_envelope(_artifact(), intel_vector_quote_hex(), collateral)
    with direct_vm.expect_revert(COLLATERAL_REVERT + " (TCB_INFO_FMSPC_MISMATCH)"):
        contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)

    _assert_still_funded(contract)


def test_expired_genuine_intel_collateral_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Genuine collateral past its nextUpdate is stale and cannot be replayed."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob, "")
    warp(direct_vm, "2026-11-01T00:00:00Z")
    envelope = evidence_envelope(_artifact(), intel_vector_quote_hex(), intel_vector_collateral())
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert(COLLATERAL_REVERT + " (PCK_CRL_EXPIRED)"):
        contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)
    _assert_still_funded(contract)


def test_production_default_rejects_harness_signed_chain(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The harness PKI is Intel's format under a different root key. A
    production-default deployment rejects it at the root of the PCK chain."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob, "")
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert(ATTESTATION_REVERT + " (PCK_ROOT_UNTRUSTED)"):
        contract.submit_execution_proof("job-001", build_attestation_quote(), OUTPUT_COMMITMENT)
    _assert_still_funded(contract)


# =============================================================================
# 2. FAIL-CLOSED REJECTION OF NON-GENUINE CHAINS AND COLLATERAL
# =============================================================================

def test_revert_on_project_defined_compact_certificate(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The compact certificate chain (cert_data_type 0x0101) that earlier
    versions accepted -- signed all the way up to the deployed root -- now
    reverts, both in its original form and with an otherwise-valid Intel
    header, and even when accompanied by valid PCS collateral."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_alice

    legacy = build_legacy_compact_quote(
        mrenclave=DEFAULT_ENCLAVE_MEASUREMENT,
        mrsigner=DEFAULT_ENCLAVE_SIGNER,
        report_data=_job_report_data(),
    )
    legacy_envelope = json.dumps({"artifact": _artifact(), "dcap_quote": legacy}, sort_keys=True)
    with direct_vm.expect_revert(ATTESTATION_REVERT):
        contract.submit_execution_proof("job-001", legacy_envelope, OUTPUT_COMMITMENT)

    from dcap_fixtures import INTEL_QE_VENDOR_ID

    compact = build_legacy_compact_quote(
        mrenclave=DEFAULT_ENCLAVE_MEASUREMENT,
        mrsigner=DEFAULT_ENCLAVE_SIGNER,
        report_data=_job_report_data(),
        vendor_id=INTEL_QE_VENDOR_ID,
    )
    envelope = evidence_envelope(_artifact(), compact, build_collateral())
    with direct_vm.expect_revert(ATTESTATION_REVERT + " (CERT_DATA_TYPE_UNSUPPORTED)"):
        contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)

    _assert_still_funded(contract)


def test_revert_on_simulated_collateral_format(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The simulated {fmspc, tcbStatus, signature} collateral is rejected in
    every position, as is unsigned or foreign-signed TCB Info. Provider stake
    cannot be declared: a zero-value stake or a bond without staked native GEN
    reverts with ERR_INVALID_COLLATERAL."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_alice
    quote = _harness_quote()

    cases = [
        (legacy_simulated_collateral(), "COLLATERAL_FORMAT_INVALID"),
        (None, "COLLATERAL_FORMAT_INVALID"),
        (build_collateral(tcb_info=json.dumps(legacy_simulated_collateral())), "TCB_INFO_MALFORMED"),
        (build_collateral(tcb_info=tcb_info_json(tamper=True)), "TCB_INFO_SIGNATURE_INVALID"),
        (build_collateral(tcb_info=tcb_info_json(signer=_foreign_signer())), "TCB_INFO_SIGNATURE_INVALID"),
        (build_collateral(tcb_info=tcb_info_json(next_update="2025-01-01T00:00:00Z")), "TCB_INFO_EXPIRED"),
        (build_collateral(tcb_info=tcb_info_json(fmspc="00906ed50000")), "TCB_INFO_FMSPC_MISMATCH"),
        (build_collateral(qe_identity=qe_identity_json(next_update="2025-01-01T00:00:00Z")), "QE_IDENTITY_EXPIRED"),
        (build_collateral(tcb_info_issuer_chain=rogue_root_pck_chain_pem().split("-----END CERTIFICATE-----\n", 1)[1]),
         "TCB_INFO_ISSUER_CHAIN_ROOT_UNTRUSTED"),
        (build_collateral(pck_crl="00" * 16), "PCK_CRL_MALFORMED"),
    ]
    for collateral, code in cases:
        envelope = json.dumps({"artifact": _artifact(), "dcap_quote": quote, "collateral": collateral})
        with direct_vm.expect_revert(COLLATERAL_REVERT + " (" + code + ")"):
            contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)
    _assert_still_funded(contract)

    # A PEM-encoded CRL is accepted exactly like the DER form.
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())
    envelope = evidence_envelope(_artifact(), quote, build_collateral(root_ca_crl=root_ca_crl_pem()))
    assert contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)["status"] == "VERIFIED"

    # Collateral (stake) is native value only.
    direct_vm.sender = direct_bob
    direct_vm.value = 0
    with direct_vm.expect_revert("ERR_INVALID_COLLATERAL"):
        contract.stake_provider()
    with direct_vm.expect_revert("ERR_INVALID_COLLATERAL"):
        contract.register_dataset(
            "unstaked-v1", "Unstaked", "No native stake behind it.", "csv", "sha256:x",
            "Approved workloads only.", JOB_PRICE,
        )
    assert contract.get_provider(address_hex(direct_bob))["total_stake"] == 0


def _foreign_signer():
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.derive_private_key(0xBAD, ec.SECP256R1())


def test_report_data_cryptographic_mismatch(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A genuine, fully signed quote whose report_data commits to a different
    output fails closed: no payout, the requester is refunded, the provider is
    slashed. Changing the report_data after signing instead breaks the quote
    signature and reverts."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_alice

    forged = bytearray(bytes.fromhex(_harness_quote()))
    forged[48 + 320:48 + 352] = hashlib.sha256(b"different output").digest()
    envelope = evidence_envelope(_artifact(), bytes(forged).hex(), build_collateral())
    with direct_vm.expect_revert(ATTESTATION_REVERT + " (SIGNATURE_INVALID)"):
        contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)
    _assert_still_funded(contract)

    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote_with_binding_mismatch(), OUTPUT_COMMITMENT
    )
    job = contract.get_job("job-001")
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "BINDING_MISMATCH"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"
    assert job["verified"] is False
    assert job["settlement_amount"] == JOB_PRICE
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_forged_or_untrusted_pck_chain_reverts(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Every way of breaking the PCK chain or the quote signatures reverts
    before any funds move: a fabricated ISV signature, a self-made root, an
    expired PCK certificate, a revoked PCK certificate, garbage cert data."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_alice

    cases = [
        (_harness_quote(tamper_signature=True), build_collateral(), "SIGNATURE_INVALID"),
        (_harness_quote(pck_chain_pem=rogue_root_pck_chain_pem()), build_collateral(), "PCK_ROOT_UNTRUSTED"),
        (_harness_quote(pck_chain_pem=expired_pck_chain_pem()), build_collateral(), "PCK_EXPIRED"),
        (_harness_quote(), build_collateral(pck_crl=pck_crl_hex([PCK_CERT_SERIAL])), "PCK_REVOKED"),
        (_harness_quote(pck_chain_pem="-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
         build_collateral(), "PCK_CERT_MALFORMED"),
        ("zz", build_collateral(), "MALFORMED_QUOTE"),
    ]
    for quote, collateral, code in cases:
        envelope = evidence_envelope(_artifact(), quote, collateral)
        with direct_vm.expect_revert(ATTESTATION_REVERT + " (" + code + ")"):
            contract.submit_execution_proof("job-001", envelope, OUTPUT_COMMITMENT)
    with direct_vm.expect_revert(ATTESTATION_REVERT + " (MALFORMED_QUOTE)"):
        contract.submit_execution_proof("job-001", "not json", OUTPUT_COMMITMENT)
    _assert_still_funded(contract)


# =============================================================================
# 3. POLICY ON AUTHENTICATED EVIDENCE
# =============================================================================

def test_genuine_quote_is_authenticated_on_chain(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Positive control: a quote with a valid PCK chain, valid collateral, a
    trusted enclave, and the correct binding settles to the provider."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.mock_llm(r".*security validator settling.*", valid_assessment())

    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof("job-001", build_attestation_quote(), OUTPUT_COMMITMENT)

    assert result["status"] == "VERIFIED"
    assert result["attestation_status"] == "ENCLAVE_VERIFIED"
    assert result["slash_amount"] == 0
    assert contract.get_marketplace_stats()["total_escrowed"] == 0


def test_non_accepted_tcb_status_is_slashed_until_admin_accepts_it(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    """A genuine Intel-signed TCB Info reporting OutOfDate gates settlement.
    Only the admin can widen the accepted set, and Revoked is never accepted."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)

    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Only the admin can manage accepted TCB statuses"):
        contract.set_accepted_tcb_status("OutOfDate", True)
    direct_vm.sender = direct_owner
    with direct_vm.expect_revert("Unknown or non-acceptable Intel TCB status"):
        contract.set_accepted_tcb_status("Revoked", True)

    out_of_date = build_collateral(tcb_info=tcb_info_json(platform_status="OutOfDate"))
    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(collateral=out_of_date), OUTPUT_COMMITMENT
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "TCB_OUTOFDATE"


def test_quoting_enclave_status_gates_settlement(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The QE Identity status is enforced independently of the platform TCB."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    collateral = build_collateral(qe_identity=qe_identity_json(qe_status="OutOfDate"))
    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(collateral=collateral), OUTPUT_COMMITMENT
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "QE_TCB_OUTOFDATE"


def test_non_intel_quoting_enclave_is_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A QE report that does not match the Intel-signed QE Identity is not a
    quote from Intel's quoting enclave."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    collateral = build_collateral(qe_identity=qe_identity_json(mrsigner="ab" * 32))
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert(ATTESTATION_REVERT + " (QE_IDENTITY_MISMATCH)"):
        contract.submit_execution_proof(
            "job-001", build_attestation_quote(collateral=collateral), OUTPUT_COMMITMENT
        )
    _assert_still_funded(contract)


def test_debug_enclave_is_slashed(direct_vm, direct_deploy, direct_alice, direct_bob):
    """A genuine quote from an enclave launched in DEBUG mode offers no
    confidentiality and is slashed."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(debug=True), OUTPUT_COMMITMENT
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "DEBUG_ENCLAVE"


def test_mismatched_mrenclave_measurement(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A genuine quote whose MRENCLAVE is not whitelisted is slashed: the
    chain is valid, the enclave identity simply is not trusted."""
    contract = _funded_job(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_alice
    result = contract.submit_execution_proof(
        "job-001", build_attestation_quote(mrenclave="99" * 32), OUTPUT_COMMITMENT
    )
    assert result["status"] == "SLASHED"
    assert result["violation_code"] == "UNTRUSTED_ENCLAVE"
    assert result["attestation_status"] == "ENCLAVE_REJECTED"


def test_trust_registry_starts_empty(direct_vm, direct_deploy):
    """No placeholder measurements ship with the contract: nothing is trusted
    until the operator whitelists an audited enclave."""
    contract = direct_deploy(CONTRACT_PATH, "")
    assert contract.is_trusted_enclave(DEFAULT_ENCLAVE_MEASUREMENT) is False
