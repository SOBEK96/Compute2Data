# Intel SGX DCAP Attestation — On-Chain Verification

This document specifies how `contracts/c2d_marketplace.py` verifies an execution
proof. The contract accepts only Intel SGX DCAP evidence in Intel's own formats, and it
verifies that evidence on chain to the pinned Intel SGX Root CA.

## 1. Evidence envelope

`submit_execution_proof(job_id, attestation_quote, output_commitment)` and
`appeal_job_verdict(job_id, justification, attestation_evidence)` take a JSON envelope:

```json
{
  "artifact":   { "dataset_commitment": "...", "input_commitment": "...", "model_id": "...",
                  "compute_spec_commitment": "<sha256 hex of the job's compute_spec>",
                  "output_commitment": "...", "result_status": "COMPLETED" },
  "dcap_quote": "<hex of the Intel SGX ECDSA quote, version 3>",
  "collateral": {
    "tcb_info":                 "<body of GET /sgx/certification/v4/tcb?fmspc=...>",
    "tcb_info_issuer_chain":    "<TCB-Info-Issuer-Chain header, PEM>",
    "qe_identity":              "<body of GET /sgx/certification/v4/qe/identity>",
    "qe_identity_issuer_chain": "<SGX-Enclave-Identity-Issuer-Chain header, PEM>",
    "pck_crl":                  "<GET /sgx/certification/v4/pckcrl?ca=processor|platform, hex DER or PEM>",
    "root_ca_crl":              "<Intel SGX Root CA CRL, hex DER or PEM>"
  }
}
```

The quote comes from the Intel DCAP quote library, called inside the provider's enclave
on Intel SGX hardware. `scripts/fetch_pcs_collateral.mjs` takes the FMSPC and the PCK CA
type from the quote's own PCK certificate and downloads the collateral from Intel PCS
verbatim. It can also assemble the whole envelope (`--artifact`). Nothing in the envelope
is trusted because of where it came from: every element is Intel-signed and verified on
chain.

## 2. Trust anchor

`INTEL_SGX_ROOT_CA_PUBKEY` is the public key of Intel's SGX Root CA
(`Intel_SGX_Provisioning_Certification_RootCA.pem`, CN=Intel SGX Root CA). It is the
only trust input. The PCK chain and the TCB Signing chain must both terminate at a
certificate carrying exactly this key.

The constructor also takes a `test_root_ca_pubkey` argument so that isolated unit tests
can sign their own X.509 hierarchy. A production deployment passes nothing.
`get_attestation_config()` reports `intel_root_ca_pinned`, so anyone can confirm which
root a deployment trusts. The deploy scripts pass no arguments.

## 3. Verification pipeline (deterministic, no network I/O)

| # | Check | Failure (revert code) |
|---|-------|-----------------------|
| 1 | Quote header: version 3, attestation key type 2 (ECDSA-256-with-P-256), SGX TEE, Intel QE vendor id `939A7233F79C4CA9940A0DB3957F0607`; exact length accounting of every section | `MALFORMED_QUOTE`, `UNSUPPORTED_QUOTE` |
| 2 | Certification data type is **5** (PEM X.509 PCK chain). Any other type is rejected, including the compact key layout `0x0101` that earlier versions accepted | `CERT_DATA_TYPE_UNSUPPORTED` |
| 3 | PCK chain (PCK Certificate → PCK Processor/Platform CA → Intel SGX Root CA): strict DER parsing, `ecdsa-with-SHA256` over P-256, name chaining, CA basic constraints, no unknown critical extensions, validity at the transaction time, every signature, and a root equal to the pinned key | `PCK_CERT_MALFORMED`, `PCK_ROOT_UNTRUSTED`, `PCK_CHAIN_INVALID`, `PCK_EXPIRED` |
| 4 | Quote signatures: the PCK key signs the QE report; QE `report_data` = `sha256(att_key ‖ qe_auth_data) ‖ 0³²`; the attestation key signs header + ISV enclave report | `QE_SIGNATURE_INVALID`, `QE_BINDING_INVALID`, `SIGNATURE_INVALID` |
| 5 | Revocation: the Root CA CRL is signed by the root, and the PCK CRL is signed by the PCK CA; both must be current. The PCK CA serial must not appear in the Root CA CRL, nor the PCK serial in the PCK CRL | `ROOT_CA_CRL_*`, `PCK_CRL_*` (collateral); `PCK_CA_REVOKED`, `PCK_REVOKED` |
| 6 | TCB Signing chain (TCB Signing cert → Intel SGX Root CA) for both PCS documents, verified to the pinned root and checked against the Root CA CRL | `TCB_INFO_ISSUER_CHAIN_*`, `QE_IDENTITY_ISSUER_CHAIN_*`, `*_SIGNER_REVOKED` |
| 7 | TCB Info v3 (`id` SGX, `tcbType` 0): signature over the exact signed `tcbInfo` bytes; duplicate JSON keys rejected; `issueDate ≤ now ≤ nextUpdate`; FMSPC and PCE-ID equal the PCK certificate's SGX extension | `TCB_INFO_MALFORMED`, `TCB_INFO_SIGNATURE_INVALID`, `TCB_INFO_EXPIRED`, `TCB_INFO_FMSPC_MISMATCH`, `TCB_INFO_PCEID_MISMATCH` |
| 8 | QE Identity v2 (`id` QE): signature and freshness as above. The QE report must match MRSIGNER, ISVPRODID, and masked MISCSELECT / ATTRIBUTES | `QE_IDENTITY_*`; `QE_IDENTITY_MISMATCH` |
| 9 | TCB evaluation: the PCK certificate's 16 SGX TCB component SVNs and PCESVN select the first satisfied TCB Info level. The QE ISVSVN selects the QE Identity level | (status passed to policy) |

Failures in rows 1–4, `PCK_*_REVOKED`, and `QE_IDENTITY_MISMATCH` revert with
`ERR_INVALID_ATTESTATION: non-genuine certificate chain rejected (<code>)`. Failures in
the PCS collateral (rows 5–8) revert with
`ERR_INVALID_COLLATERAL: simulated collateral format rejected (<code>)`. A reverted
submission changes nothing: the job stays `FUNDED`, and the provider can still submit
genuine evidence before the proof deadline.

## 4. Settlement policy on authenticated evidence

Once the evidence is established as a genuine Intel attestation, these checks settle
deterministically. A failure is a **slash**: the requester is refunded, and the provider's
job collateral plus listing bond is held by the protocol treasury, reversible by an
accepted appeal.

| Check | Slash code |
|-------|-----------|
| Platform TCB status is accepted (default: `UpToDate`; the admin may add other Intel statuses via `set_accepted_tcb_status`, never `Revoked`) | `TCB_<STATUS>`, `TCB_LEVEL_UNSUPPORTED` |
| QE TCB status is accepted | `QE_TCB_<STATUS>` |
| Enclave is not in DEBUG mode (`ATTRIBUTES.FLAGS` bit 1) | `DEBUG_ENCLAVE` |
| MRENCLAVE / MRSIGNER are whitelisted by the admin (the registry starts empty) | `UNTRUSTED_ENCLAVE`, `UNTRUSTED_SIGNER` |
| Artifact matches the on-chain job | `MODEL_MISMATCH`, `DATASET_MISMATCH`, `INPUT_COMMITMENT_MISMATCH`, `COMPUTE_SPEC_*`, `OUTPUT_COMMITMENT_INVALID` |
| `report_data = sha256(dataset_id ‖ sha256(compute_spec) ‖ sha256(output_commitment)) ‖ 0³²` | `BINDING_MISMATCH` |

A proof that passes all of these checks then goes to the multi-LLM semantic review of the
verified report.

Appeals use the same pipeline. Filing requires authenticated evidence (otherwise the
filing reverts). At adjudication, evidence that no longer verifies, for example because
its collateral expired in the meantime, **rejects** the appeal and does not revert it. An
appeal therefore cannot be stalled into the unresolved-appeal failsafe.

## 5. Provider collateral (stake)

A provider's stake is native GEN only. It is transferred with `stake_provider()`
(`gl.message.value`) and held by the contract. The listing bond and per-job collateral
are locked out of that balance; they are never declared. A zero-value stake, or a
dataset or job that the provider's available native stake cannot cover, reverts with
`ERR_INVALID_COLLATERAL`.

## 6. Operating requirements and scope

- **Quote format.** Intel SGX ECDSA quotes, version 3, with certification data type 5.
  This is the format the Intel SGX DCAP quote library produces for SGX enclaves. TDX
  quotes and version-4 envelopes are rejected (`UNSUPPORTED_QUOTE`).
- **Enclave.** Proofs can only come from an enclave on an Intel SGX platform that holds
  an Intel-issued PCK certificate. The enclave must write the job binding into
  `report_data` itself. The operator audits the enclave and whitelists its MRENCLAVE and
  MRSIGNER; until then, no proof settles.
- **Collateral freshness.** The prover supplies the collateral with the proof, so
  verification needs no network access and every validator reaches the same verdict.
  Each document is accepted only
  within its Intel-signed `thisUpdate`/`issueDate` … `nextUpdate` window, which is 30
  days for TCB Info, QE Identity, and the PCK CRL. The operator's accepted TCB statuses
  decide which platforms may settle.
- **Cost.** A full verification is 9 ECDSA P-256 verifications (Jacobian coordinates,
  one inversion each), about 27 ms in CPython on a laptop.

## 7. Evidence in the test suite

`tests/direct/test_authentic_attestation.py`:

- **Genuine Intel vectors** (`test/fixtures/intel_sgx/`, provenance in its README): a
  real SGX quote from Intel hardware plus the real Intel PCS collateral for its FMSPC. It
  verifies on chain against the **production default** (Intel root pinned). The
  resulting platform TCB status, `OutOfDateConfigurationNeeded`, is identical to the
  result of Phala's independent `dcap-qvl` verifier for the same inputs. Flipping one
  byte of the quote or of the TCB Info reverts, as does pairing the quote with genuine
  TCB Info for another FMSPC or verifying after the collateral expires.
- **Fail-closed regressions:**
  - `test_revert_on_project_defined_compact_certificate`
  - `test_revert_on_simulated_collateral_format`
  - `test_report_data_cryptographic_mismatch`
  - `test_forged_or_untrusted_pck_chain_reverts`
- **Lifecycle tests** use a harness PKI in Intel's exact formats (X.509 PCK chain with
  the SGX extension, X.509 CRLs, and signed TCB Info / QE Identity JSON). The reason is
  that a real quote's `report_data` cannot bind a test job. These run against a
  harness-root deployment. `test_production_default_rejects_harness_signed_chain`
  proves the production default rejects them.
