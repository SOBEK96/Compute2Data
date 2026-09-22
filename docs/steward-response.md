# Response to Steward Gen. Dave — Authentic Attestation (Sep 21, 2026)

**Re:** "The contract explicitly continues to accept a project-defined compact certificate
chain and simulated collateral format, while genuine Intel X.509 PCK-chain and PCS
collateral support remains future roadmap work."

**Resolution:** Genuine Intel X.509 PCK-chain and Intel PCS collateral verification is now
implemented in the contract and deployed. The compact certificate chain and the simulated
collateral format are no longer accepted anywhere: they revert.

---

## 1. What changed in the contract

| Before | Now |
|--------|-----|
| Certification data `cert_data_type 0x0101`: raw P-256 keys plus signatures (project-defined) | Only Intel `cert_data_type 5`: the PEM X.509 PCK chain from the quote, DER-parsed and verified on chain (PCK → PCK Processor/Platform CA → Intel SGX Root CA). Any other type reverts with `ERR_INVALID_ATTESTATION … (CERT_DATA_TYPE_UNSUPPORTED)` |
| Collateral `{fmspc, tcbStatus, signature}` under a project domain tag, fetched from an admin-set endpoint | Intel PCS v4 collateral exactly as Intel serves it: TCB Info v3, QE Identity v2, their TCB Signing issuer chains, the PCK CRL, and the Root CA CRL. All signatures are verified on chain to the pinned Intel root; freshness, FMSPC, and PCE-ID are enforced. Anything else reverts with `ERR_INVALID_COLLATERAL … (<code>)` |
| Separately pinned TCB Signing key; `set_attestation_endpoint` | Single trust anchor: the Intel SGX Root CA key. The TCB Signing certificate is verified to it and checked against the Root CA CRL. The endpoint setter is removed |
| No revocation checking | The Root CA CRL and PCK CRL are verified; revoked PCK CA or PCK certificates are rejected |
| QE not checked against Intel's identity | The QE report must match Intel's QE Identity (MRSIGNER, ISVPRODID, masked MISCSELECT / ATTRIBUTES); the QE TCB level is evaluated |
| Placeholder trusted measurements (`11…`, `22…`) shipped at deploy | The trust registry starts empty; the operator whitelists the audited enclave |

The full specification is in [`docs/attestation.md`](attestation.md). The verifier is
`_verify_sgx_evidence` in `contracts/c2d_marketplace.py`.

## 2. How to check it against genuine Intel material

`test/fixtures/intel_sgx/` contains a **real SGX quote issued on Intel hardware** (the
public `dcap-qvl` sample; its PCK chain ends at the real Intel SGX Root CA) and the
**real Intel PCS collateral** for its FMSPC, fetched from `api.trustedservices.intel.com`.

`tests/direct/test_authentic_attestation.py` shows:

- The production-default contract (Intel root pinned, no test anchors) authenticates this
  quote and collateral on chain. It computes platform TCB status
  `OutOfDateConfigurationNeeded` and QE status `UpToDate`. Phala's independent
  `dcap-qvl` verifier gives the same status for the same inputs.
- With that quote submitted as a proof, the contract gets past every authenticity check
  and then applies policy: it slashes on the non-accepted TCB status, or, once the status
  is accepted and the enclave whitelisted, on `BINDING_MISMATCH`, because the quote's
  report_data (`Hello, world!`) does not bind the job.
- Flipping one byte of the genuine quote reverts (`SIGNATURE_INVALID`), as does flipping
  one byte of the genuine TCB Info (`TCB_INFO_SIGNATURE_INVALID`), pairing the quote with
  genuine TCB Info for another FMSPC (`TCB_INFO_FMSPC_MISMATCH`), or verifying after the
  collateral's `nextUpdate` (`PCK_CRL_EXPIRED`).

Negative regressions in the same file:

- `test_revert_on_project_defined_compact_certificate`: the formerly accepted compact
  chain reverts in its original form and inside an otherwise-valid Intel header.
- `test_revert_on_simulated_collateral_format`: the former collateral JSON is rejected
  in every position, as are unsigned, foreign-signed, expired, wrong-FMSPC, and
  untrusted-root collateral. A zero-value stake or an unbacked bond reverts with
  `ERR_INVALID_COLLATERAL`.
- `test_report_data_cryptographic_mismatch`: a genuine quote bound to other work is
  slashed; a report_data edited after signing reverts.

Result: `./run_tests.sh` → 202 passed (lint + validation + direct suites).

## 3. Deployment

Studio-Dev (chain 61997), deployed with **no constructor arguments**:

- Contract: `0xA12282C872FB3416763399065cA63DAcD5e78a3C`
  (<https://explorer-studio-dev.genlayer.com/address/0xA12282C872FB3416763399065cA63DAcD5e78a3C>)
- Deploy tx: `0xedc493d4bef8e22c43bd29c9356bc33e010725243e75807c9f31322a1f4c670a`
  (consensus `ACCEPTED`)
- `get_attestation_config()` on the live contract returns
  `intel_root_ca_pinned: true`, the Intel SGX Root CA key,
  `quote_format: "Intel SGX ECDSA quote v3, cert_data_type 5 (X.509 PCK chain)"`, and
  `accepted_tcb_statuses: ["UpToDate"]`. `tests/integration/test_migration_smoke.py`
  asserts this against the live node.

## 4. Scope, stated plainly

- The quote format is SGX ECDSA v3 with `cert_data_type 5`, which is what the Intel
  DCAP quote library emits for SGX enclaves. TDX and v4 envelopes are rejected.
- A settling proof requires a real enclave on an Intel SGX platform, and that enclave
  must write the job binding into report_data. The job-lifecycle tests use a harness
  PKI in Intel's exact formats under a test root, because a public Intel quote cannot
  bind a test job. The production default rejects that harness root
  (`test_production_default_rejects_harness_signed_chain`).
- The prover supplies collateral with the proof. It is accepted only inside Intel's
  signed validity windows (30 days for TCB Info, QE Identity, and the PCK CRL).
