# Attestation Roadmap — Testnet Stand-in vs. Production DCAP

This document is the single source of truth for **what the Compute2Data attestation
verifier actually does today** versus **what a production-grade Intel SGX / DCAP
verifier must do**. It exists so that no reader — reviewer, integrator, or auditor —
is left to infer the trust model from marketing language.

**One-sentence summary:** the contract today runs a *DCAP-shaped stand-in* — real
ECDSA P-256 verification, real (genuine Intel) pinned root keys, but *project-defined*
quote-certificate and TCB-collateral **formats** and *no real SGX enclave in the loop*.
It is a faithful simulator of the on-chain settlement logic, not a genuine Intel quote
verifier.

---

## 1. Why a stand-in exists

Genuine Intel DCAP attestation requires three things that are simply not available in a
GenLayer testnet environment:

1. **Real SGX hardware** running the compute workload inside an enclave, producing a
   hardware-signed quote whose `report_data` commits to the workload's inputs/outputs.
2. **Intel-provisioned PCK certificates** — a per-platform X.509 chain
   (`cert_data_type 5`, PEM) issued by Intel's Provisioning Certification Service (PCS),
   terminating at the Intel SGX Root CA.
3. **Live Intel PCS collateral** — TCB Info and QE Identity JSON, signed by the Intel
   TCB Signing key, fetched from `api.trustedservices.intel.com`.

None of these can be produced by the marketplace, its tests, or its CI. Any "quote" the
project can mint is therefore, by construction, **self-signed under a repo-held key** —
which is exactly the property a genuine verifier must reject. Rather than pretend
otherwise, the contract ships an explicit stand-in and pins the *genuine* Intel roots by
default so that stand-in traffic is provably rejected under a production-style deployment.

## 2. What is genuine today

These are **not** simulated and should be treated as production-ready primitives:

| Component | Status | Notes |
| :-- | :-- | :-- |
| `_ecdsa_verify` (secp256r1) | **Genuine** | From-scratch pure-Python P-256 verify (no C ext in GenVM). Correct group law, SHA-256, `r\|\|s`. |
| `INTEL_SGX_ROOT_CA_PUBKEY` | **Genuine** | Byte-for-byte the public key of Intel's `Intel_SGX_Provisioning_Certification_RootCA.pem` (CN=Intel SGX Root CA), verified against Intel's live PCS. |
| `INTEL_TCB_SIGNING_PUBKEY` | **Genuine** | Byte-for-byte the *Intel SGX TCB Signing* cert public key served in the PCS v4 TCB-Info issuer chain. |
| Default deployment anchoring | **Genuine** | With no constructor override, the contract pins the two genuine Intel keys above. |
| report_data binding *scheme* | **Genuine design** | `sha256(dataset_id + compute_spec_hash + output_data_hash)` is the intended production binding; only the *producer* (a real enclave) is missing. |

**Proof that stand-in traffic cannot pose as real:** the regression test
`tests/direct/test_authentic_attestation.py::test_production_default_anchors_to_intel_root_and_rejects_test_keys`
deploys with the genuine Intel anchors and asserts a harness-minted quote is rejected with
`PCK_CHAIN_INVALID`. The test harness signs under deliberately different TEST anchors
(`TEST_SGX_ROOT_CA_PUBKEY` / `TEST_TCB_SIGNING_PUBKEY`, private scalars in
`test/dcap_fixtures.py`), so passing tests never exercise — and cannot forge under — the
genuine Intel root.

## 3. What is a stand-in today

These are the **project-defined simulations** a reviewer must not mistake for Intel formats:

| Component | Stand-in reality | Genuine requirement |
| :-- | :-- | :-- |
| Quote certification data | Compact layout `cert_data_type 0x0101`: `fmspc \|\| PCK_pub \|\| intermediate_pub \|\| sig(leaf) \|\| sig(intermediate)`, each key a raw 64-byte P-256 point. | Intel `cert_data_type 5`: a PEM X.509 PCK chain (PCK leaf → Intel SGX PCK Processor/Platform CA → Intel SGX Root CA) with SGX extensions (FMSPC, TCB, PCEID). |
| TCB collateral | Project JSON `{fmspc, tcbStatus, signature}` where `signature = ECDSA(TCB_key, "c2d-tcb-collateral-v1\|fmspc\|status")`. | Intel PCS TCB Info JSON (`tcbInfo` + `signature`) and QE Identity JSON, with full TCB level arrays, `nextUpdate`, and the issuer chain. |
| SGX enclave | None. `report_data` is assembled by the test harness / relayer. | A real enclave computes and hardware-seals `report_data` over the actual workload. |
| Quote header/report offsets | **Match real DCAP v3** (48-byte header, 384-byte report body, fields at real offsets). | Same — this part is already production-shaped. |

The header/report *body* offsets are real; the *certification section* and *collateral*
are where the stand-in lives.

## 4. Production path (decoupled by design)

The verifier is structured so the stand-in can be replaced **without touching** the
settlement state machine (escrow / slash / appeal), the report_data binding scheme, or the
pinned Intel roots. Concretely:

1. **X.509 PCK chain ingestion.** Replace `_compact_cert_data` parsing in
   `_verify_quote_signature_chain` with a DER/PEM X.509 path builder that (a) parses
   `cert_data_type 5`, (b) walks PCK leaf → Intel PCK CA → Intel SGX Root CA, (c) checks
   validity, basic constraints, and the SGX extension OIDs, and (d) extracts FMSPC/TCB from
   the leaf. The existing `_ecdsa_verify` is reused for each link; the genuine
   `INTEL_SGX_ROOT_CA_PUBKEY` is already the terminating anchor.
2. **Genuine PCS collateral.** Replace the stand-in JSON in `_verify_tcb_collateral` with
   Intel PCS TCB Info + QE Identity parsing: verify the `signature` over the canonical
   `tcbInfo` bytes against `INTEL_TCB_SIGNING_PUBKEY`, evaluate the platform's TCB level
   against the `tcbLevels` array (not a single `tcbStatus` string), honor `nextUpdate`, and
   fold QE Identity into the enclave-trust decision. Fetch stays on `gl.nondet.web.get`
   wrapped in `gl.eq_principle.strict_eq`.
3. **QE Identity enforcement.** Add QE Identity verification (MRSIGNER/ISVPRODID/ISVSVN of
   the Quoting Enclave itself) so the QE report is validated against Intel's published QE
   identity, not just structurally parsed.
4. **Real report_data provenance.** Document and enforce that `report_data` originates from
   an enclave running the published C2D workload image (pinned via `MRENCLAVE`), closing the
   "convention vs. hardware fact" gap noted in §3.

Steps 1–3 are contained changes to two functions plus their fixtures; the genuine roots,
the ECDSA primitive, and every downstream escrow/appeal test remain unchanged. Step 4 is an
off-chain enclave-build effort, not a contract change.

## 5. Where each claim lives in the code

- `contracts/c2d_marketplace.py` — module header (`TESTNET ATTESTATION STAND-IN ...`),
  `_parse_dcap_quote`, `_verify_quote_signature_chain`, `_verify_tcb_collateral`,
  `_expected_report_data`, and the genuine `INTEL_SGX_ROOT_CA_PUBKEY` /
  `INTEL_TCB_SIGNING_PUBKEY` constants.
- `test/dcap_fixtures.py` — the DCAP-shaped stand-in builders and the TEST anchors
  (distinct from the genuine Intel roots), guarded by `assert_pinned_keys_match()`.
- `tests/direct/test_authentic_attestation.py` — end-to-end coverage, including the
  production-default rejection test.
- `README.md` — the "Testnet Attestation Stand-in (DCAP-shaped)" section links here.
- `scripts/submit_proof.mjs` — relayer; carries no keys, forwards a stand-in envelope.
