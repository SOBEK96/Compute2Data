# Response to Steward Gen. Dave — Attestation Finding

**Re:** Finding that "the contract accepts a custom compact key chain and simulated
collateral format rather than genuine Intel DCAP quote certificates and PCS collateral."

**Verdict from our side:** **You are correct, and we have stopped claiming otherwise.**

---

## 1. Acknowledgment

Your finding is accurate. The prior submission described the verifier as "authentic Intel
SGX / DCAP" attestation. It is not. The contract verifies a **DCAP-shaped testnet
stand-in**: the quote *certification* section uses a project-defined compact layout
(`cert_data_type 0x0101`) instead of Intel's X.509 PCK chain (`cert_data_type 5`), and the
TCB collateral is a project-defined JSON rather than Intel PCS TCB Info. We have removed the
"authentic" framing from the contract, `README.md`, and `scripts/submit_proof.mjs`, and
added `docs/attestation-roadmap.md` documenting the exact stand-in vs. production boundary.
No verification *behavior* changed in this pass — only the claims were corrected to match
what the code does.

## 2. Why a stand-in is used (the unavoidable constraint)

Genuine Intel DCAP attestation requires three inputs that cannot exist in a GenLayer testnet
context:

1. **Real SGX hardware** running the workload in an enclave and hardware-signing the quote.
2. **Intel-provisioned PCK certificates** (per-platform X.509, issued by Intel PCS).
3. **Live Intel PCS collateral** (TCB Info / QE Identity signed by Intel's TCB Signing key).

Because none of these are available to the marketplace, any quote the project can produce is
**necessarily self-signed under a repo-held key**. That is precisely the property a genuine
verifier must *reject* — so presenting a self-signed vector as "genuine Intel" is not just
imprecise, it is the exact failure mode you flagged. We chose to make the stand-in explicit
rather than disguise it.

## 3. What is genuine (and independently checkable)

We want to be equally precise about what is **not** simulated, so the stand-in is not
over-read as "nothing works":

- **The ECDSA P-256 verifier (`_ecdsa_verify`) is real** — a from-scratch secp256r1
  implementation (no C extensions are available in GenVM), correct group law + SHA-256 +
  `r||s` encoding.
- **The two pinned roots are the genuine Intel keys**, verified byte-for-byte against
  Intel's published PCS material: `INTEL_SGX_ROOT_CA_PUBKEY` is Intel's SGX Root CA public
  key, and `INTEL_TCB_SIGNING_PUBKEY` is Intel's SGX TCB Signing key.
- **A default (production-style) deployment anchors to those genuine Intel roots**, and under
  that deployment our own harness-minted stand-in quotes are **rejected**. This is asserted
  by `tests/direct/test_authentic_attestation.py::test_production_default_anchors_to_intel_root_and_rejects_test_keys`,
  which expects `PCK_CHAIN_INVALID`. The test harness signs under deliberately *different*
  TEST anchors, so our passing tests can never forge under the genuine Intel root.
- **The DCAP quote header and 384-byte report body offsets already match real DCAP v3.** The
  stand-in is confined to the certification section and the collateral format.

In short: the *trust anchors* and the *crypto primitive* are production-grade; the *quote
certificate format*, the *collateral format*, and the *enclave producer* are the stand-in.

## 4. The production path is decoupled by design

The verifier is deliberately structured so the stand-in can be swapped for genuine Intel
formats **without touching** the settlement state machine (escrow / slash / appeal), the
`report_data` binding scheme, or the pinned Intel roots. The full plan is in
`docs/attestation-roadmap.md §4`; the essentials:

1. **X.509 PCK chain ingestion** — replace the compact-cert parse in
   `_verify_quote_signature_chain` with a DER/PEM path builder over `cert_data_type 5`
   (PCK leaf → Intel PCK CA → Intel SGX Root CA), reusing the existing `_ecdsa_verify` and
   the already-genuine root anchor, and extracting FMSPC/TCB from the SGX extensions.
2. **Genuine PCS collateral** — replace the stand-in JSON in `_verify_tcb_collateral` with
   Intel PCS TCB Info + QE Identity parsing: verify the signature over canonical `tcbInfo`
   bytes against the (already-genuine) `INTEL_TCB_SIGNING_PUBKEY`, evaluate the platform
   against the `tcbLevels` array, and honor `nextUpdate`.
3. **QE Identity enforcement** — validate the Quoting Enclave against Intel's published QE
   identity, not just its structure.
4. **Real report_data provenance** — bind `MRENCLAVE` to the published C2D workload image so
   `report_data` is a hardware fact, not a harness convention. (Off-chain enclave build; not
   a contract change.)

Steps 1–3 are contained changes to two functions plus their fixtures; every downstream
escrow/appeal test is unaffected. This is why we are comfortable exercising the settlement
logic today on the stand-in while the hardware/PCS integration proceeds in parallel.

## 5. What we are asking of you

We are **not** asking you to accept the stand-in as genuine attestation. We are asking you to
review the *settlement logic* (escrow, slashing, appeals, consensus review) against a
transparently-labeled simulator, with the understanding that the attestation front-end is a
drop-in replacement tracked in `docs/attestation-roadmap.md`. When real SGX hardware and
Intel PCS access are available, steps 1–3 land behind the same pinned genuine roots that are
*already* in the contract today.

Thank you for the finding — it was correct, and it made the codebase more honest.

— Compute2Data engineering

---

**Current deployment (testnet stand-in):**
`0xbA6F26bbC123FE1336c719F0FE71343167D1dBa9` on GenLayer Studio-Dev (Studio Next, Chain ID
`61997`) —
<https://explorer-studio-dev.genlayer.com/address/0xbA6F26bbC123FE1336c719F0FE71343167D1dBa9>
