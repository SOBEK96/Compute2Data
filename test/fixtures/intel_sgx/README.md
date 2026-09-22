# Genuine Intel SGX DCAP test vectors

These files are real Intel material. They are used by
`tests/direct/test_authentic_attestation.py` to show that the contract verifies genuine
Intel evidence against the pinned Intel SGX Root CA (the production default).

| File | Contents | Source |
|------|----------|--------|
| `sgx_quote.hex` | Intel SGX ECDSA quote v3 (4600 bytes, hex) issued on Intel hardware. `cert_data_type` 5; PCK chain: PCK Certificate (serial `81b77732...`, valid 2023-09-20 to 2030-09-20) → Intel SGX PCK Processor CA → Intel SGX Root CA. FMSPC `00a067110000`. `report_data` starts with `Hello, world!` | `sample/sgx_quote` in [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) (master) |
| `tcb_info_00a067110000.json` | TCB Info v3 for the quote's FMSPC; issueDate 2026-09-22T15:04:51Z, nextUpdate 2026-10-22T15:04:51Z | `GET https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00a067110000` |
| `tcb_info_00906ed50000.json` | Genuine TCB Info for a *different* FMSPC (negative test) | `GET .../v4/tcb?fmspc=00906ED50000` |
| `qe_identity.json` | QE Identity v2; issueDate 2026-09-22T15:28:47Z, nextUpdate 2026-10-22T15:28:47Z | `GET .../v4/qe/identity` |
| `tcb_signing_issuer_chain.pem` | Intel SGX TCB Signing certificate + Intel SGX Root CA (identical for both documents above) | `TCB-Info-Issuer-Chain` / `SGX-Enclave-Identity-Issuer-Chain` response headers |
| `pck_crl_processor.der.hex` | PCK Processor CA CRL (DER, hex); thisUpdate 2026-09-22T15:02:18Z, nextUpdate 2026-10-22T15:02:18Z | `GET .../v4/pckcrl?ca=processor&encoding=der` |
| `root_ca_crl.der.hex` | Intel SGX Root CA CRL (DER, hex); thisUpdate 2026-02-26, nextUpdate 2027-02-26 | `https://certificates.trustedservices.intel.com/IntelSGXRootCA.der` |

The collateral was fetched from Intel PCS on 2026-09-22 with
`scripts/fetch_pcs_collateral.mjs`. The tests evaluate it at the fixed time
`2026-09-23T00:00:00Z`, which lies inside every validity window above, so they stay
deterministic after the collateral expires.

**Cross-check.** Phala's independent verifier `dcap-qvl` (PyPI `dcap-qvl`,
`dcap_qvl.verify(quote, collateral, 1790121600)`) reports status
`OutOfDateConfigurationNeeded` for the quote with this collateral, with advisories
INTEL-SA-00289, INTEL-SA-01153 and INTEL-SA-00615. The contract's on-chain TCB
evaluation yields the same platform status (`INTEL_VECTOR_TCB_STATUS` in
`test/dcap_fixtures.py`), with QE status `UpToDate`.
