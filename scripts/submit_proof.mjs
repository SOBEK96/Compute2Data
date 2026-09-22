import fs from 'node:fs';
import path from 'node:path';
import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

// Contract address on StudioNet / Studio-Dev
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || "0xA12282C872FB3416763399065cA63DAcD5e78a3C";

// =============================================================================
// Compute2Data Attestation Proof Relayer
// -----------------------------------------------------------------------------
// Relays a proof envelope to submit_execution_proof. It carries NO signing keys
// and mints nothing; it forwards an envelope that already exists:
//
//   { "artifact": {...}, "dcap_quote": "<hex>", "collateral": {...} }
//
// dcap_quote is the Intel SGX ECDSA quote (v3) produced by the provider's
// enclave on Intel SGX hardware; collateral is the Intel PCS collateral for it.
// Build the envelope with:
//   node scripts/fetch_pcs_collateral.mjs quote.hex --artifact artifact.json \
//     --out artifacts/attestation_quote.json
//
// The contract verifies the X.509 PCK chain, the Intel CRLs, the quote
// signatures, and the TCB Info / QE Identity signatures on chain to the pinned
// Intel SGX Root CA. Evidence that is not genuine reverts with
// ERR_INVALID_ATTESTATION / ERR_INVALID_COLLATERAL.
// =============================================================================

function loadAttestationQuote() {
  const quotePath = process.env.ENCLAVE_QUOTE_PATH || path.join(process.cwd(), 'artifacts', 'attestation_quote.json');
  if (fs.existsSync(quotePath)) {
    console.log(`[Relayer] Loading proof envelope from: ${quotePath}`);
    const raw = fs.readFileSync(quotePath, 'utf8');
    return JSON.parse(raw);
  }

  // If no file exists, check CLI or ENV string
  if (process.env.ATTESTATION_QUOTE) {
    console.log('[Relayer] Loading proof envelope from ATTESTATION_QUOTE environment variable');
    return JSON.parse(process.env.ATTESTATION_QUOTE);
  }

  console.warn(`[Relayer] No proof envelope found at ${quotePath}.`);
  console.warn('[Relayer] Build one with scripts/fetch_pcs_collateral.mjs, or set ENCLAVE_QUOTE_PATH / ATTESTATION_QUOTE.');
  return null;
}

async function main() {
  const providerKey = process.env.PROVIDER_PRIVATE_KEY;
  const provider = providerKey ? createAccount(providerKey) : createAccount();
  const client = createClient({ chain: studionet, account: provider });

  console.log("=== Compute2Data Attestation Proof Relayer ===");
  console.log("Target Contract Address:", CONTRACT_ADDRESS);
  console.log("Provider Relayer Address:", provider.address);

  // 1. Verify contract attestation configuration
  const config = await client.readContract({
    address: CONTRACT_ADDRESS,
    functionName: "get_attestation_config",
    args: []
  });
  console.log("\n1. Contract Attestation Configuration:");
  console.log("   - Quote format:          ", config.quote_format);
  console.log("   - Collateral format:     ", config.collateral_format);
  console.log("   - Pinned SGX Root CA:    ", config.sgx_root_ca_pubkey);
  console.log("   - Intel root pinned:     ", config.intel_root_ca_pinned);
  console.log("   - Accepted TCB statuses: ", config.accepted_tcb_statuses);

  const jobId = process.env.JOB_ID || "job-fraud-gnn-001";
  const outputCommitment = process.env.OUTPUT_COMMITMENT || "sha256:gnn-embeddings-final-weights-verified";

  const quoteArtifact = loadAttestationQuote();
  if (!quoteArtifact) {
    console.log("\n[Notice] Submission halted: a proof envelope is required for on-chain verification.");
    console.log("  1. Obtain the SGX quote from your enclave (report_data = sha256(dataset_id || sha256(spec) || sha256(output)) || 0^32).");
    console.log("  2. node scripts/fetch_pcs_collateral.mjs quote.hex --artifact artifact.json --out artifacts/attestation_quote.json");
    console.log("  3. Re-run: node scripts/submit_proof.mjs");
    return;
  }

  const attestationQuoteStr = typeof quoteArtifact === 'string' ? quoteArtifact : JSON.stringify(quoteArtifact);

  console.log(`\n2. Relaying Execution Proof for Job: ${jobId}...`);
  const proofTx = await client.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "submit_execution_proof",
    args: [
      jobId,
      attestationQuoteStr,
      outputCommitment
    ]
  });
  console.log("   Transaction Hash (AI Consensus Running):", proofTx);

  const receipt = await client.waitForTransactionReceipt({ hash: proofTx });
  console.log("   Receipt Status:", receipt.status_name, "| Result:", receipt.result_name);

  console.log("\n3. Querying Final Job State on-chain...");
  const finalJob = await client.readContract({
    address: CONTRACT_ADDRESS,
    functionName: "get_job",
    args: [jobId]
  });
  console.log("   Final Job State:", finalJob);
}

main().catch(console.error);
