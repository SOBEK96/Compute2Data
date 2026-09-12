import fs from 'node:fs';
import path from 'node:path';
import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

// Contract address on StudioNet / Studio-Dev
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || "0x6019Bd6C1b7EB06EcC45baf5ed4470c98890F756";

// =============================================================================
// Authentic Intel SGX / DCAP Attestation Proof Relayer
// -----------------------------------------------------------------------------
// This script acts strictly as an on-chain relayer for authentic hardware-generated
// attestation artifacts produced by genuine Intel SGX / DCAP enclaves.
//
// In strict compliance with Web3 security standards and protocol trust invariants:
// 1. NO private keys or test-key minting routines are contained in this script.
// 2. Quotes CANNOT be forged or synthesized by client-side scripts.
// 3. The contract cryptographically validates the full ECDSA signature chain
//    anchored to the official Intel SGX Root CA (NIST P-256), and validates TCB
//    collateral signed by the authentic Intel TCB Signing Key.
// =============================================================================

function loadAttestationQuote() {
  const quotePath = process.env.ENCLAVE_QUOTE_PATH || path.join(process.cwd(), 'artifacts', 'authentic_quote.json');
  if (fs.existsSync(quotePath)) {
    console.log(`[Relayer] Loading authentic attestation quote from: ${quotePath}`);
    const raw = fs.readFileSync(quotePath, 'utf8');
    return JSON.parse(raw);
  }

  // If no file exists, check CLI or ENV string
  if (process.env.ATTESTATION_QUOTE) {
    console.log('[Relayer] Loading attestation quote from ATTESTATION_QUOTE environment variable');
    return JSON.parse(process.env.ATTESTATION_QUOTE);
  }

  console.warn(`[Relayer] No authentic enclave quote found at ${quotePath}.`);
  console.warn('[Relayer] Real Intel SGX enclaves dump quote artifacts to artifacts/authentic_quote.json or pass via ENCLAVE_QUOTE_PATH.');
  return null;
}

async function main() {
  const providerKey = process.env.PROVIDER_PRIVATE_KEY;
  const provider = providerKey ? createAccount(providerKey) : createAccount();
  const client = createClient({ chain: studionet, account: provider });

  console.log("=== Compute2Data Authentic Proof Relayer ===");
  console.log("Target Contract Address:", CONTRACT_ADDRESS);
  console.log("Provider Relayer Address:", provider.address);

  // 1. Verify contract attestation configuration
  const config = await client.readContract({
    address: CONTRACT_ADDRESS,
    functionName: "get_attestation_config",
    args: []
  });
  console.log("\n1. Contract Attestation Configuration:");
  console.log("   - Remote PCS Endpoint:", config.attestation_endpoint);
  console.log("   - Anchored SGX Root CA:", config.sgx_root_ca_pubkey);
  console.log("   - Anchored TCB Signer: ", config.tcb_signing_pubkey);

  const jobId = process.env.JOB_ID || "job-fraud-gnn-001";
  const outputCommitment = process.env.OUTPUT_COMMITMENT || "sha256:gnn-embeddings-final-weights-verified";

  const quoteArtifact = loadAttestationQuote();
  if (!quoteArtifact) {
    console.log("\n[Notice] Submission halted: Hardware enclave quote artifact required for on-chain verification.");
    console.log("To submit a proof:");
    console.log("  1. Run your compute workload inside an authentic Intel SGX enclave.");
    console.log("  2. Place the generated quote envelope in artifacts/authentic_quote.json");
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
