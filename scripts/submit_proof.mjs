import fs from 'node:fs';
import path from 'node:path';
import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

// Contract address on StudioNet / Studio-Dev
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || "0xbA6F26bbC123FE1336c719F0FE71343167D1dBa9";

// =============================================================================
// Compute2Data Attestation Proof Relayer (TESTNET STAND-IN)
// -----------------------------------------------------------------------------
// This script relays an attestation artifact to the contract's submit_execution_proof
// entrypoint. It carries NO signing keys and mints nothing; it only forwards a quote
// envelope that already exists on disk / in the environment.
//
// IMPORTANT -- what the contract verifies today is a TESTNET STAND-IN, not genuine
// Intel DCAP:
// 1. The contract pins the genuine Intel SGX Root CA / TCB Signing public keys, and
//    its on-chain ECDSA P-256 verifier is real. But the quote CERT layout and the TCB
//    collateral JSON are the project-defined stand-in formats (not Intel's X.509 PCK
//    chain / PCS TCB Info), so a genuine Intel-issued quote will NOT parse yet.
// 2. There is no real SGX enclave in the loop; the report_data binding is a convention
//    this simulator enforces. See docs/attestation-roadmap.md for the stand-in vs.
//    production boundary and the path to ingesting genuine PCS collateral.
// =============================================================================

function loadAttestationQuote() {
  const quotePath = process.env.ENCLAVE_QUOTE_PATH || path.join(process.cwd(), 'artifacts', 'attestation_quote.json');
  if (fs.existsSync(quotePath)) {
    console.log(`[Relayer] Loading attestation quote (stand-in envelope) from: ${quotePath}`);
    const raw = fs.readFileSync(quotePath, 'utf8');
    return JSON.parse(raw);
  }

  // If no file exists, check CLI or ENV string
  if (process.env.ATTESTATION_QUOTE) {
    console.log('[Relayer] Loading attestation quote from ATTESTATION_QUOTE environment variable');
    return JSON.parse(process.env.ATTESTATION_QUOTE);
  }

  console.warn(`[Relayer] No attestation quote envelope found at ${quotePath}.`);
  console.warn('[Relayer] Provide a DCAP-shaped stand-in quote at artifacts/attestation_quote.json or via ENCLAVE_QUOTE_PATH / ATTESTATION_QUOTE.');
  return null;
}

async function main() {
  const providerKey = process.env.PROVIDER_PRIVATE_KEY;
  const provider = providerKey ? createAccount(providerKey) : createAccount();
  const client = createClient({ chain: studionet, account: provider });

  console.log("=== Compute2Data Attestation Proof Relayer (testnet stand-in) ===");
  console.log("Target Contract Address:", CONTRACT_ADDRESS);
  console.log("Provider Relayer Address:", provider.address);

  // 1. Verify contract attestation configuration
  const config = await client.readContract({
    address: CONTRACT_ADDRESS,
    functionName: "get_attestation_config",
    args: []
  });
  console.log("\n1. Contract Attestation Configuration:");
  console.log("   - Collateral Endpoint (stand-in):", config.attestation_endpoint);
  console.log("   - Anchored SGX Root CA:", config.sgx_root_ca_pubkey);
  console.log("   - Anchored TCB Signer: ", config.tcb_signing_pubkey);

  const jobId = process.env.JOB_ID || "job-fraud-gnn-001";
  const outputCommitment = process.env.OUTPUT_COMMITMENT || "sha256:gnn-embeddings-final-weights-verified";

  const quoteArtifact = loadAttestationQuote();
  if (!quoteArtifact) {
    console.log("\n[Notice] Submission halted: an attestation quote envelope is required for on-chain verification.");
    console.log("To submit a proof against the testnet stand-in:");
    console.log("  1. Produce a DCAP-shaped stand-in quote envelope (see test/dcap_fixtures.py for the exact byte layout).");
    console.log("  2. Place it at artifacts/attestation_quote.json (or set ENCLAVE_QUOTE_PATH / ATTESTATION_QUOTE).");
    console.log("  3. Re-run: node scripts/submit_proof.mjs");
    console.log("  Note: genuine Intel SGX enclave quotes will NOT parse until the production path in docs/attestation-roadmap.md lands.");
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
