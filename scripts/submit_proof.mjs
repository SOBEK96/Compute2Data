import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

const CONTRACT_ADDRESS = "0xd1635bd866F6fd616Da1F1EBFFB686D9c01032F9";

// We need the provider account that registered the dataset:
// To make it reproducible, let's create a dedicated provider, register a job, and submit proof!
async function main() {
  const provider = createAccount();
  const requester = createAccount();

  console.log("Provider Address:", provider.address);
  console.log("Requester Address:", requester.address);

  const provClient = createClient({ chain: studionet, account: provider });
  const reqClient = createClient({ chain: studionet, account: requester });

  console.log("\n1. Provider Staking 25 GEN...");
  const stakeTx = await provClient.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "stake_provider",
    args: [],
    value: 25000000000000000000n
  });
  await provClient.waitForTransactionReceipt({ hash: stakeTx });
  console.log("✓ Provider Staked 25 GEN");

  console.log("\n2. Provider Registering Dataset...");
  const dsId = "finance-fraud-risk-v2";
  const regTx = await provClient.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "register_dataset",
    args: [
      dsId,
      "Global Institutional Settlement Flows",
      "High-frequency cross-border transaction graph for anomaly detection",
      "source_node, target_node, amount_usd, timestamp, risk_score",
      "sha256:fraud-graph-settlement-commitment-88d0",
      "Approved graph neural network risk classification models only",
      2000000000000000000n
    ]
  });
  await provClient.waitForTransactionReceipt({ hash: regTx });
  console.log("✓ Dataset Registered:", dsId);

  console.log("\n3. Requester Requesting Compute (2 GEN Escrow)...");
  const jobId = "job-fraud-gnn-001";
  const reqTx = await reqClient.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "request_compute",
    args: [
      jobId,
      dsId,
      "graph-sage-anomaly-v3",
      "Train GraphSAGE model on transaction subgraphs to output risk embeddings and ROC-AUC score",
      "sha256:gnn-hyperparams-layers3-lr0.001"
    ],
    value: 2000000000000000000n
  });
  await reqClient.waitForTransactionReceipt({ hash: reqTx });
  console.log("✓ Compute Job Funded & Escrowed:", jobId);

  console.log("\n4. Provider Submitting Execution Proof & Invoking GenLayer AI Consensus...");
  const proofMetadata = JSON.stringify({
    completed_epochs: 25,
    convergence_metric: "ROC-AUC 0.964",
    output_hash: "sha256:gnn-embeddings-final-weights-verified",
    environment: "Secure SGX Enclave v4",
    status: "SUCCESS"
  });
  const proofCommitment = "sha256:gnn-embeddings-final-weights-verified";

  const proofTx = await provClient.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "submit_execution_proof",
    args: [
      jobId,
      proofMetadata,
      proofCommitment
    ]
  });
  console.log("Proof Tx Hash (AI Consensus Running):", proofTx);
  const proofReceipt = await provClient.waitForTransactionReceipt({ hash: proofTx });
  console.log("AI Consensus Receipt Status:", proofReceipt.status_name, "Result:", proofReceipt.result_name);

  console.log("\n5. Querying Final Job State on-chain...");
  const finalJob = await provClient.readContract({
    address: CONTRACT_ADDRESS,
    functionName: "get_job",
    args: [jobId]
  });
  console.log("Final Job State:", finalJob);
}

main().catch(console.error);
