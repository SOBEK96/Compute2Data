import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

const CONTRACT_ADDRESS = "0xd1635bd866F6fd616Da1F1EBFFB686D9c01032F9";

const account = createAccount();
console.log("Using account:", account.address);

const client = createClient({
  chain: studionet,
  account: account
});

async function main() {
  console.log("1. Staking 25 GEN as Provider...");
  try {
    const stakeTx = await client.writeContract({
      address: CONTRACT_ADDRESS,
      functionName: "stake_provider",
      args: [],
      value: 25000000000000000000n
    });
    console.log("Stake Tx Hash:", stakeTx);
    const stakeReceipt = await client.waitForTransactionReceipt({ hash: stakeTx });
    console.log("Stake Receipt status:", stakeReceipt.status_name, "Result:", stakeReceipt.result_name);

    console.log("\n2. Registering Private Dataset...");
    const regTx = await client.writeContract({
      address: CONTRACT_ADDRESS,
      functionName: "register_dataset",
      args: [
        "genomics-pan-cancer-v1",
        "TCGA Pan-Cancer Clinical Cohort",
        "High-throughput multi-omics RNA-seq profiles and survival data",
        "Ensembl ID, TPM Expression, Clinical Outcome",
        "sha256:tcga-pan-cancer-2026-c2d-verified",
        "Verified differential expression & biomarker analysis only",
        3000000000000000000n
      ]
    });
    console.log("Register Dataset Tx Hash:", regTx);
    const regReceipt = await client.waitForTransactionReceipt({ hash: regTx });
    console.log("Register Receipt status:", regReceipt.status_name, "Result:", regReceipt.result_name);

    console.log("\n3. Querying Active Datasets on-chain...");
    const datasetIds = await client.readContract({
      address: CONTRACT_ADDRESS,
      functionName: "list_dataset_ids",
      args: []
    });
    console.log("Active Dataset IDs:", datasetIds);

    console.log("\n4. Requesting Compute Job with 3 GEN Escrow...");
    const reqAccount = createAccount();
    const reqClient = createClient({ chain: studionet, account: reqAccount });
    const jobTx = await reqClient.writeContract({
      address: CONTRACT_ADDRESS,
      functionName: "request_compute",
      args: [
        "c2d-job-001",
        "genomics-pan-cancer-v1",
        "deep-survival-coxnet-v3",
        "Train Cox Proportional Hazards model with L1 penalty across 33 tumor types",
        "sha256:input-params-l1-0.05"
      ],
      value: 3000000000000000000n
    });
    console.log("Request Compute Job Tx Hash:", jobTx);
    const jobReceipt = await reqClient.waitForTransactionReceipt({ hash: jobTx });
    console.log("Job Receipt status:", jobReceipt.status_name, "Result:", jobReceipt.result_name);

  } catch (err) {
    console.error("Execution error:", err);
  }
}

main();
