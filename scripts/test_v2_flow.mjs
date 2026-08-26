import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

const CONTRACT_ADDRESS = "0xAe82102D566Ea2BC4de2F2F19db526e7FE002552";

const account = createAccount();
console.log("Account:", account.address);

const client = createClient({
  chain: studionet,
  account: account
});

async function main() {
  console.log("\n1. Staking 25 GEN on v2 contract...");
  const stakeTx = await client.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "stake_provider",
    args: [],
    value: 25000000000000000000n
  });
  console.log("Stake Tx:", stakeTx);
  const stakeReceipt = await client.waitForTransactionReceipt({ hash: stakeTx });
  console.log("Stake status:", stakeReceipt.status_name, "Result:", stakeReceipt.result_name);

  console.log("\n2. Registering dataset 'genomics-pan-cancer-v1' on v2 contract...");
  const regTx = await client.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "register_dataset",
    args: [
      "genomics-pan-cancer-v1",
      "TCGA Pan-Cancer Clinical Cohort v2",
      "High-throughput multi-omics RNA-seq profiles and survival outcomes",
      "Ensembl ID, TPM Expression, Clinical Outcome",
      "sha256:tcga-pan-cancer-2026-v2-verified",
      "Verified biomarker and differential expression only",
      3000000000000000000n
    ]
  });
  console.log("Register Tx:", regTx);
  const regReceipt = await client.waitForTransactionReceipt({ hash: regTx });
  console.log("Register status:", regReceipt.status_name, "Result:", regReceipt.result_name);

  console.log("\n3. Funding compute job 'job-v2-001' (3 GEN escrow)...");
  const jobTx = await client.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "request_compute",
    args: [
      "job-v2-001",
      "genomics-pan-cancer-v1",
      "oncology-transformer-v3",
      "Fine-tune 10 epochs on pan-cancer cohort; report survival correlation.",
      "sha256:input-hyperparams-v2"
    ],
    value: 3000000000000000000n
  });
  console.log("Job Request Tx:", jobTx);
  const jobReceipt = await client.waitForTransactionReceipt({ hash: jobTx });
  console.log("Job Request status:", jobReceipt.status_name, "Result:", jobReceipt.result_name);

  console.log("\n4. Querying provider reputation on-chain...");
  const rep = await client.readContract({
    address: CONTRACT_ADDRESS,
    functionName: "get_provider_reputation",
    args: [account.address]
  });
  console.log("Provider Reputation:", rep);

  console.log("\n5. Querying global marketplace stats...");
  const stats = await client.readContract({
    address: CONTRACT_ADDRESS,
    functionName: "get_marketplace_stats",
    args: []
  });
  console.log("Marketplace Stats:", stats);
}

main();
