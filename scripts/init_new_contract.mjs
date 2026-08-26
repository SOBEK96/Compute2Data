import fs from 'fs';
import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

const NEW_CONTRACT = "0x08A1DF5D8f1DE7Cced7E03E8055E7c106eb13987";
const account = createAccount();

console.log("Initializing new contract:", NEW_CONTRACT);
console.log("Provider account:", account.address);

const client = createClient({
  chain: studionet,
  account: account
});

async function main() {
  console.log("\n1. Staking 25 GEN as Provider on new contract...");
  const stakeTx = await client.writeContract({
    address: NEW_CONTRACT,
    functionName: "stake_provider",
    args: [],
    value: 25000000000000000000n
  });
  console.log("Stake Tx Hash:", stakeTx);
  const stakeReceipt = await client.waitForTransactionReceipt({ hash: stakeTx });
  console.log("Stake Status:", stakeReceipt.status_name, "Result:", stakeReceipt.result_name);

  console.log("\n2. Registering TCGA Pan-Cancer Clinical Cohort dataset...");
  const regTx = await client.writeContract({
    address: NEW_CONTRACT,
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
  console.log("Register Tx Hash:", regTx);
  const regReceipt = await client.waitForTransactionReceipt({ hash: regTx });
  console.log("Register Status:", regReceipt.status_name, "Result:", regReceipt.result_name);

  console.log("\n3. Querying on-chain marketplace stats...");
  const stats = await client.readContract({
    address: NEW_CONTRACT,
    functionName: "get_marketplace_stats",
    args: []
  });
  console.log("Marketplace Stats:", stats);

  console.log("\n4. Updating frontend config...");
  const envPath = '/Users/ehs4n/Compute2Data/apps/web/.env.local';
  const envContent = `NEXT_PUBLIC_CONTRACT_ADDRESS=${NEW_CONTRACT}\nNEXT_PUBLIC_STUDIONET_RPC=https://studio.genlayer.com/api\nNEXT_PUBLIC_CHAIN_ID=500000\n`;
  fs.writeFileSync(envPath, envContent);

  const contractTsPath = '/Users/ehs4n/Compute2Data/apps/web/lib/contract.ts';
  let contractTs = fs.readFileSync(contractTsPath, 'utf-8');
  contractTs = contractTs.replace(/export const DEFAULT_CONTRACT_ADDRESS = "0x[a-fA-F0-9]+";/, `export const DEFAULT_CONTRACT_ADDRESS = "${NEW_CONTRACT}";`);
  fs.writeFileSync(contractTsPath, contractTs);

  console.log("\n✅ Configuration updated with new contract address:", NEW_CONTRACT);
}

main().catch(console.error);
