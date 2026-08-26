import fs from 'fs';
import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

const contractCode = fs.readFileSync('/Users/ehs4n/Compute2Data/contracts/c2d_marketplace.py', 'utf-8');

// Generate a completely fresh account for this deployment
const deployer = createAccount();
console.log("==================================================");
console.log("🌟 FRESH DEPLOYMENT ON GENLAYER STUDIONET");
console.log("==================================================");
console.log("Deployer Address:", deployer.address);

const client = createClient({
  chain: studionet,
  account: deployer
});

async function main() {
  console.log("\n🚀 Step 1: Deploying C2DMarketplace v2 contract...");
  const deployTxHash = await client.deployContract({
    code: contractCode,
    args: []
  });
  console.log("Deployment Tx Hash:", deployTxHash);

  console.log("Waiting for Multi-LLM Quorum consensus...");
  const receipt = await client.waitForTransactionReceipt({ hash: deployTxHash });
  console.log("Consensus Status:", receipt.status_name);
  console.log("Consensus Result:", receipt.result_name);

  // Extract the deployed contract address from logs
  let contractAddress = null;
  if (receipt.logs && receipt.logs.length > 0) {
    contractAddress = receipt.logs[0].address;
  }
  if (!contractAddress && receipt.contract_address) {
    contractAddress = receipt.contract_address;
  }

  console.log("\n✅ NEW CONTRACT DEPLOYED AT:", contractAddress);

  if (contractAddress) {
    console.log("\n⚡ Step 2: Initializing provider stake (25 GEN)...");
    const stakeTx = await client.writeContract({
      address: contractAddress,
      functionName: "stake_provider",
      args: [],
      value: 25000000000000000000n
    });
    console.log("Stake Tx Hash:", stakeTx);
    const stakeReceipt = await client.waitForTransactionReceipt({ hash: stakeTx });
    console.log("Stake Status:", stakeReceipt.status_name, "Result:", stakeReceipt.result_name);

    console.log("\n📦 Step 3: Registering Genesis Dataset ('genomics-pan-cancer-v1')...");
    const regTx = await client.writeContract({
      address: contractAddress,
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

    console.log("\n📊 Step 4: Reading initial marketplace stats...");
    const stats = await client.readContract({
      address: contractAddress,
      functionName: "get_marketplace_stats",
      args: []
    });
    console.log("Marketplace Stats:", stats);

    console.log("\n🔧 Step 5: Updating web app configuration...");
    const envPath = '/Users/ehs4n/Compute2Data/apps/web/.env.local';
    const envContent = `NEXT_PUBLIC_CONTRACT_ADDRESS=${contractAddress}\nNEXT_PUBLIC_STUDIONET_RPC=https://studio.genlayer.com/rpc\nNEXT_PUBLIC_CHAIN_ID=500000\n`;
    fs.writeFileSync(envPath, envContent);

    const contractTsPath = '/Users/ehs4n/Compute2Data/apps/web/lib/contract.ts';
    let contractTs = fs.readFileSync(contractTsPath, 'utf-8');
    contractTs = contractTs.replace(/export const DEFAULT_CONTRACT_ADDRESS = "0x[a-fA-F0-9]+";/, `export const DEFAULT_CONTRACT_ADDRESS = "${contractAddress}";`);
    fs.writeFileSync(contractTsPath, contractTs);

    console.log("\n🎉 ALL STEPS COMPLETED SUCCESSFULLY!");
    console.log("==================================================");
    console.log("Contract Address:", contractAddress);
    console.log("Deployer Address:", deployer.address);
    console.log("Deployment Tx:   ", deployTxHash);
    console.log("==================================================");
  }
}

main().catch(console.error);
