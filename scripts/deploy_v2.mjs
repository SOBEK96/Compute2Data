import fs from 'fs';
import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

const contractCode = fs.readFileSync('/Users/ehs4n/Compute2Data/contracts/c2d_marketplace.py', 'utf-8');

const account = createAccount();
console.log("Deployer account:", account.address);

const client = createClient({
  chain: studionet,
  account: account
});

async function deploy() {
  console.log("Deploying C2DMarketplace v2 to GenLayer StudioNet...");
  try {
    const txHash = await client.deployContract({
      code: contractCode,
      args: []
    });
    console.log("Deployment Tx Hash:", txHash);

    console.log("Waiting for Multi-LLM Consensus on deployment transaction...");
    const receipt = await client.waitForTransactionReceipt({ hash: txHash });
    console.log("Consensus Status:", receipt.status_name);
    console.log("Consensus Result:", receipt.result_name);
    console.log("Deployed Contract Address:", receipt.contract_address);

    return receipt.contract_address;
  } catch (error) {
    console.error("Deployment failed:", error);
  }
}

deploy();
