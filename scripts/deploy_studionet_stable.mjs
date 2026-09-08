import fs from 'fs';
import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

// Stable StudioNet (NOT studio-next): id 61999, RPC https://studio.genlayer.com/api.
const CONTRACT_PATH = '/Users/ehs4n/Compute2Data/contracts/c2d_marketplace.py';
const OUT_PATH = '/Users/ehs4n/Compute2Data/scripts/.last_deployment.json';

const code = fs.readFileSync(CONTRACT_PATH, 'utf-8');
const deployer = createAccount();

console.log('==================================================');
console.log('Deploying C2DMarketplace to STABLE StudioNet');
console.log('Chain ID :', studionet.id);
console.log('RPC      :', studionet.rpcUrls.default.http[0]);
console.log('Deployer :', deployer.address);
console.log('==================================================');

const client = createClient({ chain: studionet, account: deployer });

async function main() {
  const deployTxHash = await client.deployContract({ code, args: [] });
  console.log('Deployment Tx Hash:', deployTxHash);

  console.log('Waiting for consensus receipt...');
  const receipt = await client.waitForTransactionReceipt({ hash: deployTxHash, retries: 100, interval: 5000 });
  console.log('Status:', receipt.status_name, '| Result:', receipt.result_name);

  let contractAddress = receipt.contract_address || null;
  if (!contractAddress && receipt.logs && receipt.logs.length > 0) {
    contractAddress = receipt.logs[0].address;
  }
  if (!contractAddress && receipt.data && receipt.data.contract_address) {
    contractAddress = receipt.data.contract_address;
  }

  console.log('\n==================================================');
  console.log('NEW CONTRACT ADDRESS:', contractAddress);
  console.log('DEPLOYMENT TX HASH  :', deployTxHash);
  console.log('DEPLOYER ADDRESS    :', deployer.address);
  console.log('==================================================');

  fs.writeFileSync(
    OUT_PATH,
    JSON.stringify(
      {
        contract_address: contractAddress,
        deploy_tx_hash: deployTxHash,
        deployer: deployer.address,
        chain_id: studionet.id,
        rpc: studionet.rpcUrls.default.http[0],
        status: receipt.status_name,
        result: receipt.result_name,
      },
      null,
      2,
    ),
  );

  if (!contractAddress) {
    console.error('Could not extract contract address; full receipt below:');
    console.error(JSON.stringify(receipt, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('DEPLOY_FAILED:', err?.message || err);
  process.exit(1);
});
