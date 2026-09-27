import { studioDevnet } from "genlayer-js/chains";

/**
 * The one network Compute2Data runs on: GenLayer Studio-Dev ("Studio Next"),
 * chain 61997. The marketplace contract is not deployed on StudioNet (61999),
 * so every client and the wallet switcher must use this chain.
 */
export const C2D_CHAIN_ID = 61997;

/** Live deployment, see deployments/studio-dev.json. */
export const DEFAULT_CONTRACT_ADDRESS = "0xA12282C872FB3416763399065cA63DAcD5e78a3C";

const DEFAULT_RPC_URL = "https://studio-dev.genlayer.com/api";
const DEFAULT_EXPLORER_URL = "https://explorer-studio-dev.genlayer.com";

if (studioDevnet.id !== C2D_CHAIN_ID) {
  throw new Error(`genlayer-js studioDevnet is chain ${studioDevnet.id}, expected ${C2D_CHAIN_ID}.`);
}

const rpcUrl = process.env.NEXT_PUBLIC_STUDIONET_RPC || DEFAULT_RPC_URL;
export const explorerUrl = process.env.NEXT_PUBLIC_STUDIONET_EXPLORER || DEFAULT_EXPLORER_URL;

// A fresh object so genlayer-js never mutates the shared studioDevnet export.
export const c2dChain = {
  ...studioDevnet,
  rpcUrls: { default: { http: [rpcUrl] } },
  blockExplorers: { default: { name: "GenLayer Studio-Dev Explorer", url: explorerUrl } },
};

export const networkName = "GenLayer Studio-Dev";
