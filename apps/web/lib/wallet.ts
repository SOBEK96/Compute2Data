import { createAccount, generatePrivateKey } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import type { EIP1193Provider } from "viem";

import type { HexAddress } from "./contract";

type RpcError = { code?: number; message?: string; data?: { originalError?: { code?: number } } };

const USER_REJECTED = 4001;
const UNRECOGNIZED_CHAIN = 4902;
const METHOD_NOT_FOUND = -32601;

function errorCode(error: unknown) {
  const rpc = error as RpcError | null;
  return rpc?.code ?? rpc?.data?.originalError?.code;
}

/** True when a wallet does not implement the requested RPC method. */
export function isUnsupportedMethod(error: unknown) {
  if (errorCode(error) === METHOD_NOT_FOUND) return true;
  const message = (error as RpcError | null)?.message ?? "";
  return /not (supported|implemented|found)|doesn't have corresponding handler|unsupported method/i.test(
    message,
  );
}

/**
 * Best-effort switch to the chain the contract client targets, using only
 * standard EIP-3085/3326 calls. Unlike genlayer-js `client.connect()`, this
 * never touches MetaMask Snaps (`wallet_getSnaps` -> `wallet_getPermissions`),
 * which most non-MetaMask wallets reject. Only an explicit user rejection is
 * surfaced; any other failure lets the transaction proceed.
 */
export async function ensureWalletChain(provider: EIP1193Provider) {
  const chainId = `0x${studionet.id.toString(16)}` as const;
  try {
    const current = await provider.request({ method: "eth_chainId" });
    if (current === chainId) return;
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId }] });
  } catch (switchError) {
    if (errorCode(switchError) === USER_REJECTED) throw switchError;
    if (errorCode(switchError) !== UNRECOGNIZED_CHAIN) return;
    try {
      await provider.request({
        method: "wallet_addEthereumChain",
        params: [
          {
            chainId,
            chainName: studionet.name,
            nativeCurrency: studionet.nativeCurrency,
            rpcUrls: [...studionet.rpcUrls.default.http],
            blockExplorerUrls: studionet.blockExplorers?.default.url
              ? [studionet.blockExplorers.default.url]
              : undefined,
          },
        ],
      });
    } catch (addError) {
      if (errorCode(addError) === USER_REJECTED) throw addError;
    }
  }
}

// Guest mode: an in-browser burner key, kept for the tab session only.
const GUEST_KEY_STORAGE = "c2d:guest-private-key";

function readGuestKey(): HexAddress | null {
  try {
    const stored = window.sessionStorage.getItem(GUEST_KEY_STORAGE);
    return stored && /^0x[0-9a-fA-F]{64}$/.test(stored) ? (stored as HexAddress) : null;
  } catch {
    return null;
  }
}

let guestKey: HexAddress | null = null;

export function createGuestAccount() {
  guestKey = readGuestKey() ?? generatePrivateKey();
  try {
    window.sessionStorage.setItem(GUEST_KEY_STORAGE, guestKey);
  } catch {
    // Storage unavailable: the burner lives in memory for this page load.
  }
  return createAccount(guestKey);
}

export function restoreGuestAccount() {
  guestKey = readGuestKey();
  return guestKey ? createAccount(guestKey) : null;
}

export function clearGuestAccount() {
  guestKey = null;
  try {
    window.sessionStorage.removeItem(GUEST_KEY_STORAGE);
  } catch {
    // Nothing to clear.
  }
}

/** The local signer for `address` when it is the active guest burner. */
export function guestSignerFor(address: HexAddress) {
  if (!guestKey) return null;
  const account = createAccount(guestKey);
  return account.address.toLowerCase() === address.toLowerCase() ? account : null;
}
