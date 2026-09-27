"use client";

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

import type { HexAddress } from "@/lib/contract";
import {
  clearGuestAccount,
  createGuestAccount,
  restoreGuestAccount,
} from "@/lib/wallet";

type WalletStatus = "idle" | "connecting" | "connected" | "error";
type WalletMode = "injected" | "guest";

type WalletContextValue = {
  account: HexAddress | null;
  status: WalletStatus;
  error: string | null;
  mode: WalletMode | null;
  hasInjectedWallet: boolean;
  connect: () => Promise<HexAddress | null>;
  connectGuest: () => HexAddress;
  disconnect: () => void;
};

const WalletContext = createContext<WalletContextValue | null>(null);

function normalizeAccount(value: unknown): HexAddress | null {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value)
    ? (value as HexAddress)
    : null;
}

export function WalletProvider({ children }: { children: ReactNode }) {
  const [account, setAccount] = useState<HexAddress | null>(null);
  const [status, setStatus] = useState<WalletStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<WalletMode | null>(null);
  const [hasInjectedWallet, setHasInjectedWallet] = useState(false);
  const modeRef = useRef<WalletMode | null>(null);
  modeRef.current = mode;

  useEffect(() => {
    const guest = restoreGuestAccount();
    if (guest) {
      setAccount(guest.address);
      setMode("guest");
      setStatus("connected");
    }

    const ethereum = window.ethereum;
    setHasInjectedWallet(Boolean(ethereum));
    if (!ethereum) return;

    // Silent session restore via plain eth_accounts; no EIP-2255 permission
    // queries, and any provider error just leaves the app disconnected.
    let active = true;
    if (!guest) {
      Promise.resolve()
        .then(() => ethereum.request({ method: "eth_accounts" }))
        .then((accounts) => {
          if (!active || modeRef.current || !Array.isArray(accounts)) return;
          const nextAccount = normalizeAccount(accounts[0]);
          if (!nextAccount) return;
          setAccount(nextAccount);
          setMode("injected");
          setStatus("connected");
        })
        .catch(() => undefined);
    }

    const handleAccountsChanged = (accounts: readonly `0x${string}`[]) => {
      if (modeRef.current !== "injected") return;
      const nextAccount = normalizeAccount(accounts[0]);
      setAccount(nextAccount);
      setMode(nextAccount ? "injected" : null);
      setStatus(nextAccount ? "connected" : "idle");
      setError(null);
    };

    try {
      ethereum.on?.("accountsChanged", handleAccountsChanged);
    } catch {
      // Some injected providers do not implement events.
    }
    return () => {
      active = false;
      try {
        ethereum.removeListener?.("accountsChanged", handleAccountsChanged);
      } catch {
        // Ignore providers without event support.
      }
    };
  }, []);

  function connectGuest() {
    const guest = createGuestAccount();
    setAccount(guest.address);
    setMode("guest");
    setStatus("connected");
    setError(null);
    return guest.address;
  }

  async function connect() {
    if (!window.ethereum) {
      setStatus("error");
      setError(
        "No browser wallet detected. Install MetaMask or another EIP-1193 wallet, or continue in Guest Mode.",
      );
      return null;
    }

    setStatus("connecting");
    setError(null);
    try {
      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts",
      });
      const nextAccount = Array.isArray(accounts)
        ? normalizeAccount(accounts[0])
        : null;
      if (!nextAccount) throw new Error("The wallet returned an invalid account.");
      clearGuestAccount();
      setAccount(nextAccount);
      setMode("injected");
      setStatus("connected");
      return nextAccount;
    } catch (caught) {
      setStatus("error");
      setError(caught instanceof Error ? caught.message : "Wallet connection failed.");
      return null;
    }
  }

  function disconnect() {
    if (mode === "guest") clearGuestAccount();
    setAccount(null);
    setMode(null);
    setStatus("idle");
    setError(null);
  }

  return (
    <WalletContext.Provider
      value={{
        account,
        status,
        error,
        mode,
        hasInjectedWallet,
        connect,
        connectGuest,
        disconnect,
      }}
    >
      {children}
    </WalletContext.Provider>
  );
}

export function useWallet() {
  const context = useContext(WalletContext);
  if (!context) throw new Error("useWallet must be used within WalletProvider.");
  return context;
}
