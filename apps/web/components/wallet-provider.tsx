"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import type { HexAddress } from "@/lib/contract";

type WalletStatus = "idle" | "connecting" | "connected" | "error";

type WalletContextValue = {
  account: HexAddress | null;
  status: WalletStatus;
  error: string | null;
  connect: () => Promise<HexAddress | null>;
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

  useEffect(() => {
    if (!window.ethereum) return;

    let active = true;
    window.ethereum
      .request({ method: "eth_accounts" })
      .then((accounts) => {
        if (!active || !Array.isArray(accounts)) return;
        const nextAccount = normalizeAccount(accounts[0]);
        setAccount(nextAccount);
        setStatus(nextAccount ? "connected" : "idle");
      })
      .catch(() => {
        if (active) setStatus("idle");
      });

    const handleAccountsChanged = (accounts: readonly `0x${string}`[]) => {
      const nextAccount = normalizeAccount(accounts[0]);
      setAccount(nextAccount);
      setStatus(nextAccount ? "connected" : "idle");
      setError(null);
    };

    window.ethereum.on("accountsChanged", handleAccountsChanged);
    return () => {
      active = false;
      window.ethereum?.removeListener("accountsChanged", handleAccountsChanged);
    };
  }, []);

  async function connect() {
    if (!window.ethereum) {
      setStatus("error");
      setError("Install MetaMask or another EIP-1193 wallet to continue.");
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
      setAccount(nextAccount);
      setStatus("connected");
      return nextAccount;
    } catch (caught) {
      setStatus("error");
      setError(caught instanceof Error ? caught.message : "Wallet connection failed.");
      return null;
    }
  }

  function disconnect() {
    setAccount(null);
    setStatus("idle");
    setError(null);
  }

  return (
    <WalletContext.Provider
      value={{ account, status, error, connect, disconnect }}
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
