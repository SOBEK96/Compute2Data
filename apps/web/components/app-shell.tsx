"use client";

import clsx from "clsx";
import {
  Activity,
  ArrowRightLeft,
  Blocks,
  Check,
  ChevronDown,
  CircleDot,
  Copy,
  Cpu,
  Database,
  ExternalLink,
  Layers,
  LayoutGrid,
  LogOut,
  ShieldCheck,
  Sparkles,
  Wallet,
  Zap,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, type ReactNode } from "react";

import { contractAddress, isContractConfigured, networkName } from "@/lib/contract";
import { shortAddress } from "@/lib/market-data";

import { useWallet } from "./wallet-provider";

const navigation = [
  { href: "/", label: "Marketplace", icon: LayoutGrid, desc: "Explore bonded data surfaces" },
  { href: "/provider", label: "Provider Console", icon: Blocks, desc: "Stake & manage compute jobs" },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { account, status, error, connect, disconnect } = useWallet();
  const [copied, setCopied] = useState(false);
  const [walletModalOpen, setWalletModalOpen] = useState(false);

  const copyAddress = () => {
    if (!account) return;
    navigator.clipboard.writeText(account);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const switchNetworkMetaMask = async () => {
    if (typeof window === "undefined" || !window.ethereum) return;
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0x7a120" }], // 500000 StudioNet
      });
    } catch (switchError: any) {
      if (switchError.code === 4902 || switchError.data?.originalError?.code === 4902) {
        try {
          await window.ethereum.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: "0x7a120",
                chainName: "GenLayer StudioNet",
                nativeCurrency: { name: "GEN", symbol: "GEN", decimals: 18 },
                rpcUrls: ["https://studio.genlayer.com/rpc"],
                blockExplorerUrls: ["https://studio.genlayer.com"],
              },
            ],
          });
        } catch (addError) {
          console.error("Failed to add GenLayer network:", addError);
        }
      }
    }
  };

  return (
    <div className="min-h-screen bg-hero-glow selection:bg-cobalt-500/30">
      {/* Top Protocol Announcement / Ticker Bar */}
      <div className="relative z-50 border-b border-line/60 bg-carbon/95 px-4 py-1.5 backdrop-blur-md">
        <div className="mx-auto flex max-w-[1480px] items-center justify-between font-mono text-[10px] text-muted">
          <div className="flex items-center gap-6 overflow-hidden">
            <span className="flex items-center gap-1.5 text-mineral">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-mineral opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-mineral" />
              </span>
              GenLayer StudioNet AI Consensus Active
            </span>
            <span className="hidden items-center gap-1 text-paper/80 sm:flex">
              <Zap className="h-3 w-3 text-cyan-400" /> Gasless Execution • 0 GEN Fee Required
            </span>
            <span className="hidden items-center gap-1 sm:flex">
              <Cpu className="h-3 w-3 text-cobalt-400" /> Multi-LLM Quorum: GPT-5.4 + Claude 4.6 + Gemini 3
            </span>
          </div>
          <div className="flex items-center gap-4">
            {contractAddress ? (
              <span className="hidden font-mono text-cyan-300/80 md:inline">
                Contract: {shortAddress(contractAddress)}
              </span>
            ) : null}
            <a
              href="https://docs.genlayer.com"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 transition hover:text-paper"
            >
              Docs <ExternalLink className="h-2.5 w-2.5" />
            </a>
          </div>
        </div>
      </div>

      {/* Main Navbar */}
      <header className="sticky top-0 z-40 border-b border-line/80 bg-canvas/85 backdrop-blur-2xl">
        <div className="mx-auto flex h-[76px] max-w-[1480px] items-center gap-6 px-4 sm:px-6 lg:px-8">
          <Link href="/" className="group flex shrink-0 items-center gap-3">
            <div className="relative grid h-10 w-10 place-items-center overflow-hidden rounded-xl border border-cobalt-400/50 bg-gradient-to-br from-cobalt-500/20 to-cyan-500/10 shadow-glow transition duration-300 group-hover:scale-105 group-hover:border-cyan-400/60">
              <div className="absolute inset-0 bg-gradient-to-tr from-cobalt-500/10 via-transparent to-mineral/20 opacity-0 transition group-hover:opacity-100" />
              <ShieldCheck className="relative h-5 w-5 text-cyan-300 transition duration-300 group-hover:text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-extrabold tracking-[-0.03em] text-paper">
                  Compute2Data
                </span>
                <span className="rounded-md border border-cobalt-400/30 bg-cobalt-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-cobalt-300">
                  v2.0
                </span>
              </div>
              <span className="block font-mono text-[9px] uppercase tracking-[0.16em] text-muted">
                Provable AI Marketplace
              </span>
            </div>
          </Link>

          <nav className="hidden items-center gap-1.5 md:flex" aria-label="Main navigation">
            {navigation.map((item) => {
              const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={clsx(
                    "flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-semibold transition duration-200",
                    active
                      ? "border border-line-bright/60 bg-elevated text-paper shadow-card"
                      : "text-muted hover:border-line hover:bg-elevated/40 hover:text-paper",
                  )}
                >
                  <item.icon className={clsx("h-4 w-4", active ? "text-cyan-400" : "text-muted")} />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto hidden items-center gap-3 lg:flex">
            <button
              onClick={switchNetworkMetaMask}
              className="flex items-center gap-2 rounded-xl border border-line bg-carbon/80 px-3.5 py-2 font-mono text-[11px] text-muted transition hover:border-cobalt-400/60 hover:text-paper"
              title="Click to switch or add GenLayer StudioNet in MetaMask"
            >
              <CircleDot
                className={clsx(
                  "h-3 w-3 animate-pulse",
                  isContractConfigured ? "text-mineral" : "text-ember",
                )}
              />
              <span>{isContractConfigured ? "GenLayer StudioNet" : "Demo Data Mode"}</span>
              <ArrowRightLeft className="h-3 w-3 text-muted/60" />
            </button>
          </div>

          {/* Wallet Actions */}
          {account ? (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setWalletModalOpen(true)}
                className="flex shrink-0 items-center gap-2.5 rounded-xl border border-line-bright/60 bg-gradient-to-b from-elevated to-carbon px-3.5 py-2.5 text-xs font-bold text-paper shadow-card transition duration-200 hover:border-cyan-400/60"
              >
                <span className="h-2 w-2 rounded-full bg-mineral shadow-[0_0_8px_rgba(130,235,197,0.8)]" />
                <span>{shortAddress(account)}</span>
                <ChevronDown className="h-3.5 w-3.5 text-muted" />
              </button>
              <button
                type="button"
                onClick={disconnect}
                className="flex h-9 w-9 items-center justify-center rounded-xl border border-danger/30 bg-danger/10 text-danger transition hover:bg-danger hover:text-white"
                title="Disconnect Wallet"
                aria-label="Disconnect Wallet"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => void connect()}
              disabled={status === "connecting"}
              className="button-primary shrink-0 px-4 py-2.5"
            >
              <Wallet className="h-4 w-4" />
              <span>{status === "connecting" ? "Connecting..." : "Connect Wallet"}</span>
            </button>
          )}
        </div>

        {/* Mobile Navigation Bar */}
        <nav className="flex border-t border-line/60 px-3 md:hidden" aria-label="Mobile navigation">
          {navigation.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={clsx(
                  "flex flex-1 items-center justify-center gap-2 border-b-2 px-3 py-3 text-xs font-semibold",
                  active ? "border-cobalt-400 text-paper" : "border-transparent text-muted",
                )}
              >
                <item.icon className="h-3.5 w-3.5" />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </header>

      {/* Account Details Modal */}
      {walletModalOpen && account ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-canvas/80 p-4 backdrop-blur-md"
          onClick={(e) => {
            if (e.target === e.currentTarget) setWalletModalOpen(false);
          }}
        >
          <div className="panel max-w-md flex-1 rounded-2xl p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-line pb-4">
              <div>
                <h3 className="text-base font-bold text-paper">Connected Web3 Wallet</h3>
                <p className="font-mono text-[10px] text-muted">GenLayer StudioNet Session</p>
              </div>
              <button
                onClick={() => setWalletModalOpen(false)}
                className="text-muted hover:text-paper"
              >
                ✕
              </button>
            </div>

            <div className="mt-5 space-y-4">
              <div className="rounded-xl border border-line bg-canvas/60 p-4">
                <span className="label-caps block">Active Account</span>
                <div className="mt-2 flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-paper">{account}</span>
                  <button
                    onClick={copyAddress}
                    className="flex shrink-0 items-center gap-1 rounded-lg border border-line bg-elevated px-2 py-1 text-[11px] font-semibold text-muted hover:text-paper"
                  >
                    {copied ? <Check className="h-3 w-3 text-mineral" /> : <Copy className="h-3 w-3" />}
                    {copied ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl border border-line bg-canvas/60 p-3 text-center">
                  <span className="label-caps block">Network</span>
                  <span className="mt-1 block font-mono text-xs font-bold text-mineral">StudioNet</span>
                </div>
                <div className="rounded-xl border border-line bg-canvas/60 p-3 text-center">
                  <span className="label-caps block">Execution</span>
                  <span className="mt-1 block font-mono text-xs font-bold text-cyan-300">Gasless (0 GEN)</span>
                </div>
              </div>

              <button
                onClick={switchNetworkMetaMask}
                className="button-secondary w-full justify-center text-xs"
              >
                <ArrowRightLeft className="h-3.5 w-3.5 text-cobalt-300" />
                Switch / Add Network in MetaMask
              </button>

              <button
                onClick={() => {
                  disconnect();
                  setWalletModalOpen(false);
                }}
                className="flex w-full items-center justify-center gap-2 rounded-xl border border-danger/40 bg-danger/10 py-2.5 text-xs font-bold text-danger transition hover:bg-danger hover:text-white"
              >
                <LogOut className="h-3.5 w-3.5" />
                Disconnect Session
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {error ? (
        <div className="mx-auto max-w-[1480px] px-4 pt-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3 rounded-xl border border-danger/40 bg-danger/10 px-4 py-3 text-xs text-danger">
            <span className="text-base">⚠️</span>
            <span>{error}</span>
          </div>
        </div>
      ) : null}

      {children}

      {/* Modern Footer */}
      <footer className="mx-auto mt-28 max-w-[1480px] border-t border-line/80 px-4 py-12 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center justify-between gap-6 sm:flex-row">
          <div className="flex items-center gap-3">
            <div className="grid h-8 w-8 place-items-center rounded-lg border border-cobalt-400/30 bg-cobalt-500/10">
              <ShieldCheck className="h-4 w-4 text-cyan-300" />
            </div>
            <div>
              <span className="block text-xs font-bold text-paper">Compute2Data Protocol</span>
              <span className="font-mono text-[10px] text-muted">Secured by GenLayer Optimistic Democracy</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 font-mono text-[11px] text-muted">
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-mineral" /> 100% Zero Raw Data Exposure
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> Multi-LLM Quorum
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-cobalt-400" /> Automated Escrow
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
