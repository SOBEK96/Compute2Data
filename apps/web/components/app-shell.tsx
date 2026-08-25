"use client";

import clsx from "clsx";
import {
  Blocks,
  ChevronDown,
  CircleDot,
  LayoutGrid,
  ShieldCheck,
  Wallet,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

import { isContractConfigured, networkName } from "@/lib/contract";
import { shortAddress } from "@/lib/market-data";

import { useWallet } from "./wallet-provider";

const navigation = [
  { href: "/", label: "Marketplace", icon: LayoutGrid },
  { href: "/provider", label: "Provider console", icon: Blocks },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { account, status, error, connect, disconnect } = useWallet();

  return (
    <div className="min-h-screen bg-hero-glow">
      <header className="sticky top-0 z-40 border-b border-line/80 bg-canvas/80 backdrop-blur-2xl">
        <div className="mx-auto flex h-[72px] max-w-[1480px] items-center gap-6 px-4 sm:px-6 lg:px-8">
          <Link href="/" className="group flex shrink-0 items-center gap-3">
            <span className="relative grid h-9 w-9 place-items-center overflow-hidden border border-cobalt-400/50 bg-cobalt-500/10">
              <span className="absolute inset-x-1 top-2 h-px bg-mineral/80" />
              <span className="absolute inset-x-1 bottom-2 h-px bg-cobalt-400/80" />
              <ShieldCheck className="relative h-4 w-4 text-paper" />
            </span>
            <span>
              <span className="block text-sm font-extrabold tracking-[-0.02em] text-paper">
                Compute2Data
              </span>
              <span className="block font-mono text-[9px] uppercase tracking-[0.16em] text-muted">
                Verifiable AI market
              </span>
            </span>
          </Link>

          <nav className="hidden items-center gap-1 md:flex" aria-label="Main navigation">
            {navigation.map((item) => {
              const active =
                item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={clsx(
                    "flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition",
                    active
                      ? "bg-elevated text-paper"
                      : "text-muted hover:bg-elevated/50 hover:text-paper",
                  )}
                >
                  <item.icon className="h-3.5 w-3.5" />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto hidden items-center gap-2 lg:flex">
            <span className="flex items-center gap-2 rounded-lg border border-line bg-carbon/75 px-3 py-2 font-mono text-[10px] text-muted">
              <CircleDot
                className={clsx(
                  "h-3 w-3",
                  isContractConfigured ? "text-mineral" : "text-ember",
                )}
              />
              {isContractConfigured ? networkName : "Demo data mode"}
            </span>
          </div>

          {account ? (
            <button
              type="button"
              onClick={disconnect}
              className="flex shrink-0 items-center gap-2 rounded-xl border border-line bg-elevated px-3 py-2.5 text-xs font-bold text-paper transition hover:border-cobalt-400/60"
              title="Disconnect wallet from this interface"
            >
              <span className="h-2 w-2 rounded-full bg-mineral shadow-[0_0_10px_rgba(130,235,197,0.7)]" />
              <span className="hidden sm:inline">{shortAddress(account)}</span>
              <ChevronDown className="h-3.5 w-3.5 text-muted" />
            </button>
          ) : (
            <button
              type="button"
              onClick={() => void connect()}
              disabled={status === "connecting"}
              className="button-primary shrink-0 py-2.5"
            >
              <Wallet className="h-4 w-4" />
              <span className="hidden sm:inline">
                {status === "connecting" ? "Connecting" : "Connect wallet"}
              </span>
            </button>
          )}
        </div>

        <nav className="flex border-t border-line/60 px-3 md:hidden" aria-label="Mobile navigation">
          {navigation.map((item) => {
            const active =
              item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={clsx(
                  "flex flex-1 items-center justify-center gap-2 border-b-2 px-3 py-3 text-xs font-semibold",
                  active
                    ? "border-cobalt-400 text-paper"
                    : "border-transparent text-muted",
                )}
              >
                <item.icon className="h-3.5 w-3.5" />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </header>

      {error ? (
        <div className="mx-auto max-w-[1480px] px-4 pt-4 sm:px-6 lg:px-8">
          <div className="border border-danger/30 bg-danger/10 px-4 py-3 text-xs text-danger">
            {error}
          </div>
        </div>
      ) : null}

      {children}

      <footer className="mx-auto mt-24 max-w-[1480px] border-t border-line px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex flex-col justify-between gap-4 font-mono text-[10px] uppercase tracking-[0.14em] text-muted sm:flex-row">
          <span>Private data remains with its provider</span>
          <span>Settlement secured by GenLayer AI consensus</span>
        </div>
      </footer>
    </div>
  );
}
