"use client";

import clsx from "clsx";
import {
  Activity,
  ArrowDown,
  ArrowRight,
  Boxes,
  Cpu,
  Database,
  DatabaseZap,
  Filter,
  Flame,
  Layers,
  Lock,
  LockKeyhole,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  TrendingUp,
  X,
  Zap,
} from "lucide-react";
import { useDeferredValue, useEffect, useState } from "react";

import { isContractConfigured, readDatasets } from "@/lib/contract";
import {
  categoryOptions,
  demoDatasets,
  toMarketplaceDataset,
  type MarketplaceDataset,
} from "@/lib/market-data";

import { ComputeRequestModal } from "./compute-request-modal";
import { DatasetCard } from "./dataset-card";

export function MarketplaceDiscovery() {
  const [datasets, setDatasets] = useState<MarketplaceDataset[]>(demoDatasets);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<(typeof categoryOptions)[number]>("All datasets");
  const [sortBy, setSortBy] = useState<"featured" | "price_asc" | "price_desc" | "jobs">("featured");
  const [selectedDataset, setSelectedDataset] = useState<MarketplaceDataset | null>(null);
  const [loadState, setLoadState] = useState<"idle" | "loading" | "live" | "error">(
    isContractConfigured ? "loading" : "idle",
  );

  const deferredQuery = useDeferredValue(query.trim().toLowerCase());

  useEffect(() => {
    if (!isContractConfigured) return;
    let active = true;
    readDatasets()
      .then((result) => {
        if (!active) return;
        if (result.length > 0) {
          const liveMapped = result.map(toMarketplaceDataset);
          // Combine live with curated demo datasets for maximum richness
          const combined = [
            ...liveMapped,
            ...demoDatasets.filter((d) => !liveMapped.some((l) => l.id === d.id)),
          ];
          setDatasets(combined);
        } else {
          setDatasets(demoDatasets);
        }
        setLoadState("live");
      })
      .catch((err) => {
        console.warn("Read datasets failed, using fallback:", err);
        if (!active) return;
        setDatasets(demoDatasets);
        setLoadState("error");
      });
    return () => {
      active = false;
    };
  }, []);

  const filteredDatasets = datasets
    .filter((dataset) => {
      const matchesCategory = category === "All datasets" || dataset.category === category;
      const haystack = `${dataset.name} ${dataset.description} ${dataset.providerName} ${dataset.tags.join(" ")}`.toLowerCase();
      return matchesCategory && (!deferredQuery || haystack.includes(deferredQuery));
    })
    .sort((a, b) => {
      if (sortBy === "price_asc") return Number(a.priceWei - b.priceWei);
      if (sortBy === "price_desc") return Number(b.priceWei - a.priceWei);
      if (sortBy === "jobs") return b.totalJobs - a.totalJobs;
      return 0; // featured default
    });

  return (
    <main className="space-y-16 pb-24">
      {/* Hero Section with Ambient Glow and Cyber Mesh */}
      <section className="relative overflow-hidden pt-12 sm:pt-20">
        <div className="mx-auto grid max-w-[1480px] gap-12 px-4 sm:px-6 lg:grid-cols-[minmax(0,1fr)_440px] lg:px-8">
          <div className="max-w-4xl space-y-8">
            <div className="flex flex-wrap items-center gap-3">
              <span className="inline-flex items-center gap-2 rounded-full border border-cobalt-400/40 bg-gradient-to-r from-cobalt-500/20 to-cyan-500/10 px-3.5 py-1.5 font-mono text-[11px] font-bold uppercase tracking-[0.14em] text-cyan-300 shadow-glow">
                <Sparkles className="h-3.5 w-3.5 text-cyan-400" /> Compute-to-Data 2.0
              </span>
              <span className="rounded-full border border-line bg-carbon/80 px-3 py-1 font-mono text-[10px] text-muted">
                {loadState === "live"
                  ? "Connected to StudioNet Contract"
                  : loadState === "loading"
                    ? "Reading On-Chain Index..."
                    : "Live Protocol Ready"}
              </span>
            </div>

            <div className="space-y-4">
              <h1 className="text-5xl font-extrabold leading-[0.96] tracking-[-0.055em] text-paper sm:text-7xl lg:text-[80px]">
                Private Data.
                <span className="block bg-gradient-to-r from-cobalt-300 via-cyan-300 to-mineral bg-clip-text text-transparent">
                  Provable Intelligence.
                </span>
              </h1>
              <p className="max-w-2xl text-base leading-relaxed text-muted sm:text-lg">
                Discover high-value private datasets and execute AI training or inference directly within secure enclaves. Funds remain protected in escrow until GenLayer's Multi-LLM consensus validates the execution proof.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-4 pt-2">
              <a href="#datasets" className="button-primary px-6 py-3.5 text-sm">
                Explore Bonded Datasets
                <ArrowDown className="h-4 w-4" />
              </a>
              <a href="/provider" className="button-secondary px-6 py-3.5 text-sm">
                Provider Staking Console
                <ArrowRight className="h-4 w-4 text-cyan-400" />
              </a>
            </div>

            {/* Micro Feature Pillars */}
            <div className="grid grid-cols-2 gap-4 pt-4 sm:grid-cols-3">
              <div className="stat-card">
                <div className="flex items-center gap-2 text-cyan-300">
                  <Lock className="h-4 w-4" />
                  <span className="label-caps text-cyan-300">Zero Custody</span>
                </div>
                <p className="mt-2 text-xs leading-5 text-muted">Raw datasets never leave provider enclaves</p>
              </div>

              <div className="stat-card">
                <div className="flex items-center gap-2 text-mineral">
                  <Cpu className="h-4 w-4" />
                  <span className="label-caps text-mineral">Multi-LLM Quorum</span>
                </div>
                <p className="mt-2 text-xs leading-5 text-muted">Independent AI nodes verify output proofs</p>
              </div>

              <div className="stat-card col-span-2 sm:col-span-1">
                <div className="flex items-center gap-2 text-ember">
                  <Zap className="h-4 w-4" />
                  <span className="label-caps text-ember">Auto Settlement</span>
                </div>
                <p className="mt-2 text-xs leading-5 text-muted">Instant escrow release or automatic slash</p>
              </div>
            </div>
          </div>

          {/* Interactive Protocol Live Hub Card */}
          <div className="panel relative flex flex-col justify-between overflow-hidden rounded-3xl p-7 shadow-2xl lg:self-stretch">
            <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-cobalt-500 via-cyan-400 to-mineral" />
            
            <div>
              <div className="flex items-center justify-between border-b border-line pb-4">
                <div>
                  <span className="label-caps text-cyan-300">Consensus Engine</span>
                  <h3 className="mt-1 text-lg font-extrabold text-paper">GenLayer StudioNet</h3>
                </div>
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-mineral/30 bg-mineral/10 text-mineral">
                  <Activity className="h-5 w-5 animate-pulse" />
                </div>
              </div>

              <div className="mt-6 space-y-4">
                <div className="rounded-2xl border border-line bg-canvas/70 p-4">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted">Total Bonded Collateral</span>
                    <span className="font-mono font-bold text-mineral">75.0 GEN</span>
                  </div>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-line">
                    <div className="h-full w-4/5 rounded-full bg-gradient-to-r from-cobalt-400 to-mineral" />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-2xl border border-line bg-canvas/70 p-3.5">
                    <span className="label-caps block">Active Surfaces</span>
                    <strong className="mt-1 block font-mono text-xl text-paper">
                      {datasets.length} Datasets
                    </strong>
                  </div>
                  <div className="rounded-2xl border border-line bg-canvas/70 p-3.5">
                    <span className="label-caps block">Slashing Rate</span>
                    <strong className="mt-1 block font-mono text-xl text-danger">
                      0.0% Clean
                    </strong>
                  </div>
                </div>

                <div className="rounded-2xl border border-line bg-canvas/70 p-4">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-cyan-300" />
                    <span className="text-xs font-bold text-paper">Consensus Equivalence Matrix</span>
                  </div>
                  <p className="mt-2 font-mono text-[11px] leading-relaxed text-muted">
                    Leader & validators independently re-evaluate execution commitments. If proof deviates, collateral is slashed and escrow refunded.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-6 border-t border-line pt-4 font-mono text-[10px] text-muted">
              <span className="flex items-center justify-between">
                <span>Network Protocol:</span>
                <span className="text-cyan-300">Gasless EVM + Python GenVM</span>
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* Dataset Discovery & Filter Section */}
      <section id="datasets" className="mx-auto max-w-[1480px] px-4 sm:px-6 lg:px-8">
        <div className="panel rounded-3xl p-6 sm:p-8">
          <div className="flex flex-col gap-6 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <span className="label-caps text-cyan-400">Curated Data Surfaces</span>
              <h2 className="mt-1 text-3xl font-extrabold tracking-[-0.04em] text-paper sm:text-4xl">
                Explore Private Datasets
              </h2>
            </div>

            {/* Filter Controls */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <div className="relative min-w-0 sm:w-80">
                <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search name, tags, provider..."
                  className="field pl-10 pr-10"
                />
                {query ? (
                  <button
                    type="button"
                    onClick={() => setQuery("")}
                    aria-label="Clear search"
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-muted hover:text-paper"
                  >
                    <X className="h-4 w-4" />
                  </button>
                ) : null}
              </div>

              <div className="relative sm:w-56">
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as any)}
                  className="field appearance-none pl-3.5 pr-8 font-mono text-xs"
                >
                  <option value="featured">Sort: Featured</option>
                  <option value="price_asc">Price: Low to High</option>
                  <option value="price_desc">Price: High to Low</option>
                  <option value="jobs">Most Popular (Jobs)</option>
                </select>
              </div>
            </div>
          </div>

          {/* Category Chip Tabs */}
          <div className="mt-8 flex items-center gap-2 overflow-x-auto border-t border-line/80 pb-1 pt-6">
            {categoryOptions.map((opt) => {
              const active = category === opt;
              const count =
                opt === "All datasets"
                  ? datasets.length
                  : datasets.filter((d) => d.category === opt).length;

              return (
                <button
                  key={opt}
                  onClick={() => setCategory(opt)}
                  className={clsx(
                    "flex shrink-0 items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold transition duration-200",
                    active
                      ? "border border-cobalt-400/50 bg-cobalt-500 text-white shadow-cobalt"
                      : "border border-line bg-elevated/60 text-muted hover:border-line-bright hover:bg-elevated hover:text-paper",
                  )}
                >
                  <span>{opt}</span>
                  <span
                    className={clsx(
                      "rounded-md px-1.5 py-0.5 font-mono text-[10px]",
                      active ? "bg-white/20 text-white" : "bg-carbon text-muted",
                    )}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="flex items-center justify-between pt-6">
            <span className="font-mono text-[11px] text-muted">
              Showing <strong className="text-paper">{filteredDatasets.length}</strong> bonded data surfaces
            </span>
            <div className="flex items-center gap-2 font-mono text-[11px] text-mineral">
              <span className="h-2 w-2 rounded-full bg-mineral animate-ping" />
              Proof verification ready
            </div>
          </div>

          {/* Dataset Cards Grid */}
          <div className="mt-6">
            {filteredDatasets.length > 0 ? (
              <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
                {filteredDatasets.map((dataset, index) => (
                  <DatasetCard
                    key={dataset.id}
                    dataset={dataset}
                    index={index}
                    onCompute={setSelectedDataset}
                  />
                ))}
              </div>
            ) : (
              <div className="rounded-2xl border border-line bg-carbon/50 py-16 text-center">
                <Search className="mx-auto h-8 w-8 text-muted/60" />
                <h3 className="mt-4 text-lg font-bold text-paper">No data surfaces found</h3>
                <p className="mt-1 text-xs text-muted">Try changing your search terms or category filter.</p>
                <button
                  onClick={() => {
                    setQuery("");
                    setCategory("All datasets");
                  }}
                  className="button-secondary mt-6 text-xs"
                >
                  Reset Filters
                </button>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Compute Request Modal */}
      <ComputeRequestModal
        dataset={selectedDataset}
        onClose={() => setSelectedDataset(null)}
      />
    </main>
  );
}
