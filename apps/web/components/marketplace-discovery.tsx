"use client";

import clsx from "clsx";
import {
  Activity,
  ArrowDown,
  DatabaseZap,
  Filter,
  Search,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";
import { useDeferredValue, useEffect, useState } from "react";

import { DatasetCard } from "@/components/dataset-card";
import { isContractConfigured, readDatasets } from "@/lib/contract";
import {
  categoryOptions,
  demoDatasets,
  formatGen,
  type MarketplaceDataset,
} from "@/lib/market-data";

import { ComputeRequestModal } from "./compute-request-modal";

function toMarketplaceDataset(
  dataset: Awaited<ReturnType<typeof readDatasets>>[number],
): MarketplaceDataset {
  return {
    id: dataset.datasetId,
    name: dataset.name,
    description: dataset.description,
    provider: dataset.provider,
    providerName: `Provider ${dataset.provider.slice(0, 6)}`,
    category: "Language",
    format: dataset.schema.split(":")[0]?.slice(0, 22) || "Private surface",
    scale: `${dataset.openJobs} open jobs`,
    priceWei: dataset.pricePerJob,
    priceLabel: formatGen(dataset.pricePerJob),
    bondLabel: formatGen(dataset.listingBond),
    dataCommitment: dataset.dataCommitment,
    accessConditions: dataset.accessConditions,
    schema: dataset.schema,
    tags: ["On-chain", "Private", "Bonded"],
    totalJobs: dataset.totalJobs,
    verified: true,
    live: true,
  };
}

export function MarketplaceDiscovery() {
  const [datasets, setDatasets] = useState<MarketplaceDataset[]>(demoDatasets);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<(typeof categoryOptions)[number]>(
    "All datasets",
  );
  const [selectedDataset, setSelectedDataset] = useState<MarketplaceDataset | null>(null);
  const [loadState, setLoadState] = useState<"demo" | "loading" | "live" | "error">(
    isContractConfigured ? "loading" : "demo",
  );
  const deferredQuery = useDeferredValue(query.trim().toLowerCase());

  useEffect(() => {
    if (!isContractConfigured) return;
    let active = true;
    readDatasets()
      .then((result) => {
        if (!active) return;
        setDatasets(result.map(toMarketplaceDataset));
        setLoadState("live");
      })
      .catch(() => {
        if (!active) return;
        setDatasets(demoDatasets);
        setLoadState("error");
      });
    return () => {
      active = false;
    };
  }, []);

  const visibleDatasets = datasets.filter((dataset) => {
    const matchesCategory = category === "All datasets" || dataset.category === category;
    const haystack = `${dataset.name} ${dataset.description} ${dataset.providerName} ${dataset.tags.join(" ")}`.toLowerCase();
    return matchesCategory && (!deferredQuery || haystack.includes(deferredQuery));
  });

  return (
    <main>
      <section className="mx-auto grid max-w-[1480px] gap-12 px-4 pb-14 pt-16 sm:px-6 sm:pt-24 lg:grid-cols-[minmax(0,1fr)_400px] lg:px-8 lg:pb-20">
        <div className="max-w-4xl">
          <div className="mb-7 flex flex-wrap items-center gap-3">
            <span className="inline-flex items-center gap-2 rounded-full border border-cobalt-400/30 bg-cobalt-500/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-cobalt-300">
              <Sparkles className="h-3 w-3" /> Compute without custody
            </span>
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">
              {loadState === "live"
                ? "Live contract index"
                : loadState === "loading"
                  ? "Reading contract index"
                  : loadState === "error"
                    ? "RPC unavailable / showing demo data"
                    : "Demo data / contract not configured"}
            </span>
          </div>
          <h1 className="max-w-4xl text-5xl font-extrabold leading-[0.98] tracking-[-0.055em] text-paper sm:text-7xl lg:text-[84px]">
            Private data.
            <span className="block text-cobalt-300">Provable intelligence.</span>
          </h1>
          <p className="mt-7 max-w-2xl text-base leading-7 text-muted sm:text-lg">
            Discover high-value datasets, run models where the data lives, and settle only after independent AI validators verify the execution proof.
          </p>
          <a href="#datasets" className="button-secondary mt-8 w-fit">
            Explore data surfaces
            <ArrowDown className="h-4 w-4" />
          </a>
        </div>

        <div className="panel relative overflow-hidden rounded-2xl p-6 lg:self-end">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-cobalt-400 via-mineral to-ember" />
          <div className="flex items-center justify-between">
            <span className="label-caps">Settlement fabric</span>
            <Activity className="h-4 w-4 text-mineral" />
          </div>
          <div className="mt-7 grid grid-cols-[auto_1fr_auto] items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-xl bg-cobalt-500/15 text-cobalt-300">
              <DatabaseZap className="h-5 w-5" />
            </span>
            <div className="proof-rail" />
            <span className="grid h-11 w-11 place-items-center rounded-xl bg-mineral/10 text-mineral">
              <ShieldCheck className="h-5 w-5" />
            </span>
          </div>
          <div className="mt-6 grid grid-cols-3 gap-3 text-center">
            <div>
              <strong className="block text-xl">256-bit</strong>
              <span className="label-caps mt-1 block">Commitments</span>
            </div>
            <div>
              <strong className="block text-xl text-mineral">AI</strong>
              <span className="label-caps mt-1 block">Consensus</span>
            </div>
            <div>
              <strong className="block text-xl text-ember">GEN</strong>
              <span className="label-caps mt-1 block">Collateral</span>
            </div>
          </div>
          <p className="mt-6 border-t border-line pt-5 text-xs leading-5 text-muted">
            Provider stake backs every listing and active job. Malicious execution proofs trigger refund and collateral transfer.
          </p>
        </div>
      </section>

      <section id="datasets" className="mx-auto max-w-[1480px] px-4 sm:px-6 lg:px-8">
        <div className="border-y border-line py-7">
          <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <span className="label-caps text-cobalt-300">Marketplace discovery</span>
              <h2 className="mt-2 text-3xl font-extrabold tracking-[-0.04em] sm:text-4xl">
                Data surfaces ready for compute
              </h2>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row">
              <label className="relative min-w-0 sm:w-80">
                <span className="sr-only">Search datasets</span>
                <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search names, tags, providers"
                  className="field pl-10 pr-10"
                />
                {query ? (
                  <button
                    type="button"
                    onClick={() => setQuery("")}
                    aria-label="Clear search"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-paper"
                  >
                    <X className="h-4 w-4" />
                  </button>
                ) : null}
              </label>
              <label className="relative sm:w-48">
                <span className="sr-only">Filter by category</span>
                <Filter className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <select
                  value={category}
                  onChange={(event) =>
                    setCategory(event.target.value as (typeof categoryOptions)[number])
                  }
                  className="field appearance-none pl-10"
                >
                  {categoryOptions.map((option) => (
                    <option key={option}>{option}</option>
                  ))}
                </select>
              </label>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between py-6">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">
            {visibleDatasets.length} bonded datasets
          </span>
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-mineral">
            <span className="h-1.5 w-1.5 rounded-full bg-mineral" />
            Proof validation active
          </div>
        </div>

        {visibleDatasets.length ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {visibleDatasets.map((dataset, index) => (
              <DatasetCard
                key={dataset.id}
                dataset={dataset}
                index={index}
                onCompute={setSelectedDataset}
              />
            ))}
          </div>
        ) : (
          <div className="panel rounded-2xl px-6 py-20 text-center">
            <Search className="mx-auto h-7 w-7 text-muted" />
            <h3 className="mt-5 text-xl font-bold">No matching data surfaces</h3>
            <p className="mt-2 text-sm text-muted">Clear the search or choose another category.</p>
            <button
              type="button"
              onClick={() => {
                setQuery("");
                setCategory("All datasets");
              }}
              className={clsx("button-secondary mt-6")}
            >
              Reset filters
            </button>
          </div>
        )}
      </section>

      <ComputeRequestModal
        dataset={selectedDataset}
        onClose={() => setSelectedDataset(null)}
      />
    </main>
  );
}
