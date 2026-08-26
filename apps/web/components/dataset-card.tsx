import clsx from "clsx";
import {
  ArrowUpRight,
  Boxes,
  CheckCircle2,
  Cpu,
  Database,
  Fingerprint,
  LockKeyhole,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

import type { MarketplaceDataset } from "@/lib/market-data";
import { shortAddress } from "@/lib/market-data";

type DatasetCardProps = {
  dataset: MarketplaceDataset;
  index: number;
  onCompute: (dataset: MarketplaceDataset) => void;
};

export function DatasetCard({ dataset, index, onCompute }: DatasetCardProps) {
  return (
    <article
      className="panel group relative flex min-h-[440px] animate-soft-rise flex-col overflow-hidden rounded-3xl transition-all duration-300 hover:-translate-y-1.5 hover:border-cobalt-400/60 hover:shadow-glow"
      style={{ animationDelay: `${Math.min(index * 60, 300)}ms` }}
    >
      <div className="proof-rail" />

      {/* Card Header */}
      <div className="flex items-start justify-between gap-4 px-6 pt-6">
        <div className="relative grid h-12 w-12 place-items-center rounded-2xl border border-line bg-gradient-to-br from-elevated to-carbon text-cyan-300 shadow-card transition duration-300 group-hover:scale-105 group-hover:border-cyan-400/50">
          <Database className="h-5 w-5" strokeWidth={1.8} />
          {dataset.live ? (
            <span className="absolute -right-1 -top-1 flex h-3 w-3">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-mineral opacity-75" />
              <span className="relative inline-flex h-3 w-3 rounded-full bg-mineral border-2 border-carbon" />
            </span>
          ) : null}
        </div>

        <div className="flex items-center gap-2">
          {dataset.live ? (
            <span className="chip-badge border border-mineral/40 bg-mineral/10 text-mineral">
              On-Chain
            </span>
          ) : null}
          <span className="chip-badge border border-line bg-canvas/60 text-muted">
            {dataset.category}
          </span>
        </div>
      </div>

      {/* Card Body */}
      <div className="flex flex-1 flex-col px-6 pb-6 pt-5">
        <div className="mb-2.5 flex items-center gap-2 text-xs text-muted">
          <span className="font-mono text-[11px] text-paper/80">{dataset.providerName}</span>
          {dataset.verified ? (
            <span className="flex items-center gap-1 text-[10px] font-semibold text-mineral" title="Verified & Bonded Provider">
              <CheckCircle2 className="h-3.5 w-3.5" /> Bonded
            </span>
          ) : null}
        </div>

        <h3 className="text-xl font-extrabold leading-snug tracking-[-0.03em] text-paper transition duration-200 group-hover:text-cyan-300">
          {dataset.name}
        </h3>

        <p className="mt-2.5 line-clamp-3 text-xs leading-relaxed text-muted">
          {dataset.description}
        </p>

        {/* Dataset Metadata Matrix */}
        <div className="mt-5 grid grid-cols-2 gap-2 rounded-2xl border border-line bg-canvas/60 p-3">
          <div>
            <span className="label-caps block text-[9px]">Schema / Scale</span>
            <span className="mt-1 block truncate font-mono text-xs font-semibold text-paper">
              {dataset.format} • {dataset.scale}
            </span>
          </div>
          <div>
            <span className="label-caps block text-[9px]">Provider Bond</span>
            <span className="mt-1 block font-mono text-xs font-bold text-mineral">
              {dataset.bondLabel}
            </span>
          </div>
        </div>

        {/* Tags */}
        <div className="mt-3.5 flex flex-wrap gap-1.5">
          {dataset.tags.slice(0, 3).map((tag) => (
            <span
              key={tag}
              className="rounded-lg border border-line/60 bg-elevated/70 px-2 py-1 font-mono text-[10px] text-muted"
            >
              #{tag}
            </span>
          ))}
        </div>

        {/* Footer Actions */}
        <div className="mt-auto pt-6">
          <div className="mb-4 flex items-end justify-between border-t border-line/80 pt-4">
            <div>
              <span className="label-caps block text-[9px] text-muted">Compute Fee</span>
              <strong className="mt-0.5 block font-mono text-lg font-extrabold text-paper">
                {dataset.priceLabel}
              </strong>
            </div>
            <div className="text-right font-mono text-[10px] text-muted">
              <span className="flex items-center justify-end gap-1.5">
                <Boxes className="h-3 w-3 text-cobalt-400" /> {dataset.totalJobs} jobs run
              </span>
              <span className="mt-0.5 flex items-center justify-end gap-1 text-mineral">
                <LockKeyhole className="h-3 w-3" /> Proof-gated Escrow
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => onCompute(dataset)}
            className="flex w-full items-center justify-between rounded-xl border border-line-bright/60 bg-elevated px-4 py-3 text-xs font-bold text-paper shadow-card transition-all duration-300 group-hover:border-cobalt-400 group-hover:bg-gradient-to-r group-hover:from-cobalt-500 group-hover:to-cyan-500 group-hover:text-white group-hover:shadow-cobalt"
          >
            <span>Configure Compute Job</span>
            <ArrowUpRight className="h-4 w-4 transition duration-200 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </button>

          <div className="mt-2.5 flex items-center justify-between font-mono text-[9px] text-muted/60">
            <span className="truncate">Provider: {shortAddress(dataset.provider)}</span>
            <span className="truncate max-w-[120px]" title={dataset.dataCommitment}>
              {dataset.dataCommitment.slice(0, 14)}...
            </span>
          </div>
        </div>
      </div>
    </article>
  );
}
