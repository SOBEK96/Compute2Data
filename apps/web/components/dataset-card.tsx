import clsx from "clsx";
import {
  ArrowUpRight,
  Boxes,
  CircleCheck,
  Database,
  LockKeyhole,
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
      className="panel group relative flex min-h-[392px] animate-soft-rise flex-col overflow-hidden rounded-2xl transition duration-300 hover:-translate-y-1 hover:border-cobalt-400/50"
      style={{ animationDelay: `${Math.min(index * 55, 275)}ms` }}
    >
      <div className="proof-rail" />
      <div className="flex items-start justify-between gap-4 px-5 pt-5">
        <div className="grid h-11 w-11 place-items-center rounded-xl border border-line bg-elevated text-cobalt-300">
          <Database className="h-5 w-5" strokeWidth={1.6} />
        </div>
        <div className="flex items-center gap-2">
          {dataset.live ? (
            <span className="rounded-full border border-mineral/30 bg-mineral/10 px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-mineral">
              On-chain
            </span>
          ) : null}
          <span className="rounded-full border border-line bg-canvas/50 px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-muted">
            {dataset.category}
          </span>
        </div>
      </div>

      <div className="flex flex-1 flex-col px-5 pb-5 pt-5">
        <div className="mb-3 flex items-center gap-2 text-xs text-muted">
          <span>{dataset.providerName}</span>
          {dataset.verified ? (
            <CircleCheck className="h-3.5 w-3.5 text-mineral" aria-label="Bonded provider" />
          ) : null}
        </div>
        <h2 className="text-xl font-extrabold leading-tight tracking-[-0.035em] text-paper">
          {dataset.name}
        </h2>
        <p className="mt-3 line-clamp-3 text-sm leading-6 text-muted">
          {dataset.description}
        </p>

        <div className="mt-5 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line">
          <div className="bg-canvas/75 p-3">
            <span className="label-caps block">Surface</span>
            <span className="mt-1.5 block text-xs font-semibold text-paper">
              {dataset.format} / {dataset.scale}
            </span>
          </div>
          <div className="bg-canvas/75 p-3">
            <span className="label-caps block">Provider bond</span>
            <span className="mt-1.5 block text-xs font-semibold text-mineral">
              {dataset.bondLabel}
            </span>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-1.5">
          {dataset.tags.map((tag) => (
            <span
              key={tag}
              className="rounded-md bg-elevated px-2 py-1 font-mono text-[9px] text-muted"
            >
              {tag}
            </span>
          ))}
        </div>

        <div className="mt-auto pt-6">
          <div className="mb-4 flex items-end justify-between border-t border-line pt-4">
            <div>
              <span className="label-caps block">Compute price</span>
              <strong className="mt-1 block text-lg tracking-[-0.025em] text-paper">
                {dataset.priceLabel}
              </strong>
            </div>
            <div className="text-right font-mono text-[10px] text-muted">
              <span className="flex items-center gap-1.5">
                <Boxes className="h-3 w-3" /> {dataset.totalJobs} jobs
              </span>
              <span className="mt-1 flex items-center gap-1.5 text-mineral">
                <LockKeyhole className="h-3 w-3" /> Proof-gated
              </span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onCompute(dataset)}
            className={clsx(
              "flex w-full items-center justify-between rounded-xl border border-line bg-elevated px-4 py-3 text-sm font-bold text-paper transition",
              "group-hover:border-cobalt-400/60 group-hover:bg-cobalt-500 group-hover:text-white",
            )}
          >
            Configure compute
            <ArrowUpRight className="h-4 w-4" />
          </button>
          <span className="mt-3 block truncate font-mono text-[9px] text-muted/70">
            {shortAddress(dataset.provider)} / {dataset.dataCommitment}
          </span>
        </div>
      </div>
    </article>
  );
}
