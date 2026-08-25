"use client";

import {
  ArrowRight,
  CheckCircle2,
  Cpu,
  LoaderCircle,
  LockKeyhole,
  ShieldCheck,
  X,
} from "lucide-react";
import { useEffect, useId, useState, type FormEvent } from "react";

import { isContractConfigured, requestCompute } from "@/lib/contract";
import type { MarketplaceDataset } from "@/lib/market-data";

import { useWallet } from "./wallet-provider";

type ComputeRequestModalProps = {
  dataset: MarketplaceDataset | null;
  onClose: () => void;
};

type SubmissionState =
  | { phase: "idle" }
  | { phase: "pending"; message: string }
  | { phase: "success"; hash: string }
  | { phase: "error"; message: string };

export function ComputeRequestModal({ dataset, onClose }: ComputeRequestModalProps) {
  const titleId = useId();
  const { account, connect } = useWallet();
  const [jobId, setJobId] = useState("");
  const [modelId, setModelId] = useState("hf://compute2data/forecast-base-v2");
  const [computeSpec, setComputeSpec] = useState(
    "Train for 12 epochs. Return aggregate evaluation metrics and an output artifact commitment.",
  );
  const [inputCommitment, setInputCommitment] = useState("sha256:");
  const [submission, setSubmission] = useState<SubmissionState>({ phase: "idle" });

  useEffect(() => {
    if (!dataset) return;
    setJobId(`job-${dataset.id}-${Date.now().toString(36)}`);
    setSubmission({ phase: "idle" });
  }, [dataset]);

  useEffect(() => {
    if (!dataset) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && submission.phase !== "pending") onClose();
    };
    document.addEventListener("keydown", handleKeyDown);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "";
    };
  }, [dataset, onClose, submission.phase]);

  if (!dataset) return null;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!dataset) return;

    if (!isContractConfigured) {
      setSubmission({
        phase: "error",
        message:
          "Live transactions are disabled in demo mode. Configure NEXT_PUBLIC_C2D_CONTRACT_ADDRESS.",
      });
      return;
    }

    const signer = account ?? (await connect());
    if (!signer) return;

    setSubmission({ phase: "pending", message: "Waiting for wallet signature" });
    try {
      const hash = await requestCompute(signer, {
        jobId,
        datasetId: dataset.id,
        modelId,
        computeSpec,
        inputCommitment,
        price: dataset.priceWei,
      });
      setSubmission({ phase: "success", hash });
    } catch (caught) {
      setSubmission({
        phase: "error",
        message: caught instanceof Error ? caught.message : "Compute request failed.",
      });
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-end justify-center bg-canvas/85 p-0 backdrop-blur-xl sm:items-center sm:p-5"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && submission.phase !== "pending") onClose();
      }}
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="panel-raised max-h-[94vh] w-full max-w-3xl overflow-y-auto rounded-t-2xl sm:rounded-2xl"
      >
        <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-line bg-elevated/95 px-5 py-5 backdrop-blur-xl sm:px-7">
          <div>
            <span className="label-caps text-cobalt-300">Escrowed workload</span>
            <h2 id={titleId} className="mt-2 text-2xl font-extrabold tracking-[-0.04em]">
              Request private compute
            </h2>
            <p className="mt-2 text-sm text-muted">{dataset.name}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={submission.phase === "pending"}
            className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-line text-muted transition hover:bg-carbon hover:text-paper disabled:opacity-40"
            aria-label="Close compute request"
          >
            <X className="h-4 w-4" />
          </button>
        </header>

        {submission.phase === "success" ? (
          <div className="px-5 py-14 text-center sm:px-8">
            <span className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-mineral/30 bg-mineral/10 text-mineral">
              <CheckCircle2 className="h-7 w-7" />
            </span>
            <h3 className="mt-6 text-2xl font-extrabold tracking-[-0.035em]">
              Compute request accepted
            </h3>
            <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-muted">
              Payment is escrowed. The provider receives funds only after GenLayer
              consensus validates its execution proof.
            </p>
            <div className="mx-auto mt-6 max-w-lg rounded-xl border border-line bg-canvas/70 px-4 py-3 text-left font-mono text-[10px] text-muted">
              <span className="block uppercase tracking-[0.14em]">Transaction</span>
              <span className="mt-2 block break-all text-paper">{submission.hash}</span>
            </div>
            <button type="button" onClick={onClose} className="button-primary mt-7">
              Return to marketplace
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="grid gap-7 px-5 py-6 sm:px-7">
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-xl border border-line bg-canvas/55 p-4">
                <LockKeyhole className="h-4 w-4 text-cobalt-300" />
                <span className="label-caps mt-3 block">Raw data</span>
                <strong className="mt-1 block text-sm">Never transferred</strong>
              </div>
              <div className="rounded-xl border border-line bg-canvas/55 p-4">
                <Cpu className="h-4 w-4 text-ember" />
                <span className="label-caps mt-3 block">Job escrow</span>
                <strong className="mt-1 block text-sm">{dataset.priceLabel}</strong>
              </div>
              <div className="rounded-xl border border-line bg-canvas/55 p-4">
                <ShieldCheck className="h-4 w-4 text-mineral" />
                <span className="label-caps mt-3 block">Provider bond</span>
                <strong className="mt-1 block text-sm">{dataset.bondLabel}</strong>
              </div>
            </div>

            <div className="grid gap-5 sm:grid-cols-2">
              <label className="grid gap-2">
                <span className="label-caps">Job ID</span>
                <input
                  className="field font-mono text-xs"
                  value={jobId}
                  onChange={(event) => setJobId(event.target.value)}
                  required
                  maxLength={96}
                />
              </label>
              <label className="grid gap-2">
                <span className="label-caps">Model ID or URI</span>
                <input
                  className="field font-mono text-xs"
                  value={modelId}
                  onChange={(event) => setModelId(event.target.value)}
                  required
                  maxLength={256}
                />
              </label>
            </div>

            <label className="grid gap-2">
              <span className="label-caps">Compute specification</span>
              <textarea
                className="field min-h-32 resize-y leading-6"
                value={computeSpec}
                onChange={(event) => setComputeSpec(event.target.value)}
                required
                maxLength={8192}
              />
              <span className="text-xs text-muted">
                Define exact completion criteria. Validators compare the proof against this text.
              </span>
            </label>

            <label className="grid gap-2">
              <span className="label-caps">Input commitment</span>
              <input
                className="field font-mono text-xs"
                value={inputCommitment}
                onChange={(event) => setInputCommitment(event.target.value)}
                required
                maxLength={256}
              />
            </label>

            {submission.phase === "error" ? (
              <div className="rounded-xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
                {submission.message}
              </div>
            ) : null}

            <div className="flex flex-col-reverse gap-3 border-t border-line pt-5 sm:flex-row sm:items-center sm:justify-between">
              <p className="max-w-sm text-xs leading-5 text-muted">
                Invalid or malicious proof consensus refunds your escrow and pays the slashed collateral to your wallet.
              </p>
              <button
                type="submit"
                disabled={submission.phase === "pending"}
                className="button-primary min-w-48"
              >
                {submission.phase === "pending" ? (
                  <>
                    <LoaderCircle className="h-4 w-4 animate-spin" />
                    {submission.message}
                  </>
                ) : (
                  <>
                    Fund compute
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
