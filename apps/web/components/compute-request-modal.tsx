"use client";

import clsx from "clsx";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Database,
  ExternalLink,
  Fingerprint,
  Info,
  Loader2,
  Lock,
  ShieldCheck,
  Sparkles,
  X,
  Zap,
} from "lucide-react";
import { useState, type FormEvent } from "react";

import { requestCompute } from "@/lib/contract";
import type { MarketplaceDataset } from "@/lib/market-data";
import { shortAddress } from "@/lib/market-data";

import { useWallet } from "./wallet-provider";

type ComputeRequestModalProps = {
  dataset: MarketplaceDataset | null;
  onClose: () => void;
};

export function ComputeRequestModal({ dataset, onClose }: ComputeRequestModalProps) {
  const { account, connect } = useWallet();
  const [modelId, setModelId] = useState("hf://deep-transformer-oncology-v4");
  const [computeSpec, setComputeSpec] = useState(
    "Train Cox Proportional Hazards model with L1 penalty across 33 tumor types; output validation C-index and model weights commitment.",
  );
  const [inputCommitment, setInputCommitment] = useState(
    "sha256:input-hyperparams-l1-0.05-epochs25",
  );
  const [phase, setPhase] = useState<"idle" | "submitting" | "success" | "error">("idle");
  const [txHash, setTxHash] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!dataset) return null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!account) {
      const connected = await connect();
      if (!connected) return;
    }

    setPhase("submitting");
    setErrorMessage(null);

    try {
      const generatedJobId = `job-${dataset.id}-${Date.now().toString(36)}`;
      const hash = await requestCompute(account!, {
        jobId: generatedJobId,
        datasetId: dataset.id,
        modelId: modelId.trim(),
        computeSpec: computeSpec.trim(),
        inputCommitment: inputCommitment.trim(),
        price: dataset.priceWei,
      });

      setTxHash(hash);
      setPhase("success");
    } catch (err: any) {
      console.error("Compute request error:", err);
      setPhase("error");
      setErrorMessage(err.message || "Failed to submit on-chain compute request.");
    }
  };

  const generateRandomHash = () => {
    const chars = "0123456789abcdef";
    let hash = "sha256:";
    for (let i = 0; i < 32; i++) {
      hash += chars[Math.floor(Math.random() * chars.length)];
    }
    setInputCommitment(hash);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-canvas/85 p-4 backdrop-blur-xl animate-soft-rise"
      onClick={(e) => {
        if (e.target === e.currentTarget && phase !== "submitting") onClose();
      }}
    >
      <div className="panel relative max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-3xl p-6 sm:p-8 shadow-2xl">
        <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-cobalt-500 via-cyan-400 to-mineral" />

        {/* Modal Header */}
        <div className="flex items-start justify-between border-b border-line pb-5">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl border border-cobalt-400/40 bg-cobalt-500/10 text-cyan-300">
              <Cpu className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-extrabold text-paper">Configure Compute Job</h2>
                <span className="chip-badge border border-mineral/40 bg-mineral/10 text-mineral">
                  Proof-Gated Escrow
                </span>
              </div>
              <p className="font-mono text-xs text-muted">
                Target: <strong className="text-paper">{dataset.name}</strong> ({shortAddress(dataset.provider)})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={phase === "submitting"}
            className="rounded-xl border border-line bg-elevated/60 p-2 text-muted hover:border-line-bright hover:text-paper disabled:opacity-50"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Success State */}
        {phase === "success" ? (
          <div className="space-y-6 py-8 text-center">
            <div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-mineral/40 bg-mineral/10 text-mineral shadow-glow">
              <CheckCircle2 className="h-8 w-8" />
            </div>

            <div className="space-y-2">
              <h3 className="text-2xl font-extrabold text-paper">Compute Job Escrowed On-Chain!</h3>
              <p className="mx-auto max-w-md text-xs leading-relaxed text-muted">
                Your compute request has been committed on GenLayer StudioNet. Escrowed GEN is locked until the provider submits an SGX enclave execution proof and AI validators confirm validity.
              </p>
            </div>

            {txHash ? (
              <div className="mx-auto max-w-md rounded-2xl border border-line bg-canvas/70 p-4 font-mono text-xs">
                <span className="label-caps block">Transaction Hash</span>
                <span className="mt-1 block truncate text-cyan-300">{txHash}</span>
              </div>
            ) : null}

            <div className="flex justify-center gap-3 pt-4">
              <button onClick={onClose} className="button-primary px-8">
                Done & Return to Market
              </button>
            </div>
          </div>
        ) : (
          /* Form Content */
          <form onSubmit={handleSubmit} className="mt-6 space-y-6">
            {/* Step 1: Model Identifier */}
            <div className="space-y-2">
              <label className="label-caps flex items-center justify-between text-xs text-paper">
                <span>1. Model Identifier (URI or Container Hash)</span>
                <span className="font-normal text-muted">Container / HF Model</span>
              </label>
              <input
                value={modelId}
                onChange={(e) => setModelId(e.target.value)}
                placeholder="e.g. hf://deep-survival-coxnet-v3 or docker://enclave/model:1.0"
                className="field font-mono text-xs"
                required
              />
            </div>

            {/* Step 2: Compute Specification */}
            <div className="space-y-2">
              <label className="label-caps flex items-center justify-between text-xs text-paper">
                <span>2. Compute Task Specification</span>
                <span className="font-normal text-muted">Strict execution policy</span>
              </label>
              <textarea
                value={computeSpec}
                onChange={(e) => setComputeSpec(e.target.value)}
                rows={3}
                placeholder="Specify execution rules, training parameters, loss targets, and required proof format..."
                className="field text-xs"
                required
              />
            </div>

            {/* Step 3: Input Commitment */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="label-caps text-xs text-paper">
                  3. Input Cryptographic Commitment
                </label>
                <button
                  type="button"
                  onClick={generateRandomHash}
                  className="flex items-center gap-1 font-mono text-[10px] text-cyan-300 hover:underline"
                >
                  <Sparkles className="h-3 w-3" /> Auto-Generate Hash
                </button>
              </div>
              <input
                value={inputCommitment}
                onChange={(e) => setInputCommitment(e.target.value)}
                placeholder="sha256:..."
                className="field font-mono text-xs"
                required
              />
            </div>

            {/* Escrow Fee Breakdown Card */}
            <div className="rounded-2xl border border-line bg-canvas/60 p-4 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted">Dataset Compute Price:</span>
                <strong className="font-mono text-paper">{dataset.priceLabel}</strong>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted">Network Gas Fee (StudioNet):</span>
                <strong className="font-mono text-mineral">0.00 GEN (Gasless)</strong>
              </div>
              <div className="flex items-center justify-between border-t border-line/80 pt-2 text-xs">
                <span className="font-bold text-paper">Total Escrow Required:</span>
                <strong className="font-mono text-base font-extrabold text-cyan-300">
                  {dataset.priceLabel}
                </strong>
              </div>
            </div>

            {/* Security Guarantee Notice */}
            <div className="flex items-start gap-3 rounded-2xl border border-cobalt-400/30 bg-cobalt-500/10 p-3.5 text-xs text-cobalt-200">
              <ShieldCheck className="h-5 w-5 shrink-0 text-cyan-300" />
              <div className="leading-relaxed">
                <strong>Non-Custodial Guarantee:</strong> Your escrow is locked in the smart contract. If the provider fails to submit proof or submits an invalid output, you will receive a 100% refund.
              </div>
            </div>

            {errorMessage ? (
              <div className="flex items-center gap-2 rounded-xl border border-danger/40 bg-danger/10 p-3 text-xs text-danger">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            ) : null}

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                disabled={phase === "submitting"}
                className="button-secondary text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={phase === "submitting"}
                className="button-cyan px-6 py-3 text-xs"
              >
                {phase === "submitting" ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Executing AI Escrow...</span>
                  </>
                ) : (
                  <>
                    <Lock className="h-4 w-4" />
                    <span>Confirm & Escrow {dataset.priceLabel}</span>
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
