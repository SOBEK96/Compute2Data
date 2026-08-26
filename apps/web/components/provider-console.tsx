"use client";

import clsx from "clsx";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpFromLine,
  Boxes,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Cpu,
  Database,
  ExternalLink,
  FilePlus2,
  Fingerprint,
  Layers,
  Loader2,
  Lock,
  LockKeyhole,
  Plus,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Wallet,
  WalletCards,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import {
  isContractConfigured,
  readProvider,
  readProviderJobs,
  registerDataset,
  stakeProvider,
  submitExecutionProof,
  withdrawProviderStake,
  type ContractJob,
  type ProviderState,
} from "@/lib/contract";
import { formatGen, parseGen, shortAddress } from "@/lib/market-data";

import { useWallet } from "./wallet-provider";

type ActionState = { phase: "idle" | "pending" | "success" | "error"; message?: string };

const demoProvider: ProviderState = {
  provider: "0xDA5102E0fe70a609559551450B2dD1662E0746bE",
  totalStake: 50n * 10n ** 18n,
  lockedStake: 20n * 10n ** 18n,
  availableStake: 30n * 10n ** 18n,
  slashedStake: 0n,
  activeDatasets: 2,
};

const demoJobs: ContractJob[] = [
  {
    jobId: "job-fraud-gnn-001",
    requester: "0x3673...9769",
    provider: demoProvider.provider,
    datasetId: "finance-fraud-risk-v2",
    modelId: "graph-sage-anomaly-v3",
    fundedAmount: 2_000_000_000_000_000_000n,
    status: "FUNDED",
    verificationReason: "NONE",
    verificationSummary: "Awaiting execution proof submission from provider enclave.",
  },
  {
    jobId: "job-oncology-c2d-04",
    requester: "0x89ab...12cd",
    provider: demoProvider.provider,
    datasetId: "genomics-pan-cancer-v1",
    modelId: "deep-survival-coxnet-v3",
    fundedAmount: 3_000_000_000_000_000_000n,
    status: "VERIFIED",
    verificationReason: "NONE",
    verificationSummary: "GenLayer Multi-LLM consensus verified execution proof and released 3 GEN escrow.",
  },
  {
    jobId: "job-metro-traffic-02",
    requester: "0x44fa...7788",
    provider: demoProvider.provider,
    datasetId: "mobility-v1",
    modelId: "routeformer-forecast-v2",
    fundedAmount: 3_500_000_000_000_000_000n,
    status: "SLASHED",
    verificationReason: "MODEL_MISMATCH",
    verificationSummary: "Proof named a mismatched model ID. Provider collateral was slashed and requester refunded.",
  },
];

export function ProviderConsole() {
  const { account, connect } = useWallet();
  const [providerState, setProviderState] = useState<ProviderState>(demoProvider);
  const [jobs, setJobs] = useState<ContractJob[]>(demoJobs);
  const [loading, setLoading] = useState(false);

  // Staking & Dataset forms
  const [stakeInput, setStakeInput] = useState("25");
  const [withdrawInput, setWithdrawInput] = useState("10");
  const [stakeAction, setStakeAction] = useState<ActionState>({ phase: "idle" });

  // Register Dataset Form State
  const [regId, setRegId] = useState("finance-credit-risk-v3");
  const [regName, setRegName] = useState("Global Institutional Default Graph");
  const [regDesc, setRegDesc] = useState("High-frequency syndicated loan performance and counterparty risk vectors.");
  const [regSchema, setRegSchema] = useState("borrower_id, debt_to_ebitda, credit_spread, default_status");
  const [regCommit, setRegCommit] = useState("sha256:credit-graph-commitment-2026-v3");
  const [regAccess, setRegAccess] = useState("Approved non-custodial risk classification models only.");
  const [regPrice, setRegPrice] = useState("3.5");
  const [regAction, setRegAction] = useState<ActionState>({ phase: "idle" });

  // Proof Submission Studio
  const [selectedJob, setSelectedJob] = useState<ContractJob | null>(demoJobs[0]);
  const [proofMetadata, setProofMetadata] = useState(
    JSON.stringify(
      {
        completed_epochs: 25,
        convergence_metric: "ROC-AUC 0.964",
        output_hash: "sha256:gnn-embeddings-final-weights-verified",
        environment: "Secure SGX Enclave v4",
        status: "SUCCESS",
      },
      null,
      2,
    ),
  );
  const [proofCommitment, setProofCommitment] = useState("sha256:gnn-embeddings-final-weights-verified");
  const [proofAction, setProofAction] = useState<ActionState>({ phase: "idle" });

  const loadOnChainData = async () => {
    if (!account || !isContractConfigured) return;
    setLoading(true);
    try {
      const pData = await readProvider(account);
      setProviderState(pData);
      const pJobs = await readProviderJobs(account);
      if (pJobs.length > 0) {
        setJobs(pJobs);
        setSelectedJob(pJobs[0]);
      }
    } catch (err) {
      console.warn("Failed reading on-chain provider data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (account) {
      loadOnChainData();
    }
  }, [account]);

  // Handle Stake Action
  const handleStake = async (e: FormEvent) => {
    e.preventDefault();
    if (!account) return connect();
    setStakeAction({ phase: "pending", message: "Staking GEN collateral on-chain..." });
    try {
      const amount = parseGen(stakeInput);
      await stakeProvider(account, amount);
      setStakeAction({ phase: "success", message: `Successfully staked ${stakeInput} GEN!` });
      await loadOnChainData();
    } catch (err: any) {
      setStakeAction({ phase: "error", message: err.message || "Staking failed" });
    }
  };

  // Handle Withdraw Stake
  const handleWithdraw = async (e: FormEvent) => {
    e.preventDefault();
    if (!account) return connect();
    setStakeAction({ phase: "pending", message: "Withdrawing available collateral..." });
    try {
      const amount = parseGen(withdrawInput);
      await withdrawProviderStake(account, amount);
      setStakeAction({ phase: "success", message: `Withdrew ${withdrawInput} GEN!` });
      await loadOnChainData();
    } catch (err: any) {
      setStakeAction({ phase: "error", message: err.message || "Withdrawal failed" });
    }
  };

  // Handle Register Dataset
  const handleRegisterDataset = async (e: FormEvent) => {
    e.preventDefault();
    if (!account) return connect();
    setRegAction({ phase: "pending", message: "Locking bond & registering dataset on-chain..." });
    try {
      await registerDataset(account, {
        datasetId: regId.trim(),
        name: regName.trim(),
        description: regDesc.trim(),
        schema: regSchema.trim(),
        dataCommitment: regCommit.trim(),
        accessConditions: regAccess.trim(),
        pricePerJob: parseGen(regPrice),
      });
      setRegAction({ phase: "success", message: `Dataset "${regName}" registered and bonded!` });
      await loadOnChainData();
    } catch (err: any) {
      setRegAction({ phase: "error", message: err.message || "Dataset registration failed" });
    }
  };

  // Handle Proof Submission
  const handleSubmitProof = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedJob || !account) return connect();
    setProofAction({ phase: "pending", message: "Submitting proof & invoking GenLayer AI consensus..." });
    try {
      await submitExecutionProof(account, {
        jobId: selectedJob.jobId,
        executionProof: proofMetadata.trim(),
        proofCommitment: proofCommitment.trim(),
      });
      setProofAction({ phase: "success", message: "Proof submitted! Multi-LLM Quorum consensus reached." });
      await loadOnChainData();
    } catch (err: any) {
      setProofAction({ phase: "error", message: err.message || "Proof submission failed" });
    }
  };

  return (
    <main className="mx-auto max-w-[1480px] space-y-12 px-4 py-12 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="chip-badge border border-cobalt-400/40 bg-cobalt-500/10 text-cyan-300">
              <ShieldCheck className="h-3.5 w-3.5" /> Provider Staking & Enclave Hub
            </span>
            {account ? (
              <span className="font-mono text-xs text-mineral">🟢 {shortAddress(account)}</span>
            ) : null}
          </div>
          <h1 className="mt-2 text-3xl font-extrabold tracking-[-0.04em] text-paper sm:text-5xl">
            Provider Console
          </h1>
          <p className="mt-2 max-w-2xl text-xs leading-relaxed text-muted sm:text-sm">
            Stake GEN collateral to bond datasets, manage privacy-preserving compute requests, and submit cryptographic execution proofs to GenLayer&apos;s AI validator quorum.
          </p>
        </div>

        <button
          onClick={loadOnChainData}
          disabled={loading}
          className="button-secondary self-start text-xs md:self-auto"
        >
          <RefreshCw className={clsx("h-4 w-4", loading && "animate-spin text-cyan-400")} />
          Sync On-Chain State
        </button>
      </div>

      {/* Stake & Collateral Overview Cards */}
      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <div className="stat-card">
          <div className="flex items-center justify-between text-muted">
            <span className="label-caps">Total Collateral</span>
            <Wallet className="h-4 w-4 text-cobalt-400" />
          </div>
          <strong className="mt-2 block font-mono text-2xl font-extrabold text-paper">
            {formatGen(providerState.totalStake)} GEN
          </strong>
          <span className="mt-1 block font-mono text-[11px] text-muted">Total deposited stake</span>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between text-muted">
            <span className="label-caps">Locked in Bonds</span>
            <Lock className="h-4 w-4 text-ember" />
          </div>
          <strong className="mt-2 block font-mono text-2xl font-extrabold text-ember">
            {formatGen(providerState.lockedStake)} GEN
          </strong>
          <span className="mt-1 block font-mono text-[11px] text-muted">Backing {providerState.activeDatasets} active listings</span>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between text-muted">
            <span className="label-caps">Available Stake</span>
            <CheckCircle2 className="h-4 w-4 text-mineral" />
          </div>
          <strong className="mt-2 block font-mono text-2xl font-extrabold text-mineral">
            {formatGen(providerState.availableStake)} GEN
          </strong>
          <span className="mt-1 block font-mono text-[11px] text-muted">Ready for new dataset bonds</span>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between text-muted">
            <span className="label-caps">Slashed Collateral</span>
            <AlertOctagon className="h-4 w-4 text-danger" />
          </div>
          <strong className="mt-2 block font-mono text-2xl font-extrabold text-danger">
            {formatGen(providerState.slashedStake)} GEN
          </strong>
          <span className="mt-1 block font-mono text-[11px] text-muted">Zero slashing penalty</span>
        </div>
      </div>

      {/* Main Grid: Staking Management & Dataset Registration */}
      <div className="grid gap-8 lg:grid-cols-2">
        {/* Stake / Withdraw Box */}
        <div className="panel rounded-3xl p-6 sm:p-8">
          <div className="flex items-center justify-between border-b border-line pb-4">
            <div className="flex items-center gap-2.5">
              <div className="grid h-9 w-9 place-items-center rounded-xl bg-cobalt-500/10 text-cyan-300">
                <WalletCards className="h-5 w-5" />
              </div>
              <h2 className="text-lg font-bold text-paper">Collateral Management</h2>
            </div>
            <span className="font-mono text-xs text-muted">Minimum Listing Bond: 10 GEN</span>
          </div>

          <div className="mt-6 space-y-6">
            {/* Deposit Form */}
            <form onSubmit={handleStake} className="space-y-3">
              <label className="label-caps block text-paper">Stake GEN Collateral</label>
              <div className="flex gap-2">
                <input
                  type="number"
                  step="1"
                  min="1"
                  value={stakeInput}
                  onChange={(e) => setStakeInput(e.target.value)}
                  className="field font-mono text-sm"
                  placeholder="Amount in GEN"
                  required
                />
                <button
                  type="submit"
                  disabled={stakeAction.phase === "pending"}
                  className="button-primary shrink-0 px-5 text-xs"
                >
                  <ArrowDownToLine className="h-4 w-4" />
                  Stake Collateral
                </button>
              </div>
              <div className="flex gap-2 font-mono text-[11px]">
                {["10", "25", "50", "100"].map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setStakeInput(v)}
                    className="rounded-lg border border-line bg-elevated/60 px-2.5 py-1 text-muted hover:border-line-bright hover:text-paper"
                  >
                    +{v} GEN
                  </button>
                ))}
              </div>
            </form>

            {/* Withdraw Form */}
            <form onSubmit={handleWithdraw} className="border-t border-line/80 pt-6 space-y-3">
              <label className="label-caps block text-paper">Withdraw Available Collateral</label>
              <div className="flex gap-2">
                <input
                  type="number"
                  step="1"
                  min="1"
                  value={withdrawInput}
                  onChange={(e) => setWithdrawInput(e.target.value)}
                  className="field font-mono text-sm"
                  placeholder="Amount in GEN"
                  required
                />
                <button
                  type="submit"
                  disabled={stakeAction.phase === "pending"}
                  className="button-secondary shrink-0 px-5 text-xs"
                >
                  <ArrowUpFromLine className="h-4 w-4 text-ember" />
                  Withdraw
                </button>
              </div>
            </form>

            {stakeAction.message ? (
              <div
                className={clsx(
                  "flex items-center gap-2 rounded-xl p-3 text-xs",
                  stakeAction.phase === "success"
                    ? "border border-mineral/30 bg-mineral/10 text-mineral"
                    : stakeAction.phase === "error"
                      ? "border border-danger/30 bg-danger/10 text-danger"
                      : "border border-cobalt-400/30 bg-cobalt-500/10 text-cobalt-200",
                )}
              >
                {stakeAction.phase === "pending" ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                <span>{stakeAction.message}</span>
              </div>
            ) : null}
          </div>
        </div>

        {/* Register Dataset Surface */}
        <div className="panel rounded-3xl p-6 sm:p-8">
          <div className="flex items-center justify-between border-b border-line pb-4">
            <div className="flex items-center gap-2.5">
              <div className="grid h-9 w-9 place-items-center rounded-xl bg-mineral/10 text-mineral">
                <FilePlus2 className="h-5 w-5" />
              </div>
              <h2 className="text-lg font-bold text-paper">Register Data Surface</h2>
            </div>
            <span className="chip-badge border border-mineral/40 bg-mineral/10 text-mineral">
              10 GEN Bond Locked
            </span>
          </div>

          <form onSubmit={handleRegisterDataset} className="mt-6 space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label-caps block text-[9px] text-muted">Dataset Identifier</label>
                <input
                  value={regId}
                  onChange={(e) => setRegId(e.target.value)}
                  className="field mt-1 font-mono text-xs"
                  placeholder="e.g. credit-risk-v1"
                  required
                />
              </div>
              <div>
                <label className="label-caps block text-[9px] text-muted">Compute Fee (GEN)</label>
                <input
                  value={regPrice}
                  onChange={(e) => setRegPrice(e.target.value)}
                  className="field mt-1 font-mono text-xs"
                  placeholder="e.g. 3.0"
                  required
                />
              </div>
            </div>

            <div>
              <label className="label-caps block text-[9px] text-muted">Dataset Title</label>
              <input
                value={regName}
                onChange={(e) => setRegName(e.target.value)}
                className="field mt-1 text-xs"
                placeholder="e.g. TCGA Pan-Cancer Clinical Cohort"
                required
              />
            </div>

            <div>
              <label className="label-caps block text-[9px] text-muted">Schema / Columns</label>
              <input
                value={regSchema}
                onChange={(e) => setRegSchema(e.target.value)}
                className="field mt-1 font-mono text-xs"
                placeholder="column1, column2, label"
                required
              />
            </div>

            <div>
              <label className="label-caps block text-[9px] text-muted">Cryptographic Commitment</label>
              <input
                value={regCommit}
                onChange={(e) => setRegCommit(e.target.value)}
                className="field mt-1 font-mono text-xs"
                placeholder="sha256:..."
                required
              />
            </div>

            {regAction.message ? (
              <div
                className={clsx(
                  "flex items-center gap-2 rounded-xl p-3 text-xs",
                  regAction.phase === "success"
                    ? "border border-mineral/30 bg-mineral/10 text-mineral"
                    : regAction.phase === "error"
                      ? "border border-danger/30 bg-danger/10 text-danger"
                      : "border border-cobalt-400/30 bg-cobalt-500/10 text-cobalt-200",
                )}
              >
                {regAction.phase === "pending" ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                <span>{regAction.message}</span>
              </div>
            ) : null}

            <button
              type="submit"
              disabled={regAction.phase === "pending"}
              className="button-cyan w-full justify-center text-xs"
            >
              <Plus className="h-4 w-4" />
              Bond & Register Dataset On-Chain
            </button>
          </form>
        </div>
      </div>

      {/* Proof Execution & Multi-LLM Consensus Studio */}
      <section className="panel rounded-3xl p-6 sm:p-8">
        <div className="flex flex-col gap-3 border-b border-line pb-5 md:flex-row md:items-center md:justify-between">
          <div>
            <span className="label-caps text-cyan-300">Enclave Settlement Studio</span>
            <h2 className="mt-1 text-2xl font-extrabold text-paper">
              Active Compute Jobs & Proof Submissions
            </h2>
          </div>
          <span className="font-mono text-xs text-muted">
            {jobs.length} jobs indexed • AI Quorum ready
          </span>
        </div>

        <div className="mt-8 grid gap-8 lg:grid-cols-3">
          {/* Jobs List */}
          <div className="space-y-3">
            <span className="label-caps block text-paper">Select Target Job</span>
            {jobs.map((job) => {
              const active = selectedJob?.jobId === job.jobId;
              return (
                <div
                  key={job.jobId}
                  onClick={() => setSelectedJob(job)}
                  className={clsx(
                    "cursor-pointer rounded-2xl border p-4 transition-all duration-200",
                    active
                      ? "border-cobalt-400 bg-elevated shadow-card"
                      : "border-line bg-canvas/60 hover:border-line-bright hover:bg-elevated/40",
                  )}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-paper">{job.jobId}</span>
                    <span
                      className={clsx(
                        "chip-badge",
                        job.status === "VERIFIED"
                          ? "border border-mineral/30 bg-mineral/10 text-mineral"
                          : job.status === "SLASHED"
                            ? "border border-danger/30 bg-danger/10 text-danger"
                            : "border border-ember/30 bg-ember/10 text-ember",
                      )}
                    >
                      {job.status}
                    </span>
                  </div>
                  <span className="mt-2 block truncate font-mono text-[11px] text-muted">
                    Model: {job.modelId}
                  </span>
                  <div className="mt-2 flex items-center justify-between border-t border-line/60 pt-2 text-[10px] text-muted">
                    <span>Escrow: {formatGen(job.fundedAmount)} GEN</span>
                    <ChevronRight className="h-3.5 w-3.5 text-muted" />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Proof Submission Editor */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between">
              <span className="label-caps text-paper">Execution Proof Metadata (JSON)</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setProofMetadata(
                      JSON.stringify(
                        {
                          completed_epochs: 25,
                          convergence_metric: "ROC-AUC 0.964",
                          output_hash: "sha256:gnn-embeddings-final-weights-verified",
                          environment: "Secure SGX Enclave v4",
                          status: "SUCCESS",
                        },
                        null,
                        2,
                      ),
                    );
                    setProofCommitment("sha256:gnn-embeddings-final-weights-verified");
                  }}
                  className="rounded-lg border border-line bg-canvas/60 px-2.5 py-1 font-mono text-[10px] text-mineral hover:border-mineral/50"
                >
                  ✓ Valid Template
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setProofMetadata(
                      JSON.stringify(
                        {
                          completed_epochs: 5,
                          error: "TAMPERED_MODEL_MISMATCH",
                          output_hash: "sha256:fake-unverified-weights",
                          status: "FAIL",
                        },
                        null,
                        2,
                      ),
                    );
                    setProofCommitment("sha256:fake-unverified-weights");
                  }}
                  className="rounded-lg border border-line bg-canvas/60 px-2.5 py-1 font-mono text-[10px] text-danger hover:border-danger/50"
                >
                  ⚠️ Mismatch Test
                </button>
              </div>
            </div>

            <textarea
              value={proofMetadata}
              onChange={(e) => setProofMetadata(e.target.value)}
              rows={6}
              className="field font-mono text-xs leading-relaxed"
              required
            />

            <div>
              <label className="label-caps block text-[9px] text-muted">Output Proof Commitment Hash</label>
              <input
                value={proofCommitment}
                onChange={(e) => setProofCommitment(e.target.value)}
                className="field mt-1 font-mono text-xs"
                required
              />
            </div>

            {selectedJob ? (
              <div className="rounded-2xl border border-line bg-canvas/60 p-4 font-mono text-xs">
                <span className="label-caps block text-muted">Latest Validator Consensus Summary</span>
                <p className="mt-1 text-paper/90 leading-relaxed">
                  {selectedJob.verificationSummary || "No proof evaluated yet for this job."}
                </p>
              </div>
            ) : null}

            {proofAction.message ? (
              <div
                className={clsx(
                  "flex items-center gap-2 rounded-xl p-3 text-xs",
                  proofAction.phase === "success"
                    ? "border border-mineral/30 bg-mineral/10 text-mineral"
                    : proofAction.phase === "error"
                      ? "border border-danger/30 bg-danger/10 text-danger"
                      : "border border-cobalt-400/30 bg-cobalt-500/10 text-cobalt-200",
                )}
              >
                {proofAction.phase === "pending" ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                <span>{proofAction.message}</span>
              </div>
            ) : null}

            <button
              onClick={handleSubmitProof}
              disabled={proofAction.phase === "pending"}
              className="button-primary w-full justify-center text-xs"
            >
              <Send className="h-4 w-4" />
              Submit Proof to GenLayer Multi-LLM Quorum
            </button>
          </div>
        </div>
      </section>
    </main>
  );
}
