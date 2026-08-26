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
  appealJobVerdict,
  buildAttestationQuote,
  isContractConfigured,
  readProvider,
  readProviderJobs,
  readProviderReputation,
  registerDataset,
  resolveAppeal,
  stakeProvider,
  submitExecutionProof,
  withdrawProviderStake,
  type ContractJob,
  type ProviderReputation,
  type ProviderState,
} from "@/lib/contract";
import { formatGen, parseGen, shortAddress } from "@/lib/market-data";

const ONE_GEN = 1_000_000_000_000_000_000n;

// Maps a job lifecycle status to its badge styling.
function statusBadgeClass(status: string) {
  if (status === "VERIFIED" || status === "APPEAL_ACCEPTED") {
    return "border border-mineral/30 bg-mineral/10 text-mineral";
  }
  if (status === "SLASHED" || status === "APPEAL_REJECTED") {
    return "border border-danger/30 bg-danger/10 text-danger";
  }
  if (status === "APPEALED" || status === "INCONCLUSIVE") {
    return "border border-cobalt-400/30 bg-cobalt-500/10 text-cobalt-200";
  }
  return "border border-ember/30 bg-ember/10 text-ember";
}

// Maps the deterministic enclave attestation outcome to a label and styling.
function attestationBadge(status: string) {
  if (status === "ENCLAVE_VERIFIED") {
    return { label: "Enclave Verified", className: "border border-mineral/30 bg-mineral/10 text-mineral" };
  }
  if (status === "ENCLAVE_REJECTED") {
    return { label: "Enclave Rejected", className: "border border-danger/30 bg-danger/10 text-danger" };
  }
  return { label: "Attestation Pending", className: "border border-line bg-elevated/60 text-muted" };
}

function formatDeadline(epochSeconds: bigint) {
  if (epochSeconds === 0n) return "No deadline set";
  const millis = Number(epochSeconds) * 1000;
  if (!Number.isFinite(millis)) return "No deadline set";
  return new Date(millis).toISOString().replace("T", " ").replace(".000Z", " UTC");
}

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

const demoJobDefaults = {
  verified: false,
  slashAmount: 0n,
  settlementAmount: 0n,
  appealReason: "",
  appealBond: 0n,
  proofDeadline: 0n,
  appealDeadline: 0n,
  attestationMrenclave: "",
};

const demoJobs: ContractJob[] = [
  {
    jobId: "job-fraud-gnn-001",
    requester: "0x3673...9769",
    provider: demoProvider.provider,
    datasetId: "finance-fraud-risk-v2",
    modelId: "graph-sage-anomaly-v3",
    inputCommitment: "sha256:fraud-input-commitment-3a71",
    fundedAmount: 2_000_000_000_000_000_000n,
    status: "FUNDED",
    outputCommitment: "",
    attestationStatus: "PENDING",
    verificationReason: "NONE",
    verificationSummary: "Awaiting enclave attestation submission from provider.",
    ...demoJobDefaults,
    proofDeadline: 1_797_000_000n,
  },
  {
    jobId: "job-oncology-c2d-04",
    requester: "0x89ab...12cd",
    provider: demoProvider.provider,
    datasetId: "genomics-pan-cancer-v1",
    modelId: "deep-survival-coxnet-v3",
    inputCommitment: "sha256:oncology-input-commitment-9c02",
    fundedAmount: 3_000_000_000_000_000_000n,
    status: "VERIFIED",
    outputCommitment: "sha256:coxnet-survival-artifact-final",
    attestationStatus: "ENCLAVE_VERIFIED",
    verificationReason: "NONE",
    verificationSummary:
      "Enclave quote bound the artifact to the committed dataset, input and model; escrow released.",
    ...demoJobDefaults,
    verified: true,
    settlementAmount: 3_000_000_000_000_000_000n,
  },
  {
    jobId: "job-metro-traffic-02",
    requester: "0x44fa...7788",
    provider: demoProvider.provider,
    datasetId: "mobility-v1",
    modelId: "routeformer-forecast-v2",
    inputCommitment: "sha256:metro-input-commitment-77f0",
    fundedAmount: 3_500_000_000_000_000_000n,
    status: "SLASHED",
    outputCommitment: "sha256:routeformer-artifact-unverified",
    attestationStatus: "ENCLAVE_REJECTED",
    verificationReason: "MODEL_MISMATCH",
    verificationSummary:
      "Attestation artifact named a mismatched model ID. Provider collateral was slashed and requester refunded.",
    ...demoJobDefaults,
    slashAmount: 12_000_000_000_000_000_000n,
    appealDeadline: 1_797_200_000n,
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

  // Enclave Attestation Studio
  const [selectedJob, setSelectedJob] = useState<ContractJob | null>(demoJobs[0]);
  const [reputation, setReputation] = useState<ProviderReputation | null>(null);
  const [datasetCommitment, setDatasetCommitment] = useState("sha256:credit-graph-commitment-2026-v3");
  const [outputCommitment, setOutputCommitment] = useState("sha256:gnn-embeddings-final-weights-verified");
  const [resultStatus, setResultStatus] = useState("COMPLETED");
  const [tamperModel, setTamperModel] = useState(false);
  const [proofAction, setProofAction] = useState<ActionState>({ phase: "idle" });
  const [appealAction, setAppealAction] = useState<ActionState>({ phase: "idle" });

  const loadOnChainData = async () => {
    if (!account || !isContractConfigured) return;
    setLoading(true);
    try {
      const pData = await readProvider(account);
      setProviderState(pData);
      const rep = await readProviderReputation(account);
      setReputation(rep);
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
  }, [account, loadOnChainData]);

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

  // Handle Enclave Attestation Submission
  const handleSubmitProof = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedJob || !account) return connect();
    setProofAction({
      phase: "pending",
      message: "Building enclave quote & verifying artifact binding on-chain...",
    });
    try {
      const attestationQuote = await buildAttestationQuote({
        datasetCommitment: datasetCommitment.trim(),
        inputCommitment: selectedJob.inputCommitment,
        // A mismatch test intentionally binds the artifact to the wrong model.
        modelId: tamperModel ? `${selectedJob.modelId}-tampered` : selectedJob.modelId,
        outputCommitment: outputCommitment.trim(),
        resultStatus,
      });
      await submitExecutionProof(account, {
        jobId: selectedJob.jobId,
        attestationQuote,
        outputCommitment: outputCommitment.trim(),
      });
      setProofAction({
        phase: "success",
        message: "Attestation submitted. Deterministic binding verified; validator quorum reviewed the report.",
      });
      await loadOnChainData();
    } catch (err: any) {
      setProofAction({ phase: "error", message: err.message || "Attestation submission failed" });
    }
  };

  // Handle Appeal of a slashed or inconclusive verdict.
  const handleAppeal = async () => {
    if (!selectedJob || !account) return connect();
    setAppealAction({ phase: "pending", message: "Posting 1 GEN appeal bond with fresh enclave evidence..." });
    try {
      const attestationEvidence = await buildAttestationQuote({
        datasetCommitment: datasetCommitment.trim(),
        inputCommitment: selectedJob.inputCommitment,
        modelId: selectedJob.modelId,
        outputCommitment: outputCommitment.trim(),
        resultStatus: "COMPLETED",
      });
      await appealJobVerdict(account, {
        jobId: selectedJob.jobId,
        appealJustification:
          "Re-submitting a correctly signed enclave quote bound to the committed dataset, input and model.",
        attestationEvidence,
        bond: ONE_GEN,
      });
      setAppealAction({ phase: "success", message: "Appeal filed. Bond escrowed pending adjudication." });
      await loadOnChainData();
    } catch (err: any) {
      setAppealAction({ phase: "error", message: err.message || "Appeal failed" });
    }
  };

  // Adjudicate an appeal by re-verifying the submitted enclave evidence.
  const handleResolveAppeal = async () => {
    if (!selectedJob || !account) return connect();
    setAppealAction({ phase: "pending", message: "Re-verifying enclave evidence to adjudicate the appeal..." });
    try {
      await resolveAppeal(account, selectedJob.jobId);
      setAppealAction({ phase: "success", message: "Appeal adjudicated. Bond and slash settled to a terminal state." });
      await loadOnChainData();
    } catch (err: any) {
      setAppealAction({ phase: "error", message: err.message || "Appeal resolution failed" });
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
              <span className="font-mono text-xs text-mineral">Connected: {shortAddress(account)}</span>
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
            {jobs.length} jobs indexed - AI Quorum ready
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
                    <span className={clsx("chip-badge", statusBadgeClass(job.status))}>
                      {job.status}
                    </span>
                  </div>
                  <span className="mt-2 block truncate font-mono text-[11px] text-muted">
                    Model: {job.modelId}
                  </span>
                  <div className="mt-2 flex items-center gap-1.5">
                    <Fingerprint className="h-3 w-3 text-cobalt-400" />
                    <span
                      className={clsx(
                        "chip-badge text-[9px]",
                        attestationBadge(job.attestationStatus).className,
                      )}
                    >
                      {attestationBadge(job.attestationStatus).label}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center justify-between border-t border-line/60 pt-2 text-[10px] text-muted">
                    <span>Escrow: {formatGen(job.fundedAmount)} GEN</span>
                    <ChevronRight className="h-3.5 w-3.5 text-muted" />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Enclave Attestation Editor */}
          <div className="lg:col-span-2 space-y-4">
            {selectedJob ? (
              <div className="grid gap-3 rounded-2xl border border-line bg-canvas/60 p-4 sm:grid-cols-3">
                <div>
                  <span className="label-caps block text-[9px] text-muted">Lifecycle State</span>
                  <span className={clsx("chip-badge mt-1", statusBadgeClass(selectedJob.status))}>
                    {selectedJob.status}
                  </span>
                </div>
                <div>
                  <span className="label-caps block text-[9px] text-muted">Enclave Attestation</span>
                  <span
                    className={clsx(
                      "chip-badge mt-1",
                      attestationBadge(selectedJob.attestationStatus).className,
                    )}
                  >
                    <ShieldCheck className="h-3 w-3" />
                    {attestationBadge(selectedJob.attestationStatus).label}
                  </span>
                </div>
                <div>
                  <span className="label-caps block text-[9px] text-muted">Proof Deadline</span>
                  <span className="mt-1 block font-mono text-[10px] text-paper/80">
                    {formatDeadline(selectedJob.proofDeadline)}
                  </span>
                </div>
              </div>
            ) : null}

            <div className="flex items-center justify-between">
              <span className="label-caps text-paper">Enclave Quote Binding Inputs</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setResultStatus("COMPLETED");
                    setTamperModel(false);
                  }}
                  className="rounded-lg border border-line bg-canvas/60 px-2.5 py-1 font-mono text-[10px] text-mineral hover:border-mineral/50"
                >
                  Valid Quote
                </button>
                <button
                  type="button"
                  onClick={() => setTamperModel(true)}
                  className="rounded-lg border border-line bg-canvas/60 px-2.5 py-1 font-mono text-[10px] text-danger hover:border-danger/50"
                >
                  Model Mismatch Test
                </button>
              </div>
            </div>

            <p className="rounded-xl border border-line/70 bg-elevated/40 p-3 text-[11px] leading-relaxed text-muted">
              The contract derives the report data as
              <span className="font-mono text-cobalt-200"> sha256(dataset || input || model || output)</span> and
              rejects any quote whose binding, trusted measurement, or signature does not verify. No provider
              prose is trusted.
            </p>

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="label-caps block text-[9px] text-muted">Dataset Commitment</label>
                <input
                  value={datasetCommitment}
                  onChange={(e) => setDatasetCommitment(e.target.value)}
                  className="field mt-1 font-mono text-xs"
                  required
                />
              </div>
              <div>
                <label className="label-caps block text-[9px] text-muted">Bound Input Commitment</label>
                <input
                  value={selectedJob?.inputCommitment ?? ""}
                  readOnly
                  className="field mt-1 font-mono text-xs opacity-70"
                />
              </div>
              <div>
                <label className="label-caps block text-[9px] text-muted">Output Artifact Commitment</label>
                <input
                  value={outputCommitment}
                  onChange={(e) => setOutputCommitment(e.target.value)}
                  className="field mt-1 font-mono text-xs"
                  required
                />
              </div>
              <div>
                <label className="label-caps block text-[9px] text-muted">Enclave Result Status</label>
                <select
                  value={resultStatus}
                  onChange={(e) => setResultStatus(e.target.value)}
                  className="field mt-1 font-mono text-xs"
                >
                  <option value="COMPLETED">COMPLETED</option>
                  <option value="PENDING">PENDING</option>
                  <option value="FAILED">FAILED</option>
                </select>
              </div>
            </div>

            {tamperModel ? (
              <div className="flex items-center gap-2 rounded-xl border border-danger/30 bg-danger/10 p-3 text-xs text-danger">
                <ShieldAlert className="h-4 w-4" />
                <span>
                  Mismatch test armed: the quote will bind a tampered model id and must be slashed on chain.
                </span>
              </div>
            ) : null}

            {selectedJob ? (
              <div className="rounded-2xl border border-line bg-canvas/60 p-4 font-mono text-xs">
                <span className="label-caps block text-muted">Latest Validator Consensus Summary</span>
                <p className="mt-1 leading-relaxed text-paper/90">
                  {selectedJob.verificationSummary || "No attestation evaluated yet for this job."}
                </p>
                {selectedJob.attestationMrenclave ? (
                  <p className="mt-2 truncate text-[10px] text-muted">
                    MRENCLAVE: {selectedJob.attestationMrenclave}
                  </p>
                ) : null}
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
              disabled={proofAction.phase === "pending" || selectedJob?.status !== "FUNDED"}
              className="button-primary w-full justify-center text-xs"
            >
              <Send className="h-4 w-4" />
              Submit Enclave Attestation for On-Chain Verification
            </button>

            {selectedJob &&
            (selectedJob.status === "SLASHED" ||
              selectedJob.status === "INCONCLUSIVE" ||
              selectedJob.status === "APPEALED") ? (
              <div className="space-y-3 rounded-2xl border border-cobalt-400/30 bg-cobalt-500/5 p-4">
                <div className="flex items-center justify-between">
                  <span className="label-caps text-cobalt-200">Dispute Resolution</span>
                  <span className="font-mono text-[10px] text-muted">
                    Appeal window: {formatDeadline(selectedJob.appealDeadline)}
                  </span>
                </div>
                {appealAction.message ? (
                  <div
                    className={clsx(
                      "flex items-center gap-2 rounded-xl p-3 text-xs",
                      appealAction.phase === "success"
                        ? "border border-mineral/30 bg-mineral/10 text-mineral"
                        : appealAction.phase === "error"
                          ? "border border-danger/30 bg-danger/10 text-danger"
                          : "border border-cobalt-400/30 bg-cobalt-500/10 text-cobalt-200",
                    )}
                  >
                    {appealAction.phase === "pending" ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                    <span>{appealAction.message}</span>
                  </div>
                ) : null}
                <div className="flex flex-col gap-2 sm:flex-row">
                  <button
                    onClick={handleAppeal}
                    disabled={appealAction.phase === "pending" || selectedJob.status === "APPEALED"}
                    className="button-secondary flex-1 justify-center text-xs"
                  >
                    <ShieldAlert className="h-4 w-4 text-ember" />
                    File Appeal (1 GEN Bond)
                  </button>
                  <button
                    onClick={handleResolveAppeal}
                    disabled={appealAction.phase === "pending" || selectedJob.status !== "APPEALED"}
                    className="button-secondary flex-1 justify-center text-xs"
                  >
                    <Shield className="h-4 w-4 text-cobalt-300" />
                    Adjudicate Appeal
                  </button>
                </div>
              </div>
            ) : null}

            {reputation ? (
              <div className="grid grid-cols-4 gap-2 rounded-2xl border border-line bg-canvas/60 p-3 text-center font-mono text-[10px]">
                <div>
                  <span className="block text-muted">Score</span>
                  <strong className="text-mineral">{reputation.reputationScore}</strong>
                </div>
                <div>
                  <span className="block text-muted">Passed</span>
                  <strong className="text-paper">{reputation.successfulJobs}</strong>
                </div>
                <div>
                  <span className="block text-muted">Failed</span>
                  <strong className="text-danger">{reputation.failedJobs}</strong>
                </div>
                <div>
                  <span className="block text-muted">Appeals</span>
                  <strong className="text-cobalt-200">{reputation.appealedJobs}</strong>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </section>
    </main>
  );
}
