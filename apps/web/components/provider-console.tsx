"use client";

import {
  ArrowDownToLine,
  ArrowUpFromLine,
  CheckCircle2,
  CircleAlert,
  FilePlus2,
  LoaderCircle,
  LockKeyhole,
  Plus,
  ShieldAlert,
  WalletCards,
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
  provider: "0x71d9f07f3c6a39e876e50f58af641a5db06c8a20",
  totalStake: 52n * 10n ** 18n,
  lockedStake: 24n * 10n ** 18n,
  availableStake: 28n * 10n ** 18n,
  slashedStake: 0n,
  activeDatasets: 2,
};

const demoJobs: ContractJob[] = [
  {
    jobId: "job-metroflow-9af3",
    requester: "0x2e8f...c601",
    provider: demoProvider.provider,
    datasetId: "mobility-v1",
    modelId: "hf://forecast-base-v2",
    fundedAmount: 3_200_000_000_000_000_000n,
    status: "FUNDED",
    verificationReason: "",
    verificationSummary: "Proof submission expected from the provider enclave.",
  },
  {
    jobId: "job-metroflow-33c2",
    requester: "0xd8aa...77e4",
    provider: demoProvider.provider,
    datasetId: "mobility-v1",
    modelId: "s3://research/routeformer",
    fundedAmount: 3_200_000_000_000_000_000n,
    status: "VERIFIED",
    verificationReason: "NONE",
    verificationSummary: "Consensus matched the committed compute request.",
  },
  {
    jobId: "job-notes-61de",
    requester: "0xa883...ab09",
    provider: demoProvider.provider,
    datasetId: "clinical-notes-v3",
    modelId: "hf://clinical-ner-7b",
    fundedAmount: 4_600_000_000_000_000_000n,
    status: "SLASHED",
    verificationReason: "MODEL_MISMATCH",
    verificationSummary: "The submitted proof named a model different from the funded request.",
  },
];

function Metric({
  label,
  value,
  detail,
  tone = "paper",
}: {
  label: string;
  value: string;
  detail: string;
  tone?: "paper" | "mineral" | "danger" | "ember";
}) {
  const toneClass = {
    paper: "text-paper",
    mineral: "text-mineral",
    danger: "text-danger",
    ember: "text-ember",
  }[tone];
  return (
    <div className="panel rounded-2xl p-5">
      <span className="label-caps">{label}</span>
      <strong className={`mt-5 block text-2xl font-extrabold tracking-[-0.04em] ${toneClass}`}>
        {value}
      </strong>
      <span className="mt-2 block text-xs text-muted">{detail}</span>
    </div>
  );
}

export function ProviderConsole() {
  const { account, connect } = useWallet();
  const [provider, setProvider] = useState<ProviderState>(demoProvider);
  const [jobs, setJobs] = useState<ContractJob[]>(demoJobs);
  const [stakeAmount, setStakeAmount] = useState("10");
  const [withdrawAmount, setWithdrawAmount] = useState("5");
  const [proofJob, setProofJob] = useState<ContractJob | null>(null);
  const [action, setAction] = useState<ActionState>({ phase: "idle" });
  const [showRegister, setShowRegister] = useState(false);

  useEffect(() => {
    if (!account || !isContractConfigured) return;
    let active = true;
    Promise.all([readProvider(account), readProviderJobs(account)])
      .then(([nextProvider, nextJobs]) => {
        if (!active) return;
        setProvider(nextProvider);
        setJobs(nextJobs);
      })
      .catch((caught) => {
        if (active) {
          setAction({
            phase: "error",
            message: caught instanceof Error ? caught.message : "Provider data could not load.",
          });
        }
      });
    return () => {
      active = false;
    };
  }, [account]);

  async function runAction(actionFn: (signer: `0x${string}`) => Promise<string>) {
    if (!isContractConfigured) {
      setAction({
        phase: "error",
        message: "Live transactions are disabled in demo mode. Configure the contract address.",
      });
      return;
    }
    const signer = account ?? (await connect());
    if (!signer) return;
    setAction({ phase: "pending", message: "Waiting for network confirmation" });
    try {
      const hash = await actionFn(signer);
      setAction({ phase: "success", message: `Accepted ${shortAddress(hash)}` });
      const [nextProvider, nextJobs] = await Promise.all([
        readProvider(signer),
        readProviderJobs(signer),
      ]);
      setProvider(nextProvider);
      setJobs(nextJobs);
    } catch (caught) {
      setAction({
        phase: "error",
        message: caught instanceof Error ? caught.message : "Transaction failed.",
      });
    }
  }

  return (
    <main className="mx-auto max-w-[1480px] px-4 pb-10 pt-10 sm:px-6 sm:pt-14 lg:px-8">
      <div className="flex flex-col justify-between gap-6 border-b border-line pb-8 lg:flex-row lg:items-end">
        <div>
          <div className="flex items-center gap-3">
            <span className="label-caps text-mineral">Provider console</span>
            <span className="rounded-full border border-mineral/30 bg-mineral/10 px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-mineral">
              Bonded operator
            </span>
          </div>
          <h1 className="mt-3 text-4xl font-extrabold tracking-[-0.05em] sm:text-5xl">
            Operate your data surfaces.
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted">
            Manage collateral, publish private datasets, and answer funded workloads with proof metadata. Raw data never touches this dashboard or the contract.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button type="button" onClick={() => setShowRegister(true)} className="button-secondary">
            <FilePlus2 className="h-4 w-4" />
            Register dataset
          </button>
          <button type="button" onClick={() => setProofJob(jobs.find((job) => job.status === "FUNDED") ?? null)} className="button-primary">
            <Plus className="h-4 w-4" />
            Submit proof
          </button>
        </div>
      </div>

      <div className="grid gap-4 py-7 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Total stake" value={formatGen(provider.totalStake)} detail="Provider collateral" />
        <Metric label="Locked collateral" value={formatGen(provider.lockedStake)} detail={`${provider.activeDatasets} active listings`} tone="mineral" />
        <Metric label="Available stake" value={formatGen(provider.availableStake)} detail="Can back new listings" tone="ember" />
        <Metric label="Slashed to date" value={formatGen(provider.slashedStake)} detail="Consensus-enforced loss" tone={provider.slashedStake ? "danger" : "paper"} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="panel overflow-hidden rounded-2xl">
          <div className="flex flex-col justify-between gap-4 border-b border-line px-5 py-5 sm:flex-row sm:items-center">
            <div>
              <span className="label-caps">Workload queue</span>
              <h2 className="mt-2 text-xl font-extrabold tracking-[-0.035em]">Proof obligations</h2>
            </div>
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">
              {jobs.length} indexed jobs
            </span>
          </div>
          <div className="divide-y divide-line">
            {jobs.map((job) => {
              const pending = job.status === "FUNDED";
              const slashed = job.status === "SLASHED";
              return (
                <div key={job.jobId} className="grid gap-4 px-5 py-5 sm:grid-cols-[minmax(0,1fr)_150px_130px] sm:items-center">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate font-mono text-xs text-paper">{job.jobId}</span>
                      <span className={`rounded-full px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em] ${pending ? "bg-ember/10 text-ember" : slashed ? "bg-danger/10 text-danger" : "bg-mineral/10 text-mineral"}`}>
                        {job.status}
                      </span>
                    </div>
                    <p className="mt-2 truncate text-sm text-muted">{job.modelId}</p>
                    <p className="mt-1 font-mono text-[10px] text-muted/70">Requester {job.requester}</p>
                  </div>
                  <div className="sm:text-right">
                    <span className="label-caps block">Escrow</span>
                    <strong className="mt-1 block text-sm text-paper">{formatGen(job.fundedAmount)}</strong>
                  </div>
                  <div className="sm:text-right">
                    {pending ? (
                      <button type="button" onClick={() => setProofJob(job)} className="button-primary w-full py-2.5 text-xs sm:w-auto">
                        Answer proof
                      </button>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted">
                        {slashed ? <ShieldAlert className="h-3.5 w-3.5 text-danger" /> : <CheckCircle2 className="h-3.5 w-3.5 text-mineral" />}
                        {slashed ? job.verificationReason : "Consensus matched"}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        <aside className="grid content-start gap-5">
          <StakePanel
            stakeAmount={stakeAmount}
            setStakeAmount={setStakeAmount}
            withdrawAmount={withdrawAmount}
            setWithdrawAmount={setWithdrawAmount}
            onStake={() => runAction((signer) => stakeProvider(signer, parseGen(stakeAmount)))}
            onWithdraw={() => runAction((signer) => withdrawProviderStake(signer, parseGen(withdrawAmount)))}
          />
          <div className="panel rounded-2xl p-5">
            <div className="flex items-center gap-3">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-cobalt-500/10 text-cobalt-300"><WalletCards className="h-4 w-4" /></span>
              <div>
                <span className="label-caps">Settlement status</span>
                <strong className="mt-1 block text-sm">{isContractConfigured ? "Live contract" : "Demo workspace"}</strong>
              </div>
            </div>
            <p className="mt-4 text-xs leading-5 text-muted">
              Every active listing locks a 10 GEN bond. Each funded workload locks an additional 2 GEN execution collateral.
            </p>
          </div>
        </aside>
      </div>

      {action.phase !== "idle" ? (
        <div className={`fixed bottom-5 right-5 z-50 flex max-w-sm items-start gap-3 rounded-xl border px-4 py-3 text-sm shadow-panel ${action.phase === "error" ? "border-danger/30 bg-danger/10 text-danger" : action.phase === "success" ? "border-mineral/30 bg-mineral/10 text-mineral" : "border-cobalt-400/30 bg-cobalt-500/10 text-cobalt-300"}`}>
          {action.phase === "pending" ? <LoaderCircle className="mt-0.5 h-4 w-4 shrink-0 animate-spin" /> : action.phase === "error" ? <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" /> : <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />}
          <span>{action.message}</span>
        </div>
      ) : null}

      <ProofModal job={proofJob} onClose={() => setProofJob(null)} onSubmit={(input) => runAction((signer) => submitExecutionProof(signer, input))} />
      <RegisterModal open={showRegister} onClose={() => setShowRegister(false)} onSubmit={(input) => runAction((signer) => registerDataset(signer, input))} />
    </main>
  );
}

function StakePanel({
  stakeAmount,
  setStakeAmount,
  withdrawAmount,
  setWithdrawAmount,
  onStake,
  onWithdraw,
}: {
  stakeAmount: string;
  setStakeAmount: (value: string) => void;
  withdrawAmount: string;
  setWithdrawAmount: (value: string) => void;
  onStake: () => void;
  onWithdraw: () => void;
}) {
  return (
    <section className="panel rounded-2xl p-5">
      <div className="flex items-center justify-between">
        <div>
          <span className="label-caps">Collateral controls</span>
          <h2 className="mt-2 text-xl font-extrabold tracking-[-0.035em]">Stake manager</h2>
        </div>
        <LockKeyhole className="h-5 w-5 text-mineral" />
      </div>
      <div className="mt-6 grid gap-4">
        <label className="grid gap-2">
          <span className="label-caps">Add GEN</span>
          <div className="flex gap-2">
            <input className="field" value={stakeAmount} onChange={(event) => setStakeAmount(event.target.value)} inputMode="decimal" />
            <button type="button" onClick={onStake} className="button-primary px-3" aria-label="Add provider stake" title="Add provider stake"><ArrowUpFromLine className="h-4 w-4" /></button>
          </div>
        </label>
        <label className="grid gap-2">
          <span className="label-caps">Release available</span>
          <div className="flex gap-2">
            <input className="field" value={withdrawAmount} onChange={(event) => setWithdrawAmount(event.target.value)} inputMode="decimal" />
            <button type="button" onClick={onWithdraw} className="button-secondary px-3" aria-label="Release provider stake" title="Release provider stake"><ArrowDownToLine className="h-4 w-4" /></button>
          </div>
        </label>
      </div>
      <p className="mt-5 border-t border-line pt-4 text-xs leading-5 text-muted">
        Locked GEN cannot be withdrawn while a dataset is active or a compute proof is unresolved.
      </p>
    </section>
  );
}

function ProofModal({
  job,
  onClose,
  onSubmit,
}: {
  job: ContractJob | null;
  onClose: () => void;
  onSubmit: (input: { jobId: string; executionProof: string; proofCommitment: string }) => void;
}) {
  const [proof, setProof] = useState("");
  const [commitment, setCommitment] = useState("sha256:");
  useEffect(() => {
    if (job) {
      setProof("");
      setCommitment("sha256:");
    }
  }, [job]);
  if (!job) return null;
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit({ jobId: job.jobId, executionProof: proof, proofCommitment: commitment });
    onClose();
  };
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-canvas/85 p-0 backdrop-blur-xl sm:items-center sm:p-5">
      <form onSubmit={submit} className="panel-raised w-full max-w-xl rounded-t-2xl p-5 sm:rounded-2xl sm:p-7">
        <span className="label-caps text-ember">Execution proof</span>
        <h2 className="mt-2 text-2xl font-extrabold tracking-[-0.04em]">Answer {job.jobId}</h2>
        <p className="mt-3 text-sm leading-6 text-muted">Validators compare these claims against the original request. Include commitments and aggregate metrics, never raw records.</p>
        <label className="mt-6 grid gap-2"><span className="label-caps">Proof metadata</span><textarea className="field min-h-36 resize-y leading-6" value={proof} onChange={(event) => setProof(event.target.value)} required maxLength={16384} placeholder="Completed job ...; dataset ...; model ...; input ...; output ...; metrics ..." /></label>
        <label className="mt-5 grid gap-2"><span className="label-caps">Proof commitment</span><input className="field font-mono text-xs" value={commitment} onChange={(event) => setCommitment(event.target.value)} required maxLength={256} /></label>
        <div className="mt-7 flex justify-end gap-3"><button type="button" onClick={onClose} className="button-secondary">Cancel</button><button type="submit" className="button-primary">Submit to consensus</button></div>
      </form>
    </div>
  );
}

function RegisterModal({
  open,
  onClose,
  onSubmit,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (input: { datasetId: string; name: string; description: string; schema: string; dataCommitment: string; accessConditions: string; pricePerJob: bigint }) => void;
}) {
  const [datasetId, setDatasetId] = useState("dataset-");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [schema, setSchema] = useState("");
  const [commitment, setCommitment] = useState("sha256:");
  const [conditions, setConditions] = useState("");
  const [price, setPrice] = useState("3");
  if (!open) return null;
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit({ datasetId, name, description, schema, dataCommitment: commitment, accessConditions: conditions, pricePerJob: parseGen(price) });
    onClose();
  };
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-canvas/85 p-0 backdrop-blur-xl sm:items-center sm:p-5">
      <form onSubmit={submit} className="panel-raised max-h-[94vh] w-full max-w-2xl overflow-y-auto rounded-t-2xl p-5 sm:rounded-2xl sm:p-7">
        <span className="label-caps text-mineral">New data surface</span>
        <h2 className="mt-2 text-2xl font-extrabold tracking-[-0.04em]">Register dataset</h2>
        <p className="mt-3 text-sm leading-6 text-muted">The contract locks a 10 GEN listing bond from your available stake when this listing activates.</p>
        <div className="mt-6 grid gap-5 sm:grid-cols-2">
          <label className="grid gap-2"><span className="label-caps">Dataset ID</span><input className="field font-mono text-xs" value={datasetId} onChange={(event) => setDatasetId(event.target.value)} required maxLength={96} /></label>
          <label className="grid gap-2"><span className="label-caps">Display name</span><input className="field" value={name} onChange={(event) => setName(event.target.value)} required maxLength={160} /></label>
        </div>
        <label className="mt-5 grid gap-2"><span className="label-caps">Description</span><textarea className="field min-h-24 resize-y" value={description} onChange={(event) => setDescription(event.target.value)} required maxLength={4096} /></label>
        <label className="mt-5 grid gap-2"><span className="label-caps">Schema and surface</span><input className="field" value={schema} onChange={(event) => setSchema(event.target.value)} placeholder="Parquet: field_a, field_b, field_c" required maxLength={4096} /></label>
        <div className="mt-5 grid gap-5 sm:grid-cols-2"><label className="grid gap-2"><span className="label-caps">Data commitment</span><input className="field font-mono text-xs" value={commitment} onChange={(event) => setCommitment(event.target.value)} required maxLength={256} /></label><label className="grid gap-2"><span className="label-caps">Price per job / GEN</span><input className="field font-mono text-xs" value={price} onChange={(event) => setPrice(event.target.value)} required inputMode="decimal" /></label></div>
        <label className="mt-5 grid gap-2"><span className="label-caps">Access conditions</span><textarea className="field min-h-24 resize-y" value={conditions} onChange={(event) => setConditions(event.target.value)} required maxLength={4096} /></label>
        <div className="mt-7 flex justify-end gap-3"><button type="button" onClick={onClose} className="button-secondary">Cancel</button><button type="submit" className="button-primary">Lock bond and publish</button></div>
      </form>
    </div>
  );
}
