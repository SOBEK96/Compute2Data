import { createClient } from "genlayer-js";
import { testnetBradbury } from "genlayer-js/chains";
import type { CalldataEncodable } from "genlayer-js/types";
import { ExecutionResult, TransactionStatus } from "genlayer-js/types";

export type HexAddress = `0x${string}`;

export type ContractDataset = {
  datasetId: string;
  provider: string;
  name: string;
  description: string;
  schema: string;
  dataCommitment: string;
  accessConditions: string;
  pricePerJob: bigint;
  active: boolean;
  listingBond: bigint;
  openJobs: number;
  totalJobs: number;
};

export type ProviderState = {
  provider: string;
  totalStake: bigint;
  lockedStake: bigint;
  availableStake: bigint;
  slashedStake: bigint;
  activeDatasets: number;
};

export type ContractJob = {
  jobId: string;
  requester: string;
  provider: string;
  datasetId: string;
  modelId: string;
  inputCommitment: string;
  fundedAmount: bigint;
  status: string;
  outputCommitment: string;
  attestationStatus: string;
  attestationMrenclave: string;
  verificationReason: string;
  verificationSummary: string;
  verified: boolean;
  slashAmount: bigint;
  settlementAmount: bigint;
  appealReason: string;
  appealBond: bigint;
  proofDeadline: bigint;
  appealDeadline: bigint;
};

export type MarketplaceStats = {
  totalStaked: bigint;
  totalEscrowed: bigint;
  totalSlashed: bigint;
  totalAppealBonds: bigint;
  totalDatasets: number;
  totalJobs: number;
  minimumDatasetStake: bigint;
  minimumJobCollateral: bigint;
  minimumAppealBond: bigint;
};

export type ProviderReputation = {
  provider: string;
  successfulJobs: number;
  failedJobs: number;
  appealedJobs: number;
  completedJobs: number;
  reputationScore: number;
};

// Domain separation tags provisioned inside contracts/c2d_marketplace.py. The
// browser reproduces the exact bytes the enclave signs and the contract
// re-derives on chain so an attestation can be assembled client-side.
const BINDING_DOMAIN = "c2d-attestation-binding-v1";
const QUOTE_DOMAIN = "c2d-enclave-quote-v1";
export const DEFAULT_ENCLAVE_MEASUREMENT = "11".repeat(32);
export const DEFAULT_ENCLAVE_SIGNER = "22".repeat(32);

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export type AttestationArtifact = {
  datasetCommitment: string;
  inputCommitment: string;
  modelId: string;
  outputCommitment: string;
  resultStatus?: string;
  mrenclave?: string;
  mrsigner?: string;
};

/**
 * Assemble a TEE/SGX style enclave attestation quote whose report data
 * cryptographically binds the produced artifact to the exact dataset
 * commitment, requester input commitment and model id.
 */
export async function buildAttestationQuote(artifact: AttestationArtifact): Promise<string> {
  const mrenclave = artifact.mrenclave ?? DEFAULT_ENCLAVE_MEASUREMENT;
  const mrsigner = artifact.mrsigner ?? DEFAULT_ENCLAVE_SIGNER;
  const resultStatus = artifact.resultStatus ?? "COMPLETED";
  const reportData = await sha256Hex(
    [
      BINDING_DOMAIN,
      artifact.datasetCommitment,
      artifact.inputCommitment,
      artifact.modelId,
      artifact.outputCommitment,
    ].join("|"),
  );
  const quoteSignature = await sha256Hex(
    [QUOTE_DOMAIN, mrenclave, mrsigner, reportData].join("|"),
  );
  return JSON.stringify({
    enclave: {
      mrenclave,
      mrsigner,
      report_data: reportData,
      quote_signature: quoteSignature,
    },
    artifact: {
      dataset_commitment: artifact.datasetCommitment,
      input_commitment: artifact.inputCommitment,
      model_id: artifact.modelId,
      output_commitment: artifact.outputCommitment,
      result_status: resultStatus,
    },
  });
}

const configuredAddress = process.env.NEXT_PUBLIC_C2D_CONTRACT_ADDRESS ?? "";

export const contractAddress = /^0x[0-9a-fA-F]{40}$/.test(configuredAddress)
  ? (configuredAddress as HexAddress)
  : null;

export const isContractConfigured = contractAddress !== null;
export const networkName = "GenLayer Bradbury";

const readClient = createClient({ chain: testnetBradbury });

function asRecord(value: unknown): Record<string, unknown> {
  if (value instanceof Map) {
    return Object.fromEntries(value.entries()) as Record<string, unknown>;
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error("Contract returned an unexpected record.");
}

function asString(value: unknown) {
  return typeof value === "string" ? value : String(value ?? "");
}

function asBigInt(value: unknown) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  return 0n;
}

function asNumber(value: unknown) {
  const parsed = asBigInt(value);
  return parsed > BigInt(Number.MAX_SAFE_INTEGER)
    ? Number.MAX_SAFE_INTEGER
    : Number(parsed);
}

function getField(record: Record<string, unknown>, snake: string, camel: string) {
  return record[snake] ?? record[camel];
}

function requireContractAddress() {
  if (!contractAddress) {
    throw new Error("Set NEXT_PUBLIC_C2D_CONTRACT_ADDRESS to enable live transactions.");
  }
  return contractAddress;
}

async function writeAndWait(
  account: HexAddress,
  functionName: string,
  args: CalldataEncodable[],
  value: bigint,
) {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("Install an EIP-1193 wallet to sign this transaction.");
  }

  const client = createClient({
    chain: testnetBradbury,
    account,
    provider: window.ethereum,
  });
  await client.connect("testnetBradbury");
  const hash = await client.writeContract({
    address: requireContractAddress(),
    functionName,
    args,
    value,
  });
  const receipt = await client.waitForTransactionReceipt({
    hash,
    status: TransactionStatus.ACCEPTED,
  });

  if (receipt.txExecutionResultName === ExecutionResult.FINISHED_WITH_ERROR) {
    throw new Error("The contract rejected the transaction during execution.");
  }

  return String(hash);
}

export async function readDatasets(): Promise<ContractDataset[]> {
  const address = requireContractAddress();
  const idsValue = await readClient.readContract({
    address,
    functionName: "list_dataset_ids",
    args: [],
  });
  const ids = Array.isArray(idsValue) ? idsValue.map(asString) : [];

  const datasets = await Promise.all(
    ids.map(async (datasetId) => {
      const value = await readClient.readContract({
        address,
        functionName: "get_dataset",
        args: [datasetId],
      });
      const record = asRecord(value);
      return {
        datasetId,
        provider: asString(getField(record, "provider", "provider")),
        name: asString(getField(record, "name", "name")),
        description: asString(getField(record, "description", "description")),
        schema: asString(getField(record, "schema", "schema")),
        dataCommitment: asString(
          getField(record, "data_commitment", "dataCommitment"),
        ),
        accessConditions: asString(
          getField(record, "access_conditions", "accessConditions"),
        ),
        pricePerJob: asBigInt(getField(record, "price_per_job", "pricePerJob")),
        active: Boolean(getField(record, "active", "active")),
        listingBond: asBigInt(getField(record, "listing_bond", "listingBond")),
        openJobs: asNumber(getField(record, "open_jobs", "openJobs")),
        totalJobs: asNumber(getField(record, "total_jobs", "totalJobs")),
      };
    }),
  );

  return datasets.filter((dataset) => dataset.active);
}

export async function readProvider(account: HexAddress): Promise<ProviderState> {
  const value = await readClient.readContract({
    address: requireContractAddress(),
    functionName: "get_provider",
    args: [account],
  });
  const record = asRecord(value);
  return {
    provider: asString(getField(record, "provider", "provider")),
    totalStake: asBigInt(getField(record, "total_stake", "totalStake")),
    lockedStake: asBigInt(getField(record, "locked_stake", "lockedStake")),
    availableStake: asBigInt(
      getField(record, "available_stake", "availableStake"),
    ),
    slashedStake: asBigInt(getField(record, "slashed_stake", "slashedStake")),
    activeDatasets: asNumber(
      getField(record, "active_datasets", "activeDatasets"),
    ),
  };
}

export async function readProviderJobs(account: HexAddress): Promise<ContractJob[]> {
  const address = requireContractAddress();
  const idsValue = await readClient.readContract({
    address,
    functionName: "list_job_ids",
    args: [],
  });
  const ids = Array.isArray(idsValue) ? idsValue.map(asString) : [];
  const jobs = await Promise.all(
    ids.map(async (jobId) => {
      const value = await readClient.readContract({
        address,
        functionName: "get_job",
        args: [jobId],
      });
      const record = asRecord(value);
      return {
        jobId,
        requester: asString(getField(record, "requester", "requester")),
        provider: asString(getField(record, "provider", "provider")),
        datasetId: asString(getField(record, "dataset_id", "datasetId")),
        modelId: asString(getField(record, "model_id", "modelId")),
        inputCommitment: asString(
          getField(record, "input_commitment", "inputCommitment"),
        ),
        fundedAmount: asBigInt(getField(record, "funded_amount", "fundedAmount")),
        status: asString(getField(record, "status", "status")),
        outputCommitment: asString(
          getField(record, "output_commitment", "outputCommitment"),
        ),
        attestationStatus: asString(
          getField(record, "attestation_status", "attestationStatus"),
        ),
        attestationMrenclave: asString(
          getField(record, "attestation_mrenclave", "attestationMrenclave"),
        ),
        verificationReason: asString(
          getField(record, "verification_reason", "verificationReason"),
        ),
        verificationSummary: asString(
          getField(record, "verification_summary", "verificationSummary"),
        ),
        verified: Boolean(getField(record, "verified", "verified")),
        slashAmount: asBigInt(getField(record, "slash_amount", "slashAmount")),
        settlementAmount: asBigInt(
          getField(record, "settlement_amount", "settlementAmount"),
        ),
        appealReason: asString(getField(record, "appeal_reason", "appealReason")),
        appealBond: asBigInt(getField(record, "appeal_bond", "appealBond")),
        proofDeadline: asBigInt(getField(record, "proof_deadline", "proofDeadline")),
        appealDeadline: asBigInt(
          getField(record, "appeal_deadline", "appealDeadline"),
        ),
      };
    }),
  );
  return jobs.filter((job) => job.provider.toLowerCase() === account.toLowerCase());
}

export async function readMarketplaceStats(): Promise<MarketplaceStats> {
  const value = await readClient.readContract({
    address: requireContractAddress(),
    functionName: "get_marketplace_stats",
    args: [],
  });
  const record = asRecord(value);
  return {
    totalStaked: asBigInt(getField(record, "total_staked", "totalStaked")),
    totalEscrowed: asBigInt(getField(record, "total_escrowed", "totalEscrowed")),
    totalSlashed: asBigInt(getField(record, "total_slashed", "totalSlashed")),
    totalAppealBonds: asBigInt(
      getField(record, "total_appeal_bonds", "totalAppealBonds"),
    ),
    totalDatasets: asNumber(getField(record, "total_datasets", "totalDatasets")),
    totalJobs: asNumber(getField(record, "total_jobs", "totalJobs")),
    minimumDatasetStake: asBigInt(
      getField(record, "minimum_dataset_stake", "minimumDatasetStake"),
    ),
    minimumJobCollateral: asBigInt(
      getField(record, "minimum_job_collateral", "minimumJobCollateral"),
    ),
    minimumAppealBond: asBigInt(
      getField(record, "minimum_appeal_bond", "minimumAppealBond"),
    ),
  };
}

export async function readProviderReputation(
  account: HexAddress,
): Promise<ProviderReputation> {
  const value = await readClient.readContract({
    address: requireContractAddress(),
    functionName: "get_provider_reputation",
    args: [account],
  });
  const record = asRecord(value);
  return {
    provider: asString(getField(record, "provider", "provider")),
    successfulJobs: asNumber(getField(record, "successful_jobs", "successfulJobs")),
    failedJobs: asNumber(getField(record, "failed_jobs", "failedJobs")),
    appealedJobs: asNumber(getField(record, "appealed_jobs", "appealedJobs")),
    completedJobs: asNumber(getField(record, "completed_jobs", "completedJobs")),
    reputationScore: asNumber(
      getField(record, "reputation_score", "reputationScore"),
    ),
  };
}

export function stakeProvider(account: HexAddress, amount: bigint) {
  return writeAndWait(account, "stake_provider", [], amount);
}

export function withdrawProviderStake(account: HexAddress, amount: bigint) {
  return writeAndWait(account, "withdraw_stake", [amount], 0n);
}

export function registerDataset(
  account: HexAddress,
  input: {
    datasetId: string;
    name: string;
    description: string;
    schema: string;
    dataCommitment: string;
    accessConditions: string;
    pricePerJob: bigint;
  },
) {
  return writeAndWait(
    account,
    "register_dataset",
    [
      input.datasetId,
      input.name,
      input.description,
      input.schema,
      input.dataCommitment,
      input.accessConditions,
      input.pricePerJob,
    ],
    0n,
  );
}

export function requestCompute(
  account: HexAddress,
  input: {
    jobId: string;
    datasetId: string;
    modelId: string;
    computeSpec: string;
    inputCommitment: string;
    price: bigint;
  },
) {
  return writeAndWait(
    account,
    "request_compute",
    [
      input.jobId,
      input.datasetId,
      input.modelId,
      input.computeSpec,
      input.inputCommitment,
    ],
    input.price,
  );
}

export function submitExecutionProof(
  account: HexAddress,
  input: { jobId: string; attestationQuote: string; outputCommitment: string },
) {
  return writeAndWait(
    account,
    "submit_execution_proof",
    [input.jobId, input.attestationQuote, input.outputCommitment],
    0n,
  );
}

export function cancelExpiredJob(account: HexAddress, jobId: string) {
  return writeAndWait(account, "cancel_expired_job", [jobId], 0n);
}

export function appealJobVerdict(
  account: HexAddress,
  input: { jobId: string; appealJustification: string; attestationEvidence: string; bond: bigint },
) {
  return writeAndWait(
    account,
    "appeal_job_verdict",
    [input.jobId, input.appealJustification, input.attestationEvidence],
    input.bond,
  );
}

export function resolveAppeal(account: HexAddress, jobId: string) {
  return writeAndWait(account, "resolve_appeal", [jobId], 0n);
}
