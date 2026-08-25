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
  fundedAmount: bigint;
  status: string;
  verificationReason: string;
  verificationSummary: string;
};

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
        fundedAmount: asBigInt(getField(record, "funded_amount", "fundedAmount")),
        status: asString(getField(record, "status", "status")),
        verificationReason: asString(
          getField(record, "verification_reason", "verificationReason"),
        ),
        verificationSummary: asString(
          getField(record, "verification_summary", "verificationSummary"),
        ),
      };
    }),
  );
  return jobs.filter((job) => job.provider.toLowerCase() === account.toLowerCase());
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
  input: { jobId: string; executionProof: string; proofCommitment: string },
) {
  return writeAndWait(
    account,
    "submit_execution_proof",
    [input.jobId, input.executionProof, input.proofCommitment],
    0n,
  );
}
