export type DatasetCategory =
  | "Mobility"
  | "Health"
  | "Climate"
  | "Finance"
  | "Language";

export type MarketplaceDataset = {
  id: string;
  name: string;
  description: string;
  provider: string;
  providerName: string;
  category: DatasetCategory;
  format: string;
  scale: string;
  priceWei: bigint;
  priceLabel: string;
  bondLabel: string;
  dataCommitment: string;
  accessConditions: string;
  schema: string;
  tags: string[];
  totalJobs: number;
  verified: boolean;
  live: boolean;
};

export const demoDatasets: MarketplaceDataset[] = [
  {
    id: "mobility-v1",
    name: "MetroFlow trajectory vectors",
    description:
      "Anonymized urban movement windows for congestion forecasting and route optimization.",
    provider: "0x71d9f07f3c6a39e876e50f58af641a5db06c8a20",
    providerName: "Vector Transit Lab",
    category: "Mobility",
    format: "Parquet",
    scale: "2.8B rows",
    priceWei: 3_200_000_000_000_000_000n,
    priceLabel: "3.2 GEN",
    bondLabel: "12 GEN",
    dataCommitment: "sha256:4a1c...e09f",
    accessConditions: "Aggregate prediction workloads with no row-level output.",
    schema: "timestamp, zone_id, speed, occupancy, weather_bucket",
    tags: ["Forecasting", "Time series", "Urban"],
    totalJobs: 86,
    verified: true,
    live: false,
  },
  {
    id: "clinical-notes-v3",
    name: "SynNote clinical narratives",
    description:
      "High-fidelity synthetic care notes for medical language models and entity extraction.",
    provider: "0x4c20371e64df51f5c156c9cf3c44134aa04ef119",
    providerName: "Aster Health Compute",
    category: "Health",
    format: "JSONL",
    scale: "48M notes",
    priceWei: 4_600_000_000_000_000_000n,
    priceLabel: "4.6 GEN",
    bondLabel: "16 GEN",
    dataCommitment: "sha256:19ff...ab72",
    accessConditions: "Research models with signed non-diagnostic use policy.",
    schema: "note_id, specialty, narrative, coded_entities, chronology",
    tags: ["NLP", "Synthetic", "Clinical"],
    totalJobs: 41,
    verified: true,
    live: false,
  },
  {
    id: "crop-index-v2",
    name: "TerraCrop multispectral index",
    description:
      "Seasonal satellite observations for crop health, yield estimation, and drought response.",
    provider: "0xa87dce10c699f3b0fffb564339a0149cb15231cd",
    providerName: "TerraScope Cooperative",
    category: "Climate",
    format: "GeoTIFF",
    scale: "640 TB",
    priceWei: 5_100_000_000_000_000_000n,
    priceLabel: "5.1 GEN",
    bondLabel: "18 GEN",
    dataCommitment: "sha256:8d41...90ce",
    accessConditions: "No geographic reconstruction below the approved tile size.",
    schema: "tile_id, capture_time, red, nir, swir, cloud_mask",
    tags: ["Vision", "Geospatial", "Agriculture"],
    totalJobs: 112,
    verified: true,
    live: false,
  },
  {
    id: "risk-events-v5",
    name: "Atlas transaction risk graph",
    description:
      "Labeled transaction topology for anomaly detection and fraud model benchmarking.",
    provider: "0x9f8215ac6c8dca5fa41c90a670c22156df83ae70",
    providerName: "Atlas Risk Systems",
    category: "Finance",
    format: "GraphML",
    scale: "910M edges",
    priceWei: 6_800_000_000_000_000_000n,
    priceLabel: "6.8 GEN",
    bondLabel: "24 GEN",
    dataCommitment: "sha256:ce72...4d18",
    accessConditions: "Detection and scoring only; no entity re-identification.",
    schema: "entity_hash, transfer_edge, event_time, risk_label",
    tags: ["Graph", "Anomaly", "Risk"],
    totalJobs: 63,
    verified: true,
    live: false,
  },
  {
    id: "call-intent-v2",
    name: "Relay support intent corpus",
    description:
      "Consent-cleared support transcripts with resolution outcomes and intent taxonomies.",
    provider: "0xb8213d34a03f6d2f20f039c3e873bb0e68fc922a",
    providerName: "Relay CX Research",
    category: "Language",
    format: "Arrow",
    scale: "17M sessions",
    priceWei: 2_700_000_000_000_000_000n,
    priceLabel: "2.7 GEN",
    bondLabel: "12 GEN",
    dataCommitment: "sha256:669a...f810",
    accessConditions: "Intent classification and summarization with filtered outputs.",
    schema: "session_id, turns, intent, resolution, satisfaction_bucket",
    tags: ["Conversation", "Intent", "Support"],
    totalJobs: 29,
    verified: true,
    live: false,
  },
  {
    id: "grid-demand-v4",
    name: "NorthGrid demand telemetry",
    description:
      "Regional power-demand curves with weather and renewable generation context.",
    provider: "0xe19319e39f8d0a2db098c6b8245f7ec9339dd4b1",
    providerName: "NorthGrid Data Trust",
    category: "Climate",
    format: "Delta Lake",
    scale: "8.2B samples",
    priceWei: 3_900_000_000_000_000_000n,
    priceLabel: "3.9 GEN",
    bondLabel: "14 GEN",
    dataCommitment: "sha256:37bb...6f05",
    accessConditions: "Aggregate regional forecasts with a minimum 15-minute interval.",
    schema: "region, interval, demand_mw, generation_mix, temperature",
    tags: ["Energy", "Forecasting", "Telemetry"],
    totalJobs: 54,
    verified: true,
    live: false,
  },
];

export const categoryOptions = [
  "All datasets",
  "Mobility",
  "Health",
  "Climate",
  "Finance",
  "Language",
] as const;

export function shortAddress(address: string) {
  if (address.length < 12) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function formatGen(value: bigint) {
  const whole = value / 10n ** 18n;
  const decimal = ((value % 10n ** 18n) / 10n ** 16n)
    .toString()
    .padStart(2, "0")
    .replace(/0+$/, "");
  return decimal ? `${whole}.${decimal} GEN` : `${whole} GEN`;
}

export function parseGen(value: string) {
  const normalized = value.trim();
  if (!/^\d+(\.\d{0,18})?$/.test(normalized)) {
    throw new Error("Enter a valid GEN amount with up to 18 decimal places.");
  }
  const [whole, decimal = ""] = normalized.split(".");
  return BigInt(whole) * 10n ** 18n + BigInt(decimal.padEnd(18, "0"));
}
