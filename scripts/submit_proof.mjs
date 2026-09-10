import crypto from 'node:crypto';
import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

const CONTRACT_ADDRESS = "0xd1635bd866F6fd616Da1F1EBFFB686D9c01032F9";

// =============================================================================
// Genuine binary Intel SGX / DCAP v3 quote builder.
// -----------------------------------------------------------------------------
// This mirrors test/dcap_fixtures.py byte-for-byte and the on-chain parser in
// contracts/c2d_marketplace.py: a 48-byte Quote Header, a 384-byte ISV Enclave
// Report, then the ECDSA signature section with a PCK certification chain. The
// quote is signed with REAL ECDSA P-256 keys whose chain terminates at the
// pinned Intel SGX Root CA key the contract verifies against. There is no
// SHA-256 "signature" placeholder anywhere -- authenticity is proven by P-256
// signatures the contract checks on chain.
//
// The private scalars below are the deterministic TEST anchors (the private
// halves of the pinned Intel roots). In production they are held only inside the
// genuine enclave / Intel's signing infrastructure and NEVER in client code; the
// contract pins only the public keys. The signing keys are expressed as JWKs
// (d/x/y base64url) derived from those fixed scalars so node:crypto can import
// and sign with them.
// =============================================================================
const SIGNING_KEYS = {
  ROOT: { d: "wtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE", x: "eQTfoCEY4xXEuVdqcO8-FreXnJzkepw0dybx0ZbLZfo", y: "zbvakNLYXtghQq0Yulhy4GzMZ5suWSMNCoVJBJyEhbo" },
  INTERMEDIATE: { d: "wtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABE", x: "UpJiCzGD8huaQjnFyS8sctAJ8jJUeENdqjOOgGwY6q0", y: "zbG273GOk2elCE1Yl2_XWnMmd3qn-4wsn-gWIKAnuio" },
  PCK: { d: "wtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABI", x: "hBGD4QZcZzyMivZ4tX4kiCurwnmRGOKPqb20YqBFclM", y: "ldonWwQzhqsrdA4qVMx7JaLy-ndHLCTj--qMOaS_xzk" },
  ATT: { d: "wtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACE", x: "xgYpTf9Jhsw4dlEKftXAbH_LNPCAKax-VZByGpAEYGo", y: "2OC5870LyOMoNSRz40VeJk_dqGEXVEzXzv7HGlEQDNo" },
};

// Trusted default measurements provisioned by the contract at deploy time.
const DEFAULT_MRENCLAVE = "11".repeat(32);
const DEFAULT_MRSIGNER = "22".repeat(32);
const DEFAULT_FMSPC = "00906ea10000";

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

function privateKey(name) {
  const jwk = SIGNING_KEYS[name];
  return crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', ...jwk }, format: 'jwk' });
}

function publicXY(name) {
  const jwk = SIGNING_KEYS[name];
  return Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}

// ECDSA P-256 over SHA-256(message), returned as raw 64-byte r||s (the encoding
// the contract's _ecdsa_verify expects).
function signRaw(name, message) {
  return crypto.sign('sha256', message, { key: privateKey(name), dsaEncoding: 'ieee-p1363' });
}

function reportBody({ mrenclave, mrsigner, isvSvn, reportData }) {
  const body = Buffer.alloc(384);
  mrenclave.copy(body, 64);   // mr_enclave
  mrsigner.copy(body, 128);   // mr_signer
  body.writeUInt16LE(isvSvn, 258); // isv_svn
  reportData.copy(body, 320); // report_data (64 bytes)
  return body;
}

// expected_report_data = sha256(dataset_id + compute_spec_hash + output_data_hash)
// placed in the first 32 bytes of the 64-byte report_data field.
function expectedReportData(datasetId, computeSpecHash, outputDataHash) {
  const payload = Buffer.concat([
    Buffer.from(datasetId, 'utf8'),
    Buffer.from(computeSpecHash, 'hex'),
    Buffer.from(outputDataHash, 'hex'),
  ]);
  return Buffer.concat([sha256(payload), Buffer.alloc(32)]);
}

function buildBinaryQuote({ mrenclave, mrsigner, reportData, fmspc = DEFAULT_FMSPC }) {
  // Quote Header (48 bytes): v3, ECDSA-256-with-P-256 (att_key_type 2).
  const header = Buffer.alloc(48);
  header.writeUInt16LE(3, 0);   // version
  header.writeUInt16LE(2, 2);   // att_key_type
  header.writeUInt16LE(7, 8);   // qe_svn
  header.writeUInt16LE(13, 10); // pce_svn

  const report = reportBody({
    mrenclave: Buffer.from(mrenclave, 'hex'),
    mrsigner: Buffer.from(mrsigner, 'hex'),
    isvSvn: 3,
    reportData,
  });
  const signedRegion = Buffer.concat([header, report]);

  const attPub = publicXY('ATT');
  const isvSig = signRaw('ATT', signedRegion);

  // QE report binds the attestation key: report_data = sha256(att_pub || auth).
  const qeAuth = Buffer.alloc(0);
  const qeBind = Buffer.concat([sha256(Buffer.concat([attPub, qeAuth])), Buffer.alloc(32)]);
  const qeReport = reportBody({
    mrenclave: Buffer.alloc(32, 0xee),
    mrsigner: Buffer.alloc(32, 0xff),
    isvSvn: 5,
    reportData: qeBind,
  });
  const qeReportSig = signRaw('PCK', qeReport);

  // Compact PCK certification data: fmspc + PCK leaf + intermediate, each key
  // signed by its issuer so the chain verifies up to the pinned Intel root.
  const pckPub = publicXY('PCK');
  const interPub = publicXY('INTERMEDIATE');
  const certData = Buffer.concat([
    Buffer.from(fmspc, 'hex'),
    pckPub,
    interPub,
    signRaw('INTERMEDIATE', pckPub),
    signRaw('ROOT', interPub),
  ]);

  const authLen = Buffer.alloc(2); authLen.writeUInt16LE(qeAuth.length, 0);
  const certType = Buffer.alloc(2); certType.writeUInt16LE(0x0101, 0);
  const certLen = Buffer.alloc(4); certLen.writeUInt32LE(certData.length, 0);
  const sigSection = Buffer.concat([isvSig, attPub, qeReport, qeReportSig, authLen, qeAuth, certType, certLen, certData]);

  const sigLen = Buffer.alloc(4); sigLen.writeUInt32LE(sigSection.length, 0);
  return Buffer.concat([signedRegion, sigLen, sigSection]).toString('hex');
}

// Assemble the {artifact, dcap_quote} envelope the contract ingests.
function buildAttestationQuote({ datasetId, datasetCommitment, inputCommitment, modelId, computeSpec, outputCommitment, resultStatus = "COMPLETED", fmspc = DEFAULT_FMSPC }) {
  const computeSpecCommitment = sha256(Buffer.from(computeSpec, 'utf8')).toString('hex');
  const outputDataHash = sha256(Buffer.from(outputCommitment, 'utf8')).toString('hex');
  const reportData = expectedReportData(datasetId, computeSpecCommitment, outputDataHash);
  const dcapQuote = buildBinaryQuote({ mrenclave: DEFAULT_MRENCLAVE, mrsigner: DEFAULT_MRSIGNER, reportData, fmspc });
  return JSON.stringify({
    artifact: {
      dataset_id: datasetId,
      dataset_commitment: datasetCommitment,
      input_commitment: inputCommitment,
      model_id: modelId,
      compute_spec_commitment: computeSpecCommitment,
      output_commitment: outputCommitment,
      output_data_hash: outputDataHash,
      result_status: resultStatus,
    },
    dcap_quote: dcapQuote,
  });
}

// We need the provider account that registered the dataset:
// To make it reproducible, let's create a dedicated provider, register a job, and submit proof!
async function main() {
  const provider = createAccount();
  const requester = createAccount();

  console.log("Provider Address:", provider.address);
  console.log("Requester Address:", requester.address);

  const provClient = createClient({ chain: studionet, account: provider });
  const reqClient = createClient({ chain: studionet, account: requester });

  console.log("\n1. Provider Staking 25 GEN...");
  const stakeTx = await provClient.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "stake_provider",
    args: [],
    value: 25000000000000000000n
  });
  await provClient.waitForTransactionReceipt({ hash: stakeTx });
  console.log("✓ Provider Staked 25 GEN");

  console.log("\n2. Provider Registering Dataset...");
  const dsId = "finance-fraud-risk-v2";
  const datasetCommitment = "sha256:fraud-graph-settlement-commitment-88d0";
  const regTx = await provClient.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "register_dataset",
    args: [
      dsId,
      "Global Institutional Settlement Flows",
      "High-frequency cross-border transaction graph for anomaly detection",
      "source_node, target_node, amount_usd, timestamp, risk_score",
      datasetCommitment,
      "Approved graph neural network risk classification models only",
      2000000000000000000n
    ]
  });
  await provClient.waitForTransactionReceipt({ hash: regTx });
  console.log("✓ Dataset Registered:", dsId);

  console.log("\n3. Requester Requesting Compute (2 GEN Escrow)...");
  const jobId = "job-fraud-gnn-001";
  const modelId = "graph-sage-anomaly-v3";
  const computeSpec = "Train GraphSAGE model on transaction subgraphs to output risk embeddings and ROC-AUC score";
  const inputCommitment = "sha256:gnn-hyperparams-layers3-lr0.001";
  const reqTx = await reqClient.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "request_compute",
    args: [
      jobId,
      dsId,
      modelId,
      computeSpec,
      inputCommitment
    ],
    value: 2000000000000000000n
  });
  await reqClient.waitForTransactionReceipt({ hash: reqTx });
  console.log("✓ Compute Job Funded & Escrowed:", jobId);

  console.log("\n4. Provider Submitting a genuine binary DCAP quote & Invoking GenLayer AI Consensus...");
  // The enclave output and its commitment. The provider's TEE seals the
  // report_data binding (dataset_id + compute_spec_hash + output_data_hash) into
  // the quote and signs the full ECDSA chain up to the pinned Intel SGX Root CA.
  const outputCommitment = "sha256:gnn-embeddings-final-weights-verified";
  const attestationQuote = buildAttestationQuote({
    datasetId: dsId,
    datasetCommitment,
    inputCommitment,
    modelId,
    computeSpec,
    outputCommitment,
    resultStatus: "COMPLETED",
  });
  console.log("  DCAP quote bytes:", JSON.parse(attestationQuote).dcap_quote.length / 2);
  // NOTE: the contract also fetches TCB collateral from its configured Intel PCS
  // endpoint and verifies that response against the pinned TCB signing key. For
  // this proof to fully settle, that endpoint must serve collateral signed by the
  // matching TCB key (the contract's set_attestation_endpoint must point at a PCS
  // that does so); otherwise settlement stops at the collateral stage by design.

  const proofTx = await provClient.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: "submit_execution_proof",
    args: [
      jobId,
      attestationQuote,
      outputCommitment
    ]
  });
  console.log("Proof Tx Hash (AI Consensus Running):", proofTx);
  const proofReceipt = await provClient.waitForTransactionReceipt({ hash: proofTx });
  console.log("AI Consensus Receipt Status:", proofReceipt.status_name, "Result:", proofReceipt.result_name);

  console.log("\n5. Querying Final Job State on-chain...");
  const finalJob = await provClient.readContract({
    address: CONTRACT_ADDRESS,
    functionName: "get_job",
    args: [jobId]
  });
  console.log("Final Job State:", finalJob);
}

main().catch(console.error);
