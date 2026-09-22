// Fetch the Intel PCS collateral for an Intel SGX ECDSA quote (v3).
//
// The contract verifies a proof envelope { artifact, dcap_quote, collateral } on
// chain against the pinned Intel SGX Root CA. This script produces the
// `collateral` part from Intel's Provisioning Certification Service (v4 API):
// it reads the quote, takes the FMSPC and the issuing PCK CA (processor or
// platform) from the quote's PCK certificate, and downloads, verbatim:
//
//   tcb_info / tcb_info_issuer_chain         GET /sgx/certification/v4/tcb?fmspc=..
//   qe_identity / qe_identity_issuer_chain   GET /sgx/certification/v4/qe/identity
//   pck_crl                                  GET /sgx/certification/v4/pckcrl?ca=..&encoding=der
//   root_ca_crl                              the Intel SGX Root CA CRL (DER)
//
// Nothing here is trusted by the contract: every item is Intel-signed and is
// verified on chain. Collateral is valid until its nextUpdate (about 30 days).
//
// Usage:
//   node scripts/fetch_pcs_collateral.mjs <quote.hex|quote.bin> [--artifact artifact.json] [--out file.json]
//
// With --artifact, the output is the complete proof envelope for
// submit_execution_proof / appeal_job_verdict; otherwise it is the collateral.

import fs from "node:fs";
import { X509Certificate } from "node:crypto";

const PCS = "https://api.trustedservices.intel.com/sgx/certification/v4";
const ROOT_CA_CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";
const FMSPC_OID = Buffer.from("060a2a864886f84d010d0104", "hex"); // 1.2.840.113741.1.13.1.4

function readQuote(path) {
  const raw = fs.readFileSync(path);
  const text = raw.toString("utf8").trim();
  return /^[0-9a-fA-F]+$/.test(text) ? Buffer.from(text, "hex") : raw;
}

function pckChainFromQuote(quote) {
  if (quote.readUInt16LE(0) !== 3 || quote.readUInt16LE(2) !== 2) {
    throw new Error("Expected an Intel SGX ECDSA-P256 quote, version 3");
  }
  let off = 48 + 384 + 4 + 64 + 64 + 384 + 64;
  off += 2 + quote.readUInt16LE(off);
  const certType = quote.readUInt16LE(off);
  const certSize = quote.readUInt32LE(off + 2);
  if (certType !== 5) throw new Error(`Quote certification data type ${certType} is not an Intel PCK chain (5)`);
  const pem = quote.subarray(off + 6, off + 6 + certSize).toString("ascii").replace(/\0+$/, "");
  const certs = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  if (certs.length !== 3) throw new Error("Expected PCK, PCK CA and root certificates in the quote");
  return certs.map((c) => new X509Certificate(c));
}

function fmspcOf(pckCert) {
  const der = pckCert.raw;
  const at = der.indexOf(FMSPC_OID);
  if (at < 0 || der[at + FMSPC_OID.length] !== 0x04 || der[at + FMSPC_OID.length + 1] !== 0x06) {
    throw new Error("PCK certificate has no SGX FMSPC extension");
  }
  const start = at + FMSPC_OID.length + 2;
  return der.subarray(start, start + 6).toString("hex");
}

async function get(url, issuerChainHeader) {
  const res = await fetch(url);
  if (res.status !== 200) throw new Error(`${url} -> HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  const chain = issuerChainHeader ? decodeURIComponent(res.headers.get(issuerChainHeader) ?? "") : "";
  if (issuerChainHeader && !chain) throw new Error(`${url} did not return ${issuerChainHeader}`);
  return { body, chain };
}

async function main() {
  const args = process.argv.slice(2);
  const quotePath = args.find((a) => !a.startsWith("--"));
  const flag = (name) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  if (!quotePath) {
    console.error("usage: node scripts/fetch_pcs_collateral.mjs <quote.hex|quote.bin> [--artifact artifact.json] [--out file.json]");
    process.exit(2);
  }

  const quote = readQuote(quotePath);
  const [pck, pckCa] = pckChainFromQuote(quote);
  const fmspc = fmspcOf(pck);
  const ca = pckCa.subject.includes("Platform CA") ? "platform" : "processor";
  console.error(`[pcs] FMSPC ${fmspc}, PCK CA: ${ca}`);

  const tcb = await get(`${PCS}/tcb?fmspc=${fmspc}`, "TCB-Info-Issuer-Chain");
  const qe = await get(`${PCS}/qe/identity`, "SGX-Enclave-Identity-Issuer-Chain");
  const pckCrl = await get(`${PCS}/pckcrl?ca=${ca}&encoding=der`);
  const rootCrl = await get(ROOT_CA_CRL_URL);

  const collateral = {
    tcb_info: tcb.body.toString("utf8"),
    tcb_info_issuer_chain: tcb.chain,
    qe_identity: qe.body.toString("utf8"),
    qe_identity_issuer_chain: qe.chain,
    pck_crl: pckCrl.body.toString("hex"),
    root_ca_crl: rootCrl.body.toString("hex"),
  };
  const nextUpdate = JSON.parse(collateral.tcb_info).tcbInfo.nextUpdate;
  console.error(`[pcs] TCB Info valid until ${nextUpdate}`);

  const artifactPath = flag("--artifact");
  const output = artifactPath
    ? {
        artifact: JSON.parse(fs.readFileSync(artifactPath, "utf8")),
        dcap_quote: quote.toString("hex"),
        collateral,
      }
    : collateral;
  const text = JSON.stringify(output);
  const outPath = flag("--out");
  if (outPath) {
    fs.writeFileSync(outPath, text);
    console.error(`[pcs] wrote ${outPath}`);
  } else {
    process.stdout.write(text + "\n");
  }
}

main().catch((err) => {
  console.error(`[pcs] ${err.message}`);
  process.exit(1);
});
