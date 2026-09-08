# 🌱 Compute2Data: Autonomous Privacy-Preserving AI Compute Marketplace on GenLayer

<p align="center">
  <img src="https://img.shields.io/badge/Network-GenLayer%20StudioNet-00E5FF?style=for-the-badge&logo=ethereum" alt="Network" />
  <img src="https://img.shields.io/badge/Language-Python%20GenVM-3776AB?style=for-the-badge&logo=python" alt="Python" />
  <img src="https://img.shields.io/badge/Frontend-Next.js%2014-000000?style=for-the-badge&logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/Tests-11%2F11%20Passed%20(100%25)-10B981?style=for-the-badge" alt="Tests" />
  <img src="https://img.shields.io/badge/Spec--Kit-SDD%20Ratified-8B5CF6?style=for-the-badge" alt="Spec Kit" />
  <img src="https://img.shields.io/badge/Author-Saeid%20(%40Handik4)-6366F1?style=for-the-badge" alt="Author" />
  <img src="https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge" alt="License" />
</p>

---

## 📖 Table of Contents
1. [Executive Summary & Problem Statement](#-executive-summary--problem-statement)
2. [How It Works: Architectural Overview](#-how-it-works-architectural-overview)
3. [Intelligent Contract Deep Dive (v2.0)](#-intelligent-contract-deep-dive-v20)
4. [Spec-Driven Development (GitHub Spec Kit)](#-spec-driven-development-github-spec-kit)
5. [Live On-Chain Deployment & Proofs](#-live-on-chain-deployment--proofs)
6. [Step-by-Step Developer Quickstart](#-step-by-step-developer-quickstart)
7. [Mathematical Models & Slashing Economics](#-mathematical-models--slashing-economics)
8. [Security & Prompt Injection Defenses](#-security--prompt-injection-defenses)
9. [Project Structure](#-project-structure)
10. [Authors & Community](#-authors--community)

---

## 💡 Executive Summary & Problem Statement

### The Privacy-Compute Bottleneck
High-utility enterprise datasets (e.g., electronic health records, genomic biobanks, financial transaction graphs, satellite imagery) are trapped in isolated institutional silos. Dataset owners cannot publicly share raw data due to:
- Strict regulatory penalties (HIPAA, GDPR, CCPA).
- Intellectual property and trade secret exposure.
- Lack of verifiable trust in decentralized execution.

### The Compute2Dataata Paradigm
**Compute2Dataata** fundamentally solves this through **GenLayer Intelligent Contracts**:
- **Zero Raw Data Exposure**: Models travel to the data enclave, not the other way around.
- **Cryptographic Data Commitments**: Dataset providers lock GEN collateral and register immutable SHA-256 data schemas.
- **Automated Escrow Protocol**: Researchers fund compute jobs with zero gas fees on GenLayer StudioNet.
- **Autonomous Multi-LLM Quorum Verification**: GenLayer validators (running diverse model families like GPT-5.4, Claude 4.6, and Gemini 3) evaluate cryptographic execution proofs against input parameters, releasing escrowed payments to providers or slashing malicious actors automatically.

---

## 🏛️ How It Works: Architectural Overview

```mermaid
sequenceDiagram
    autonumber
    actor Provider as 🏢 Dataset Provider
    participant Contract as ⛓️ C2D Intelligent Contract
    actor Researcher as 🔬 AI Researcher
    participant Enclave as 🛡️ Private Enclave
    participant Quorum as 🤖 GenLayer Multi-LLM Quorum

    Note over Provider,Contract: Phase 1: Collateral & Registration
    Provider->>Contract: stake_provider(25 GEN)
    Provider->>Contract: register_dataset(id, schema, data_commitment, price)
    Contract-->>Provider: 10 GEN Listing Bond Locked

    Note over Researcher,Contract: Phase 2: Compute Request & Escrow
    Researcher->>Contract: request_compute(job_id, model_id, spec, input_hash) + 3 GEN
    Contract-->>Researcher: 3 GEN Escrowed (Job Status: FUNDED)
    Contract-->>Provider: 2 GEN Job Collateral Locked

    Note over Provider,Enclave: Phase 3: Enclave Execution
    Provider->>Enclave: Run model on private dataset rows
    Enclave-->>Provider: Generate output hash & execution proof metadata

    Note over Provider,Quorum: Phase 4: Non-Deterministic AI Verification
    Provider->>Contract: submit_execution_proof(job_id, proof_metadata, proof_hash)
    Contract->>Quorum: gl.vm.run_nondet_unsafe(assess_proof, validate_assessment)
    Quorum->>Quorum: Cross-LLM Evaluation against Cryptographic Commitments

    alt Verdict: VALID (Consensus Achieved)
        Quorum-->>Contract: Verdict: VALID | Violation: NONE
        Contract->>Provider: Transfer 3 GEN Escrow + Unlock 2 GEN Collateral
        Contract-->>Contract: Increment Provider Reputation Score
    else Verdict: INVALID / MALICIOUS
        Quorum-->>Contract: Verdict: INVALID | Violation: MODEL_MISMATCH
        Contract->>Researcher: Refund 3 GEN Escrow + 12 GEN Slashing Reward
        Contract-->>Provider: Slash 12 GEN Collateral & Deactivate Dataset
    else Requester Timeout
        Researcher->>Contract: cancel_expired_job(job_id)
        Contract->>Researcher: 100% Escrow Refunded (3 GEN)
        Contract->>Provider: Collateral Released Without Penalty
    end
```

---

## 🧠 Intelligent Contract Deep Dive (v2.0)

The contract is written in Python for the **GenVM** sandbox, pinned to runner `# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }`.

### 1. Storage Layout & Data Structures
```python
@allow_storage
@dataclass
class Dataset:
    provider: Address
    name: str
    description: str
    schema: str
    data_commitment: str
    access_conditions: str
    price_per_job: u256
    active: bool
    listing_bond: u256
    open_jobs: u256
    total_jobs: u256

@allow_storage
@dataclass
class ComputeJob:
    requester: Address
    provider: Address
    dataset_id: str
    model_id: str
    compute_spec: str
    input_commitment: str
    funded_amount: u256
    status: str                         # FUNDED, VERIFIED, SLASHED, INCONCLUSIVE, CANCELLED, APPEALED
    execution_proof_commitment: str
    proof_metadata: str
    verification_reason: str
    verification_summary: str
    verified: bool
    collateral_amount: u256
    slash_amount: u256
    settlement_amount: u256
    appeal_reason: str                  # [NEW in v2.0]
    appeal_bond: u256                   # [NEW in v2.0]
```

### 2. Complete Method Catalog

| Category | Method | Access / Type | Description |
| :--- | :--- | :--- | :--- |
| **Staking** | `stake_provider()` | `write.payable` | Deposits GEN collateral into the provider balance. |
| **Staking** | `withdraw_stake(amount)` | `write` | Withdraws unbonded available stake to provider wallet. |
| **Datasets** | `register_dataset(...)` | `write` | Locks `10 GEN` listing bond and registers dataset metadata. |
| **Datasets** | `set_dataset_active(...)` | `write` | Toggles dataset availability; unlocks the listing bond when deactivated with 0 open jobs. |
| **Compute** | `request_compute(...)` | `write.payable` | Escrows compute payment and locks `2 GEN` provider collateral. |
| **Compute** | `cancel_expired_job(id)` | `write` | **[v2.0]** Cancels pending job after its deadline, refunds 100% escrow to requester. |
| **Verification**| `submit_execution_proof(...)`| `write` | Deterministic binding + **authentic remote attestation** (`gl.nondet.web.get`), then Multi-LLM consensus review. |
| **Attestation** | `set_attestation_endpoint(url)` | `write` | **[admin]** Repoints the remote attestation authority (https only). |
| **Attestation** | `set_trusted_enclave / set_trusted_signer` | `write` | **[admin]** Manages the `MRENCLAVE` / `MRSIGNER` trust registry. |
| **Disputes** | `appeal_job_verdict(...)` | `write.payable` | **[v2.0]** Files formal dispute with `1 GEN` appeal bond. |
| **Disputes** | `resolve_appeal(id)` | `write` | Re-verifies the appeal evidence through the same authentic attestation path; accept reverses the verdict, reject finalizes it. |
| **Disputes** | `claim_unresolved_appeal(id)` | `write` | **Failsafe** for an unresolved/no-quorum appeal: returns the bond and, for an inconclusive-origin appeal, fully releases escrow + collateral. |
| **Analytics** | `get_marketplace_stats()` | `view` | **[v2.0]** Returns TVL, total escrow, slashed funds, job counts. |
| **Attestation** | `get_attestation_config()` | `view` | Returns the active attestation endpoint and OK status token. |
| **Analytics** | `get_provider_reputation(addr)`| `view` | **[v2.0]** Computes provider reliability percentage (0-100%). |
| **Queries** | `get_dataset(id)` | `view` | Returns complete metadata for a dataset. |
| **Queries** | `list_dataset_ids()` | `view` | Returns list of all registered dataset keys. |
| **Queries** | `get_job(id)` | `view` | Returns complete state and proofs for a compute job. |
| **Queries** | `list_job_ids()` | `view` | Returns list of all job IDs. |
| **Queries** | `get_provider(addr)` | `view` | Returns total, locked, slashed, and available stake. |
| **Queries** | `get_market_config()` | `view` | Returns protocol collateral parameters. |

---

## 🛠️ Spec-Driven Development (GitHub Spec Kit)

Compute2Dataata follows the rigorous **Spec-Driven Development (SDD)** process powered by [GitHub Spec Kit](https://github.com/github/spec-kit):

```text
 📜 .specify/memory/constitution.md     --> Project Non-Negotiables & GenLayer Rules
 📝 specs/001-compute2data-marketplace  --> Baseline Market Architecture & Quorum
 🚀 specs/002-c2d-contract-levelup      --> v2.0 Upgrades (Timeouts, Appeals, Reputation)
 🤖 .github/skills/speckit-*            --> AI Assisted Spec Generation & Verification
```

---

## 🌐 Live On-Chain Deployment & Proofs

### GenLayer StudioNet Specifications

| Parameter | On-Chain Value |
| :--- | :--- |
| **Network Name** | `GenLayer StudioNet` (Stable, Gasless AI Sandbox) |
| **Chain ID** | `61999` (`0xF22F`) |
| **Native Token** | **GEN** |
| **RPC Endpoint** | `https://studio.genlayer.com/api` |
| **Explorer** | `https://explorer-studio.genlayer.com` |
| **Active Contract (authentic attestation)** | [`0x56d484AAe50070BE82CcB6F888E8fC51124C2EDd`](https://explorer-studio.genlayer.com/address/0x56d484AAe50070BE82CcB6F888E8fC51124C2EDd) |
| **Deployer Address** | `0x91b82b1F3317B7C141ba6Cbdd0b666AA563b9cDb` |
| **Deployment Transaction**| `0x059168ed040823a2df20158587a52d9d007b3d3b2e098c6b798f6748d1cd33be` |
| **Consensus Receipt** | `ACCEPTED` / `MAJORITY_AGREE` (100% Validator Agreement) |

---

## ⚡ Step-by-Step Developer Quickstart

### 1. Prerequisites
- **Python 3.10+** (isolated via `uv` or `pipx`)
- **Node.js 18+** & `npm`
- **GenVM Linter & Test Harness**:
```bash
pipx install genvm-lint
pipx install genlayer-test
```

### 2. Clone & Run Automated Tests
```bash
git clone https://github.com/SOBEK96/Compute2Data.git
cd Compute2Dataata

# Run 100% automated lint and test suite
./run_tests.sh
```
Expected output:
```text
✓ Lint passed (3 checks)
✓ Validation passed
  Contract: C2DMarketplace
  Methods: 17 (8 view, 9 write)
============================== 11 passed in 0.26s ==============================
```

### 3. Start the Modern Next.js 14 Web App
```bash
cd apps/web
npm install
npm run build
npm run start -- -p 3000
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser!

---

## 📐 Mathematical Models & Slashing Economics

### 1. Collateral Locking Invariants
For any provider $P$, the total collateral $C_{\text{total}}$ must always satisfy:
$$C_{\text{total}} \ge C_{\text{locked}} = (N_{\text{datasets}} \times B_{\text{listing}}) + (N_{\text{active\_jobs}} \times B_{\text{job}})$$
where:
- $B_{\text{listing}} = 10 \text{ GEN}$ (Listing bond)
- $B_{\text{job}} = 2 \text{ GEN}$ (Per-job active execution bond)

### 2. Slashing Equation
Upon an `INVALID` verdict, the slashed penalty $S$ awarded to the researcher is:
$$S = B_{\text{job}} + B_{\text{listing}} = 12 \text{ GEN}$$
The researcher receives a total settlement $R$:
$$R = \text{Funded Escrow} + S = 3 \text{ GEN} + 12 \text{ GEN} = 15 \text{ GEN}$$

### 3. Dynamic Provider Reputation
The on-chain reputation score $\rho \in [0, 100]$ is computed deterministically:
$$\rho = \begin{cases} 100 & \text{if } J_{\text{completed}} = 0 \\ \lfloor \frac{J_{\text{success}} \times 100}{J_{\text{completed}}} \rfloor & \text{if } J_{\text{completed}} > 0 \end{cases}$$

---

## 🛡️ Security & Prompt Injection Defenses

The contract utilizes GenLayer's non-deterministic AI sandbox with strict prompt sanitization:

```python
# Untrusted metadata is quarantined inside explicit containment tags
UNTRUSTED_EVIDENCE_JSON_BEGIN
{evidence_json}
UNTRUSTED_EVIDENCE_JSON_END
```

### Security Defenses:
1. **Untrusted Data Isolation**: The LLM prompt explicitly instructs validators that JSON evidence is untrusted data and forbids executing embedded commands.
2. **Reentrancy Protection**: GenLayer's transaction model and `_Recipient.emit_transfer(..., on="finalized")` prevents cross-contract reentrancy.
3. **Deterministic State Guards**: All state checks (balance validation, permissions, existence) occur in deterministic Python *before* entering `gl.vm.run_nondet_unsafe`.

### 🔒 Authentic TEE Attestation Verification

> **Authenticity is established by an independent remote attestation authority, not by any hash the contract re-derives from public values.**

The contract **no longer** re-derives an enclave signature from public values on chain.
An attacker who knows only the public `MRENCLAVE` / `MRSIGNER` / `report_data` can no
longer fabricate an acceptance, because those public values cannot make a real
attestation authority vouch for a quote that no genuine enclave signed. Verification is
layered across two complementary checks:

**1. Deterministic five-field binding (network-free, `_inspect_enclave_quote`).**
`report_data` must equal the canonical digest over
`dataset_commitment | input(workload)_commitment | model_id | compute_spec_commitment |
output_commitment` (`_binding_digest`). Substituting *any* committed field yields a
different binding and is rejected on-chain with a deterministic code
(`DATASET_MISMATCH`, `INPUT_COMMITMENT_MISMATCH`, `MODEL_MISMATCH`,
`COMPUTE_SPEC_MISMATCH`, `BINDING_MISMATCH`, …) before any network I/O.

**2. Authentic remote attestation (`_authenticate_quote`).** The opaque quote is
submitted to an Intel **DCAP/PCS or IAS** style verifier over `gl.nondet.web.get`,
wrapped in `gl.eq_principle.strict_eq` so **every validator independently re-verifies the
quote and must agree on the exact verdict**. The authority cryptographically checks the
DCAP/ECDSA quote against Intel's collateral and returns the *authenticated* measurements,
`report_data`, and a TCB status. The contract trusts **only** what the authority returns
and then:

- requires the authority's status to be `OK` — any other value (`SIGNATURE_INVALID`,
  `QUOTE_EXPIRED`, `GROUP_OUT_OF_DATE`, an `ATTESTATION_HTTP_5xx` transport failure, …)
  is carried straight through as a deterministic settlement/slash code;
- binds the verdict to the exact quote by requiring the authenticated
  `MRENCLAVE`/`MRSIGNER`/`report_data` to match both the quote's claim and the on-chain
  five-field binding (`ATTESTATION_REPORT_MISMATCH` otherwise), so an `OK` verdict for
  some other quote cannot be replayed against this job;
- checks the *authenticated* `MRENCLAVE`/`MRSIGNER` against the admin **trust registry**
  (`trusted_enclaves` / `trusted_signers`).

Because the verdict flows through `strict_eq`, a **browser-fabricated attestation reverts
deterministically** — every validator reaches the same rejection. The attestation
endpoint is admin-configurable at runtime via `set_attestation_endpoint(...)` (https
only) and exposed through `get_attestation_config()`. This path is verified end-to-end in
`tests/direct/test_authentic_attestation.py` (genuine acceptance, browser fabrication,
authority outage, identity mismatch, endpoint rotation).

### ⚖️ Inconclusive & Unresolved Appeal Handling

Every settlement path is terminal and moves escrow, collateral, and appeal bond
deterministically — funds can **never** be stranded, even when consensus cannot decide.

- **Inconclusive verdict (no appeal).** When the semantic review returns `INCONCLUSIVE`,
  the job holds its escrow and collateral open for the provider's appeal window. If the
  provider never appeals, `cancel_expired_job` refunds 100% of the escrow to the
  requester and releases the collateral once that window closes.
- **Unresolved / no-quorum appeal (failsafe).** If a filed appeal is never adjudicated
  within its window — i.e. it fails to reach quorum or otherwise resolves to an
  inconclusive state — `claim_unresolved_appeal` is the failsafe. It **always** returns
  the bond to the provider, and for an **inconclusive-origin** appeal (where escrow and
  collateral are still live) it **fully unwinds the job**: 100% of the buyer escrow is
  refunded to the requester and 100% of the provider collateral is released. **Nobody is
  slashed**, because the protocol could not establish fault (`total_slashed` is
  unchanged; the job settles to `CANCELLED` with reason `APPEAL_INCONCLUSIVE_RELEASED`).
- **Adjudicated appeal.** `resolve_appeal` re-runs the appeal evidence through the same
  authentic attestation path: an accept restores/settles funds to the provider, a reject
  finalizes the slash and forfeits the bond to the requester.

This failsafe is proven by
`tests/direct/test_compute_data_regression.py::test_unresolved_inconclusive_appeal_releases_escrow_and_collateral`,
which asserts 100% escrow release **and** 100% collateral release with zero slashing.

---

## 📂 Project Structure

```text
Compute2Dataata/
├── contracts/
│   └── c2d_marketplace.py         # 🐍 GenLayer Intelligent Contract (v2.0)
├── test/
│   ├── conftest.py                # 🧪 Pytest Fixtures & Mocks
│   └── test_c2d_marketplace.py   # 🧪 11 Unit & Attack Scenario Tests
├── specs/                         # 📜 GitHub Spec Kit Specifications
│   ├── 001-compute2data-autonomous-marketplace/
│   └── 002-c2d-contract-levelup/
├── scripts/
│   ├── fresh_deploy.mjs           # 🚀 Deployment Script
│   └── init_new_contract.mjs      # ⚡ Genesis On-Chain Staking & Registration
├── apps/
│   └── web/                       # 🌐 Next.js 14 App Router Frontend
│       ├── app/                   # App pages (/, /provider)
│       ├── components/            # AppShell, MarketplaceDiscovery, DatasetCard, Modals
│       └── lib/                   # contract.ts, market-data.ts
├── run_tests.sh                   # 🛠️ Automated CI Test Runner
└── README.md                      # 📖 Master Educational Documentation
```

---

## 👥 Authors & Community

- **Architect & Lead Developer**: [Sobek (@SOBEK96)](https://github.com/SOBEK96)
- **Built for**: [GenLayer Ecosystem](https://genlayer.com)
- **Framework**: GitHub Spec Kit (Spec-Driven Development)

<p align="center">
  <b>Built with ❤️ on GenLayer — Intelligent Contracts for Autonomous AI Systems.</b>
</p>
