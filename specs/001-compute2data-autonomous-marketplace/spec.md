# Feature Specification: Compute2Data Autonomous Marketplace

**Feature ID**: `001-compute2data-autonomous-marketplace`  
**Status**: `RATIFIED / IMPLEMENTED`  
**Network**: `GenLayer StudioNet`  
**Contract Address**: `0xd1635bd866F6fd616Da1F1EBFFB686D9c01032F9`  
**Author**: [Saeid (@SOBEK96)](https://github.com/SOBEK96)

---

## 1. Executive Summary & Problem Statement

### 1.1 The Privacy-Compute Dilemma
Modern AI innovation is bottle-necked by access to high-value private datasets (electronic health records, institutional financial transaction graphs, satellite imagery, mobility telemetry). Dataset providers cannot publish raw data without risking privacy violations, regulatory fines, and intellectual property theft.

### 1.2 The Compute2Data Solution
Compute2Data establishes a **non-custodial Compute-to-Data marketplace** on GenLayer. 
- Dataset providers lock **GEN collateral** and publish cryptographically committed dataset schemas (`data_commitment`).
- AI researchers submit compute requests with model specifications and **GEN escrow**.
- Computation runs inside private enclaves without exposing raw rows.
- **GenLayer's Multi-LLM AI Validator Quorum** evaluates execution proof metadata against input and dataset commitments to autonomously release escrow payments or slash malicious providers.

---

## 2. User Personas & Core Workflows

```
  ┌──────────────────────┐         ┌───────────────────────────┐         ┌────────────────────────┐
  │   Dataset Provider   │         │   GenLayer Intelligent    │         │     AI Researcher      │
  │                      │         │         Contract          │         │                        │
  └──────────┬───────────┘         └─────────────┬─────────────┘         └───────────┬────────────┘
             │                                   │                                   │
             │ 1. stake_provider(25 GEN)         │                                   │
             ├──────────────────────────────────►│                                   │
             │                                   │                                   │
             │ 2. register_dataset(schema, hash) │                                   │
             ├──────────────────────────────────►│                                   │
             │                                   │                                   │
             │                                   │ 3. request_compute(priceWei)      │
             │                                   │◄──────────────────────────────────┤
             │                                   │ (3 GEN locked in Escrow)          │
             │                                   │                                   │
             │ 4. Run enclave & submit_proof()   │                                   │
             ├──────────────────────────────────►│                                   │
             │                                   │                                   │
             │                                   │ 5. Multi-LLM AI Quorum (GPT/Claude)│
             │                                   │    Consensus: VALID / INVALID     │
             │                                   │                                   │
             │ 6. Autonomous Escrow Settlement   │                                   │
             │◄──────────────────────────────────┤                                   │
             │ (Provider receives 3 GEN)         │                                   │
             │                                   │                                   │
```

### 2.1 Persona A: High-Security Dataset Provider
1. Connects Web3 wallet to GenLayer StudioNet.
2. Deposits at least `10 GEN` dataset listing bond plus `2 GEN` per-job collateral.
3. Publishes dataset metadata: identifier, title, description, schema, access conditions, and SHA-256 data commitment.
4. Monitors incoming compute jobs and executes jobs in isolated environments.
5. Submits execution proof metadata and cryptographic output hashes to trigger on-chain settlement.

### 2.2 Persona B: AI Researcher / Model Scientist
1. Discovers bonded datasets across categories (Genomics, Finance, Mobility, Climate, NLP).
2. Configures compute parameters (Model ID, Task Specification, Input Commitment).
3. Locks compute fee in smart contract escrow with 0 gas fees on StudioNet.
4. Receives cryptographically verified training results or automatic 100% refund in case of proof rejection.

---

## 3. Functional Requirements (FR)

| ID | Requirement Name | Description |
| :--- | :--- | :--- |
| **FR-001** | **Collateral Staking** | Providers must deposit GEN collateral (`stake_provider`). Minimum listing bond is `10 GEN`. |
| **FR-002** | **Bond Locking** | Active dataset listings lock `10 GEN` from the provider's available stake, preventing withdrawal while active. |
| **FR-003** | **Dataset Registration** | Providers register unique dataset IDs with cryptographic data commitments and access policies (`register_dataset`). |
| **FR-004** | **Compute Request & Escrow** | Requesters fund jobs matching the exact dataset price (`request_compute`). Funds are locked in contract escrow. |
| **FR-005** | **Proof Submission Control** | Only the registered provider of the specific dataset can submit execution proofs (`submit_execution_proof`). |
| **FR-006** | **AI Quorum Consensus** | GenLayer validators evaluate proof metadata against request parameters via `gl.vm.run_nondet_unsafe`. |
| **FR-007** | **Equivalence Principle** | Validators must achieve non-deterministic consensus (`MAJORITY_AGREE`) across multiple LLM families (GPT-5.4, Claude 4.6, Gemini 3). |
| **FR-008** | **Autonomous Payout** | Upon `VALID` verdict, escrowed funds are transferred to the provider and collateral is unlocked. |
| **FR-009** | **Malicious Slashing** | Upon `INVALID` verdict, provider collateral is slashed and 100% of escrow is refunded to the requester. |
| **FR-010** | **Inconclusive Hold** | Upon `INCONCLUSIVE` verdict, funds and collateral remain safely locked for further evidence. |
| **FR-011** | **Collateral Withdrawal** | Providers can withdraw unbonded available stake at any time (`withdraw_stake`). |
| **FR-012** | **State Observability** | Public view methods allow real-time queries for datasets, jobs, provider stakes, and protocol statistics. |

---

## 4. Security & Error Classification

- **`[EXPECTED]` Deterministic Errors**:
  - `Available stake is below the dataset bond`
  - `Stake amount must be greater than zero`
  - `Only the dataset provider can submit proof`
  - `Job does not exist` / `Job is not awaiting proof`
- **`[LLM_ERROR]` Non-Deterministic Transient Errors**:
  - Model timeout, rate-limiting, or JSON parsing mismatch triggering validator rotation.

---

## 5. Verification & Acceptance Criteria

- [x] **Linting**: `genvm-lint check` passes 3/3 checks on `C2DMarketplace`.
- [x] **Unit Testing**: 7/7 Pytest unit tests pass in `< 0.2s`.
- [x] **On-Chain Deployment**: Live on GenLayer StudioNet at `0xd1635bd866F6fd616Da1F1EBFFB686D9c01032F9`.
- [x] **Real Transactions**: Provider staking, dataset registration, job escrow, and AI proof evaluation verified on-chain.
- [x] **Frontend Web App**: Next.js 14 App Router, Glassmorphism design system, MetaMask integration, and live deployment on `http://localhost:3000`.
