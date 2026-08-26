# Feature Specification: Compute2Data Intelligent Contract v2.0 Level-Up

**Feature ID**: `002-c2d-contract-levelup`  
**Status**: `APPROVED / IN IMPLEMENTATION`  
**Network**: `GenLayer StudioNet`  
**Author**: [Saeid (@SOBEK96)](https://github.com/SOBEK96)

---

## 1. Executive Summary & Goals

The goal of this upgrade is to evolve the `C2DMarketplace` intelligent contract into a **production-grade, dispute-resilient, and reputation-tracked Compute-to-Data protocol** on GenLayer.

### 1.1 Core Problems Solved
1. **Unresponsive Provider Lockup**: In v1.0, if a dataset provider never submits execution proof after a requester funds a job, the escrowed GEN remains locked indefinitely.
2. **AI Dispute Inflexibility**: In v1.0, an `INVALID` verdict immediately slashes the provider without an opportunity for technical appeal with enclave hardware attestation logs.
3. **Lack of Historical Reputation**: Requesters have no on-chain metrics to verify provider reliability before funding expensive training jobs.
4. **Scattered Metrics**: Protocol analytics required multiple separate view queries.

---

## 2. Functional Requirements (FR)

### FR-101: Job Cancellation & Escrow Auto-Refund (`cancel_expired_job`)
- Requesters can cancel a funded compute job if the provider has not submitted an execution proof within a reasonable window or if explicitly cancelled prior to proof intake.
- When cancelled:
  - Job status updates to `CANCELLED`.
  - 100% of the `funded_amount` is refunded to the `requester`.
  - Provider's collateral allocated to the job is released back to available stake.
  - Active jobs counter on the dataset is decremented.

### FR-102: On-Chain Appeal & Challenge Mechanism (`appeal_job_verdict`)
- If a job receives an `INVALID` or `INCONCLUSIVE` verdict, the dataset provider can file a formal on-chain appeal.
- Requires posting a configurable **Appeal Bond** (`1 GEN`).
- Records the `appeal_reason` and `attestation_evidence` in job storage.
- Updates job status to `APPEALED`, triggering secondary validator quorum review.

### FR-103: Provider Reputation Scoring (`get_provider_reputation`)
- Contract tracks on-chain lifecycle metrics for each provider:
  - `successful_jobs`: Total jobs verified and paid.
  - `failed_jobs`: Total jobs slashed due to invalid proofs.
  - `appealed_jobs`: Total disputes filed.
  - `reputation_score`: Score computed as `(successful_jobs * 100) / total_completed_jobs` (base 100).
- Public view method `get_provider_reputation(provider: Address) -> dict`.

### FR-104: Global Protocol Metrics Aggregator (`get_marketplace_stats`)
- Single aggregated query returning:
  - `total_staked`: Total collateral deposited.
  - `total_escrowed`: Total compute funds processed.
  - `total_slashed`: Total penalties collected.
  - `total_datasets`: Count of active data surfaces.
  - `total_jobs`: Total compute jobs created across protocol.

---

## 3. Storage Schema Evolution

```python
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
    appeal_reason: str                  # [NEW v2.0]
    appeal_bond: u256                   # [NEW v2.0]
```

---

## 4. Verification & Testing Requirements

- [ ] All new methods must pass `genvm-lint check` (3/3 checks passed).
- [ ] Unit tests for `cancel_expired_job` (authorized requester only, status check).
- [ ] Unit tests for `appeal_job_verdict` (bond requirements, status transition).
- [ ] Unit tests for `get_provider_reputation` and `get_marketplace_stats`.
- [ ] Live deployment to GenLayer StudioNet with transaction receipts verified.
