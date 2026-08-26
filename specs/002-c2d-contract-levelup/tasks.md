# Actionable Implementation Tasks: C2D Contract Level-Up v2.0

**Feature ID**: `002-c2d-contract-levelup`  
**Specification**: [`specs/002-c2d-contract-levelup/spec.md`](file:///Users/ehs4n/Compute2Data/specs/002-c2d-contract-levelup/spec.md)  
**Plan**: [`specs/002-c2d-contract-levelup/plan.md`](file:///Users/ehs4n/Compute2Data/specs/002-c2d-contract-levelup/plan.md)  
**Deployed Contract Address**: `0xD63B71E7cC32C8A81dFd1A26b89D4c059BE15226`  
**Status**: `100% COMPLETED & VERIFIED ON STUDIONET`

---

## Phase 1: Contract Implementation (contracts/c2d_marketplace.py)

- [x] **TASK-002-1**: Update `ComputeJob` dataclass with `appeal_reason` and `appeal_bond`.
- [x] **TASK-002-2**: Add protocol state fields (`minimum_appeal_bond`, `provider_successful_jobs`, `provider_failed_jobs`, `provider_appealed_jobs`).
- [x] **TASK-002-3**: Implement `cancel_expired_job(job_id: str)` with refund and collateral release.
- [x] **TASK-002-4**: Implement `appeal_job_verdict(job_id: str, appeal_justification: str, attestation_evidence: str)` payable method.
- [x] **TASK-002-5**: Implement `get_provider_reputation(provider_address: str)` view method.
- [x] **TASK-002-6**: Implement `get_marketplace_stats()` view method.
- [x] **TASK-002-7**: Run `genvm-lint check contracts/c2d_marketplace.py` and ensure 3/3 checks pass (17 methods: 8 view, 9 write).

---

## Phase 2: Unit Testing & Coverage (test/test_c2d_marketplace.py)

- [x] **TASK-002-8**: Implement unit tests for `cancel_expired_job` (authorized requester & refund verification).
- [x] **TASK-002-9**: Implement unit tests for unauthorized cancellation rejection.
- [x] **TASK-002-10**: Implement unit tests for `appeal_job_verdict` with appeal bond.
- [x] **TASK-002-11**: Implement unit tests for `get_provider_reputation` calculation.
- [x] **TASK-002-12**: Implement unit tests for `get_marketplace_stats`.
- [x] **TASK-002-13**: Run `./run_tests.sh` and ensure all tests pass (11/11 passed, 100%).

---

## Phase 3: Deployment & Live StudioNet Verification

- [x] **TASK-002-14**: Deploy upgraded v2 contract (enclave attestation + full state machine) to GenLayer StudioNet (`0xD63B71E7cC32C8A81dFd1A26b89D4c059BE15226`, Tx `0x5ab76291694bdeeacd327e49eedbdad8f4d98037f8bb7c2c8069a37531210231`).
- [x] **TASK-002-15**: Verify on-chain consensus receipt (`MAJORITY_AGREE`, Tx `0x3b1464a9b5c01cd3c656f9c2520a7112387c580a2ac8d3f78c8cf3b7097294b2`).
- [x] **TASK-002-16**: Test live on-chain staking (`0x442f7c79...`), dataset registration (`0x98549949...`), job escrow (`0x1bcb6db0...`), and reputation queries.
- [x] **TASK-002-17**: Update frontend `.env.local` and `contract.ts`.
- [x] **TASK-002-18**: Commit all v2 artifacts to git repository on branch `main`.
