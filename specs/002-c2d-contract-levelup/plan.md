# Technical Implementation Plan: Compute2Data v2.0 Level-Up

**Specification**: [`specs/002-c2d-contract-levelup/spec.md`](file:///Users/ehs4n/Compute2Data/specs/002-c2d-contract-levelup/spec.md)  
**Target File**: `contracts/c2d_marketplace.py`  
**Test File**: `test/test_c2d_marketplace.py`

---

## 1. Method Signatures to Implement

### 1.1 `cancel_expired_job` (Write)
```python
@gl.public.write
def cancel_expired_job(self, job_id: str) -> None:
    """Allow requester to cancel a funded job before proof is submitted and recover 100% escrow."""
```
**Validation Logic**:
- `job_id` exists in `self.jobs`.
- `job.status == "FUNDED"`.
- `gl.message.sender_address == job.requester`.
- Decrement `dataset.open_jobs`.
- Unlock provider collateral (`collateral_amount`).
- Refund `job.funded_amount` to `requester` via `_Recipient.emit_transfer`.
- Update `job.status = "CANCELLED"`.

### 1.2 `appeal_job_verdict` (Write, Payable)
```python
@gl.public.write.payable
def appeal_job_verdict(
    self,
    job_id: str,
    appeal_justification: str,
    attestation_evidence: str,
) -> None:
    """Allow dataset provider to post an appeal bond and dispute an INVALID/INCONCLUSIVE verdict."""
```
**Validation Logic**:
- `job_id` exists in `self.jobs`.
- `job.status in ("SLASHED", "INCONCLUSIVE")`.
- `gl.message.sender_address == job.provider`.
- `gl.message.value >= self.minimum_appeal_bond` (`1 GEN`).
- Update `job.status = "APPEALED"`.
- Store `job.appeal_reason` and record appeal metrics.

### 1.3 `get_provider_reputation` (View)
```python
@gl.public.view
def get_provider_reputation(self, provider: Address) -> dict:
    """Return historical job statistics and calculated reliability rating for a provider."""
```

### 1.4 `get_marketplace_stats` (View)
```python
@gl.public.view
def get_marketplace_stats(self) -> dict:
    """Return global protocol aggregate metrics."""
```

---

## 2. Testing Strategy

1. `test_requester_can_cancel_funded_job_and_receive_refund`: Test clean cancellation and balance unlock.
2. `test_non_requester_cannot_cancel_job`: Test access control error `[EXPECTED]`.
3. `test_cannot_cancel_verified_or_slashed_job`: Test state transition error `[EXPECTED]`.
4. `test_provider_can_appeal_slashed_job_with_bond`: Test appeal submission and status update.
5. `test_reputation_and_marketplace_stats_accuracy`: Test dynamic scoring calculation.
