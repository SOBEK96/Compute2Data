# Technical Implementation Plan: Compute2Data Protocol

**Specification**: [`specs/001-compute2data-autonomous-marketplace/spec.md`](file:///Users/ehs4n/Compute2Data/specs/001-compute2data-autonomous-marketplace/spec.md)  
**Status**: `COMPLETED & RATIFIED`  
**Network**: `GenLayer StudioNet`  
**Contract**: [`0xd1635bd866F6fd616Da1F1EBFFB686D9c01032F9`](file:///Users/ehs4n/Compute2Data/contracts/c2d_marketplace.py)

---

## 1. Technical Architecture & Component Layout

```
├── contracts/
│   └── c2d_marketplace.py         # GenLayer Intelligent Contract (GenVM Python)
│                                  # 12 Methods: 6 View, 6 Write (Staking, Listing, Escrow, AI Proof, Slashing)
├── apps/
│   └── web/                       # Next.js 14 Web3 Application
│       ├── app/                   # App Router Pages (/, /provider, layout, globals.css)
│       ├── components/            # AppShell, MarketplaceDiscovery, DatasetCard, ProviderConsole, Modals
│       └── lib/                   # contract.ts, market-data.ts
├── test/
│   ├── conftest.py                # GenLayer Direct Test Fixtures
│   └── test_c2d_marketplace.py   # 7 Comprehensive Pytest Unit Tests
└── scripts/
    ├── execute_onchain_flow.mjs   # Automated Staking & Job Request Script
    └── submit_proof.mjs           # Multi-LLM AI Consensus Proof Submission Script
```

---

## 2. Smart Contract Data Structures & Storage Layout

### 2.1 Storage Dataclasses
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
    status: str                         # FUNDED, VERIFIED, SLASHED, INCONCLUSIVE
    execution_proof_commitment: str
    proof_metadata: str
    verification_reason: str
    verification_summary: str
    verified: bool
    collateral_amount: u256
    slash_amount: u256
    settlement_amount: u256
```

---

## 3. Multi-LLM Non-Deterministic Quorum Consensus Architecture

The contract implements `gl.vm.run_nondet_unsafe` with a structured system prompt:
1. **Prompt Sanitization**: Evidence JSON is wrapped in `UNTRUSTED_EVIDENCE_JSON_BEGIN` and `UNTRUSTED_EVIDENCE_JSON_END`.
2. **Deterministic Rules**: Models are instructed never to request raw dataset access and to verify cryptographic bindings between `input_commitment`, `compute_spec`, `data_commitment`, and `proof_commitment`.
3. **Structured Schema**:
```json
{
  "verdict": "VALID" | "INVALID" | "INCONCLUSIVE",
  "violation_code": "NONE" | "MODEL_MISMATCH" | "SPEC_VIOLATION" | "INSUFFICIENT_EVIDENCE",
  "summary": "Detailed explanation of consensus decision"
}
```

---

## 4. Frontend Design System

- **Framework**: Next.js 14.2 (App Router) + React 18
- **Styling**: Vanilla TailwindCSS with Cyber Glow, Glassmorphism, and JetBrains Mono typography.
- **Web3 Integration**: `genlayer-js` + EIP-1193 MetaMask provider with automatic StudioNet network addition (`0x7a120`).

---

## 5. Security & Verification Strategy

1. **Lint Verification**: `genvm-lint check contracts/c2d_marketplace.py`.
2. **Automated Unit Tests**: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -p gltest_direct -v`.
3. **On-Chain Deployment**: Live deployment with `genlayer deploy` capturing transaction receipt with `MAJORITY_AGREE`.
4. **End-to-End Flow**: Execute live transactions testing staking, dataset listing, job escrow, and proof verification.
