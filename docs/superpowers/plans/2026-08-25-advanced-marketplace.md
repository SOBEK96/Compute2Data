# Advanced Compute2Data Marketplace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add collateral-backed dataset listings, consensus-enforced slashing, direct-mode contract tests, and a connected premium marketplace interface.

**Architecture:** Each active dataset locks an isolated provider bond from GEN deposited into the contract. Compute payments remain escrowed until a comparative GenLayer AI decision marks an execution proof valid, invalid, or inconclusive; valid work pays the provider, invalid work refunds escrow plus slashed collateral to the requester, and inconclusive work remains open. The Next.js app uses a wallet context and a small GenLayer client layer so marketplace and provider routes share transaction and read behavior.

**Tech Stack:** GenLayer Python SDK, `genlayer-test`, pytest, Next.js 14, React 18, TypeScript, Tailwind CSS 3, `genlayer-js`, Lucide React.

## Global Constraints

- Keep the pinned production GenVM runner hash on the first contract line.
- Use `u256`, `TreeMap`, `DynArray`, and storage dataclasses for persisted contract state.
- Use `gl.vm.run_nondet_unsafe` with independent validator re-execution and stable decision-field comparison.
- Store no raw dataset content on-chain or in validator prompts.
- Use only standard English and no Persian, RTL, localized strings, names, comments, or configuration.
- Build responsive desktop and mobile interfaces with keyboard focus and reduced-motion support.

---

### Task 1: Collateralized Contract Settlement

**Files:**
- Modify: `contracts/c2d_marketplace.py`
- Test: `test/test_c2d_marketplace.py`

**Interfaces:**
- Consumes: payable GEN deposits through `gl.message.value`.
- Produces: `stake_provider()`, `withdraw_stake(amount)`, bonded `register_dataset(...)`, `get_provider(address)`, and a three-outcome `submit_execution_proof(...)` settlement.

- [ ] Add provider stake, locked stake, slash history, active dataset count, dataset bond, and open-job state fields.
- [ ] Require one minimum bond per active dataset and release only unused collateral.
- [ ] Compare proof commitments and execution claims against the original dataset and compute request in an injection-resistant prompt.
- [ ] Require validators to independently rerun assessment and agree on both verdict and violation code.
- [ ] Pay providers for valid work, slash and compensate requesters for invalid work, and leave inconclusive work funded for resubmission.
- [ ] Run `genvm-lint check contracts/c2d_marketplace.py` and expect contract validation to pass.

### Task 2: Direct Consensus Tests

**Files:**
- Create: `test/conftest.py`
- Create: `test/test_c2d_marketplace.py`
- Create: `pyproject.toml`

**Interfaces:**
- Consumes: direct-mode fixtures, payable VM value, and `mock_llm` responses.
- Produces: coverage for staking gates, valid settlement, malicious slashing, authorization, and validator agreement/disagreement.

- [ ] Build reusable helpers that stake, register, and fund a deterministic job.
- [ ] Test that unstaked providers cannot list and unavailable stake cannot be withdrawn.
- [ ] Mock `VALID` proof consensus and assert provider stake remains locked and the job becomes `VERIFIED`.
- [ ] Mock `INVALID` proof consensus and assert escrow refund, slash amount, dataset suspension, and provider accounting.
- [ ] Swap validator mocks after leader execution and assert matching decisions agree while conflicting decisions disagree.
- [ ] Run `pytest test -v` and expect all cases to pass.

### Task 3: Tailwind Marketplace Application

**Files:**
- Modify: `apps/web/package.json`
- Create: `apps/web/tailwind.config.ts`
- Create: `apps/web/postcss.config.mjs`
- Modify: `apps/web/app/globals.css`
- Modify: `apps/web/app/layout.tsx`
- Modify: `apps/web/app/page.tsx`
- Create: `apps/web/app/provider/page.tsx`
- Create: `apps/web/components/app-shell.tsx`
- Create: `apps/web/components/wallet-provider.tsx`
- Create: `apps/web/components/dataset-card.tsx`
- Create: `apps/web/components/compute-request-modal.tsx`
- Create: `apps/web/components/provider-console.tsx`
- Create: `apps/web/lib/contract.ts`
- Create: `apps/web/lib/market-data.ts`
- Create: `apps/web/types/ethereum.d.ts`

**Interfaces:**
- Consumes: `NEXT_PUBLIC_C2D_CONTRACT_ADDRESS`, browser EIP-1193 wallet provider, and GenLayer Bradbury RPC.
- Produces: connected wallet state, contract reads, payable compute and stake writes, dataset registration, discovery route, modal flow, and provider route.

- [ ] Configure Tailwind tokens for carbon, cobalt, mineral mint, warm white, and status colors.
- [ ] Build a responsive shell with route navigation, network status, and wallet controls.
- [ ] Read contract datasets when an address is configured and retain explicit demo data when it is not.
- [ ] Build filterable dataset cards and an accessible compute-request dialog.
- [ ] Build provider stake controls, collateral metrics, dataset registration, and workload status views.
- [ ] Route every transaction through `genlayer-js`, await accepted consensus, and expose pending, success, and error states.
- [ ] Run `npm run lint`, `npm run typecheck`, and `npm run build`; expect all commands to exit successfully.

### Task 4: Final Compliance Verification

**Files:**
- Modify: `README.md`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: completed contract, tests, and frontend.
- Produces: setup instructions and reproducible verification commands.

- [ ] Document stake/slash economics, environment variables, frontend commands, and test commands.
- [ ] Search first-party source and configuration files for Persian and RTL Unicode ranges and expect zero matches.
- [ ] Rerun contract lint, pytest, frontend lint, typecheck, and production build against the final state.
