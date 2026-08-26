# Compute2Data & GenLayer Spec-Driven Development Constitution

## Core Principles

### I. GenLayer Intelligent Contract Purity
- Contracts MUST pin an immutable GenVM runner hash (e.g. `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`).
- Storage structures MUST use GenLayer types (`TreeMap`, `Array`, `Address`, `u256`, `@allow_storage`).
- Non-deterministic operations (AI LLM prompting, web scraping) MUST adhere to the Equivalence Principle and be evaluated strictly within `gl.vm.run_nondet_unsafe`.
- Error handling must classify deterministic vs transient/LLM errors explicitly (`[EXPECTED]` vs `[LLM_ERROR]`).

### II. Test-Driven Verification (NON-NEGOTIABLE)
- All contract logic MUST pass `genvm-lint check` (3/3 checks) with 0 errors.
- Unit tests (`tests/direct/`) and exploit scenarios MUST pass with 100% success rate before deployment.
- Tests MUST execute in isolated environments with `pytest.ini` (`-p no:hydra_pytest -p gltest_direct`).

### III. Modern, Ultra-Clean Frontend Standards
- Built with modern Next.js (App Router), TailwindCSS, and custom Glassmorphism/Cyber Mesh aesthetics.
- Strict dark mode support, glowing gradients, micro-animations, and high-DPI responsive design.
- Zero broken routes, zero missing dependencies, and zero build warnings (`tsc --noEmit` + `next build` clean).

### IV. Web3 Wallet & Network Compliance
- Native network token MUST be named **GEN**.
- MetaMask network switcher must target GenLayer StudioNet (`Chain ID: 0x7a120` / `500000`).
- Header must include active address indicator, copy tool, and dedicated red Disconnect action.

### V. Security Hygiene & Author Attribution
- 0 leaks of local usernames or absolute filepaths.
- Official Project Author: **Saeid** ([@Handik4](https://github.com/Handik4)).
- Comprehensive `.gitignore` filtering virtual environments, keystores, build caches, and OS artifacts.

## Governance
This constitution serves as the immutable guidance for all Spec Kit workflows (`/speckit-specify`, `/speckit-plan`, `/speckit-tasks`, `/speckit-implement`).

**Version**: 1.0.0 | **Ratified**: 2026-08-26 | **Network**: GenLayer StudioNet
