# Development Roadmap & Phase Plan

## Phase 0: Foundational Architecture (CURRENT)
- [x] Canonical domain entities (`Program`, `Target`, `Investigation`, `AnalysisJob`, `EvidenceArtifact`, `Finding`)
- [x] 10-state finding transition state machine with legal transition enforcement
- [x] Cryptographic SHA-256 evidence hashing and integrity verification
- [x] Modular program adapters (Immunefi, HackenProof, Cantina, HackerOne, Custom)
- [x] Modular target adapters (EVM, Solana/Rust, Clarity/Stacks, Move, Web/API)
- [x] Generic `BaseEngine` contract and `EngineRegistry` with true availability checks
- [x] Background job orchestrator with structured logging and cancellation
- [x] Real-time WebSocket event broadcaster (`/ws`)
- [x] Full-stack REST API and professional security researcher IDE/workbench UI
- [x] Zero mock findings / Zero simulated engine output / Strict anti-fabrication

---

## Phase 1: Source Acquisition & Static Analysis Integration (DELIVERED)
- [x] Pinned git clone & local tree hashing worker (`packages/source`)
- [x] Semgrep engine integration & rule pack compiler (`packages/static-analysis`, `engines/placeholders/semgrep.ts`)
- [x] Tree-sitter AST export and tokenization pipelines
- [ ] Slither Solidity static analyzer installation (engine present; requires `slither` on PATH)

## Phase 2: Formal Verification & Symbolic Execution (PARTIALLY DELIVERED)
- [x] Z3 SMT solver harness (`packages/formal-verification`)
- [x] Foundry invariant fuzzing harness (`packages/dynamic-verification`)
- [x] Clarinet test execution container (adapter present; requires `clarinet` on PATH)
- [ ] Angr binary analysis engine (engine present; requires `angr` on PATH)

## Phase 3: AI Reasoning & Triage Agent (DELIVERED)
- [x] Sandboxed agent runtime for authorized vulnerability triage (`packages/agent-runtime`)
- [x] Evidence-conditioned LLM reasoning with mandatory proof-of-concept verification
- [x] Automated report generation matching bounty platform markdown schemas

> Note: this file previously described Phases 1–3 as PLANNED while the code for them was
> already present and, in the case of Semgrep, Z3 and Foundry, covered by passing tests.
> The engine columns above distinguish "adapter implemented" from "binary installed on the
> host running the tests" — the latter is what determines the test count.
