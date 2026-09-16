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

## Phase 1: Source Acquisition & Static Analysis Integration (PLANNED)
*Will add real security engines incrementally:*
- Pinned git clone & local tree hashing worker
- Semgrep engine container integration & rule pack compiler
- Slither Solidity static analyzer installation
- AST export and tokenization pipelines

## Phase 2: Formal Verification & Symbolic Execution (PLANNED)
- Z3 SMT solver harness
- Angr binary analysis engine
- Foundry invariant fuzzing harness
- Clarinet test execution container

## Phase 3: AI Reasoning & Triage Agent (PLANNED)
- Sandboxed agent runtime for authorized vulnerability triage
- Evidence-conditioned LLM reasoning with mandatory proof-of-concept verification
- Automated report generation matching bounty platform markdown schemas
