# Intent Security Workbench Architecture (Phase 0)

## System Overview

The **Intent Security Workbench** is a modular, production-oriented, multi-program security research platform designed to support authorized security research across multiple bounty platforms (Immunefi, HackenProof, Cantina, HackerOne), blockchain ecosystems (EVM, Solana, Clarity/Stacks, Move), and Web/API targets.

### Core Architectural Principle

The platform enforces strict modularity and separation of concerns:

1. **Core Platform (`packages/core`)**: Canonical domain models, state machines, and lifecycle transitions.
2. **Program Adapters (`adapters/programs`)**: Normalization of bounty policies, scope boundaries, and exclusion rules across platforms.
3. **Target Adapters (`adapters/targets`)**: Ecosystem-specific target handling and source code verification.
4. **Analysis Engines (`engines/`)**: Pluggable interface for static, symbolic, and dynamic analysis tools.
5. **Orchestrator & Background Workers (`packages/orchestrator`, `workers/`)**: Asynchronous execution queue, structured logging, and WebSocket event telemetry.
6. **Evidence & Provenance System (`packages/evidence`)**: Machine-verifiable SHA-256 cryptographic provenance chain.
7. **Security Sandbox (`sandbox/`, `packages/agent-runtime`)**: Strict boundary enforcement preventing arbitrary command execution.
8. **Research Workbench UI (`src/`, `apps/web`)**: Real-time researcher IDE displaying verified database records and live execution telemetry without synthetic data.

```
┌──────────────────────────────────────────────────────────┐
│                   Researcher Workbench UI                │
│              (React + Vite + Tailwind + Lucide)           │
└────────────┬─────────────────────────────▲───────────────┘
             │ REST API                    │ WebSocket Events
┌────────────▼─────────────────────────────┴───────────────┐
│                   Express / FastAPI Backend              │
│       (Program / Target / Investigation / Finding API)   │
└────────────┬─────────────────────────────┬───────────────┘
             │                             │
┌────────────▼──────────────┐ ┌────────────▼───────────────┐
│     Database Store        │ │    Job Orchestrator &      │
│  (Relational Persistence) │ │    Execution Workers       │
└────────────┬──────────────┘ └────────────┬───────────────┘
             │                             │
┌────────────▼──────────────┐ ┌────────────▼───────────────┐
│   Evidence Provenance     │ │    Engine Interface        │
│   (SHA-256 Byte Hasher)   │ │  (Real Availability Check) │
└───────────────────────────┘ └────────────────────────────┘
```

## Anti-Fabrication Mandate

- Every security engine execution, proof, or target test must produce genuine machine-verifiable evidence.
- No synthetic findings or fabricated vulnerability counts are permitted.
- Missing executables produce explicit `UNAVAILABLE / NOT_INSTALLED` statuses.
