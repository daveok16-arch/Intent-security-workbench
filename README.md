# Intent Security Workbench

A modular, production-oriented platform for authorized multi-program security research:
program scoping, evidence provenance, background job orchestration, and findings whose
state transitions are enforced by a machine-verifiable verification state machine.

Supports multiple bounty platforms (Immunefi, HackenProof, Cantina, HackerOne, custom)
and multiple ecosystems (EVM, Solana/Rust, Clarity/Stacks, Move, Web/API).

## Anti-fabrication mandate

The core invariant of this codebase: every engine execution, proof, or target test must
produce genuine machine-verifiable evidence.

- No synthetic findings and no fabricated vulnerability counts.
- A missing executable produces an explicit `NOT_INSTALLED` / `UNAVAILABLE` result with
  exit code `127` and **zero** findings — never a simulated success.
- Artifacts carry real SHA-256 digests and byte sizes, computed from their actual content.
- Engines that never executed report `duration_ms: 0`; no timing is invented.

Because of this, the test suite asserts against whatever the host genuinely reports. The
pass count therefore depends on the installed toolchain: a bare checkout fails six tests
that require `forge`/`anvil`, and passes the rest. Engines for Slither, Angr and CodeQL
report `NOT_INSTALLED` until their binaries are present; Semgrep, Z3, Tree-sitter, Spectral
and git run for real. See `AGENTS.md` for the exact matrix.

## Architecture

| Area | Location | Responsibility |
| --- | --- | --- |
| Core domain | `packages/core` | Entities, finding state machine, scope decisions |
| Program adapters | `adapters/programs` | Normalize bounty policies and scope across platforms |
| Target adapters | `adapters/targets` | Ecosystem-specific source verification |
| Engines | `engines/` | Pluggable analysis engines behind one `BaseEngine` contract |
| Orchestrator | `packages/orchestrator` | Background queue, structured logging, cancellation |
| Evidence | `packages/evidence` | SHA-256 provenance chain and artifact storage |
| Static analysis | `packages/static-analysis` | Tree-sitter and Semgrep integration |
| API analysis | `packages/api-analysis` | OpenAPI parsing, Spectral linting, BOLA differential |
| Formal verification | `packages/formal-verification` | Z3 SMT harness |
| Dynamic verification | `packages/dynamic-verification` | Foundry/Clarinet reproduction runs |
| Agent runtime | `packages/agent-runtime` | Sandboxed AI controller and policy gate |
| Workbench UI | `src/` | React researcher IDE with live WebSocket telemetry |
| Backend | `server.ts` | REST API and `/ws` event broadcaster |

See `docs/ARCHITECTURE.md`, `docs/ENGINE_INTERFACE.md`, `docs/EVIDENCE_MODEL.md`,
`docs/DATA_MODEL.md`, `docs/JOB_SYSTEM.md`, and `docs/SECURITY_MODEL.md` for detail.

## Requirements

- Node.js 20+ (developed against 22)
- External analysis binaries, resolved from `PATH` and standard tool directories
  (`~/.foundry/bin`, `~/.local/bin`, `~/.cargo/bin`, `/usr/local/bin`,
  `./usr/local/bin`, `./node_modules/.bin`):
  - **git** — source acquisition and integrity
  - **semgrep** — static analysis
  - **z3** — formal verification (`z3-solver` 4.x)
  - **forge** / **anvil** — dynamic verification (Foundry)
  - **spectral** — OpenAPI linting (installed via npm)

## Setup

```bash
npm install

# Formal verification: the suite asserts a 4.x version string.
pip install "z3-solver==4.13.0.0"

# Dynamic verification (EVM fixtures).
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Static analysis. Version 1.17x.
pip install semgrep
```

## Usage

```bash
npm run dev        # dev server with Vite middleware (API_PORT/API_HOST honored)
npm run build      # production frontend build + server bundle
npm start          # run the built server
npm test           # vitest — 172 tests
npm run lint       # tsc --noEmit
```

The server binds `API_PORT` (default `3000`) and `API_HOST` (default `0.0.0.0`).

### CLI

```bash
./bin/intent --help
```

Covers programs, targets, scope evaluation, source acquisition, static analysis,
API/BOLA analysis, formal verification (Z3), and dynamic verification (Foundry/Clarinet).

## Configuration

Copy `.env.example` and adjust. Every variable is documented there with its
classification (required/optional, secret or not, safe for frontend). Highlights:

| Variable | Default | Notes |
| --- | --- | --- |
| `API_PORT` | `3000` | HTTP + WebSocket port |
| `API_HOST` | `0.0.0.0` | Bind address |
| `SANDBOX_ALLOW_ARBITRARY_SHELL` | `false` | Must stay `false` |
| `SANDBOX_STRICT_SCOPE_CHECK` | `true` | Enforce scope authorization |
| `AI_PROVIDER` | `none` | Deterministic mode when unset |
| `DATABASE_URL` / `REDIS_URL` | unset | In-memory persistence and in-process queue when unset |

Never place credentials in `VITE_*` variables; they are bundled into browser assets.
