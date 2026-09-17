# AGENTS.md — Intent Security Workbench

## What this is
Full-stack security research workbench (React/Vite UI + Express/WS backend, TypeScript throughout).
Phase plan and architecture live in `docs/` (`ARCHITECTURE.md`, `PHASES.md`, `ENGINE_INTERFACE.md`,
`EVIDENCE_MODEL.md`, `JOB_SYSTEM.md`, `DATA_MODEL.md`, `SECURITY_MODEL.md`).

## How the repository behaves (important)
- **Anti-fabrication mandate**: every engine must report genuine availability. Missing tools return
  `NOT_INSTALLED` / `UNAVAILABLE` with exit code 127 and zero findings. Never stub results.
- **The test suite is host-independent by design.** It passes both with and without
  slither/angr/clarinet installed. Negative-availability tests construct engines with a pinned
  binary name that cannot exist (e.g. `new SlitherEngine('intent-nonexistent-slither-binary')`), so
  they assert the anti-fabrication invariant rather than the developer's installed toolchain.
  Do not add assertions that depend on a tool being absent from the host.
- Binaries are resolved by `packages/config/src/binary_resolver.ts`, which searches `PATH` plus
  standard tool directories (`~/.foundry/bin`, `~/.local/bin`, `~/.cargo/bin`, `/usr/local/bin`,
  `./usr/local/bin`, `./node_modules/.bin`). Engines must not rely on bare `which`.

## Toolchain setup
Binaries are found without exporting PATH, but installing them is still required for the engines to
do real work:
```bash
chmod +x usr/local/bin/*              # if present; bundled tools may lack exec bits
pip install "z3-solver==4.13.0.0"     # tests assert /4\.\d+\.\d+/
pip install semgrep                   # real Semgrep 1.17x (not the regex fallback)
curl -L https://foundry.paradigm.xyz | bash && foundryup   # forge/anvil into ~/.foundry/bin
```
Install `semgrep` system-wide (not only `--user`): the scan runs with a sandboxed `HOME`, so
user-site packages are invisible and it fails with `ModuleNotFoundError`.

Engines for angr/codeql/slither/foundry/clarinet are Phase 1/2 placeholders. If their binary *is*
present they return a structured `FAILED` result with `ENGINE_NOT_IMPLEMENTED` — they never throw
and never fabricate findings. `FoundryEngine` intentionally looks for `foundry` (a toolkit name
with no such binary) and stays `NOT_INSTALLED`; real Forge/Anvil execution lives in Phase 5
dynamic verification via `ToolDetector.detectForge()`.

## Commands
```bash
npm install
npm run lint        # tsc --noEmit
npm test            # vitest run — 172 tests
npm run build       # vite build + esbuild bundle of server.ts
npm run dev         # tsx server.ts (dev mode, Vite middleware mode)
./bin/intent --help # CLI (`intent` subcommands for programs/targets/scope/analyze/verify)
```

## Running the server
`API_PORT` / `API_HOST` are honored at `server.listen`. Default is 3000, but the sandbox proxy
forwards **12000** and **12001**, so start it as:
```bash
API_PORT=12000 npx tsx server.ts
```
In dev mode Vite middleware serves through Express, which is why `vite.config.ts` needs
`allowedHosts: ['.prod-runtime.all-hands.dev', 'localhost', '127.0.0.1']` — without it the proxied
host gets `403 Blocked request`.

## Docker
`docker/Dockerfile.web` builds a single image that runs `dist/server.cjs` and serves the UI plus
`/ws`. Analysis binaries are deliberately not installed, so engines honestly report
`NOT_INSTALLED` inside the container.
```bash
docker build -f docker/Dockerfile.web -t intent-workbench .
docker run -p 3000:3000 intent-workbench
```

## Architecture map

```
engines/                     IEngine implementations (BaseEngine contract)
  placeholders/              real executors: treesitter, semgrep, static_analysis, z3,
                             spectral, git_integrity
                             Phase 1/2 stubs: angr, codeql, slither, foundry, clarinet
packages/
  core/                      entities, finding state machine, scope/investigation gates
  config/                    binary_resolver (PATH + standard dirs), AI provider config
  orchestrator/              job queue; builds the engine execution context
  static-analysis/           tree-sitter + semgrep + correlation + candidate store
  api-analysis/              OpenAPI parse, Spectral lint, BOLA differential
  formal-verification/       Z3 detector/executor, SMT-LIB2 compiler, model soundness
  dynamic-verification/      real forge/anvil/clarinet exec, PoC + state diff
  evidence/                  SHA-256 artifacts, provenance chain, event log
  agent-runtime/             AI control plane (see below)
adapters/                    program + target normalization per platform/ecosystem
sandbox/                     command boundary deny-list used by the AI policy gate
```

### AI software-engineer control plane (`packages/agent-runtime`)

This is the layer that drives the workbench like a researcher. It is **not** an LLM
wrapper by default — with no API key it runs the `DeterministicProvider`, a rule-based
expert engine, so the whole loop is reproducible offline.

```
objective
  -> AISecurityController.executeObjective()     controller.ts
       1. resolve/create investigation (adopts store-assigned id)
       2. generateInitialPlan() -> 7-stage plan
       3. auto-advance loop: step() up to 8 iterations
  -> step() asks globalAIProviderClient.reason(context)
       provider = LLMProviderRegistry.getProvider()
         gemini (if GEMINI_API_KEY) else deterministic
  -> suggest suggested_tool_calls[]
  -> ToolRegistry.invokeTool(name, params, ctx)   schema-validated, 31 typed tools
  -> PolicyGate.evaluateAction(...)               scope + sandbox + approval gate
  -> globalJobOrchestrator.createJob()            real engine execution
  -> job events feed back as verified FACTS
```

State invariants worth knowing:
- `PERMITTED_PHASE_TRANSITIONS` (state_machine.ts) is the authoritative phase graph. It
  also enforces prerequisites: `SCOPE_VALIDATION` needs a program, `ANALYSIS_EXECUTION`
  needs a capability matrix, `VERIFICATION_REQUESTED` needs a hypothesis/candidate, and
  `COMPLETED` is refused while blockers exist.
- The controller keeps 6 record kinds per investigation: FACT (verified) vs HYPOTHESIS
  vs PLAN vs DECISION vs BLOCKER vs UNKNOWN. Never present a hypothesis as a fact.
- `PolicyGate` blocks: unregistered targets, OUT_OF_SCOPE targets, sandbox violations,
  and sensitive actions (dynamic verification, fork creation) until `has_user_approval`.
- Jobs dispatched by the controller must carry the controller's `investigation_id`; the
  controller adopts the store-assigned id on auto-create so these agree.

## Engine install reality

Installing a binary does **not** make a placeholder engine productive. `angr`, `codeql`,
`slither`, `foundry`, and `clarinet` return `ENGINE_NOT_IMPLEMENTED` when their binary is
present (see `BaseEngine.notImplementedResult`). Only the engines listed as "real
executors" above produce findings. `foundry` intentionally resolves the non-existent
toolkit name `foundry` and stays `NOT_INSTALLED`; real Forge use is Phase 5 dynamic
verification via `ToolDetector.detectForge()`.

System-wide (not `--user`) installs are required, because engine subprocesses run with a
sandboxed `HOME`:

```bash
sudo pip install semgrep slither-analyzer solc-select
sudo pip install "angr==9.2.160" "pycparser==2.22" "z3-solver==4.13.0.0"
sudo -E solc-select install 0.8.20 && sudo -E solc-select use 0.8.20
# clarinet: repo moved to stx-labs/clarinet; asset name is clarinet-linux-x64-glibc.tar.gz
# codeql:   codeql-bundle-linux64.tar.gz from github/codeql-action releases
```

**angr must stay at 9.2.160.** angr 10.x pins `z3-solver==5.1.0.0`, but
`tests/unit/formal_verification.test.ts` asserts z3 matches `/4\.\d+\.\d+/`, so upgrading
angr silently breaks the Z3 suite. 9.2.160 pins `z3-solver==4.13.0.0` and needs
`pycparser==2.22` (3.x breaks `angr.sim_type`).

## Gotchas
- `npm run build` warns about a >500 kB chunk (the UI bundle). Harmless.
- Foundry fixtures write into `fixtures/dynamic_verification/**/out/` and `cache/`; the dev server's
  Vite watcher reloads the page on each write. Those paths are *not* actually gitignored — 116
  `out/`/`cache/` files are tracked, so running `npm test` dirties the working tree with solc
  build-id churn. `git checkout -- fixtures/dynamic_verification/` after a test run.
- A Semgrep scan root is resolved to an absolute path before execution: `cwd` is set to the target
  directory, so a relative root would be resolved from inside itself and rejected with exit 2.
- Semgrep JSON error envelopes also start with `{`; `parseSemgrepOutput` requires an object with no
  `errors` entries before a run counts as `COMPLETED`.
- The orchestrator builds the engine execution context; engines read `investigation_id` from it.
  Any code path that runs a job must not hand-roll a context missing those keys, or engines fall
  back to `inv-unknown` and their candidates become unattributable.
- Artifacts built via `createEvidenceArtifact` outside `storeEvidenceArtifact` (formal/dynamic
  verification) must be persisted with `globalDB.saveEvidence`, which mirrors the registered bytes;
  `evidence.set(...)` alone makes integrity checks report `INVALID` and downloads return empty.
- `rawArtifactStorage.set(id, artifact.content_preview)` stores only the 500-char preview, silently
  truncating artifacts whose real payload is longer. Use `saveEvidence`.
- Spectral discovers its ruleset by walking up from the **process cwd**, and a run that finds
  violations exits 2. `SpectralAnalysisService` therefore resolves the spec to an absolute path and
  sets the child `cwd` to the spec's directory, and `SpectralEngine` treats exit 2 as SUCCESS (a
  completed audit with findings) rather than an engine failure. Same class of bug as the Semgrep
  relative-root issue.
- The `angr` CLI has no `--version` flag (it exits 2 with usage text), so `AngrEngine` overrides
  `get_version()` to read `angr.__version__`. A default probe misreports a healthy install as BROKEN.
- `tests/unit/dynamic_verification.test.ts` and the Clarinet-missing integration test must pin a
  binary path that cannot exist (`/nonexistent/bin/clarinet`). They previously used the default
  lookup, which made them fail on any host that *does* have Clarinet installed.