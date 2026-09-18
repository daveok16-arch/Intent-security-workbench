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
npm test            # vitest run
npm run build       # vite build + esbuild bundle of server.ts
npm run dev         # tsx server.ts (dev mode, Vite middleware mode)
./bin/intent --help # CLI (`intent` subcommands for programs/targets/scope/analyze/verify)

./scripts/setup-tools.sh          # install missing analysis binaries
./scripts/setup-tools.sh --check  # report only
npx tsx tools/benchmark_precision.ts  # rule precision/recall benchmark
```

## Engine precision

The structural engine requires genuine HTTP route context *and* real data flow
before reporting BOLA, so ordinary library code is not flagged. It understands the
shapes real applications use: `req.params.x`, `req.query.x`, `req.body.x`,
destructured bindings (`const { userId } = req.params`), and data layers named with
a `DAO`/`Repository`/`Model`/`Store` suffix.

Measured results:

| Target | Findings | Notes |
| --- | --- | --- |
| This project's own `packages/` | 0 | was 45, all false positives |
| Labelled unit benchmark | 3 TP / 0 FP / 0 FN | `tools/benchmark_precision.ts` |
| OWASP NodeGoat | **1** | the documented IDOR in `app/routes/allocations.js` |
| OWASP Juice Shop | **10** | BOLA in `routes/basketItems.ts`; hardcoded credentials in `routes/login.ts`, `lib/insecurity.ts` |
| OpenZeppelin Ethernaut | **5** | among 25+ documented-vulnerable levels |
| OpenZeppelin Contracts (audited) | **0** | 367 files; any hit would be a false positive |

The audited-OpenZeppelin result is the precision control: 0 findings across 367
reviewed files. Ethernaut is the recall control.

### Solidity coverage

Originally there was **one** Solidity rule, so the canonical vulnerability classes
went undetected — Ethernaut's `Reentrance.sol` was missed entirely. Added
`RULE-REENT-001` (external call preceding a state update, CWE-841). Ethernaut
findings went from 2 to 5. Two Semgrep syntax details cost real time and are worth
remembering:

- `pattern: A; B; C;` with adjacent statements matches **nothing** in Solidity; the
  `...` sequence ellipsis is required.
- `$STATE = $EXPR` does not match compound assignments like `-=`, so the update
  forms must be enumerated. `$S[..]` is a parse error; indexed access needs
  `$S[$KEY]`.

A rule that matches a region in several `pattern-either` variants produces
overlapping results for one defect (Ethernaut `Stake.sol` returned three ranges for
one call site). The Semgrep service now collapses overlapping same-rule ranges,
keeping the widest.

### Reentrancy guard suppression

The order-based rule also fired on the **fixed** Juice Shop contract, which uses a
manual mutex: a flag is assigned before the call and reset after. That reset is what
the rule sees. Expressing the exclusion in the rule did not work — several
`pattern-not-inside` variants were verified to still match, so Semgrep's cross-block
reasoning for Solidity is unreliable here.

The check is done in `SemgrepAnalysisService.isGuardedReentrancy`, where it can be
reasoned about and tested: if a state variable is assigned both before and after the
call *within the same function*, it is acting as a guard. Two bugs were found and
fixed while building it, both caught by corpus results rather than by inspection:

- Matching any `=` treated the comparison in `if (balances[msg.sender] >= _amount)`
  as an assignment, which wrongly suppressed Ethernaut's canonical reentrancy.
- A fixed-width window reached into the *preceding* function, so `donate()`'s write
  to `balances` looked like a guard for `withdraw()`. The window now walks to the
  enclosing function boundaries.

`tests/unit/rule_precision.test.ts` pins both directions: a genuine reentrancy must
survive, and a mutex-protected variant must not be reported.

Run against real applications with:
```bash
./scripts/benchmark-corpus.sh                 # clones and benchmarks both
npx tsx tools/triage_findings.ts <dir>        # shows each finding with its code
```

Evidence in findings is extracted from the source (the actual request value and
the actual data-layer call). It is never a hardcoded placeholder — reporting a
fixed `req.params.id` / `db.getAccount(...)` for every hit would assert things the
code does not contain.

The Semgrep rule pack is validated before each scan. An invalid generated rule
would otherwise make Semgrep emit an empty `results` array, which is
indistinguishable from a clean scan, silently disabling a rule class.

Optional engines (`angr`, `codeql`, `slither`, `foundry`, `clarinet`) are Phase 1/2
placeholders: if their binary is present they return a structured `FAILED` result
with `ENGINE_NOT_IMPLEMENTED`, and they never fabricate findings.
`FoundryEngine` intentionally looks for `foundry` (a toolkit name with no such
binary) and stays `NOT_INSTALLED`; real Forge/Anvil execution lives in Phase 5
dynamic verification via `ToolDetector.detectForge()`.

## Persistence

Domain records (programs, targets, scope entries, investigations, findings,
evidence metadata, verification results) persist to `storage/db/workbench-state.json`
via a debounced, atomically-replaced snapshot, and are restored on startup. Set
`PERSISTENCE_ENABLED=false` for fully ephemeral behaviour. Binary artifact content
lives in the artifact storage layer, not in the snapshot.

## Security posture

Authentication is **off by default** for local single-user use. Set `AUTH_TOKEN`
before binding to a network interface: without it, any client that can reach the
port has full read/write access to research data and can trigger analysis
execution. `ALLOWED_ORIGINS` adds a browser origin allowlist. Both are enforced
globally for `/api` and for the `/ws` handshake, so a new route cannot bypass them.
`/api/health`, `/api/readiness` and `/api/version` stay open for liveness probes.

Query-string tokens (`?token=`) are accepted only on the WebSocket handshake, where
browsers cannot set headers; on REST they are rejected so the token cannot leak via
access logs, browser history or `Referer`.

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

## Gotchas
- `npm run build` warns about a >500 kB chunk (the UI bundle). Harmless.
- **The suite must stay idempotent — do not let tests touch `storage/db/`.** The store
  write-through-persists every mutation to `storage/db/workbench-state.json` and rehydrates it in
  the `DatabaseStore` constructor. Tests used to inherit the default directory, so records written
  by one test file were restored on the next run and `tests/integration/phase_0_2_evidence_provenance.test.ts`
  saw stale evidence alongside its own (4 instead of 2). The suite therefore passed on a clean
  checkout and failed on an immediate re-run. `vitest.config.ts` now pins `PERSISTENCE_DIR` to a
  per-run temp directory. Keep it that way: if you add a test that constructs a `DatabaseStore`,
  it must not read or write the developer's real snapshot.
- Foundry fixtures write into `fixtures/dynamic_verification/**/out/` and `cache/`; the dev server's
  Vite watcher reloads the page on each write. Those paths are gitignored.
- A Semgrep scan root is resolved to an absolute path before execution: `cwd` is set to the target
  directory, so a relative root would be resolved from inside itself and rejected with exit 2.
- Semgrep JSON error envelopes also start with `{`; `parseSemgrepOutput` requires an object with no
  `errors` entries before a run counts as `COMPLETED`.