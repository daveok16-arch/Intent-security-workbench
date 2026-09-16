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

## Gotchas
- `npm run build` warns about a >500 kB chunk (the UI bundle). Harmless.
- Foundry fixtures write into `fixtures/dynamic_verification/**/out/` and `cache/`; the dev server's
  Vite watcher reloads the page on each write. Those paths are gitignored.
- A Semgrep scan root is resolved to an absolute path before execution: `cwd` is set to the target
  directory, so a relative root would be resolved from inside itself and rejected with exit 2.
- Semgrep JSON error envelopes also start with `{`; `parseSemgrepOutput` requires an object with no
  `errors` entries before a run counts as `COMPLETED`.