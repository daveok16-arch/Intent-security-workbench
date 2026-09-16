# Engine Abstraction Layer Specification (Phase 0.1)

## Overview

The **Engine Abstraction Layer** provides a typed, extensible, and anti-fabrication framework for integrating security analysis tools into the Intent Security Workbench.

### Non-Negotiable Rule
The workbench must never claim an engine executed, detected vulnerabilities, or is available unless the underlying binary was verified on the host system. A missing engine must **NEVER** be represented as successful or available.

---

## 1. Engine Base Interface

All security engines implement the `IEngine` interface and extend `BaseEngine`:

```typescript
export interface IEngine {
  readonly name: string;
  readonly engine_id: string;
  readonly version: string;
  readonly description: string;
  readonly capabilities: string[];
  readonly supported_target_types: string[];
  readonly supported_languages: string[];
  readonly executable: string;

  check_availability(): Promise<EngineAvailability>;
  get_version(): Promise<string | null>;
  prepare(targetId: string, context: Record<string, any>): Promise<boolean>;
  execute(targetId: string, operation: string, context: Record<string, any>): Promise<EngineResult>;
  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[];
  cleanup(context: Record<string, any>): Promise<void>;
}
```

---

## 2. Availability & Execution Lifecycle

### Engine Availability States
| Status | Meaning |
| :--- | :--- |
| `AVAILABLE` | The binary executable exists on system PATH, responds to version interrogation, and is ready to execute. |
| `NOT_INSTALLED` | The binary was not found on system PATH. Version is reported as `null` / unknown. |
| `UNAVAILABLE` | The engine is disabled or restricted in the current sandbox environment. |
| `BROKEN` | The binary exists on PATH but fails during basic execution checks (e.g. permission error, crash on `--version`). |

### Job & Execution States
| Status | Meaning |
| :--- | :--- |
| `READY` | Pre-flight conditions and targets prepared. |
| `RUNNING` | Process is actively executing on the host / worker. |
| `COMPLETED` | Engine completed with exit code 0 and generated verifiable stdout/artifacts. |
| `FAILED` | Engine returned non-zero exit code or threw an execution error. |
| `CANCELLED` | Execution aborted by user or timeout. |

---

## 3. Data Models

### EngineAvailability Model
```typescript
export interface EngineAvailability {
  engine_id: string;
  name: string;
  status: EngineAvailabilityStatus;
  executable: string;
  detected_path: string | null;
  version: string | null;
  checked_at: string;
  error: string | null;
  capabilities: string[];
}
```

### EngineResult Model
```typescript
export interface EngineResult {
  id: string;
  engine_id: string;
  engine_name: string;
  engine_version: string;
  status: EngineResultStatus; // 'SUCCESS' | 'FAILED' | 'CANCELLED' | 'UNAVAILABLE'
  target_id: string;
  investigation_id?: string;
  command: string;
  working_directory: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  exit_code: number;
  stdout: string;
  stderr: string;
  findings: EngineFinding[];
  artifacts: EngineArtifact[];
  environment: {
    hostname: string;
    os: string;
    node_version: string;
    executable_path?: string | null;
    [key: string]: any;
  };
  error?: string | null;
}
```

### EngineFinding Model
Represents raw parser outputs generated directly by an engine:
```typescript
export interface EngineFinding {
  id: string;
  title: string;
  description: string;
  severity: Severity | string;
  category: string;
  cwe?: string[];
  owasp?: string[];
  confidence: Confidence | string;
  file: string;
  line_start?: number;
  line_end?: number;
  evidence?: string;
  metadata?: Record<string, any>;
}
```

### EngineArtifact Model
Represents actual output files generated during execution:
```typescript
export interface EngineArtifact {
  id: string;
  type: string;
  path: string;
  sha256: string;
  size: number;
  mime_type: string;
  created_at: string;
  metadata?: Record<string, any>;
}
```

---

## 4. Engine Registry

The `EngineRegistry` maintains registered engines and serves as the single source of truth for binary verification:
- `register(engine: BaseEngine): void`
- `get(engine_id: string): BaseEngine | undefined`
- `list(): BaseEngine[]`
- `check_all(): Promise<EngineAvailability[]>`
- `check(engine_id: string): Promise<EngineAvailability>`

Default registered engines in Phase 0.1:
1. `treesitter` (Tree-sitter AST & CST Parser)
2. `semgrep` (Semgrep Static Analyzer)
3. `z3` (Z3 SMT Theorem Prover)
4. `angr` (Angr Binary Analysis Platform)
5. `codeql` (CodeQL Semantic Code Analyzer)
6. `slither` (Slither Solidity Static Analyzer)
7. `foundry` (Foundry Ethereum Development Toolkit)
8. `clarinet` (Clarinet Clarity Contract Analyzer)
9. `spectral` (Spectral OpenAPI Linter)
10. `git-source-integrity` (Host Git Provenance Verifier)

---

## 5. Distinction Between Artifact Concepts

To prevent ambiguity and maintain strict anti-fabrication standards, the workbench clearly distinguishes five distinct stages:

1. **ENGINE METADATA**:
   Declarative configuration of what an engine represents (name, executable identifier, supported languages, expected capabilities). Does *not* imply the tool exists on host.

2. **ENGINE AVAILABILITY**:
   Real-time verified status of the tool on the host PATH. Only when `check_availability()` successfully executes the binary's version command does status become `AVAILABLE`.

3. **ENGINE EXECUTION**:
   A discrete run of the binary in a sandboxed execution context against a target, producing real process exit codes, execution durations, standard streams, and file artifacts.

4. **ENGINE FINDING**:
   Raw finding candidates parsed from an engine's raw stdout/JSON output. Engine findings are unverified by default.

5. **PLATFORM VALIDATED FINDING**:
   A finding that has traversed the workbench state machine (`CANDIDATE` -> `ANALYZING` -> `TESTING` -> `REPRODUCED` -> `VALIDATED` -> `CONFIRMED`) with cryptographic SHA-256 evidence linking real inputs, outputs, and reproduction scripts.

---

## 6. Integrating a New Engine

To add a new engine to the Intent Security Workbench:

1. Create a new subclass in `engines/placeholders/<engine_name>.ts` extending `BaseEngine`.
2. Define the static metadata (`engine_id`, `name`, `version`, `executable`, `capabilities`, `supported_target_types`, `supported_languages`).
3. Implement `prepare()`, `execute()`, `parse_result()`, and `cleanup()`.
4. Register the instance in `EngineRegistry.registerDefaults()` inside `engines/engine_registry.ts`.
5. Expose endpoints and tests in `tests/unit/engine_abstraction.test.ts`.
