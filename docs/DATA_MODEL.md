# Core Data Model & State Machine (Phase 0)

## Entities

### Program
Represents an authorized bounty program or research scope.
- `id`: Unique identifier (e.g. `prog-...`)
- `name`: Display name of the program
- `platform`: `IMMUNEFI` | `HACKENPROOF` | `CANTINA` | `HACKERONE` | `CUSTOM`
- `external_identifier`: Platform URL or external slug
- `scope`: List of in-scope assets / contracts / domains
- `exclusions`: Explicit out-of-scope clauses
- `bounty_policy`: Terms, reward tiers, safe harbor stipulations
- `disclosure_policy`: Coordinated disclosure timeline
- `technology`: Technology tags (e.g. `Solidity`, `Rust`, `TypeScript`)

### Target
Specific asset belonging to a Program.
- `id`: Unique identifier (e.g. `tgt-...`)
- `program_id`: Foreign key to `Program`
- `name`: Target moniker (e.g. `VaultCore`, `RouterV2`)
- `target_type`: `SMART_CONTRACT` | `PROTOCOL` | `WEB_APPLICATION` | `REST_API` | `BINARY_NODE` | `LIBRARY`
- `ecosystem`: `EVM` | `SOLANA_RUST` | `CLARITY_STACKS` | `MOVE` | `WEB_API` | `COSMOS` | `OTHER`
- `repository_url`: Git clone URL
- `commit_hash`: Pinned commit hash
- `source_hash`: SHA-256 tree hash
- `source_acquisition_status`: `SOURCE_NOT_ACQUIRED` | `SOURCE_ACQUIRED` | `SOURCE_ACQUISITION_FAILED`
- `deployment_information`: Addresses, network IDs, endpoints

### Investigation
Active research workspace linking targets, jobs, evidence, and findings.
- `id`: Unique identifier (e.g. `inv-...`)
- `program_id`: Foreign key to `Program`
- `target_id`: Foreign key to `Target`
- `status`: `CREATED` | `ACTIVE` | `PAUSED` | `COMPLETED` | `ARCHIVED`

### AnalysisJob
Background execution of an engine against a target.
- `id`: Unique identifier (e.g. `job-...`)
- `investigation_id`: Foreign key to `Investigation`
- `target_id`: Foreign key to `Target`
- `engine`: Engine moniker (e.g. `git-source-integrity`, `semgrep-static-analyzer`)
- `operation`: Action performed (e.g. `verify_commit`, `ast_rule_scan`)
- `status`: `QUEUED` | `RUNNING` | `COMPLETED` | `FAILED` | `CANCELLED`
- `started_at` / `completed_at`: Timestamps
- `exit_code`: Numeric exit code
- `stdout_artifact_id` / `stderr_artifact_id`: References to stored `EvidenceArtifact`
- `error`: Error description if failed

### EvidenceArtifact
Immutable evidence generated during investigation.
- `id`: Unique identifier (e.g. `art-...`)
- `investigation_id`: Foreign key to `Investigation`
- `artifact_type`: `RAW_STDOUT` | `RAW_STDERR` | `SOURCE_SNAPSHOT` | `AST_EXPORT` | `EXECUTION_TRACE` | `TRANSACTION_PAYLOAD` | `REPRODUCTION_SCRIPT` | `SYSTEM_LOG`
- `producer`: Producing engine or subsystem
- `producer_version`: Version string
- `command`: Command executed
- `target_hash`: Target state hash
- `sha256`: Cryptographic SHA-256 digest of artifact payload
- `byte_size`: Content size in bytes
- `path_or_reference`: Internal URI

### Finding
Candidate or verified vulnerability issue.
- `id`: Unique identifier (e.g. `fnd-...`)
- `investigation_id`: Foreign key to `Investigation`
- `target_id`: Foreign key to `Target`
- `title`: Vulnerability summary
- `category`: Taxonomy classification
- `severity`: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`
- `status`: 10-State Machine (see below)
- `confidence`: `HIGH` | `MEDIUM` | `LOW` | `UNVERIFIED`
- `evidence_artifact_ids`: Array of linked `EvidenceArtifact` IDs

## Finding State Machine

```
   ┌───────────┐
   │ CANDIDATE │
   └─────┬─────┘
         │
         ▼
   ┌───────────┐       ┌──────────────┐
   │ ANALYZING ├──────►│ INCONCLUSIVE │
   └─────┬─────┘       └──────────────┘
         │
         ▼
┌───────────────────────┐
│ VERIFICATION_REQUIRED │
└────────┬──────────────┘
         │
         ▼
   ┌─────────┐
   │ TESTING │
   └────┬────┘
        │
        ▼
  ┌────────────┐
  │ REPRODUCED │
  └─────┬──────┘
        │
        ▼
  ┌───────────┐
  │ VALIDATED │
  └─────┬─────┘
        │ (Must have verified evidence artifacts attached)
        ▼
  ┌───────────┐
  │ CONFIRMED │ (Terminal verified state)
  └───────────┘
```

At any stage before CONFIRMED, an item may transition to `REJECTED` or `OUT_OF_SCOPE`.
Transitions to `VALIDATED` and `CONFIRMED` are blocked unless machine-verifiable evidence artifacts are linked.
