# Background Job System (Phase 0)

## Job Lifecycle

All background work in the workbench runs through explicit state transitions:

```
[QUEUED] ──► [RUNNING] ──┬──► [COMPLETED] (exit code 0, artifacts hashed)
                         ├──► [FAILED]    (exit code != 0 or unavailable engine)
                         └──► [CANCELLED] (operator abort)
```

## Invariants

1. **No Simulated Percentages**: The system displays truthful states (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`).
2. **Structured Logging**: Every job records timestamped log entries (`INFO`, `WARN`, `ERROR`, `DEBUG`) persisted in the execution registry.
3. **Artifact Production**: Process `stdout` and `stderr` are automatically captured as `EvidenceArtifact` records with full cryptographic SHA-256 hashes.
4. **Real-Time Streaming**: All job state changes and log events are broadcast to connected WebSocket clients at `/ws`.
5. **Retry Handling**: Configurable retry counts (`max_retries`) with backoff and error tracking.
