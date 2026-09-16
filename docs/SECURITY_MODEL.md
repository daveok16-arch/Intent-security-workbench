# Security Model & Sandbox Isolation (Phase 0)

## Security Principles

1. **Authorization Scope Boundary**: The system operates strictly within scopes defined by the researcher and validated against the Program's authorization policy.
2. **No Arbitrary Shell Execution**: The public API rejects raw, unvalidated shell command execution strings.
3. **Engine Containment**: Analysis engines are invoked via strictly typed parameters, avoiding shell interpolation vulnerabilities.
4. **No Automated External Scanning**: External network interactions are restricted; Phase 0 focuses on local and sandbox-isolated source code analysis.
5. **Deterministic Evidence Verification**: Artifacts cannot be mutated after creation without invalidating their SHA-256 hash checksums.
