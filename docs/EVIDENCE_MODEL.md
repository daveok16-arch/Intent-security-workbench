# Evidence & Provenance Model (Phase 0)

## Provenance Chain

Every artifact produced by an engine execution maintains a verified provenance chain:

```
Investigation ID
   └── Target ID
         └── Source Snapshot Hash
               └── Engine Identifier & Version
                     └── Exact Command String Executed
                           └── Execution Timestamps & Exit Code
                                 └── Artifact Payload (SHA-256 Digest)
```

## Cryptographic Digest

- Hash algorithm: **SHA-256** (FIPS 180-4).
- Hash input: Exact binary payload or UTF-8 byte representation.
- Verification API: `/api/evidence/:id/verify` re-computes the hash over stored bytes and reports `INTEGRITY_VERIFIED` or `INTEGRITY_COMPROMISED`.
- Extensibility: The data schema is structured for future addition of cryptographic signature attestations (e.g. cosign, in-toto, Sigstore) in subsequent phases.
