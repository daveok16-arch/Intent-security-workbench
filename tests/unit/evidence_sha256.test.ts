import { describe, it, expect } from 'vitest';
import { computeArtifactSHA256, createEvidenceArtifact, verifyArtifactIntegrity } from '../../packages/evidence/src/index.js';
import { ArtifactType } from '../../packages/core/src/index.js';

describe('Evidence Hashing & Integrity Verification Tests (Phase 0 Requirement 13 & 14)', () => {
  it('should compute deterministic SHA-256 over exact string bytes', () => {
    const rawContent = 'contract VulnerableVault { function withdraw() public {} }';
    const hash = computeArtifactSHA256(rawContent);
    expect(hash).toBe('b323ec588c3368aab982361e6acf5d82b53d2d2f3929075dccfa8ad296993f06');
  });

  it('should create an evidence artifact with genuine byte size and hash', () => {
    const rawPayload = '{"target": "0x123", "status": "analyzed"}';
    const { artifact } = createEvidenceArtifact({
      id: 'art-test-01',
      investigation_id: 'inv-test-01',
      artifact_type: ArtifactType.RAW_STDOUT,
      producer: 'git-source-integrity',
      producer_version: '1.0.0',
      command: 'git --version',
      content: rawPayload,
      path_or_reference: 'jobs/1/stdout.log',
    });

    expect(artifact.sha256).toBe(computeArtifactSHA256(rawPayload));
    expect(artifact.byte_size).toBe(Buffer.byteLength(rawPayload, 'utf-8'));
    expect(artifact.content_preview).toContain('{"target": "0x123"');
  });

  it('should detect tampering when actual bytes deviate from recorded SHA-256', () => {
    const originalContent = 'clean stdout log';
    const { artifact } = createEvidenceArtifact({
      id: 'art-test-02',
      investigation_id: 'inv-test-01',
      artifact_type: ArtifactType.RAW_STDOUT,
      producer: 'git-source-integrity',
      producer_version: '1.0.0',
      command: 'git --version',
      content: originalContent,
      path_or_reference: 'jobs/2/stdout.log',
    });

    // Verify untouched content passes
    const validCheck = verifyArtifactIntegrity(artifact, originalContent);
    expect(validCheck.valid).toBe(true);

    // Verify tampered content fails
    const tamperedContent = 'tampered stdout log injected by adversary';
    const invalidCheck = verifyArtifactIntegrity(artifact, tamperedContent);
    expect(invalidCheck.valid).toBe(false);
    expect(invalidCheck.actual).not.toBe(artifact.sha256);
  });
});
