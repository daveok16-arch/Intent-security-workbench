/**
 * Evidence & Provenance Tracking System for Intent Security Workbench
 * Phase 0.2 Evidence & Provenance Subsystem
 *
 * Ground-truth evidence locker, append-only event trail, filesystem artifact storage,
 * and deterministic cryptographic provenance graphs.
 */

import crypto, { createHash } from 'crypto';
import { ArtifactType, EvidenceArtifact } from '../../core/src/index.js';
import { LocalFilesystemArtifactStorage } from './storage/local_storage.js';
import { IArtifactStorage, ArtifactIntegrityResult } from './storage/storage_interface.js';

export * from './storage/storage_interface.js';
export * from './storage/local_storage.js';
export * from './provenance.js';
export * from './events.js';
export * from './snapshot.js';

export const globalArtifactStorage: IArtifactStorage = new LocalFilesystemArtifactStorage();

/**
 * Computes exact cryptographic SHA-256 hash over raw byte content or string data.
 * No mock/simulated hashes.
 */
export function computeArtifactSHA256(content: string | Buffer): string {
  const hash = createHash('sha256');
  if (typeof content === 'string') {
    hash.update(Buffer.from(content, 'utf-8'));
  } else {
    hash.update(content);
  }
  return hash.digest('hex');
}

export const registeredEvidenceArtifacts = new Map<string, { artifact: EvidenceArtifact; content: string | Buffer }>();

/**
 * Verifies that an artifact's recorded SHA-256 matches its actual binary content.
 * Supports passing either an EvidenceArtifact with content, or an artifact ID string.
 */
export function verifyArtifactIntegrity(
  artifactOrId: EvidenceArtifact | string,
  actualContent?: string | Buffer
): {
  valid: boolean;
  verified: boolean;
  status: 'VALID' | 'INVALID';
  expected_sha256: string;
  actual_sha256: string;
  computed_sha256: string;
  expected?: string;
  actual?: string;
} {
  if (typeof artifactOrId === 'string') {
    const registered = registeredEvidenceArtifacts.get(artifactOrId);
    if (registered) {
      const computedHash = computeArtifactSHA256(registered.content);
      const valid = registered.artifact.sha256.toLowerCase() === computedHash.toLowerCase();
      return {
        valid,
        verified: valid,
        status: valid ? 'VALID' : 'INVALID',
        expected_sha256: registered.artifact.sha256,
        actual_sha256: computedHash,
        computed_sha256: computedHash,
        expected: registered.artifact.sha256,
        actual: computedHash,
      };
    }

    return {
      valid: false,
      verified: false,
      status: 'INVALID',
      expected_sha256: '',
      actual_sha256: '',
      computed_sha256: '',
      expected: '',
      actual: '',
    };
  }

  const artifact = artifactOrId;
  if (actualContent !== undefined) {
    const actualHash = computeArtifactSHA256(actualContent);
    const valid = artifact.sha256.toLowerCase() === actualHash.toLowerCase();
    return {
      valid,
      verified: valid,
      status: valid ? 'VALID' : 'INVALID',
      expected_sha256: artifact.sha256,
      actual_sha256: actualHash,
      computed_sha256: actualHash,
      expected: artifact.sha256,
      actual: actualHash,
    };
  }

  return {
    valid: false,
    verified: false,
    status: 'INVALID',
    expected_sha256: artifact.sha256,
    actual_sha256: '',
    computed_sha256: '',
    expected: artifact.sha256,
    actual: '',
  };
}

/**
 * Constructs a real, machine-verifiable EvidenceArtifact with SHA-256 hash and metadata.
 */
export function createEvidenceArtifact(params: {
  id?: string;
  investigation_id: string;
  target_id?: string;
  artifact_type: ArtifactType | string;
  producer: string;
  producer_version: string;
  command?: string;
  working_directory?: string;
  source_snapshot_id?: string | null;
  target_hash?: string;
  content: string | Buffer;
  filename?: string;
  path_or_reference?: string;
  path?: string;
  mime_type?: string;
  metadata?: Record<string, any>;
}): EvidenceArtifact & { artifact: EvidenceArtifact; rawContent: string | Buffer } {
  const artifactId = params.id || `art-${crypto.randomBytes(6).toString('hex')}`;
  const rawContent = params.content;
  const sha256 = computeArtifactSHA256(rawContent);
  const size_bytes = typeof rawContent === 'string' ? Buffer.byteLength(rawContent, 'utf-8') : rawContent.length;
  
  const contentPreview = typeof rawContent === 'string'
    ? rawContent.slice(0, 500)
    : `[Binary content: ${size_bytes} bytes]`;

  const relPath = params.path || params.path_or_reference || (params.filename ? `evidence/${params.filename}` : `evidence/${artifactId}.bin`);
  const mime = params.mime_type || (typeof rawContent === 'string' ? 'text/plain' : 'application/octet-stream');

  const artifact: EvidenceArtifact = {
    id: artifactId,
    investigation_id: params.investigation_id,
    target_id: params.target_id,
    artifact_type: params.artifact_type,
    producer: params.producer,
    producer_version: params.producer_version,
    source_snapshot_id: params.source_snapshot_id,
    command: params.command || '',
    working_directory: params.working_directory,
    target_hash: params.target_hash,
    path: relPath,
    size_bytes,
    sha256,
    mime_type: mime,
    // Aliases
    type: params.artifact_type as any,
    byte_size: size_bytes,
    path_or_reference: relPath,
    content_preview: contentPreview,
    metadata: params.metadata || {},
    created_at: new Date().toISOString(),
  };

  registeredEvidenceArtifacts.set(artifactId, { artifact, content: rawContent });

  // `artifact` and `rawContent` are exposed as non-enumerable convenience
  // accessors. Making them enumerable created a self-reference
  // (`result.artifact === result`), which made every artifact unserializable and
  // broke `JSON.stringify`, websocket broadcasts, and API responses.
  return Object.defineProperties(artifact, {
    artifact: { value: artifact, enumerable: false, writable: false, configurable: true },
    rawContent: { value: rawContent, enumerable: false, writable: false, configurable: true },
  }) as EvidenceArtifact & { artifact: EvidenceArtifact; rawContent: string | Buffer };
}

