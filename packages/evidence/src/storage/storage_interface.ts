/**
 * Artifact Storage Interface
 * Phase 0.2 Evidence & Provenance Subsystem
 */

export type StorageCategory = 'source' | 'engines' | 'evidence' | 'reports';

export interface StoredArtifactMetadata {
  path: string;
  absolute_path: string;
  sha256: string;
  size_bytes: number;
  mime_type: string;
  created_at: string;
}

export interface ArtifactIntegrityResult {
  valid: boolean;
  status: 'VALID' | 'INVALID';
  expected_sha256: string;
  actual_sha256: string;
  size_bytes: number;
  error?: string;
}

export interface IArtifactStorage {
  /**
   * Stores an artifact safely on disk/storage backend, calculating its actual SHA-256 and byte size.
   */
  store(
    investigationId: string,
    category: StorageCategory,
    filename: string,
    content: Buffer | string,
    mimeType?: string
  ): Promise<StoredArtifactMetadata>;

  /**
   * Synchronously stores an artifact on disk, calculating actual SHA-256 and byte size.
   */
  storeSync?(
    investigationId: string,
    category: StorageCategory,
    filename: string,
    content: Buffer | string,
    mimeType?: string
  ): StoredArtifactMetadata;

  /**
   * Reads raw bytes of an artifact.
   */
  read(relativePath: string): Promise<Buffer>;

  /**
   * Reads UTF-8 text content of an artifact.
   */
  readText(relativePath: string): Promise<string>;

  /**
   * Checks if an artifact exists on storage.
   */
  exists(relativePath: string): Promise<boolean>;

  /**
   * Verifies the cryptographic SHA-256 integrity of an artifact on disk against expected hash.
   */
  verifyIntegrity(
    relativePath: string,
    expectedSha256: string
  ): Promise<ArtifactIntegrityResult>;

  /**
   * Resolves safe relative path to an absolute path, preventing directory traversal.
   */
  resolveSafePath(relativePath: string): string;

  /**
   * Deletes an artifact from storage.
   */
  delete(relativePath: string): Promise<boolean>;
}
