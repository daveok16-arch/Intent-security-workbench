/**
 * Local Filesystem Artifact Storage
 * Phase 0.2 Evidence & Provenance Subsystem
 *
 * Stores artifacts under:
 * storage/
 *   investigations/
 *     <investigation_id>/
 *       source/
 *       engines/
 *       evidence/
 *       reports/
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
  IArtifactStorage,
  StorageCategory,
  StoredArtifactMetadata,
  ArtifactIntegrityResult,
} from './storage_interface.js';

export class LocalFilesystemArtifactStorage implements IArtifactStorage {
  private rootDir: string;

  constructor(rootDir: string = './storage') {
    this.rootDir = path.resolve(rootDir);
    this.ensureDirectory(this.rootDir);
  }

  /**
   * Helper to ensure a directory exists synchronously.
   */
  private ensureDirectory(dirPath: string): void {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
  }

  /**
   * Sanitizes filenames to prevent injection and directory traversal.
   */
  public sanitizeFilename(filename: string): string {
    // Strip null bytes, slashes, and control characters
    const base = path.basename(filename).replace(/[\x00-\x1f\x80-\x9f\\/<>:"|?*]/g, '_');
    return base.trim() || `artifact_${Date.now()}.bin`;
  }

  /**
   * Sanitizes investigation ID for path creation.
   */
  public sanitizeInvestigationId(id: string): string {
    const clean = id.replace(/[^a-zA-Z0-9_-]/g, '_');
    return clean || 'default';
  }

  /**
   * Resolves safe relative path to an absolute path, strictly preventing directory traversal.
   */
  public resolveSafePath(relativePath: string): string {
    if (!relativePath || typeof relativePath !== 'string') {
      throw new Error('Invalid relative path specified');
    }

    // Reject null byte injection
    if (relativePath.indexOf('\0') !== -1) {
      throw new Error('Null byte detected in path');
    }

    // Normalize and resolve absolute path
    const absolute = path.resolve(this.rootDir, relativePath);

    // Verify it stays strictly within root directory
    const relativeToRoot = path.relative(this.rootDir, absolute);
    if (relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot) || relativePath.startsWith('/') || relativePath.startsWith('\\')) {
      throw new Error(`Security Violation: Path traversal detected outside storage root: '${relativePath}'`);
    }

    return absolute;
  }

  /**
   * Stores an artifact safely on disk, computing its SHA-256 and byte size.
   */
  public async store(
    investigationId: string,
    category: StorageCategory,
    filename: string,
    content: Buffer | string,
    mimeType: string = 'text/plain'
  ): Promise<StoredArtifactMetadata> {
    const cleanInvId = this.sanitizeInvestigationId(investigationId);
    const cleanFilename = this.sanitizeFilename(filename);

    const relativeDirPath = path.join('investigations', cleanInvId, category);
    const absoluteDirPath = path.join(this.rootDir, relativeDirPath);
    this.ensureDirectory(absoluteDirPath);

    const relativeFilePath = path.join(relativeDirPath, cleanFilename);
    const absoluteFilePath = path.join(this.rootDir, relativeFilePath);

    // Convert string to Buffer if necessary
    const buffer = typeof content === 'string' ? Buffer.from(content, 'utf-8') : content;

    // Write file to disk
    await fs.promises.writeFile(absoluteFilePath, buffer);

    // Compute exact SHA-256 over actual bytes written
    const hash = crypto.createHash('sha256').update(buffer).digest('hex');
    const size_bytes = buffer.length;
    const created_at = new Date().toISOString();

    return {
      path: relativeFilePath.replace(/\\/g, '/'),
      absolute_path: absoluteFilePath,
      sha256: hash,
      size_bytes,
      mime_type: mimeType,
      created_at,
    };
  }

  /**
   * Synchronously stores an artifact safely on disk, computing SHA-256 and byte size.
   */
  public storeSync(
    investigationId: string,
    category: StorageCategory,
    filename: string,
    content: Buffer | string,
    mimeType: string = 'text/plain'
  ): StoredArtifactMetadata {
    const cleanInvId = this.sanitizeInvestigationId(investigationId);
    const cleanFilename = this.sanitizeFilename(filename);

    const relativeDirPath = path.join('investigations', cleanInvId, category);
    const absoluteDirPath = path.join(this.rootDir, relativeDirPath);
    this.ensureDirectory(absoluteDirPath);

    const relativeFilePath = path.join(relativeDirPath, cleanFilename);
    const absoluteFilePath = path.join(this.rootDir, relativeFilePath);

    const buffer = typeof content === 'string' ? Buffer.from(content, 'utf-8') : content;
    fs.writeFileSync(absoluteFilePath, buffer);

    const hash = crypto.createHash('sha256').update(buffer).digest('hex');
    const size_bytes = buffer.length;
    const created_at = new Date().toISOString();

    return {
      path: relativeFilePath.replace(/\\/g, '/'),
      absolute_path: absoluteFilePath,
      sha256: hash,
      size_bytes,
      mime_type: mimeType,
      created_at,
    };
  }

  /**
   * Reads raw binary bytes of an artifact.
   */
  public async read(relativePath: string): Promise<Buffer> {
    const absPath = this.resolveSafePath(relativePath);
    if (!fs.existsSync(absPath)) {
      throw new Error(`Artifact not found on storage: ${relativePath}`);
    }
    return fs.promises.readFile(absPath);
  }

  /**
   * Reads UTF-8 text content of an artifact.
   */
  public async readText(relativePath: string): Promise<string> {
    const buffer = await this.read(relativePath);
    return buffer.toString('utf-8');
  }

  /**
   * Checks if an artifact exists on storage.
   */
  public async exists(relativePath: string): Promise<boolean> {
    try {
      const absPath = this.resolveSafePath(relativePath);
      return fs.existsSync(absPath);
    } catch {
      return false;
    }
  }

  /**
   * Verifies the cryptographic SHA-256 integrity of an artifact on disk.
   */
  public async verifyIntegrity(
    relativePath: string,
    expectedSha256: string
  ): Promise<ArtifactIntegrityResult> {
    try {
      const absPath = this.resolveSafePath(relativePath);
      if (!fs.existsSync(absPath)) {
        return {
          valid: false,
          status: 'INVALID',
          expected_sha256: expectedSha256,
          actual_sha256: '',
          size_bytes: 0,
          error: `Artifact file does not exist at path: ${relativePath}`,
        };
      }

      const buffer = await fs.promises.readFile(absPath);
      const actualHash = crypto.createHash('sha256').update(buffer).digest('hex');
      const size_bytes = buffer.length;
      const valid = actualHash.toLowerCase() === expectedSha256.toLowerCase();

      return {
        valid,
        status: valid ? 'VALID' : 'INVALID',
        expected_sha256: expectedSha256,
        actual_sha256: actualHash,
        size_bytes,
      };
    } catch (err: any) {
      return {
        valid: false,
        status: 'INVALID',
        expected_sha256: expectedSha256,
        actual_sha256: '',
        size_bytes: 0,
        error: err.message || String(err),
      };
    }
  }

  /**
   * Deletes an artifact from storage.
   */
  public async delete(relativePath: string): Promise<boolean> {
    try {
      const absPath = this.resolveSafePath(relativePath);
      if (fs.existsSync(absPath)) {
        await fs.promises.unlink(absPath);
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }
}
