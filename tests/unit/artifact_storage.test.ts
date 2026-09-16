import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { LocalFilesystemArtifactStorage } from '../../packages/evidence/src/storage/local_storage.js';
import * as fs from 'fs';
import * as path from 'path';

describe('Phase 0.2 — LocalFilesystemArtifactStorage Tests', () => {
  const testStorageDir = path.resolve(process.cwd(), 'storage/test_storage_tmp');
  let storage: LocalFilesystemArtifactStorage;

  beforeEach(() => {
    if (fs.existsSync(testStorageDir)) {
      fs.rmSync(testStorageDir, { recursive: true, force: true });
    }
    storage = new LocalFilesystemArtifactStorage(testStorageDir);
  });

  afterEach(() => {
    if (fs.existsSync(testStorageDir)) {
      fs.rmSync(testStorageDir, { recursive: true, force: true });
    }
  });

  it('should store and read artifact content preserving exact bytes', async () => {
    const rawContent = 'SECURITY_AUDIT_OUTPUT_RAW_BYTES_12345';
    const metadata = await storage.store('inv-001', 'evidence', 'stdout.log', rawContent);

    expect(metadata.size_bytes).toBe(Buffer.byteLength(rawContent, 'utf-8'));
    expect(metadata.sha256).toBeDefined();

    const exists = await storage.exists(metadata.path);
    expect(exists).toBe(true);

    const readContent = await storage.readText(metadata.path);
    expect(readContent).toBe(rawContent);
  });

  it('should compute cryptographic SHA-256 digest matching standard crypto and verify integrity', async () => {
    const rawContent = 'contract Test { uint256 a; }';
    const metadata = await storage.store('inv-002', 'source', 'source.sol', rawContent);

    const check = await storage.verifyIntegrity(metadata.path, metadata.sha256);
    expect(check.valid).toBe(true);
    expect(check.status).toBe('VALID');
    expect(check.actual_sha256).toBe(metadata.sha256);
  });

  it('should reject directory traversal attempts securely in resolveSafePath', () => {
    const maliciousPaths = [
      '../outside.txt',
      '../../etc/passwd',
      'foo/../../../bar.txt',
    ];

    for (const p of maliciousPaths) {
      expect(() => storage.resolveSafePath(p)).toThrow();
    }
  });

  it('should delete artifacts correctly', async () => {
    const metadata = await storage.store('inv-003', 'evidence', 'temp.log', 'temporary data');
    expect(await storage.exists(metadata.path)).toBe(true);

    const deleted = await storage.delete(metadata.path);
    expect(deleted).toBe(true);
    expect(await storage.exists(metadata.path)).toBe(false);
  });
});
