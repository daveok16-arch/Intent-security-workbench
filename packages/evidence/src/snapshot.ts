/**
 * Source Snapshot Management Service
 * Phase 0.2 Evidence & Provenance Subsystem
 *
 * Ground-truth source acquisition and cryptographic tree/file hashing.
 * A snapshot only reaches 'ACQUIRED' state when actual source bytes are retrieved and hashed.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { SourceSnapshot, SourceSnapshotStatus } from '../../core/src/index.js';
import { IArtifactStorage } from './storage/storage_interface.js';

export class SourceSnapshotService {
  private snapshots: Map<string, SourceSnapshot> = new Map();
  private storage?: IArtifactStorage;

  constructor(storage?: IArtifactStorage) {
    this.storage = storage;
  }

  /**
   * Registers an initial snapshot intent in PENDING status.
   */
  public createPendingSnapshot(params: {
    id?: string;
    target_id: string;
    investigation_id?: string;
    repository_url?: string;
    commit_hash?: string;
    branch?: string;
    acquisition_method: string;
    metadata?: Record<string, any>;
  }): SourceSnapshot {
    const id = params.id || `snap-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();

    const snapshot: SourceSnapshot = {
      id,
      target_id: params.target_id,
      investigation_id: params.investigation_id,
      repository_url: params.repository_url,
      commit_hash: params.commit_hash,
      branch: params.branch,
      acquisition_method: params.acquisition_method,
      status: SourceSnapshotStatus.PENDING,
      metadata: params.metadata || {},
      created_at: now,
      updated_at: now,
    };

    this.snapshots.set(id, snapshot);
    return snapshot;
  }

  /**
   * Transitions status to ACQUIRING.
   */
  public markAcquiring(snapshotId: string): SourceSnapshot {
    const snap = this.snapshots.get(snapshotId);
    if (!snap) throw new Error(`SourceSnapshot '${snapshotId}' not found.`);
    snap.status = SourceSnapshotStatus.ACQUIRING;
    snap.updated_at = new Date().toISOString();
    return snap;
  }

  /**
   * Finalizes snapshot with real byte content hash, transitioning to ACQUIRED.
   */
  public async acquireFromContent(
    snapshotId: string,
    content: Buffer | string,
    filename: string = 'source_archive.tar.gz'
  ): Promise<SourceSnapshot> {
    const snap = this.snapshots.get(snapshotId);
    if (!snap) throw new Error(`SourceSnapshot '${snapshotId}' not found.`);

    const buffer = typeof content === 'string' ? Buffer.from(content, 'utf-8') : content;
    const source_hash = crypto.createHash('sha256').update(buffer).digest('hex');
    const now = new Date().toISOString();

    let storagePath: string | undefined;
    if (this.storage && snap.investigation_id) {
      const stored = await this.storage.store(
        snap.investigation_id,
        'source',
        `${snapshotId}_${filename}`,
        buffer,
        'application/octet-stream'
      );
      storagePath = stored.path;
    }

    snap.status = SourceSnapshotStatus.ACQUIRED;
    snap.source_hash = source_hash;
    snap.acquired_at = now;
    snap.storage_path = storagePath;
    snap.updated_at = now;

    return snap;
  }

  /**
   * Hashes a local directory tree deterministically.
   */
  public static computeDirectoryTreeHash(dirPath: string): string {
    if (!fs.existsSync(dirPath)) {
      throw new Error(`Directory '${dirPath}' does not exist for source snapshot.`);
    }

    const hash = crypto.createHash('sha256');

    function walk(currentDir: string) {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      // Sort alphabetically for deterministic ordering
      entries.sort((a, b) => a.name.localeCompare(b.name));

      for (const entry of entries) {
        if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'dist') {
          continue; // Skip transient/build dirs
        }

        const fullPath = path.join(currentDir, entry.name);
        const relPath = path.relative(dirPath, fullPath).replace(/\\/g, '/');

        if (entry.isDirectory()) {
          hash.update(`DIR:${relPath}\n`);
          walk(fullPath);
        } else if (entry.isFile()) {
          const fileContent = fs.readFileSync(fullPath);
          const fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');
          hash.update(`FILE:${relPath}:${fileHash}:${fileContent.length}\n`);
        }
      }
    }

    walk(dirPath);
    return hash.digest('hex');
  }

  /**
   * Acquires snapshot from local directory.
   */
  public acquireFromLocalDirectory(snapshotId: string, dirPath: string): SourceSnapshot {
    const snap = this.snapshots.get(snapshotId);
    if (!snap) throw new Error(`SourceSnapshot '${snapshotId}' not found.`);

    const sourceHash = SourceSnapshotService.computeDirectoryTreeHash(dirPath);
    const now = new Date().toISOString();

    snap.status = SourceSnapshotStatus.ACQUIRED;
    snap.source_hash = sourceHash;
    snap.acquired_at = now;
    snap.updated_at = now;
    snap.metadata = {
      ...snap.metadata,
      source_directory: dirPath,
    };

    return snap;
  }

  /**
   * Marks snapshot as FAILED.
   */
  public markFailed(snapshotId: string, errorReason: string): SourceSnapshot {
    const snap = this.snapshots.get(snapshotId);
    if (!snap) throw new Error(`SourceSnapshot '${snapshotId}' not found.`);

    snap.status = SourceSnapshotStatus.FAILED;
    snap.updated_at = new Date().toISOString();
    snap.metadata = {
      ...snap.metadata,
      failure_reason: errorReason,
    };

    return snap;
  }

  public registerSnapshot(snapshot: SourceSnapshot): SourceSnapshot {
    this.snapshots.set(snapshot.id, snapshot);
    return snapshot;
  }

  public getSnapshot(id: string): SourceSnapshot | undefined {
    return this.snapshots.get(id);
  }

  public listSnapshots(target_id?: string): SourceSnapshot[] {
    let list = Array.from(this.snapshots.values());
    if (target_id) {
      list = list.filter(s => s.target_id === target_id);
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }
}

export const globalSourceSnapshotService = new SourceSnapshotService();
