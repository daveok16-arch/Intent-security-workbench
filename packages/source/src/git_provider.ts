/**
 * Git Source Provider for Intent Security Workbench
 * Phase 1 Scope & Target Authorization Subsystem
 *
 * Real sandboxed Git source code acquisition, exact commit checkout,
 * security sandboxing against hook execution & path traversal,
 * and deterministic cryptographic source tree hashing.
 */

import { execFile } from 'child_process';
import crypto, { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import {
  Target,
  SourceSnapshot,
  SourceSnapshotStatus,
  SourceAcquisitionStatus,
  ArtifactType,
  EvidenceEventType,
} from '../../core/src/index.js';
import {
  globalArtifactStorage,
  createEvidenceArtifact,
  globalEvidenceEventManager,
} from '../../evidence/src/index.js';
import { SourceSnapshotService, globalSourceSnapshotService } from '../../evidence/src/snapshot.js';
import { createSanitizedProcessEnv, redactUriCredentials } from '../../config/src/index.js';

const execFileAsync = promisify(execFile);

export const GIT_PROVIDER_VERSION = '1.0.0-phase1';

export function sanitizeRelativePath(relPath: string): string {
  if (!relPath) return '';
  const normalized = relPath.replace(/\\/g, '/');
  if (normalized.startsWith('/') || normalized.startsWith('\\') || path.isAbsolute(relPath)) {
    throw new Error(`Directory traversal detected: Absolute paths are forbidden (${relPath})`);
  }
  if (normalized.includes('../') || normalized.includes('/..') || normalized === '..' || normalized.includes('..\\')) {
    throw new Error(`Directory traversal detected in relative path: ${relPath}`);
  }
  return normalized.replace(/^\.\//, '');
}

export async function computeTreeHash(dirPath: string): Promise<{ treeHash: string; fileCount: number; totalBytes: number }> {
  if (!fs.existsSync(dirPath)) {
    throw new Error(`Directory does not exist: ${dirPath}`);
  }

  const allFiles: { relPath: string; hash: string; size: number }[] = [];

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === '.git') continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const fileContent = fs.readFileSync(fullPath);
        const fileHash = createHash('sha256').update(fileContent).digest('hex');
        const relPath = path.relative(dirPath, fullPath).replace(/\\/g, '/');
        allFiles.push({
          relPath,
          hash: fileHash,
          size: fileContent.length,
        });
      }
    }
  }

  walk(dirPath);

  allFiles.sort((a, b) => a.relPath.localeCompare(b.relPath));

  const manifestLines = allFiles.map(f => `${f.relPath}:${f.hash}`).join('\n');
  const treeHash = createHash('sha256').update(manifestLines).digest('hex');
  const totalBytes = allFiles.reduce((acc, f) => acc + f.size, 0);

  return {
    treeHash,
    fileCount: allFiles.length,
    totalBytes,
  };
}

export interface SourceAcquisitionResult {
  success: boolean;
  snapshot?: SourceSnapshot;
  resolved_commit_sha?: string;
  source_hash?: string;
  storage_path?: string;
  artifact_id?: string;
  file_count?: number;
  total_bytes?: number;
  execution_time_ms?: number;
  error?: string;
  logs?: string;
}

export interface SourceProvider {
  readonly provider_name: string;
  readonly provider_version: string;
  validate(targetOrRef: Target | string): { valid: boolean; error?: string };
  acquire(
    target: Target,
    options?: {
      destination?: string;
      branch?: string;
      commit?: string;
      timeout_ms?: number;
      investigation_id?: string;
    }
  ): Promise<SourceAcquisitionResult>;
  get_revision(repoPath: string): Promise<string>;
  calculate_source_hash(dirPath: string): Promise<string>;
  cleanup(targetOrDir: string): Promise<void>;
  verify_source_integrity(
    snapshot: SourceSnapshot
  ): Promise<{
    verified: boolean;
    computed_hash: string;
    stored_hash: string;
    expected_hash?: string;
    actual_hash?: string;
    error?: string;
  }>;
}

export type ISourceProvider = SourceProvider;

export class GitSourceProvider implements SourceProvider {
  public readonly provider_name = 'git';
  public readonly provider_version = GIT_PROVIDER_VERSION;
  private sandboxBaseDir: string;

  constructor(sandboxBaseDir?: string) {
    this.sandboxBaseDir = sandboxBaseDir || path.resolve(process.cwd(), 'data/sources');
    if (!fs.existsSync(this.sandboxBaseDir)) {
      fs.mkdirSync(this.sandboxBaseDir, { recursive: true });
    }
  }

  /**
   * Validates target repository reference or URL.
   */
  public validate(targetOrRef: Target | string): { valid: boolean; error?: string } {
    const ref = typeof targetOrRef === 'string' ? targetOrRef : targetOrRef.repository_url || '';
    if (!ref) {
      return { valid: false, error: 'Repository reference or URL is required.' };
    }
    return this.validateRepoReference(ref);
  }

  /**
   * Static validation of a repository URL or path.
   */
  public static validateRepositoryUrl(ref: string): { valid: boolean; error?: string } {
    if (!ref || ref.trim().length === 0) {
      return { valid: false, error: 'Repository URL or path is required.' };
    }
    const trimmed = ref.trim();
    if (trimmed.startsWith('--') || trimmed.includes(';') || trimmed.includes('|') || trimmed.includes('`') || trimmed.includes('$')) {
      return { valid: false, error: 'Malicious repository reference format rejected.' };
    }
    return { valid: true };
  }

  /**
   * Resolves the exact commit revision SHA of a local checked-out repository.
   */
  public async get_revision(repoPath: string): Promise<string> {
    const resolvedPath = path.resolve(repoPath);
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`Repository path does not exist: ${resolvedPath}`);
    }
    const { stdout } = await execFileAsync(
      'git',
      ['-c', 'core.hooksPath=/dev/null', 'rev-parse', 'HEAD'],
      { cwd: resolvedPath, timeout: 10000 }
    );
    return stdout.trim();
  }

  /**
   * Computes deterministic cryptographic source tree hash over a directory.
   */
  public async calculate_source_hash(dirPath: string): Promise<string> {
    return GitSourceProvider.computeDirectoryHash(dirPath);
  }

  /**
   * Cleans up local checkout directory.
   */
  public async cleanup(targetOrDir: string): Promise<void> {
    let dir = targetOrDir;
    if (typeof targetOrDir === 'string' && !path.isAbsolute(targetOrDir)) {
      dir = path.join(this.sandboxBaseDir, targetOrDir);
    }
    const resolved = path.resolve(dir);
    const resolvedBase = path.resolve(this.sandboxBaseDir);
    if (resolved.startsWith(resolvedBase) || resolved.startsWith('/tmp')) {
      if (fs.existsSync(resolved)) {
        fs.rmSync(resolved, { recursive: true, force: true });
      }
    }
  }

  /**
   * Redacts potential credentials, tokens, or private URLs from logs.
   */
  private redactSecrets(text: string): string {
    if (!text) return '';
    return text
      .replace(/https?:\/\/[^@\s]+@/g, 'https://[REDACTED_CREDENTIALS]@')
      .replace(/token=[a-zA-Z0-9_-]+/g, 'token=[REDACTED]');
  }

  /**
   * Validates target repository reference against path traversal and malicious inputs.
   */
  private validateRepoReference(repoUrl: string): { valid: boolean; error?: string } {
    if (!repoUrl || repoUrl.trim().length === 0) {
      return { valid: false, error: 'Repository URL or path is required.' };
    }

    const trimmed = repoUrl.trim();

    // Check for obvious shell injection or suspicious arguments
    if (trimmed.startsWith('--') || trimmed.includes(';') || trimmed.includes('|') || trimmed.includes('`') || trimmed.includes('$')) {
      return { valid: false, error: 'Malicious repository reference format rejected.' };
    }

    return { valid: true };
  }

  /**
   * Deterministically computes a SHA256 cryptographic hash of a source directory tree.
   */
  public static computeDirectoryHash(dirPath: string): string {
    return SourceSnapshotService.computeDirectoryTreeHash(dirPath);
  }

  /**
   * Acquires a Git repository into a secure sandboxed directory, resolves the exact commit,
   * hashes the source tree, and creates immutable evidence artifacts.
   */
  public async acquire(
    target: Target,
    options?: {
      destination?: string;
      branch?: string;
      commit?: string;
      timeout_ms?: number;
      investigation_id?: string;
    }
  ): Promise<SourceAcquisitionResult> {
    const repoUrl = target.repository_url || target.identifier;
    if (!repoUrl) {
      return {
        success: false,
        error: `Target '${target.name}' does not specify a repository URL or repository identifier.`,
      };
    }

    const validation = this.validateRepoReference(repoUrl);
    if (!validation.valid) {
      return {
        success: false,
        error: `Repository validation failed: ${validation.error}`,
      };
    }

    const timeout = options?.timeout_ms || 120000;
    const now = new Date().toISOString();
    const snapId = `snap-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const destDir = options?.destination || path.join(this.sandboxBaseDir, `${target.id}_${snapId}`);

    // Prevent path traversal
    const resolvedDest = path.resolve(destDir);
    const resolvedBase = path.resolve(this.sandboxBaseDir);
    if (!resolvedDest.startsWith(resolvedBase) && !resolvedDest.startsWith('/tmp')) {
      return {
        success: false,
        error: `Destination path traversal rejected: ${resolvedDest} is outside ${resolvedBase}`,
      };
    }

    // Clean destination if exists
    if (fs.existsSync(resolvedDest)) {
      fs.rmSync(resolvedDest, { recursive: true, force: true });
    }
    fs.mkdirSync(resolvedDest, { recursive: true });

    let logs = '';
    const logBuffer: string[] = [];

    const appendLog = (msg: string) => {
      const sanitized = this.redactSecrets(msg);
      logBuffer.push(`[${new Date().toISOString()}] ${sanitized}`);
    };

    appendLog(`Initiating source acquisition for target '${target.name}' (${target.id})`);
    appendLog(`Repository source: ${repoUrl}`);

    const invId = options?.investigation_id || `inv-target-${target.id}`;

    // Record acquisition started event
    try {
      globalEvidenceEventManager.recordEvent({
        investigation_id: invId,
        event_type: EvidenceEventType.SOURCE_ACQUISITION_STARTED,
        actor: 'git-source-provider',
        producer: 'GitSourceProvider',
        producer_version: this.provider_version,
        metadata: {
          target_id: target.id,
          repository_url: repoUrl,
          requested_commit: target.commit_hash || options?.commit,
          branch: options?.branch || target.branch,
        },
      });
    } catch {
      // Best-effort
    }

    try {
      // 1. Check if source is a local directory
      const isLocalPath = fs.existsSync(repoUrl) && fs.statSync(repoUrl).isDirectory();

      let resolvedCommitSha = '';

      if (isLocalPath) {
        appendLog(`Detected local directory source at ${repoUrl}. Copying repository files...`);
        // Copy directory safely without executing hooks
        fs.cpSync(repoUrl, resolvedDest, {
          recursive: true,
          filter: (src) => {
            const basename = path.basename(src);
            // Copy everything except transient / external hooks
            if (basename === 'hooks' && src.includes('.git')) return false;
            return true;
          },
        });

        // Try getting real commit sha if local git repo
        if (fs.existsSync(path.join(resolvedDest, '.git'))) {
          try {
            const targetCommit = options?.commit || target.commit_hash;
            const targetBranch = options?.branch || target.branch;
            if (targetCommit) {
              appendLog(`Checking out local target commit: ${targetCommit}`);
              await execFileAsync(
                'git',
                ['-c', 'core.hooksPath=/dev/null', 'checkout', targetCommit],
                { cwd: resolvedDest, timeout: 15000 }
              );
            } else if (targetBranch) {
              appendLog(`Checking out local target branch: ${targetBranch}`);
              await execFileAsync(
                'git',
                ['-c', 'core.hooksPath=/dev/null', 'checkout', targetBranch],
                { cwd: resolvedDest, timeout: 15000 }
              );
            }

            const { stdout } = await execFileAsync(
              'git',
              ['-c', 'core.hooksPath=/dev/null', 'rev-parse', 'HEAD'],
              { cwd: resolvedDest, timeout: 10000 }
            );
            resolvedCommitSha = stdout.trim();
            appendLog(`Resolved local Git commit SHA: ${resolvedCommitSha}`);
          } catch (e: any) {
            resolvedCommitSha = options?.commit || target.commit_hash || 'HEAD-LOCAL-UNCOMMITTED';
          }
        } else {
          resolvedCommitSha = options?.commit || target.commit_hash || 'UNVERSIONED-LOCAL-SOURCE';
        }
      } else {
        // Remote Git repository clone with secure sandbox flags
        appendLog(`Cloning remote repository into sandbox with hook execution disabled...`);

        // Clone with core.hooksPath=/dev/null and --no-tags
        const cloneArgs = [
          '-c',
          'core.hooksPath=/dev/null',
          'clone',
          '--no-tags',
          repoUrl,
          resolvedDest,
        ];

        appendLog(`Executing: git ${cloneArgs.map((arg) => redactUriCredentials(arg)).join(' ')}`);
        const cloneResult = await execFileAsync('git', cloneArgs, {
          timeout,
          env: createSanitizedProcessEnv({
            GIT_TERMINAL_PROMPT: '0', // Prevent blocking on credentials
          }),
        });

        if (cloneResult.stdout) appendLog(`Git stdout: ${cloneResult.stdout}`);
        if (cloneResult.stderr) appendLog(`Git stderr: ${cloneResult.stderr}`);

        // If a specific commit or branch is requested, checkout with hooks disabled
        const targetCommit = options?.commit || target.commit_hash;
        const targetBranch = options?.branch || target.branch;

        if (targetCommit) {
          appendLog(`Checking out target commit: ${targetCommit}`);
          const checkoutResult = await execFileAsync(
            'git',
            ['-c', 'core.hooksPath=/dev/null', 'checkout', targetCommit],
            { cwd: resolvedDest, timeout: 30000, env: createSanitizedProcessEnv() }
          );
          if (checkoutResult.stdout) appendLog(`Checkout stdout: ${checkoutResult.stdout}`);
          if (checkoutResult.stderr) appendLog(`Checkout stderr: ${checkoutResult.stderr}`);
        } else if (targetBranch) {
          appendLog(`Checking out target branch: ${targetBranch}`);
          const checkoutResult = await execFileAsync(
            'git',
            ['-c', 'core.hooksPath=/dev/null', 'checkout', targetBranch],
            { cwd: resolvedDest, timeout: 30000, env: createSanitizedProcessEnv() }
          );
          if (checkoutResult.stdout) appendLog(`Checkout branch stdout: ${checkoutResult.stdout}`);
        }

        // Obtain exact resolved commit SHA
        const revParseResult = await execFileAsync(
          'git',
          ['-c', 'core.hooksPath=/dev/null', 'rev-parse', 'HEAD'],
          { cwd: resolvedDest, timeout: 10000, env: createSanitizedProcessEnv() }
        );
        resolvedCommitSha = revParseResult.stdout.trim();
        appendLog(`Successfully resolved exact commit SHA: ${resolvedCommitSha}`);
      }

      // Compute deterministic cryptographic source tree hash
      appendLog(`Computing cryptographic SHA-256 hash over directory tree...`);
      const sourceHash = GitSourceProvider.computeDirectoryHash(resolvedDest);
      appendLog(`Computed source tree hash: ${sourceHash}`);

      // Create SourceSnapshot object
      const snapshot: SourceSnapshot = {
        id: snapId,
        target_id: target.id,
        investigation_id: options?.investigation_id,
        repository_url: repoUrl,
        commit_hash: target.commit_hash || resolvedCommitSha,
        resolved_commit_sha: resolvedCommitSha,
        branch: options?.branch || target.branch,
        acquisition_method: 'git_clone',
        retrieval_timestamp: now,
        acquired_at: now,
        source_hash: sourceHash,
        provider: this.provider_name,
        provider_version: this.provider_version,
        acquisition_status: SourceSnapshotStatus.ACQUIRED,
        status: SourceSnapshotStatus.ACQUIRED,
        storage_path: resolvedDest,
        metadata: {
          resolved_commit: resolvedCommitSha,
          source_tree_hash: sourceHash,
          target_ecosystem: target.ecosystem,
          acquisition_node: process.env.HOSTNAME || 'workbench-engine',
        },
        created_at: now,
        updated_at: now,
      };

      // Register snapshot in globalSourceSnapshotService
      try {
        globalSourceSnapshotService.registerSnapshot(snapshot);
      } catch {
        // Best-effort
      }

      // Record Evidence Artifacts (Metadata + Acquisition Log)
      let artifactId = `art-${snapId}`;
      let logArtifactId: string | undefined;

      try {
        const artifactContent = JSON.stringify({
          snapshot_id: snapId,
          target_id: target.id,
          repository_url: repoUrl,
          resolved_commit_sha: resolvedCommitSha,
          source_hash: sourceHash,
          acquired_at: now,
          provider: this.provider_name,
        }, null, 2);

        await globalArtifactStorage.store(
          invId,
          'source',
          `snapshot_${snapId}.json`,
          artifactContent,
          'application/json'
        );

        artifactId = `art-${snapId}`;

        // Also store execution acquisition log artifact
        logs = logBuffer.join('\n');
        await globalArtifactStorage.store(
          invId,
          'source',
          `acquisition_log_${snapId}.txt`,
          logs,
          'text/plain'
        );
        logArtifactId = `art-log-${snapId}`;
      } catch (err: any) {
        appendLog(`Warning: Failed to record artifact into storage: ${err.message}`);
      }

      // Record Evidence Events (SOURCE_ACQUISITION_COMPLETED & SOURCE_ACQUIRED)
      try {
        const outputArtifacts = [artifactId];
        if (logArtifactId) outputArtifacts.push(logArtifactId);

        globalEvidenceEventManager.recordEvent({
          investigation_id: invId,
          event_type: EvidenceEventType.SOURCE_ACQUISITION_COMPLETED,
          actor: 'git-source-provider',
          producer: 'GitSourceProvider',
          producer_version: this.provider_version,
          output_artifacts: outputArtifacts,
          metadata: {
            snapshot_id: snapId,
            target_id: target.id,
            resolved_commit_sha: resolvedCommitSha,
            source_hash: sourceHash,
            artifact_id: artifactId,
            file_count: snapshot.metadata?.file_count,
            total_bytes: snapshot.metadata?.total_bytes,
          },
        });

        // Also record SOURCE_ACQUIRED for backwards compatibility
        globalEvidenceEventManager.recordEvent({
          investigation_id: invId,
          event_type: EvidenceEventType.SOURCE_ACQUIRED,
          actor: 'git-source-provider',
          producer: 'GitSourceProvider',
          producer_version: this.provider_version,
          output_artifacts: outputArtifacts,
          metadata: {
            snapshot_id: snapId,
            target_id: target.id,
            resolved_commit_sha: resolvedCommitSha,
            source_hash: sourceHash,
            artifact_id: artifactId,
          },
        });
      } catch (err: any) {
        appendLog(`Warning: Failed to record event into event manager: ${err.message}`);
      }

      logs = logBuffer.join('\n');

      return {
        success: true,
        snapshot,
        resolved_commit_sha: resolvedCommitSha,
        source_hash: sourceHash,
        storage_path: resolvedDest,
        artifact_id: artifactId,
        logs,
      };
    } catch (error: any) {
      appendLog(`Error during source acquisition: ${error.message}`);
      logs = logBuffer.join('\n');

      // Record failure event
      try {
        globalEvidenceEventManager.recordEvent({
          investigation_id: options?.investigation_id || `inv-target-${target.id}`,
          event_type: EvidenceEventType.SOURCE_ACQUISITION_FAILED,
          actor: 'git-source-provider',
          producer: 'GitSourceProvider',
          metadata: {
            target_id: target.id,
            error: this.redactSecrets(error.message),
            repository_url: repoUrl,
          },
        });
      } catch (e) {}

      return {
        success: false,
        error: this.redactSecrets(error.message),
        logs,
      };
    }
  }

  /**
   * Verifies that the source directory content on disk matches the stored cryptographic hash.
   */
  public async verify_source_integrity(
    snapshot: SourceSnapshot
  ): Promise<{
    verified: boolean;
    computed_hash: string;
    stored_hash: string;
    expected_hash?: string;
    actual_hash?: string;
    error?: string;
  }> {
    const storagePath = snapshot.storage_path;
    const storedHash = snapshot.source_hash || '';

    if (!storagePath || !fs.existsSync(storagePath)) {
      return {
        verified: false,
        computed_hash: 'FILE_NOT_FOUND',
        stored_hash: storedHash,
        expected_hash: storedHash,
        actual_hash: 'FILE_NOT_FOUND',
        error: `Storage path does not exist: ${storagePath}`,
      };
    }

    try {
      const computed = GitSourceProvider.computeDirectoryHash(storagePath);
      return {
        verified: computed === storedHash,
        computed_hash: computed,
        stored_hash: storedHash,
        expected_hash: storedHash,
        actual_hash: computed,
      };
    } catch (e: any) {
      return {
        verified: false,
        computed_hash: `ERROR: ${e.message}`,
        stored_hash: storedHash,
        expected_hash: storedHash,
        actual_hash: `ERROR: ${e.message}`,
        error: e.message,
      };
    }
  }
}

export const globalGitSourceProvider = new GitSourceProvider();
