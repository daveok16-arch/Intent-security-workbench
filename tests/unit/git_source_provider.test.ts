import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'path';
import fs from 'fs';
import { execFileSync } from 'child_process';
import {
  globalGitSourceProvider,
  computeTreeHash,
  sanitizeRelativePath,
  GitSourceProvider,
} from '../../packages/source/src/git_provider.js';
import {
  Target,
  TargetType,
  Ecosystem,
  SourceSnapshotStatus,
  ArtifactType,
} from '../../packages/core/src/index.js';
import { globalArtifactStorage, globalEvidenceEventManager } from '../../packages/evidence/src/index.js';

describe('GitSourceProvider (Sandboxed Repository Acquisition & Exact Checkouts)', () => {
  const tempFixtureDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempFixtureDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
    tempFixtureDirs.length = 0;
  });

  it('prevents directory traversal attacks in relative paths', () => {
    expect(() => sanitizeRelativePath('../../../etc/passwd')).toThrow(/Directory traversal detected/);
    expect(() => sanitizeRelativePath('..\\..\\windows\\system32')).toThrow(/Directory traversal detected/);
    expect(() => sanitizeRelativePath('/absolute/path')).toThrow(/Directory traversal detected/);
    expect(sanitizeRelativePath('contracts/Token.sol')).toBe('contracts/Token.sol');
  });

  it('rejects malicious repository references with command injection or dangerous flags', () => {
    const maliciousUrls = [
      '--upload-pack=evil',
      'https://github.com/org/repo.git; rm -rf /',
      'https://github.com/org/repo.git | cat /etc/passwd',
      'https://github.com/org/repo.git`touch /tmp/pwn`',
      'https://github.com/org/repo.git$(whoami)',
    ];

    for (const url of maliciousUrls) {
      const result = GitSourceProvider.validateRepositoryUrl(url);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/Malicious repository reference format rejected/);
    }
  });

  it('computes deterministic SHA-256 tree hash for a file directory ignoring .git', async () => {
    const testDir = path.join(process.cwd(), '.test_fixtures', `tree_test_${Date.now()}`);
    tempFixtureDirs.push(testDir);
    fs.mkdirSync(path.join(testDir, 'src'), { recursive: true });
    fs.mkdirSync(path.join(testDir, '.git'), { recursive: true });

    fs.writeFileSync(path.join(testDir, 'src', 'Vault.sol'), 'contract Vault { function deposit() external {} }');
    fs.writeFileSync(path.join(testDir, 'README.md'), '# Test Project');
    fs.writeFileSync(path.join(testDir, '.git', 'config'), 'dummy git config that must be ignored');

    const { treeHash, fileCount, totalBytes } = await computeTreeHash(testDir);
    expect(treeHash).toHaveLength(64);
    expect(fileCount).toBe(2); // Only Vault.sol and README.md, .git ignored
    expect(totalBytes).toBeGreaterThan(0);
  });

  it('acquires a real temporary Git repository and checks out the exact specified commit', async () => {
    // 1. Create a real temporary local Git repository
    const localRepoDir = path.join(process.cwd(), '.test_fixtures', `real_git_${Date.now()}`);
    tempFixtureDirs.push(localRepoDir);
    fs.mkdirSync(localRepoDir, { recursive: true });

    // Initialize git repo with config
    execFileSync('git', ['init'], { cwd: localRepoDir });
    execFileSync('git', ['config', 'user.name', 'Workbench Test'], { cwd: localRepoDir });
    execFileSync('git', ['config', 'user.email', 'test@workbench.internal'], { cwd: localRepoDir });

    // Commit 1: Initial Vault v1
    fs.writeFileSync(path.join(localRepoDir, 'Vault.sol'), 'contract VaultV1 { uint256 public balance; }');
    execFileSync('git', ['add', 'Vault.sol'], { cwd: localRepoDir });
    execFileSync('git', ['commit', '-m', 'Initial Vault v1'], { cwd: localRepoDir });
    const commit1 = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: localRepoDir }).toString().trim();

    // Commit 2: Vault v2
    fs.writeFileSync(path.join(localRepoDir, 'Vault.sol'), 'contract VaultV2 { uint256 public balance; address public owner; }');
    execFileSync('git', ['add', 'Vault.sol'], { cwd: localRepoDir });
    execFileSync('git', ['commit', '-m', 'Upgrade to Vault v2'], { cwd: localRepoDir });
    const commit2 = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: localRepoDir }).toString().trim();

    expect(commit1).not.toBe(commit2);

    // 2. Request acquisition of EXACT commit 1
    const target: Target = {
      id: `tgt-test-${Date.now()}`,
      program_id: 'prog-test-local',
      name: 'Local Test Git Target',
      target_type: TargetType.REPOSITORY,
      ecosystem: Ecosystem.EVM,
      repository_url: localRepoDir,
      commit_hash: commit1,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const result = await globalGitSourceProvider.acquire(target, {
      commit: commit1,
      investigation_id: 'inv-test-git-01',
    });

    expect(result.success).toBe(true);
    expect(result.resolved_commit_sha).toBe(commit1);
    expect(result.snapshot).toBeDefined();
    expect(result.snapshot?.commit_hash).toBe(commit1);
    expect(result.snapshot?.resolved_commit_sha).toBe(commit1);
    expect(result.source_hash).toBeDefined();
    expect(result.source_hash?.length).toBe(64);

    // Verify destination files match commit 1 content
    const acquiredFile = fs.readFileSync(path.join(result.storage_path!, 'Vault.sol'), 'utf-8');
    expect(acquiredFile).toBe('contract VaultV1 { uint256 public balance; }');

    // Verify evidence was created in artifact storage
    expect(result.artifact_id).toBeDefined();
    const storedSnapshot = await globalArtifactStorage.readText(`investigations/inv-test-git-01/source/snapshot_${result.snapshot?.id}.json`);
    expect(storedSnapshot).toBeDefined();
    const parsed = JSON.parse(storedSnapshot);
    expect(parsed.resolved_commit_sha).toBe(commit1);
    expect(parsed.target_id).toBe(target.id);

    // Clean up acquired directory
    if (result.storage_path) {
      tempFixtureDirs.push(result.storage_path);
    }
  });

  it('fails gracefully when given invalid or unreachable git repository URL', async () => {
    const target: Target = {
      id: 'tgt-nonexistent',
      program_id: 'prog-test',
      name: 'Unreachable Repo',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      repository_url: 'https://invalid-non-existent-domain.xyz/repo.git',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const result = await globalGitSourceProvider.acquire(target, { timeout_ms: 3000 });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});
