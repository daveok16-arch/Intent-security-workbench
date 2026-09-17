/**
 * Anti-fabrication tests for engine result reporting.
 *
 * Two violations the evidence review found:
 *  - `GitSourceIntegrityEngine` swallowed a failed `git status` / `git log` and
 *    returned a version string on stdout with `status: SUCCESS` and
 *    `exit_code: 0`, asserting work that never happened.
 *  - `BaseEngine.describeArtifact` published an artifact descriptor with an
 *    empty `sha256`, `size: 0`, and an invented `created_at` when the id was not
 *    a registered artifact.
 */

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { GitSourceIntegrityEngine } from '../../engines/placeholders/git_integrity.js';
import { BaseEngine } from '../../engines/base_engine.js';
import { EngineResultStatus } from '../../engines/types.js';

describe('engines never report fabricated success', () => {
  it('reports FAILED (not SUCCESS with exit 0) when git status cannot run', async () => {
    const engine = new GitSourceIntegrityEngine();
    // A directory that is not a git repository.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'not-a-repo-'));

    try {
      const result = await engine.execute('tgt-1', 'status', { working_directory: dir });

      expect(result.status).toBe(EngineResultStatus.FAILED);
      expect(result.exit_code).not.toBe(0);
      expect(result.error).toBeTruthy();
      expect(result.findings).toHaveLength(0);
      // The git version string must not be smuggled into stdout as a result.
      expect(result.stdout).toBe('');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('still succeeds for a real git repository', async () => {
    const engine = new GitSourceIntegrityEngine();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'a-repo-'));
    try {
      const { execFileSync } = await import('child_process');
      execFileSync('git', ['init'], { cwd: dir, stdio: 'ignore' });

      const result = await engine.execute('tgt-1', 'status', { working_directory: dir });
      expect(result.status).toBe(EngineResultStatus.SUCCESS);
      expect(result.exit_code).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('describeArtifact refuses to invent provenance', () => {
  // Expose the protected helper for direct assertions.
  class Probe extends BaseEngine {
    readonly name = 'Probe';
    readonly engine_id = 'probe';
    readonly version = '0.0.0';
    readonly description = 'test probe';
    readonly capabilities: string[] = [];
    readonly supported_target_types: string[] = [];
    readonly supported_languages: string[] = [];
    readonly executable = 'probe';
    async prepare() { return true; }
    async execute() {
      return this.failedResult('t', {}, 'probe', new Date().toISOString(), new Date().toISOString(), Date.now(), 'nope');
    }
    parse_result() { return []; }
    async cleanup() {}
    public describe(id: string, type: string, p: string) {
      return this.describeArtifact(id, type, p);
    }
  }

  it('returns null for an unregistered artifact id instead of an empty digest', () => {
    const probe = new Probe();
    const descriptor = probe.describe('art-does-not-exist', 'AST', 'ast/x');
    expect(descriptor).toBeNull();
  });

  it('reports real timing and a non-zero exit for a failed result', async () => {
    const probe = new Probe();
    const result = await probe.execute();
    expect(result.status).toBe(EngineResultStatus.FAILED);
    expect(result.exit_code).toBe(1);
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });
});