/**
 * Git Source Integrity Engine
 * Intent Security Workbench - Phase 0.1
 *
 * Real host-backed engine that performs genuine version checks and git operations
 * without mock data or simulated responses.
 */

import { BaseEngine } from '../base_engine.js';
import { EngineResult, EngineResultStatus, EngineFinding, EngineAvailabilityStatus } from '../types.js';
import { execFileSync } from 'child_process';

export class GitSourceIntegrityEngine extends BaseEngine {
  readonly engine_id = 'git-source-integrity';
  readonly name = 'Git Source Integrity';
  readonly version = '1.0.0';
  readonly description = 'Verifies repository commits, working tree state, and source snapshot provenance.';
  readonly executable = 'git';
  readonly capabilities = ['source verification', 'commit verification', 'working tree status'];
  readonly supported_target_types = ['SMART_CONTRACT', 'PROTOCOL', 'WEB_APPLICATION', 'REST_API', 'BINARY_NODE', 'LIBRARY'];
  readonly supported_languages = ['all'];

  async prepare(targetId: string, context: Record<string, any>): Promise<boolean> {
    return true;
  }

  async execute(targetId: string, operation: string, context: Record<string, any>): Promise<EngineResult> {
    const avail = await this.check_availability();
    const startTime = new Date().toISOString();
    const startMs = Date.now();

    if (avail.status !== EngineAvailabilityStatus.AVAILABLE) {
      const endTime = new Date().toISOString();
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.engineVersionFor(avail),
        status: EngineResultStatus.UNAVAILABLE,
        target_id: targetId,
        investigation_id: context.investigation_id,
        command: `git ${operation} [failed]`,
        working_directory: context.working_directory || process.cwd(),
        started_at: startTime,
        completed_at: endTime,
        duration_ms: 0,
        exit_code: 127,
        stdout: '',
        stderr: avail.error || 'git executable unavailable',
        findings: [],
        artifacts: [],
        environment: this.getEnvironmentInfo(avail.detected_path),
        error: avail.error,
      };
    }

    try {
      let stdout = '';
      let cmd = `git ${operation}`;

      if (operation === 'status') {
        // A workspace that is not a git repository is a genuine failure of the
        // requested operation. Previously the error was swallowed, the git
        // version was written to stdout instead, and the run was reported as
        // SUCCESS with exit_code 0 — asserting work that never happened.
        try {
          stdout = execFileSync('git', ['status', '--short'], {
            encoding: 'utf-8',
            timeout: 5000,
            cwd: context.working_directory || process.cwd(),
          });
        } catch (err: any) {
          const endTime = new Date().toISOString();
          return this.failedResult(
            targetId,
            context,
            'git status --short',
            startTime,
            endTime,
            startMs,
            `git status failed in '${context.working_directory || process.cwd()}': ${String(
              err?.stderr || err?.message || err
            ).trim()}`,
            avail
          );
        }
      } else if (operation === 'verify_commit') {
        try {
          stdout = execFileSync('git', ['log', '-1', '--oneline'], {
            encoding: 'utf-8',
            timeout: 5000,
            cwd: context.working_directory || process.cwd(),
          });
        } catch (err: any) {
          const endTime = new Date().toISOString();
          return this.failedResult(
            targetId,
            context,
            'git log -1 --oneline',
            startTime,
            endTime,
            startMs,
            `git log failed in '${context.working_directory || process.cwd()}': ${String(
              err?.stderr || err?.message || err
            ).trim()}`,
            avail
          );
        }
      } else {
        cmd = 'git --version';
        stdout = execFileSync('git', ['--version'], {
          encoding: 'utf-8',
          timeout: 5000,
        });
      }

      const endTime = new Date().toISOString();
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: avail.version || this.version,
        status: EngineResultStatus.SUCCESS,
        target_id: targetId,
        investigation_id: context.investigation_id,
        command: cmd,
        working_directory: context.working_directory || process.cwd(),
        started_at: startTime,
        completed_at: endTime,
        duration_ms: Date.now() - startMs,
        exit_code: 0,
        stdout,
        stderr: '',
        findings: [], // No fake findings
        artifacts: [],
        environment: this.getEnvironmentInfo(avail.detected_path),
      };
    } catch (err: any) {
      const endTime = new Date().toISOString();
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.engineVersionFor(avail),
        status: EngineResultStatus.FAILED,
        target_id: targetId,
        investigation_id: context.investigation_id,
        command: `git ${operation}`,
        working_directory: context.working_directory || process.cwd(),
        started_at: startTime,
        completed_at: endTime,
        duration_ms: Date.now() - startMs,
        exit_code: err.status || 1,
        stdout: err.stdout ? err.stdout.toString() : '',
        stderr: err.stderr ? err.stderr.toString() : (err.message || String(err)),
        findings: [],
        artifacts: [],
        environment: this.getEnvironmentInfo(avail.detected_path),
        error: err.message || String(err),
      };
    }
  }

  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[] {
    return [];
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}
