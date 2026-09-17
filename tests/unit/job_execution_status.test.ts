/**
 * The job execution status must reflect what the engine actually produced.
 *
 * `ENGINE_COMPLETED_WITH_FINDINGS` was defined but never assigned: the success
 * branch hardcoded `ENGINE_COMPLETED_NO_FINDINGS`, so a static-analysis run that
 * stored 128 candidates still reported "completed with no findings". The
 * execution status contradicted the results the same run persisted.
 */

import { describe, it, expect } from 'vitest';
import { JobOrchestrator } from '../../packages/orchestrator/src/index.js';
import { EngineExecutionStatus, JobStatus } from '../../packages/core/src/index.js';
import { BaseEngine } from '../../engines/base_engine.js';
import { EngineResult, EngineResultStatus } from '../../engines/types.js';

function engineReturning(id: string, findings: any[]): BaseEngine {
  class FixedEngine extends BaseEngine {
    readonly name = id;
    readonly engine_id = id;
    readonly version = '1.0.0';
    readonly description = 'fixed-output test engine';
    readonly capabilities: string[] = [];
    readonly supported_target_types: string[] = [];
    readonly supported_languages: string[] = [];
    readonly executable = 'fixed';

    // The orchestrator refuses to execute an engine whose binary does not
    // resolve. This engine is in-process, so it reports itself available rather
    // than depending on a tool being installed on the test host.
    async check_availability() {
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: 'AVAILABLE' as any,
        executable: this.executable,
        detected_path: process.execPath,
        version: this.version,
        checked_at: new Date().toISOString(),
        error: null,
        capabilities: this.capabilities,
      };
    }

    async prepare() { return true; }
    async execute(): Promise<EngineResult> {
      const now = new Date().toISOString();
      return {
        id: `res-${id}`,
        engine_id: id,
        engine_name: id,
        engine_version: '1.0.0',
        status: EngineResultStatus.SUCCESS,
        target_id: 'tgt-1',
        investigation_id: 'inv-status-1',
        command: 'fixed',
        working_directory: process.cwd(),
        started_at: now,
        completed_at: now,
        duration_ms: 1,
        exit_code: 0,
        stdout: '{}',
        stderr: '',
        findings,
        artifacts: [],
        environment: { hostname: 'test', os: 'test', node_version: process.version },
      };
    }
    parse_result() { return []; }
    async cleanup() {}
  }
  return new FixedEngine();
}

describe('job execution status reflects real output', () => {
  it('reports WITH_FINDINGS when the engine produced findings', async () => {
    const orchestrator = new JobOrchestrator();
    orchestrator.registerEngine(engineReturning('with-findings-engine', [
      {
        id: 'f1', title: 't', description: 'd', severity: 'HIGH', category: 'BOLA',
        confidence: 'HIGH', file: 'a.ts', line_start: 1, line_end: 2,
      },
    ]));

    const job = orchestrator.createJob({
      investigation_id: 'inv-status-1',
      target_id: 'tgt-1',
      engine: 'with-findings-engine',
      operation: 'analyze',
    });

    const finished = await orchestrator.runJob(job.id);
    expect(finished.status).toBe(JobStatus.COMPLETED);
    expect(finished.execution_status).toBe(EngineExecutionStatus.ENGINE_COMPLETED_WITH_FINDINGS);
  });

  it('reports NO_FINDINGS when the engine produced none', async () => {
    const orchestrator = new JobOrchestrator();
    orchestrator.registerEngine(engineReturning('no-findings-engine', []));

    const job = orchestrator.createJob({
      investigation_id: 'inv-status-2',
      target_id: 'tgt-1',
      engine: 'no-findings-engine',
      operation: 'analyze',
    });

    const finished = await orchestrator.runJob(job.id);
    expect(finished.execution_status).toBe(EngineExecutionStatus.ENGINE_COMPLETED_NO_FINDINGS);
  });
});