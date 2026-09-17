import { describe, it, expect } from 'vitest';
import { JobOrchestrator } from '../../packages/orchestrator/src/index.js';
import { JobStatus } from '../../packages/core/src/index.js';
import { BaseEngine, EngineResultStatus } from '../../engines/index.js';
import { globalEngineRegistry } from '../../engines/engine_registry.js';

describe('Job Queue & Orchestrator Execution Workflow (Phase 0 Requirement 6, 7, 8, 9)', () => {
  it('should queue a real job and transition to QUEUED with logs', () => {
    const orchestrator = new JobOrchestrator();
    const emittedEvents: string[] = [];

    orchestrator.subscribe((event) => {
      emittedEvents.push(event.type);
    });

    const job = orchestrator.createJob({
      id: 'job-int-01',
      investigation_id: 'inv-01',
      target_id: 'tgt-01',
      engine: 'git-source-integrity',
      operation: 'verify_commit',
    });

    expect(job.status).toBe(JobStatus.QUEUED);
    expect(emittedEvents).toContain('job_created');
    expect(emittedEvents).toContain('job_queued');

    const logs = orchestrator.getLogs(job.id);
    expect(logs.length).toBeGreaterThan(0);
    expect(logs[0].message).toContain('Job job-int-01 created');
  });

  it('should execute a real job with available git engine and reach COMPLETED state', async () => {
    const orchestrator = new JobOrchestrator();
    const emittedEvents: string[] = [];

    orchestrator.subscribe((event) => {
      emittedEvents.push(event.type);
    });

    const job = orchestrator.createJob({
      id: 'job-int-02',
      investigation_id: 'inv-01',
      target_id: 'tgt-01',
      engine: 'git-source-integrity',
      operation: 'verify_commit',
    });

    const completedJob = await orchestrator.runJob(job.id);

    expect(completedJob.status).toBe(JobStatus.COMPLETED);
    expect(completedJob.exit_code).toBe(0);
    expect(completedJob.stdout_artifact_id).toBeDefined();
    expect(emittedEvents).toContain('job_started');
    expect(emittedEvents).toContain('job_completed');
  });

  it('should fail cleanly when engine is missing or unavailable without synthetic success', async () => {
    const orchestrator = new JobOrchestrator();
    const emittedEvents: string[] = [];

    orchestrator.subscribe((event) => {
      emittedEvents.push(event.type);
    });

    const job = orchestrator.createJob({
      id: 'job-int-03',
      investigation_id: 'inv-01',
      target_id: 'tgt-01',
      engine: 'semgrep-static-analyzer',
      operation: 'ast_rule_scan',
    });

    const failedJob = await orchestrator.runJob(job.id);

    expect(failedJob.status).toBe(JobStatus.FAILED);
    expect(failedJob.exit_code).toBe(127);
    expect(failedJob.error).toContain('not found');
    expect(emittedEvents).toContain('job_failed');
  });

  it('should support job cancellation before completion', async () => {
    const orchestrator = new JobOrchestrator();
    const job = orchestrator.createJob({
      id: 'job-int-04',
      investigation_id: 'inv-01',
      target_id: 'tgt-01',
      engine: 'git-source-integrity',
      operation: 'verify_commit',
    });

    const cancelled = await orchestrator.cancelJob(job.id);
    expect(cancelled.status).toBe(JobStatus.CANCELLED);
  });

  it('should pass job identity into the engine execution context', async () => {
    // Engines resolve investigation/target identity from the execution context.
    // If the orchestrator omitted them, engines fell back to `inv-unknown` and
    // their candidates/evidence became unattributable to the real investigation.
    const seen: Record<string, any>[] = [];

    class ContextProbeEngine extends BaseEngine {
      readonly engine_id = 'context-probe';
      readonly name = 'Context Probe';
      readonly version = '1.0.0';
      readonly description = 'Test-only engine that records the context it receives.';
      readonly executable = 'git';
      readonly capabilities = ['probe'];
      readonly supported_target_types = ['LIBRARY'];
      readonly supported_languages = ['javascript'];

      async prepare(_targetId: string, _context: Record<string, any>): Promise<boolean> {
        return true;
      }

      parse_result(): [] {
        return [];
      }

      async cleanup(_context: Record<string, any>): Promise<void> {}

      async execute(targetId: string, operation: string, context: Record<string, any>) {
        seen.push({ targetId, operation, context });
        return {
          id: 'res-context-probe',
          engine_id: this.engine_id,
          engine_name: this.name,
          engine_version: this.version,
          status: EngineResultStatus.SUCCESS,
          target_id: targetId,
          command: 'context-probe',
          working_directory: process.cwd(),
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          duration_ms: 0,
          exit_code: 0,
          stdout: 'probe',
          stderr: '',
          findings: [],
          artifacts: [],
          environment: this.getEnvironmentInfo(),
          error: null,
        };
      }
    }

    globalEngineRegistry.register(new ContextProbeEngine());
    try {
      const orchestrator = new JobOrchestrator();
      const job = orchestrator.createJob({
        id: 'job-int-05',
        investigation_id: 'inv-context-propagation',
        target_id: 'tgt-context-propagation',
        engine: 'context-probe',
        operation: 'probe_op',
        metadata: { source_directory: '/tmp/source' },
      });

      const completed = await orchestrator.runJob(job.id);
      expect(completed.status).toBe(JobStatus.COMPLETED);

      expect(seen).toHaveLength(1);
      expect(seen[0].targetId).toBe('tgt-context-propagation');
      expect(seen[0].operation).toBe('probe_op');
      // Job identity must survive alongside caller-supplied metadata.
      expect(seen[0].context.investigation_id).toBe('inv-context-propagation');
      expect(seen[0].context.target_id).toBe('tgt-context-propagation');
      expect(seen[0].context.source_directory).toBe('/tmp/source');
    } finally {
      globalEngineRegistry.unregister('context-probe');
    }
  });
});
