import { describe, it, expect } from 'vitest';
import { JobOrchestrator } from '../../packages/orchestrator/src/index.js';
import { JobStatus } from '../../packages/core/src/index.js';

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
});
