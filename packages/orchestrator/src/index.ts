/**
 * Job Orchestrator & Execution Manager for Intent Security Workbench
 * Phase 0.2 Evidence & Provenance Subsystem
 * 
 * Strict job status lifecycle:
 * QUEUED -> RUNNING -> COMPLETED | FAILED | CANCELLED
 * 
 * Strict Phase 0 & 0.2 Failure Semantics:
 * - NO_ENGINE
 * - ENGINE_NOT_INSTALLED
 * - ENGINE_UNAVAILABLE
 * - ENGINE_EXECUTION_FAILED
 * - ENGINE_COMPLETED_NO_FINDINGS
 * - ENGINE_COMPLETED_WITH_FINDINGS
 * 
 * NEVER fabricate engine results. Output is strictly grounded in real executed process streams.
 */

import {
  AnalysisJob,
  JobStatus,
  ArtifactType,
  EngineExecutionStatus,
  EvidenceEventType,
} from '../../core/src/index.js';
import { globalEngineRegistry } from '../../../engines/engine_registry.js';
import {
  createEvidenceArtifact,
  globalEvidenceEventManager,
  globalArtifactStorage,
} from '../../evidence/src/index.js';

export type JobEventListener = (event: {
  type: 'job_created' | 'job_queued' | 'job_started' | 'job_completed' | 'job_failed' | 'job_cancelled';
  job: AnalysisJob;
  timestamp: string;
}) => void;

export interface StructuredJobLog {
  job_id: string;
  level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG';
  message: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

export class JobOrchestrator {
  private jobs: Map<string, AnalysisJob> = new Map();
  private logs: Map<string, StructuredJobLog[]> = new Map();
  private listeners: Set<JobEventListener> = new Set();
  private activeExecutions: Map<string, AbortController> = new Map();

  constructor(public storage?: any) {}

  registerEngine(engine: any): void {
    globalEngineRegistry.register(engine);
  }

  subscribe(listener: JobEventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(type: 'job_created' | 'job_queued' | 'job_started' | 'job_completed' | 'job_failed' | 'job_cancelled', job: AnalysisJob) {
    const timestamp = new Date().toISOString();
    for (const listener of this.listeners) {
      try {
        listener({ type, job, timestamp });
      } catch (err) {
        console.error('Job listener error:', err);
      }
    }
  }

  log(job_id: string, level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG', message: string, metadata?: Record<string, any>) {
    const entry: StructuredJobLog = {
      job_id,
      level,
      message,
      timestamp: new Date().toISOString(),
      metadata,
    };
    if (!this.logs.has(job_id)) {
      this.logs.set(job_id, []);
    }
    this.logs.get(job_id)!.push(entry);
  }

  getLogs(job_id: string): StructuredJobLog[] {
    return this.logs.get(job_id) || [];
  }

  createJob(params: {
    id?: string;
    investigation_id: string;
    target_id: string;
    engine: string;
    operation: string;
    max_retries?: number;
    metadata?: Record<string, any>;
  }): AnalysisJob {
    const id = params.id || `job-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const job: AnalysisJob = {
      id,
      investigation_id: params.investigation_id,
      target_id: params.target_id,
      engine: params.engine,
      operation: params.operation,
      status: JobStatus.QUEUED,
      retry_count: 0,
      max_retries: params.max_retries ?? 2,
      metadata: params.metadata || {},
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    this.jobs.set(job.id, job);
    this.log(job.id, 'INFO', `Job ${job.id} created for engine ${job.engine} (${job.operation}). Status: QUEUED`);
    this.emit('job_created', job);
    this.emit('job_queued', job);
    return job;
  }

  getJob(id: string): AnalysisJob | undefined {
    return this.jobs.get(id);
  }

  listJobs(filter?: { investigation_id?: string; status?: JobStatus }): AnalysisJob[] {
    let list = Array.from(this.jobs.values());
    if (filter?.investigation_id) {
      list = list.filter(j => j.investigation_id === filter.investigation_id);
    }
    if (filter?.status) {
      list = list.filter(j => j.status === filter.status);
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  async cancelJob(id: string): Promise<AnalysisJob> {
    const job = this.jobs.get(id);
    if (!job) throw new Error(`Job ${id} not found.`);

    if (job.status === JobStatus.COMPLETED || job.status === JobStatus.FAILED) {
      throw new Error(`Cannot cancel job in terminal state ${job.status}`);
    }

    const controller = this.activeExecutions.get(id);
    if (controller) {
      controller.abort();
      this.activeExecutions.delete(id);
    }

    job.status = JobStatus.CANCELLED;
    job.completed_at = new Date().toISOString();
    job.updated_at = new Date().toISOString();
    this.log(job.id, 'WARN', `Job ${id} was cancelled by operator.`);
    this.emit('job_cancelled', job);
    return job;
  }

  async runJob(id: string, onArtifactCreated?: (artifact: any, rawContent?: any) => void): Promise<AnalysisJob> {
    const job = this.jobs.get(id);
    if (!job) throw new Error(`Job ${id} not found.`);

    const controller = new AbortController();
    this.activeExecutions.set(id, controller);

    job.status = JobStatus.RUNNING;
    job.started_at = new Date().toISOString();
    job.updated_at = new Date().toISOString();
    this.log(job.id, 'INFO', `Job execution started on worker. Engine: ${job.engine}`);
    this.emit('job_started', job);

    // Record ENGINE_STARTED event
    globalEvidenceEventManager.recordEvent({
      investigation_id: job.investigation_id,
      event_type: EvidenceEventType.ENGINE_STARTED,
      actor: 'job-orchestrator',
      producer: job.engine,
      producer_version: 'unknown',
      metadata: {
        job_id: job.id,
        operation: job.operation,
        target_id: job.target_id,
      },
    });

    const engine = globalEngineRegistry.get(job.engine);
    if (!engine) {
      job.status = JobStatus.FAILED;
      job.execution_status = EngineExecutionStatus.NO_ENGINE;
      job.completed_at = new Date().toISOString();
      job.exit_code = 127;
      job.error = `NO_ENGINE: Engine '${job.engine}' was not found in the system registry.`;
      job.updated_at = new Date().toISOString();
      this.log(job.id, 'ERROR', job.error);
      
      // Record ENGINE_FAILED event
      globalEvidenceEventManager.recordEvent({
        investigation_id: job.investigation_id,
        event_type: EvidenceEventType.ENGINE_FAILED,
        actor: 'job-orchestrator',
        producer: job.engine,
        producer_version: '0.0.0',
        metadata: {
          job_id: job.id,
          execution_status: EngineExecutionStatus.NO_ENGINE,
          error: job.error,
        },
      });

      this.emit('job_failed', job);
      this.activeExecutions.delete(id);
      return job;
    }

    try {
      this.log(job.id, 'INFO', `Checking availability for engine ${engine.name}...`);
      const avail = await engine.check_availability();
      if (avail.status !== 'AVAILABLE' as any && (avail as any).available !== true) {
        job.status = JobStatus.FAILED;
        job.execution_status = (avail.status as any) === 'NOT_INSTALLED'
          ? EngineExecutionStatus.ENGINE_NOT_INSTALLED
          : EngineExecutionStatus.ENGINE_UNAVAILABLE;
        job.completed_at = new Date().toISOString();
        job.exit_code = 127;
        job.error = avail.error || (avail as any).reason || `Engine executable '${engine.executable}' is unavailable.`;
        job.updated_at = new Date().toISOString();
        this.log(job.id, 'ERROR', `Engine unavailable: ${job.error}`);

        // Record ENGINE_FAILED event
        globalEvidenceEventManager.recordEvent({
          investigation_id: job.investigation_id,
          event_type: EvidenceEventType.ENGINE_FAILED,
          actor: 'job-orchestrator',
          producer: engine.name,
          producer_version: engine.version,
          metadata: {
            job_id: job.id,
            execution_status: job.execution_status,
            error: job.error,
          },
        });

        this.emit('job_failed', job);
        this.activeExecutions.delete(id);
        return job;
      }

      this.log(job.id, 'INFO', `Engine available at ${avail.detected_path || 'system'}. Preparing execution context...`);
      await engine.prepare(job.target_id, job.metadata);

      this.log(job.id, 'INFO', `Executing engine operation: ${job.operation}...`);
      const result = await engine.execute(job.target_id, job.operation, job.metadata);

      job.completed_at = result.completed_at || (result as any).execution_end || new Date().toISOString();
      job.exit_code = result.exit_code;
      job.updated_at = new Date().toISOString();

      const executedCmd = result.command || (result as any).command_executed || `${engine.executable} ${job.operation}`;
      const outputArtifactIds: string[] = [];

      // Store real stdout as artifact if present
      if (result.stdout !== undefined && result.stdout !== null && result.stdout !== '') {
        const stdoutFilename = `job_${job.id}_stdout.log`;
        let stdoutStoredPath = `investigations/${job.investigation_id}/engines/${stdoutFilename}`;
        try {
          if (typeof (globalArtifactStorage as any).storeSync === 'function') {
            const meta = (globalArtifactStorage as any).storeSync(
              job.investigation_id,
              'engines',
              stdoutFilename,
              result.stdout,
              'text/plain'
            );
            stdoutStoredPath = meta.path;
          } else {
            const meta = await globalArtifactStorage.store(
              job.investigation_id,
              'engines',
              stdoutFilename,
              result.stdout,
              'text/plain'
            );
            stdoutStoredPath = meta.path;
          }
        } catch (err) {
          console.warn('Storage store for stdout failed:', err);
        }

        const stdoutArtifact = createEvidenceArtifact({
          id: `art-stdout-${job.id}-${Date.now()}`,
          investigation_id: job.investigation_id,
          target_id: job.target_id,
          artifact_type: ArtifactType.ENGINE_STDOUT,
          producer: engine.name,
          producer_version: avail.version || engine.version,
          command: executedCmd,
          content: result.stdout,
          path: stdoutStoredPath,
          path_or_reference: stdoutStoredPath,
        });
        job.stdout_artifact_id = stdoutArtifact.artifact.id;
        outputArtifactIds.push(stdoutArtifact.artifact.id);
        if (onArtifactCreated) onArtifactCreated(stdoutArtifact.artifact, stdoutArtifact.rawContent);
      }

      // Store real stderr as artifact if present
      if (result.stderr !== undefined && result.stderr !== null && result.stderr !== '') {
        const stderrFilename = `job_${job.id}_stderr.log`;
        let stderrStoredPath = `investigations/${job.investigation_id}/engines/${stderrFilename}`;
        try {
          if (typeof (globalArtifactStorage as any).storeSync === 'function') {
            const meta = (globalArtifactStorage as any).storeSync(
              job.investigation_id,
              'engines',
              stderrFilename,
              result.stderr,
              'text/plain'
            );
            stderrStoredPath = meta.path;
          } else {
            const meta = await globalArtifactStorage.store(
              job.investigation_id,
              'engines',
              stderrFilename,
              result.stderr,
              'text/plain'
            );
            stderrStoredPath = meta.path;
          }
        } catch (err) {
          console.warn('Storage store for stderr failed:', err);
        }

        const stderrArtifact = createEvidenceArtifact({
          id: `art-stderr-${job.id}-${Date.now()}`,
          investigation_id: job.investigation_id,
          target_id: job.target_id,
          artifact_type: ArtifactType.ENGINE_STDERR,
          producer: engine.name,
          producer_version: avail.version || engine.version,
          command: executedCmd,
          content: result.stderr,
          path: stderrStoredPath,
          path_or_reference: stderrStoredPath,
        });
        job.stderr_artifact_id = stderrArtifact.artifact.id;
        outputArtifactIds.push(stderrArtifact.artifact.id);
        if (onArtifactCreated) onArtifactCreated(stderrArtifact.artifact, stderrArtifact.rawContent);
      }

      const isSuccess = result.status === ('SUCCESS' as any) || (result as any).success === true;
      if (isSuccess && (result as any).output) {
        const outputFilename = `job_${job.id}_result.json`;
        let resultStoredPath = `investigations/${job.investigation_id}/engines/${outputFilename}`;
        const outputStr = typeof (result as any).output === 'string' ? (result as any).output : JSON.stringify((result as any).output, null, 2);
        try {
          if (typeof (globalArtifactStorage as any).storeSync === 'function') {
            const meta = (globalArtifactStorage as any).storeSync(
              job.investigation_id,
              'engines',
              outputFilename,
              outputStr,
              'application/json'
            );
            resultStoredPath = meta.path;
          }
        } catch (err) {
          console.warn('Storage store for result output failed:', err);
        }

        const resultArtifact = createEvidenceArtifact({
          id: `art-result-${job.id}-${Date.now()}`,
          investigation_id: job.investigation_id,
          target_id: job.target_id,
          artifact_type: ArtifactType.ENGINE_RESULT,
          producer: engine.name,
          producer_version: avail.version || engine.version,
          command: executedCmd,
          content: outputStr,
          path: resultStoredPath,
          path_or_reference: resultStoredPath,
          mime_type: 'application/json',
        });
        outputArtifactIds.push(resultArtifact.artifact.id);
        if (onArtifactCreated) onArtifactCreated(resultArtifact.artifact, resultArtifact.rawContent);
      }
      if (isSuccess) {
        job.status = JobStatus.COMPLETED;
        job.execution_status = EngineExecutionStatus.ENGINE_COMPLETED_NO_FINDINGS;
        this.log(job.id, 'INFO', `Job completed successfully with exit code ${result.exit_code}.`);

        // Record ENGINE_COMPLETED event
        globalEvidenceEventManager.recordEvent({
          investigation_id: job.investigation_id,
          event_type: EvidenceEventType.ENGINE_COMPLETED,
          actor: 'job-orchestrator',
          producer: engine.name,
          producer_version: avail.version || engine.version,
          output_artifacts: outputArtifactIds,
          metadata: {
            job_id: job.id,
            exit_code: result.exit_code,
            execution_status: job.execution_status,
          },
        });

        this.emit('job_completed', job);
      } else {
        job.status = JobStatus.FAILED;
        job.execution_status = EngineExecutionStatus.ENGINE_EXECUTION_FAILED;
        job.error = result.error || `Process exited with code ${result.exit_code}`;
        this.log(job.id, 'ERROR', `Job execution failed: ${job.error}`);

        // Record ENGINE_FAILED event
        globalEvidenceEventManager.recordEvent({
          investigation_id: job.investigation_id,
          event_type: EvidenceEventType.ENGINE_FAILED,
          actor: 'job-orchestrator',
          producer: engine.name,
          producer_version: avail.version || engine.version,
          output_artifacts: outputArtifactIds,
          metadata: {
            job_id: job.id,
            exit_code: result.exit_code,
            execution_status: job.execution_status,
            error: job.error,
          },
        });

        this.emit('job_failed', job);
      }

      if (typeof (engine as any).cleanup === 'function') {
        await engine.cleanup(job.metadata);
      }
    } catch (err: any) {
      job.status = JobStatus.FAILED;
      job.execution_status = EngineExecutionStatus.ENGINE_EXECUTION_FAILED;
      job.completed_at = new Date().toISOString();
      job.exit_code = 1;
      job.error = err.message || String(err);
      job.updated_at = new Date().toISOString();
      this.log(job.id, 'ERROR', `Unexpected worker execution error: ${job.error}`);

      // Record ENGINE_FAILED event
      globalEvidenceEventManager.recordEvent({
        investigation_id: job.investigation_id,
        event_type: EvidenceEventType.ENGINE_FAILED,
        actor: 'job-orchestrator',
        producer: engine.name,
        producer_version: engine.version,
        metadata: {
          job_id: job.id,
          execution_status: job.execution_status,
          error: job.error,
        },
      });

      this.emit('job_failed', job);
    } finally {
      this.activeExecutions.delete(id);
    }

    return job;
  }
}

export const globalJobOrchestrator = new JobOrchestrator();
