/**
 * Clarinet Clarity Analysis Engine
 * Intent Security Workbench - Phase 5
 *
 * Real Clarinet integration. Clarinet's `check` runs syntax, type and lint
 * analysis (including the check_checker pass for unchecked-data flow) over a
 * Clarinet project. A bare `.clar` file is scaffolded into a throwaway project
 * so any directory of contracts can be analysed.
 *
 * A missing binary reports NOT_INSTALLED with zero findings and exit code 127.
 */

import { dirname } from 'path';
import { BaseEngine } from '../base_engine.js';
import {
  EngineResult,
  EngineResultStatus,
  EngineFinding,
  EngineAvailabilityStatus,
  EngineAvailability,
  EngineArtifact,
} from '../types.js';
import {
  globalClarinetService,
  ClarinetAnalysisService,
} from '../../packages/dynamic-verification/src/clarinet_service.js';

export class ClarinetEngine extends BaseEngine {
  readonly engine_id = 'clarinet';
  readonly name = 'Clarinet';
  private _version: string = 'unknown';
  readonly description = 'Clarity smart contract runtime, testing framework, and static analysis environment for Stacks blockchain.';
  readonly executable: string;
  readonly capabilities = ['Clarity syntax/type check', 'lint analysis', 'check_checker data flow'];
  readonly supported_target_types = ['SMART_CONTRACT', 'PROTOCOL'];
  readonly supported_languages = ['clarity'];

  private service: ClarinetAnalysisService;

  constructor(executable = 'clarinet') {
    super();
    this.executable = executable;
    this.service = executable === 'clarinet' ? globalClarinetService : new ClarinetAnalysisService(executable);
  }

  get version(): string {
    return this._version;
  }

  async check_availability(): Promise<EngineAvailability> {
    const checked_at = new Date().toISOString();
    const res = await this.service.checkAvailability();

    if (res.available && res.path) {
      if (res.version) this._version = res.version;
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.AVAILABLE,
        executable: this.executable,
        detected_path: res.path,
        version: res.version,
        checked_at,
        error: null,
        capabilities: this.capabilities,
      };
    }

    return {
      engine_id: this.engine_id,
      name: this.name,
      status: res.status === 'BROKEN' ? EngineAvailabilityStatus.BROKEN : EngineAvailabilityStatus.NOT_INSTALLED,
      executable: this.executable,
      detected_path: res.path,
      version: null,
      checked_at,
      error: res.error || `Executable '${this.executable}' is not installed or not found on system PATH.`,
      capabilities: this.capabilities,
    };
  }

  async prepare(targetId: string, context: Record<string, any>): Promise<boolean> {
    const avail = await this.check_availability();
    return avail.status === EngineAvailabilityStatus.AVAILABLE;
  }

  async execute(targetId: string, operation: string, context: Record<string, any>): Promise<EngineResult> {
    const avail = await this.check_availability();
    const startTime = new Date().toISOString();

    if (avail.status !== EngineAvailabilityStatus.AVAILABLE) {
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.version,
        status: EngineResultStatus.UNAVAILABLE,
        target_id: targetId,
        investigation_id: context.investigation_id,
        command: `${this.executable} check [attempted]`,
        working_directory: context.working_directory || process.cwd(),
        started_at: startTime,
        completed_at: new Date().toISOString(),
        duration_ms: 0,
        exit_code: 127,
        stdout: '',
        stderr: avail.error || `Executable '${this.executable}' is not installed.`,
        findings: [],
        artifacts: [],
        environment: this.getEnvironmentInfo(avail.detected_path),
        error: `ENGINE_UNAVAILABLE: ${this.name} (${this.executable}) is not installed on host.`,
      };
    }

    const sourceDir =
      context.source_directory ||
      context.target_directory ||
      context.working_directory ||
      (context.contract_file ? dirname(context.contract_file) : process.cwd());

    const run = await this.service.analyze(sourceDir, {
      timeoutMs: context.timeout_ms,
      keepWorkspace: context.keep_workspace === true,
    });

    const findings: EngineFinding[] = run.diagnostics.map((d, idx) => ({
      id: `clarinet-${idx + 1}`,
      title: `[Clarinet] ${d.message}`,
      description: d.message,
      severity: ClarinetAnalysisService.severityFor(d.level),
      category: 'CLARITY_STATIC_ANALYSIS',
      cwe: [],
      confidence: 'MEDIUM',
      file: d.file,
      line_start: d.start_line,
      line_end: d.end_line,
      evidence: d.suggestion || d.message,
      metadata: {
        diagnostic_level: d.level,
        start_column: d.start_column,
        end_column: d.end_column,
        suggestion: d.suggestion,
      },
    }));

    const artifacts: EngineArtifact[] = [];
    const artifactId = await this.registerOutputArtifact(
      context.investigation_id,
      targetId,
      `${this.engine_id}-json`,
      run.stdout
    );
    if (artifactId) {
      {
        const art = this.describeArtifact(artifactId, 'ENGINE_OUTPUT', `${this.engine_id}/diagnostics.json`);
        if (art) artifacts.push(art);
      }
    }

    return {
      id: `res-${this.engine_id}-${Date.now()}`,
      engine_id: this.engine_id,
      engine_name: this.name,
      engine_version: run.version || this.version,
      status: run.status === 'COMPLETED' ? EngineResultStatus.SUCCESS : EngineResultStatus.FAILED,
      target_id: targetId,
      investigation_id: context.investigation_id,
      command: run.command,
      working_directory: sourceDir,
      started_at: startTime,
      completed_at: new Date().toISOString(),
      duration_ms: run.duration_ms,
      exit_code: run.status === 'COMPLETED' ? 0 : run.exit_code || 1,
      stdout: run.stdout,
      stderr: run.stderr,
      findings,
      artifacts,
      environment: this.getEnvironmentInfo(run.executable_path),
      error: run.error,
    };
  }

  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[] {
    const parsed = globalClarinetService.parseClarinetOutput(rawOutput.stdout);
    if (!parsed) return [];
    return parsed.diagnostics.map((d, idx) => ({
      id: `clarinet-${idx + 1}`,
      title: `[Clarinet] ${d.message}`,
      description: d.message,
      severity: ClarinetAnalysisService.severityFor(d.level),
      category: 'CLARITY_STATIC_ANALYSIS',
      confidence: 'MEDIUM',
      file: d.file,
      line_start: d.start_line,
      line_end: d.end_line,
    }));
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}