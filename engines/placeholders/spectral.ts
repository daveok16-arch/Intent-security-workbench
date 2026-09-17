/**
 * Spectral OpenAPI Linter Engine
 * Intent Security Workbench - Phase 3
 *
 * Real Spectral execution integration, accurate version reporting,
 * and zero synthetic results.
 */

import { BaseEngine } from '../base_engine.js';
import {
  EngineResult,
  EngineResultStatus,
  EngineFinding,
  EngineAvailabilityStatus,
  EngineAvailability,
} from '../types.js';
import { globalSpectralService, SpectralAnalysisService } from '../../packages/api-analysis/src/spectral_service.js';

export class SpectralEngine extends BaseEngine {
  readonly engine_id = 'spectral';
  readonly name = 'Spectral';
  private _version: string = '6.16.3';
  readonly description = 'Flexible JSON/YAML linter with out-of-the-box support for OpenAPI v2/v3 and AsyncAPI definitions.';
  readonly executable: string;
  readonly capabilities = ['OpenAPI linting', 'contract validation', 'schema rules'];
  readonly supported_target_types = ['REST_API', 'WEB_APPLICATION'];
  readonly supported_languages = ['json', 'yaml', 'openapi'];

  private service: SpectralAnalysisService;

  constructor(executable = 'spectral') {
    super();
    this.executable = executable;
    this.service = executable === 'spectral' ? globalSpectralService : new SpectralAnalysisService(executable);
  }

  get version(): string {
    return this._version;
  }

  async check_availability(): Promise<EngineAvailability> {
    const checked_at = new Date().toISOString();

    const res = await this.service.checkAvailability();
    if (res.available && res.path) {
      if (res.version) {
        this._version = res.version;
      }
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
      status: EngineAvailabilityStatus.NOT_INSTALLED,
      executable: this.executable,
      detected_path: null,
      version: null,
      checked_at,
      error: res.error || `Executable '${this.executable}' is not installed.`,
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

    if (avail.status !== EngineAvailabilityStatus.AVAILABLE || !avail.detected_path) {
      const endTime = new Date().toISOString();
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: null,
        status: EngineResultStatus.UNAVAILABLE,
        target_id: targetId,
        investigation_id: context.investigation_id,
        command: `${this.executable} lint [attempted]`,
        working_directory: context.working_directory || process.cwd(),
        started_at: startTime,
        completed_at: endTime,
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

    const specPath = context.specification_path || context.file || '';
    const rulesetPath = context.ruleset_path;
    const lintResult = await this.service.lintSpecification(specPath, rulesetPath);
    const endTime = new Date().toISOString();

    // Spectral exit codes: 0 = clean, 2 = findings at/above fail-severity,
    // 1 = unexpected error, 127 = binary unavailable. A run that completed and
    // reported rule violations is a successful analysis, not an engine failure.
    const completed = lintResult.exit_code === 0 || lintResult.exit_code === 2;

    return {
      id: `res-${this.engine_id}-${Date.now()}`,
      engine_id: this.engine_id,
      engine_name: this.name,
      engine_version: avail.version,
      status: completed ? EngineResultStatus.SUCCESS : EngineResultStatus.FAILED,
      target_id: targetId,
      investigation_id: context.investigation_id,
      command: lintResult.command,
      working_directory: context.working_directory || process.cwd(),
      started_at: startTime,
      completed_at: endTime,
      duration_ms: lintResult.duration_ms,
      exit_code: lintResult.exit_code,
      stdout: lintResult.stdout,
      stderr: lintResult.stderr,
      findings: lintResult.findings,
      artifacts: [],
      environment: this.getEnvironmentInfo(avail.detected_path),
      error: completed ? null : lintResult.error,
    };
  }

  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[] {
    return [];
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}
