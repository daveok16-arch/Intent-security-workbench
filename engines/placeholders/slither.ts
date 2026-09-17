/**
 * Slither Solidity Static Analysis Engine
 * Intent Security Workbench - Phase 2
 *
 * Real Slither integration: compiles the target with solc, runs Slither's
 * detector suite, and maps genuine detector hits onto engine findings.
 * A missing binary reports NOT_INSTALLED with zero findings and exit code 127.
 */

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
  globalSlitherService,
  SlitherAnalysisService,
} from '../../packages/static-analysis/src/slither_service.js';

export class SlitherEngine extends BaseEngine {
  readonly engine_id = 'slither';
  readonly name = 'Slither';
  private _version: string = 'unknown';
  readonly description = 'Static analysis framework for Solidity smart contracts providing dataflow analysis and vulnerability detection.';
  readonly executable: string;
  readonly capabilities = ['Solidity static analysis', 'dataflow analysis', 'detector suite'];
  readonly supported_target_types = ['SMART_CONTRACT', 'PROTOCOL'];
  readonly supported_languages = ['solidity'];

  private service: SlitherAnalysisService;

  constructor(executable = 'slither') {
    super();
    this.executable = executable;
    this.service = executable === 'slither' ? globalSlitherService : new SlitherAnalysisService(executable);
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
        engine_version: this.engineVersionFor(avail),
        status: EngineResultStatus.UNAVAILABLE,
        target_id: targetId,
        investigation_id: context.investigation_id,
        command: `${this.executable} . --json - [attempted]`,
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

    const targetDir =
      context.target_directory || context.source_directory || context.working_directory || process.cwd();

    const run = await this.service.analyze(targetDir, {
      timeoutMs: context.timeout_ms,
      args: Array.isArray(context.slither_args) ? context.slither_args : undefined,
    });

    const findings = this.toFindings(run.detectors);

    // Persist real Slither stdout as machine-verifiable evidence.
    const artifacts: EngineArtifact[] = [];
    const artifactId = await this.registerOutputArtifact(
      context.investigation_id,
      targetId,
      `${this.engine_id}-json`,
      run.stdout
    );
    if (artifactId) {
      {
        const art = this.describeArtifact(artifactId, 'ENGINE_OUTPUT', `${this.engine_id}/stdout.json`);
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
      working_directory: targetDir,
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
    const parsed = globalSlitherService.parseSlitherOutput(rawOutput.stdout);
    if (!parsed) return [];
    return this.toFindings(parsed.detectors);
  }

  /**
   * One finding per detector, anchored at its first non-dependency source
   * element. Slither reports each detector once with affected elements attached.
   */
  private toFindings(detectors: Array<{
    check: string;
    impact: string;
    confidence: string;
    description: string;
    reference?: string;
    elements: Array<{ type: string; name: string; file: string; lines: number[] }>;
  }>): EngineFinding[] {
    return detectors.map((det, idx) => {
      const primary = det.elements.find(e => e.file && !e.file.includes('node_modules')) || det.elements[0];
      const lines = primary?.lines || [];
      return {
        id: `slither-${det.check}-${idx + 1}`,
        title: `[Slither] ${det.check}`,
        description: det.description || `Slither detector '${det.check}' matched.`,
        severity: SlitherAnalysisService.severityFor(det.impact),
        category: 'SOLIDITY_STATIC_ANALYSIS',
        cwe: SlitherAnalysisService.cwesFor(det.check),
        confidence: SlitherAnalysisService.confidenceFor(det.confidence),
        file: primary?.file || '',
        line_start: lines.length > 0 ? Math.min(...lines) : undefined,
        line_end: lines.length > 0 ? Math.max(...lines) : undefined,
        evidence: det.description?.split('\n')[0] || '',
        metadata: {
          detector_id: det.check,
          impact: det.impact,
          detector_confidence: det.confidence,
          reference: det.reference,
          affected_elements: det.elements.length,
        },
      };
    });
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}