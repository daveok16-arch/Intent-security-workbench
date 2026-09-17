/**
 * Semgrep Security Analysis Engine
 * Intent Security Workbench - Phase 2
 *
 * Real Semgrep CLI static analysis engine for pattern matching,
 * semantic code search, and taint tracking.
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
import { globalSemgrepService, SemgrepAnalysisService } from '../../packages/static-analysis/src/semgrep_service.js';
import { globalSecurityRuleRegistry } from '../../packages/static-analysis/src/rule_registry.js';

/** Semgrep's own finding levels, mapped onto platform severity. */
function mapSemgrepSeverity(level: string | undefined): string {
  switch ((level || '').toUpperCase()) {
    case 'ERROR':
      return 'HIGH';
    case 'WARNING':
      return 'MEDIUM';
    case 'INFO':
      return 'LOW';
    default:
      return 'MEDIUM';
  }
}

/**
 * Resolves a rule definition for a Semgrep check id. The generated rule pack
 * lives in a temp directory, so Semgrep namespaces every check as
 * `tmp.intent-semgrep-<rand>.<RULE_ID>`. Try the exact id first, then the
 * trailing segment, so metadata is not silently lost.
 */
function lookupRule(checkId: string) {
  if (!checkId) return undefined;
  const direct = globalSecurityRuleRegistry.get(checkId);
  if (direct) return direct;
  const segments = checkId.split('.');
  for (let i = segments.length - 1; i >= 0; i--) {
    const candidate = segments.slice(i).join('.');
    const found = globalSecurityRuleRegistry.get(candidate);
    if (found) return found;
    const single = globalSecurityRuleRegistry.get(segments[i]);
    if (single) return single;
  }
  return undefined;
}

export class SemgrepEngine extends BaseEngine {
  readonly engine_id = 'semgrep';
  readonly name = 'Semgrep';
  private _version: string = '1.176.0';
  readonly description = 'Lightweight static analysis engine for pattern matching, semantic code search, and taint tracking.';
  readonly executable: string;
  readonly capabilities = ['static analysis', 'pattern matching', 'taint analysis', 'ast rule scan'];
  readonly supported_target_types = ['SMART_CONTRACT', 'WEB_APPLICATION', 'REST_API', 'LIBRARY'];
  readonly supported_languages = ['javascript', 'typescript', 'python', 'solidity', 'go', 'java', 'c'];

  private service: SemgrepAnalysisService;

  constructor(executable = 'semgrep') {
    super();
    this.executable = executable;
    this.service = executable === 'semgrep' ? globalSemgrepService : new SemgrepAnalysisService(executable);
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

  async execute(
    targetIdOrContext: string | Record<string, any>,
    operationOrContext?: string | Record<string, any>,
    context?: Record<string, any>
  ): Promise<EngineResult> {
    let targetId: string;
    let operation: string;
    let ctx: Record<string, any>;

    if (typeof targetIdOrContext === 'object' && targetIdOrContext !== null) {
      ctx = targetIdOrContext;
      targetId = ctx.target_id || 'tgt-unknown';
      operation = 'scan';
    } else {
      targetId = targetIdOrContext as string;
      if (typeof operationOrContext === 'object' && operationOrContext !== null) {
        ctx = operationOrContext;
        operation = 'scan';
      } else {
        operation = (operationOrContext as string) || 'scan';
        ctx = context || {};
      }
    }

    const avail = await this.check_availability();
    const startTime = new Date().toISOString();
    const startMs = Date.now();

    if (avail.status !== EngineAvailabilityStatus.AVAILABLE) {
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.version,
        status: EngineResultStatus.UNAVAILABLE,
        target_id: targetId,
        investigation_id: ctx.investigation_id,
        command: `${this.executable} scan [attempted]`,
        working_directory: ctx.working_directory || process.cwd(),
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

    const sourceDir = ctx.target_directory || ctx.source_directory || ctx.working_directory || process.cwd();
    const sourceSnapshotId = ctx.source_snapshot_id || 'snap-unknown';
    const investigationId = ctx.investigation_id;

    const scanRes = await this.service.executeScan(
      sourceDir,
      sourceSnapshotId,
      investigationId,
      targetId,
      ctx.rules_yaml
    );

    const findings: EngineFinding[] = scanRes.candidates.map(c => ({
      id: c.id,
      title: c.title,
      description: c.confidence_basis,
      severity: c.severity,
      category: c.category,
      cwe: c.cwe_ids,
      owasp: c.owasp_categories,
      confidence: c.confidence,
      file: c.file_path,
      line_start: c.line_start,
      line_end: c.line_end,
      evidence: c.matched_code,
      metadata: c.metadata,
    }));

    const artifacts: EngineArtifact[] = scanRes.artifactIds
      .map(id => this.describeArtifact(id, 'ENGINE_OUTPUT', `artifacts/${id}`))
      .filter((a): a is EngineArtifact => a !== null);

    const status = scanRes.execution.status === 'COMPLETED' ? EngineResultStatus.SUCCESS : EngineResultStatus.FAILED;

    return {
      id: `res-${this.engine_id}-${Date.now()}`,
      engine_id: this.engine_id,
      engine_name: this.name,
      engine_version: scanRes.execution.version || this.version,
      status,
      target_id: targetId,
      investigation_id: investigationId,
      command: scanRes.execution.command,
      working_directory: sourceDir,
      started_at: startTime,
      completed_at: new Date().toISOString(),
      duration_ms: scanRes.execution.duration_ms,
      exit_code: scanRes.execution.exit_code,
      stdout: scanRes.execution.stdout,
      stderr: scanRes.execution.stderr,
      findings,
      artifacts,
      environment: this.getEnvironmentInfo(scanRes.execution.executable_path),
      error: scanRes.execution.error,
    };
  }

  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[] {
    try {
      if (!rawOutput.stdout) return [];
      const parsed = JSON.parse(rawOutput.stdout);
      const results = parsed.results || [];
      return results.map((r: any, idx: number) => {
        const rule = lookupRule(r.check_id);
        return {
          id: `sg-find-${idx}`,
          title: r.check_id,
          description: r.extra?.message || '',
          // Semgrep reports its own WARNING/ERROR levels; map onto platform
          // severity rather than leaking a non-platform value through.
          severity: rule?.severity || mapSemgrepSeverity(r.extra?.severity),
          category: 'STATIC_ANALYSIS',
          cwe: rule?.cwe_ids || [],
          confidence: rule?.confidence || 'MEDIUM',
          file: r.path,
          line_start: r.start?.line,
          line_end: r.end?.line,
          evidence: r.extra?.lines,
        };
      });
    } catch {
      return [];
    }
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}
