/**
 * CodeQL Semantic Analysis Engine
 * Intent Security Workbench - Phase 2
 *
 * Real CodeQL integration: extracts a queryable database from the target source
 * tree, evaluates a security query suite, and maps SARIF results onto engine
 * findings with CodeQL's own security-severity scores.
 *
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
  globalCodeQLService,
  CodeQLAnalysisService,
} from '../../packages/static-analysis/src/codeql_service.js';

export class CodeQLEngine extends BaseEngine {
  readonly engine_id = 'codeql';
  readonly name = 'CodeQL';
  private _version: string = 'unknown';
  readonly description = 'Semantic code analysis engine queryable as a database for deep semantic, data-flow, and taint analysis.';
  readonly executable: string;
  readonly capabilities = ['semantic analysis', 'data-flow analysis', 'taint tracking', 'SARIF output'];
  readonly supported_target_types = ['SMART_CONTRACT', 'WEB_APPLICATION', 'REST_API', 'LIBRARY'];
  readonly supported_languages = ['javascript', 'typescript', 'python', 'java', 'cpp', 'csharp', 'go', 'ruby'];

  private service: CodeQLAnalysisService;

  constructor(executable = 'codeql') {
    super();
    this.executable = executable;
    this.service = executable === 'codeql' ? globalCodeQLService : new CodeQLAnalysisService(executable);
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
        command: `${this.executable} database analyze [attempted]`,
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
      context.target_directory || context.source_directory || context.working_directory || process.cwd();

    const run = await this.service.analyze(sourceDir, {
      timeoutMs: context.timeout_ms,
      language: context.language,
      suite: context.query_suite,
      keepDatabase: context.keep_database === true,
    });

    const findings: EngineFinding[] = run.findings.map((f, idx) => {
      // CodeQL reports absolute or db-relative URIs; normalise to a path when
      // the URI is a filesystem location.
      const file = f.file.startsWith('file://') ? f.file.replace('file://', '') : f.file;
      return {
        id: `codeql-${f.rule_id.replace(/[^A-Za-z0-9-]/g, '_')}-${idx + 1}`,
        title: `[CodeQL] ${f.rule_id}`,
        description: f.message || `CodeQL query '${f.rule_id}' reported a result.`,
        severity: f.severity,
        category: 'SEMANTIC_DATAFLOW_ANALYSIS',
        cwe: f.cwe,
        confidence: 'MEDIUM',
        file,
        line_start: f.line_start,
        line_end: f.line_end,
        evidence: f.snippet || f.message,
        metadata: {
          rule_id: f.rule_id,
          rule_name: f.rule_name,
          security_severity: f.security_severity,
          help_uri: f.help_uri,
          language: run.language,
        },
      };
    });

    const artifacts: EngineArtifact[] = [];
    const artifactId = await this.registerOutputArtifact(
      context.investigation_id,
      targetId,
      `${this.engine_id}-analysis`,
      run.stdout
    );
    if (artifactId) {
      artifacts.push(this.describeArtifact(artifactId, 'ENGINE_OUTPUT', `${this.engine_id}/analysis.log`));
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
    const parsed = globalCodeQLService.parseSarif(rawOutput.stdout);
    if (!parsed) return [];
    return parsed.map((f, idx) => ({
      id: `codeql-${idx + 1}`,
      title: `[CodeQL] ${f.rule_id}`,
      description: f.message,
      severity: f.severity,
      category: 'SEMANTIC_DATAFLOW_ANALYSIS',
      cwe: f.cwe,
      confidence: 'MEDIUM',
      file: f.file,
      line_start: f.line_start,
      line_end: f.line_end,
    }));
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}