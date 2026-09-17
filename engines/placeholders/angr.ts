/**
 * Angr Binary Analysis Engine
 * Intent Security Workbench - Phase 2
 *
 * Real angr integration. angr is a Python library, so analysis runs through the
 * bundled `angr_analyzer.py` driver, which performs CFG recovery and dangerous
 * symbol resolution on a real binary and returns JSON.
 *
 * A missing library reports NOT_INSTALLED with zero findings and exit code 127.
 */

import { execFileSync } from 'child_process';
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
  globalAngrService,
  AngrAnalysisService,
} from '../../packages/dynamic-verification/src/angr_service.js';

export class AngrEngine extends BaseEngine {
  readonly engine_id = 'angr';
  readonly name = 'Angr';
  private _version: string = 'unknown';
  readonly description = 'Multi-architecture binary analysis platform combining symbolic execution, control-flow recovery, and vulnerability discovery.';
  readonly executable: string;
  readonly capabilities = ['binary analysis', 'CFG recovery', 'symbolic execution', 'dangerous symbol detection'];
  readonly supported_target_types = ['BINARY_NODE', 'LIBRARY'];
  readonly supported_languages = ['x86', 'x86_64', 'arm', 'mips', 'wasm'];

  private service: AngrAnalysisService;

  constructor(executable = 'angr') {
    super();
    this.executable = executable;
    this.service = executable === 'angr' ? globalAngrService : new AngrAnalysisService(executable);
  }

  get version(): string {
    return this._version;
  }

  /**
   * The `angr` console script accepts no `--version` flag (it exits 2 with
   * usage text), so the module metadata is the authoritative version signal.
   */
  async get_version(resolvedPath?: string | null): Promise<string | null> {
    if (!resolvedPath) return null;
    try {
      const output = execFileSync('python3', ['-c', 'import angr; print(angr.__version__)'], {
        encoding: 'utf-8',
        timeout: 60000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      return output || null;
    } catch {
      return null;
    }
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
      // A resolved-but-unimportable module is BROKEN; a missing one is NOT_INSTALLED.
      status: res.status === 'FAILED' ? EngineAvailabilityStatus.BROKEN : EngineAvailabilityStatus.NOT_INSTALLED,
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
        command: `${this.executable} [attempted]`,
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

    const binaryPath = context.binary_path || context.target_directory || context.working_directory;
    if (!binaryPath) {
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.engineVersionFor(avail),
        status: EngineResultStatus.FAILED,
        target_id: targetId,
        investigation_id: context.investigation_id,
        command: `${this.executable} [no binary supplied]`,
        working_directory: process.cwd(),
        started_at: startTime,
        completed_at: new Date().toISOString(),
        duration_ms: 0,
        exit_code: 1,
        stdout: '',
        stderr: 'No binary_path supplied for angr analysis.',
        findings: [],
        artifacts: [],
        environment: this.getEnvironmentInfo(avail.detected_path),
        error: 'ANGR_MISSING_TARGET: no binary_path supplied in execution context.',
      };
    }

    const run = await this.service.analyze(binaryPath, { timeoutMs: context.timeout_ms });
    const findings = this.toFindings(run.result, binaryPath);

    const artifacts: EngineArtifact[] = [];
    const artifactId = await this.registerOutputArtifact(
      context.investigation_id,
      targetId,
      `${this.engine_id}-analysis`,
      run.stdout
    );
    if (artifactId) {
      {
        const art = this.describeArtifact(artifactId, 'ENGINE_OUTPUT', `${this.engine_id}/analysis.json`);
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
      working_directory: context.working_directory || process.cwd(),
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

  /**
   * Turns recovered binary facts into findings. The strongest signal is a
   * dangerous libc symbol that resolves to a concrete call site, since that
   * proves the call is reachable rather than merely declared.
   */
  private toFindings(
    result: Awaited<ReturnType<AngrAnalysisService['analyze']>>['result'],
    binaryPath: string
  ): EngineFinding[] {
    if (!result || !result.ok) return [];

    const callSiteBySymbol = new Map<string, string>();
    for (const site of result.call_sites || []) {
      if (!callSiteBySymbol.has(site.symbol)) callSiteBySymbol.set(site.symbol, site.addr);
    }

    const findings: EngineFinding[] = [];

    for (const symbol of result.dangerous_imports || []) {
      const info = AngrAnalysisService.symbolInfo(symbol);
      if (!info) continue;
      const callAddr = callSiteBySymbol.get(symbol);
      findings.push({
        id: `angr-${symbol}`,
        title: `[Angr] ${info.title}`,
        description:
          `Binary imports '${symbol}'` +
          (callAddr ? ` and resolves a call site at ${callAddr}.` : ' (import stub resolved, call site not located).'),
        severity: info.severity,
        category: 'BINARY_ANALYSIS',
        cwe: info.cwe,
        confidence: callAddr ? 'MEDIUM' : 'LOW',
        file: binaryPath,
        evidence: callAddr ? `call-site ${callAddr}` : `import ${symbol}`,
        metadata: {
          symbol,
          call_site: callAddr || null,
          arch: result.binary?.arch,
          bits: result.binary?.bits,
          functions_recovered: result.functions,
          pie: result.binary?.pie,
          nx: result.binary?.nx,
        },
      });
    }

    return findings;
  }

  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[] {
    const parsed = globalAngrService.parseAnalyzerOutput(rawOutput.stdout);
    return this.toFindings(parsed, rawOutput.stdout ? 'binary' : '');
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}