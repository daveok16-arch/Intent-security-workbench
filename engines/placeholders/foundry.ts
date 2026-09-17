/**
 * Foundry Toolkit Engine
 * Intent Security Workbench - Phase 5
 *
 * Drives the real Foundry toolkit. The toolkit has no `foundry` binary, so
 * availability resolves `forge` via ToolDetector and the engine name reflects
 * the toolkit. `forge test --json` results are mapped onto findings: a passing
 * test whose name asserts an exploit demonstrates the flaw reproduces, and a
 * failing test is evidence a candidate exploit did NOT hold.
 *
 * A missing forge reports NOT_INSTALLED with zero findings and exit code 127.
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
  globalFoundryService,
  FoundryAnalysisService,
} from '../../packages/dynamic-verification/src/foundry_service.js';

export class FoundryEngine extends BaseEngine {
  readonly engine_id = 'foundry';
  readonly name = 'Foundry';
  private _version: string = 'unknown';
  readonly description = 'Blazing fast, portable, and modular toolkit for Ethereum application development and test execution.';
  /**
   * The Foundry toolkit ships `forge`, `anvil`, `cast` and `chisel`; there is no
   * `foundry` binary. Availability therefore resolves `forge`, while the engine
   * identity remains the toolkit.
   */
  readonly executable: string;
  readonly capabilities = ['Solidity compilation', 'test execution', 'exploit reproduction', 'trace analysis'];
  readonly supported_target_types = ['SMART_CONTRACT', 'PROTOCOL'];
  readonly supported_languages = ['solidity'];

  private service: FoundryAnalysisService;

  constructor(executable = 'forge') {
    super();
    this.executable = executable;
    this.service = executable === 'forge' ? globalFoundryService : new FoundryAnalysisService(executable);
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
      error: res.error || `Foundry toolchain ('${this.executable}') is not installed or not found on system PATH.`,
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
        command: `forge test --json [attempted]`,
        working_directory: context.working_directory || process.cwd(),
        started_at: startTime,
        completed_at: new Date().toISOString(),
        duration_ms: 0,
        exit_code: 127,
        stdout: '',
        stderr: avail.error || `Foundry toolchain is not installed.`,
        findings: [],
        artifacts: [],
        environment: this.getEnvironmentInfo(avail.detected_path),
        error: `ENGINE_UNAVAILABLE: ${this.name} ('${this.executable}') is not installed on host.`,
      };
    }

    const projectDir =
      context.project_directory ||
      context.target_directory ||
      context.source_directory ||
      context.working_directory ||
      process.cwd();

    const run = await this.service.analyze(projectDir, {
      timeoutMs: context.timeout_ms,
      matchTest: context.match_test,
    });

    const findings = this.toFindings(run, projectDir);

    const artifacts: EngineArtifact[] = [];
    const artifactId = await this.registerOutputArtifact(
      context.investigation_id,
      targetId,
      `${this.engine_id}-tests`,
      run.stdout
    );
    if (artifactId) {
      {
        const art = this.describeArtifact(artifactId, 'ENGINE_OUTPUT', `${this.engine_id}/forge-test.json`);
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
      working_directory: projectDir,
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
   * A passing exploit-named test is positive evidence the flaw reproduces; a
   * failing one is evidence the exploit did not hold. Both are recorded so the
   * state machine can decide, rather than the engine asserting a verdict.
   */
  private toFindings(
    run: Awaited<ReturnType<FoundryAnalysisService['analyze']>>,
    projectDir: string
  ): EngineFinding[] {
    const findings: EngineFinding[] = [];

    for (const t of run.results) {
      const isPass = /^success$/i.test(t.status);
      const isFail = /^failure$/i.test(t.status);
      const exploitNamed = FoundryAnalysisService.looksLikeExploitTest(t.test_name);

      if (isPass && exploitNamed) {
        findings.push({
          id: `foundry-exploit-${t.suite}-${t.test_name}`,
          title: `[Foundry] Exploit test passed: ${t.test_name}`,
          description:
            `Forge test '${t.test_name}' in ${t.suite} passed, which indicates the asserted ` +
            `unauthorized behaviour is reproducible against the compiled contracts.`,
          severity: 'HIGH',
          category: 'DYNAMIC_REPRODUCTION',
          cwe: ['CWE-284'],
          confidence: 'MEDIUM',
          file: t.suite,
          evidence: `forge test passed: ${t.test_name}`,
          metadata: {
            suite: t.suite,
            test_name: t.test_name,
            gas: t.gas,
            durations: t.duration,
            reproduction: 'exploit test passed',
            project_directory: projectDir,
          },
        });
      } else if (isFail && exploitNamed) {
        findings.push({
          id: `foundry-notrepro-${t.suite}-${t.test_name}`,
          title: `[Foundry] Exploit test failed: ${t.test_name}`,
          description:
            `Forge test '${t.test_name}' in ${t.suite} failed (${t.reason || 'no reason reported'}), ` +
            `indicating the asserted unauthorized behaviour did not reproduce.`,
          severity: 'INFO',
          category: 'DYNAMIC_REPRODUCTION',
          cwe: [],
          confidence: 'MEDIUM',
          file: t.suite,
          evidence: t.reason || 'exploit test failed',
          metadata: {
            suite: t.suite,
            test_name: t.test_name,
            reason: t.reason,
            reproduction: 'exploit test did not reproduce',
            project_directory: projectDir,
          },
        });
      }
    }

    return findings;
  }

  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[] {
    const parsed = globalFoundryService.parseForgeOutput(rawOutput.stdout);
    if (!parsed) return [];
    return this.toFindings(
      {
        status: 'COMPLETED',
        executable_path: null,
        version: null,
        command: 'forge test --json',
        exit_code: rawOutput.exit_code,
        stdout: rawOutput.stdout,
        stderr: rawOutput.stderr,
        duration_ms: 0,
        suites: parsed.suites,
        tests_passed: parsed.results.filter(r => /^success$/i.test(r.status)).length,
        tests_failed: parsed.results.filter(r => /^failure$/i.test(r.status)).length,
        results: parsed.results,
        error: null,
      },
      ''
    );
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}