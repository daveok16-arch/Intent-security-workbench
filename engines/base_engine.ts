/**
 * Base Engine Class
 * Intent Security Workbench - Phase 0.1
 *
 * Provides typed base execution semantics, accurate binary verification,
 * and strict anti-fabrication invariants across all security analysis engines.
 */

import { execFileSync } from 'child_process';
import os from 'os';
import { resolveExecutable } from '../packages/config/src/binary_resolver.js';
import { registeredEvidenceArtifacts } from '../packages/evidence/src/index.js';
import {
  IEngine,
  EngineAvailability,
  EngineAvailabilityStatus,
  EngineResult,
  EngineResultStatus,
  EngineFinding,
  EngineArtifact,
} from './types.js';

export abstract class BaseEngine implements IEngine {
  abstract readonly name: string;
  abstract readonly engine_id: string;
  abstract readonly version: string;
  abstract readonly description: string;
  abstract readonly capabilities: string[];
  abstract readonly supported_target_types: string[];
  abstract readonly supported_languages: string[];
  abstract readonly executable: string;

  /**
   * CLI argument(s) used for extracting the actual engine version.
   * Defaults to ['--version'].
   */
  protected versionArgs: string[] = ['--version'];

  /**
   * Helper property for backward compatibility with Phase 0 checks.
   */
  get binaryName(): string {
    return this.executable;
  }

  /**
   * Check executable availability in the real environment.
   * Never fabricates availability or versions.
   */
  async check_availability(): Promise<EngineAvailability> {
    const checked_at = new Date().toISOString();

    // 1. Check if executable exists in PATH
    let detectedPath: string | null = null;
    try {
      // Validate executable name does not contain shell injection characters
      if (!/^[a-zA-Z0-9_-]+$/.test(this.executable)) {
        return {
          engine_id: this.engine_id,
          name: this.name,
          status: EngineAvailabilityStatus.UNAVAILABLE,
          executable: this.executable,
          detected_path: null,
          version: null,
          checked_at,
          error: `Invalid executable identifier '${this.executable}'.`,
          capabilities: this.capabilities,
        };
      }

      const out = resolveExecutable(this.executable);
      if (out) {
        detectedPath = out;
      }
    } catch {
      // Binary not found on system PATH
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.NOT_INSTALLED,
        executable: this.executable,
        detected_path: null,
        version: null,
        checked_at,
        error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
        capabilities: this.capabilities,
      };
    }

    if (!detectedPath) {
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.NOT_INSTALLED,
        executable: this.executable,
        detected_path: null,
        version: null,
        checked_at,
        error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
        capabilities: this.capabilities,
      };
    }

    // 2. Executable exists on PATH. Test actual execution by querying real version.
    try {
      const realVersion = await this.get_version(detectedPath);
      if (realVersion) {
        return {
          engine_id: this.engine_id,
          name: this.name,
          status: EngineAvailabilityStatus.AVAILABLE,
          executable: this.executable,
          detected_path: detectedPath,
          version: realVersion,
          checked_at,
          error: null,
          capabilities: this.capabilities,
        };
      } else {
        return {
          engine_id: this.engine_id,
          name: this.name,
          status: EngineAvailabilityStatus.BROKEN,
          executable: this.executable,
          detected_path: detectedPath,
          version: null,
          checked_at,
          error: `Binary at '${detectedPath}' exists but failed to return a valid version string.`,
          capabilities: this.capabilities,
        };
      }
    } catch (err: any) {
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.BROKEN,
        executable: this.executable,
        detected_path: detectedPath,
        version: null,
        checked_at,
        error: `Binary at '${detectedPath}' threw error during execution: ${err.message || String(err)}`,
        capabilities: this.capabilities,
      };
    }
  }

  /**
   * Alias for backward compatibility.
   */
  async check_available(): Promise<{
    available: boolean;
    name: string;
    version?: string;
    binary_path?: string;
    reason?: string;
    checked_at: string;
    status?: EngineAvailabilityStatus;
  }> {
    const avail = await this.check_availability();
    return {
      available: avail.status === EngineAvailabilityStatus.AVAILABLE,
      name: this.name,
      version: avail.version || undefined,
      binary_path: avail.detected_path || undefined,
      reason: avail.error || undefined,
      checked_at: avail.checked_at,
      status: avail.status,
    };
  }

  /**
   * Query the actual executable for its real version string.
   * Returns null if binary is missing or cannot execute.
   */
  async get_version(resolvedPath?: string | null): Promise<string | null> {
    try {
      const target = resolvedPath || resolveExecutable(this.executable);
      if (!target) return null;
      const output = execFileSync(target, this.versionArgs, {
        encoding: 'utf-8',
        timeout: 3000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();

      if (!output) return null;
      // Extract the first meaningful line or version token
      const firstLine = output.split('\n')[0].trim();
      return firstLine || output;
    } catch {
      return null;
    }
  }

  abstract prepare(targetId: string, context: Record<string, any>): Promise<boolean>;

  abstract execute(
    targetId: string,
    operation: string,
    context: Record<string, any>
  ): Promise<EngineResult>;

  abstract parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[];

  abstract cleanup(context: Record<string, any>): Promise<void>;

  /**
   * Result for an engine whose binary exists but whose real execution is not yet
   * implemented (Phase 1/2 placeholders). Returns a structured FAILED result
   * rather than throwing, and reports no findings so nothing is fabricated.
   */
  protected notImplementedResult(
    targetId: string,
    operation: string,
    context: Record<string, any>,
    availability: EngineAvailability
  ): EngineResult {
    const now = new Date().toISOString();
    return {
      id: `res-${this.engine_id}-${Date.now()}`,
      engine_id: this.engine_id,
      engine_name: this.name,
      engine_version: availability.version || this.version,
      status: EngineResultStatus.FAILED,
      target_id: targetId,
      investigation_id: context.investigation_id,
      command: `${this.executable} ${operation} [not implemented]`,
      working_directory: context.working_directory || process.cwd(),
      started_at: now,
      completed_at: now,
      duration_ms: 0,
      exit_code: -1,
      stdout: '',
      stderr: `${this.name} execution is not implemented in this phase.`,
      findings: [],
      artifacts: [],
      environment: this.getEnvironmentInfo(availability.detected_path),
      error: `ENGINE_NOT_IMPLEMENTED: ${this.name} binary is present at '${availability.detected_path}' but real execution is deferred to a later integration phase.`,
    };
  }

  /**
   * Version string to report on an EngineResult.
   *
   * The declared `version` is a build constant describing what the engine
   * supports, not evidence that this binary is installed. Reporting it on a
   * result produced by a missing binary would assert a version that was never
   * interrogated on the host. When availability is anything other than
   * AVAILABLE, report 'unknown' instead.
   */
  protected engineVersionFor(availability?: EngineAvailability | null): string {
    if (availability?.status === EngineAvailabilityStatus.AVAILABLE) {
      return availability.version || this.version;
    }
    return 'unknown';
  }

  /**
   * Builds an honest FAILED result for an operation that did not succeed.
   * `duration_ms` reflects real elapsed time and `exit_code` is non-zero, so no
   * timing or success is invented. Engines use this instead of swallowing an
   * error and reporting SUCCESS with exit code 0.
   */
  protected failedResult(
    targetId: string,
    context: Record<string, any>,
    command: string,
    startedAt: string,
    completedAt: string,
    startedMs: number,
    error: string,
    availability?: EngineAvailability | null
  ): EngineResult {
    return {
      id: `res-${this.engine_id}-${Date.now()}`,
      engine_id: this.engine_id,
      engine_name: this.name,
      engine_version: availability?.version || this.version,
      status: EngineResultStatus.FAILED,
      target_id: targetId,
      investigation_id: context.investigation_id,
      command,
      working_directory: context.working_directory || process.cwd(),
      started_at: startedAt,
      completed_at: completedAt,
      duration_ms: Math.max(0, startedMs ? Date.now() - startedMs : 0),
      exit_code: 1,
      stdout: '',
      stderr: error,
      findings: [],
      artifacts: [],
      environment: this.getEnvironmentInfo(availability?.detected_path),
      error: `ENGINE_EXECUTION_FAILED: ${error}`,
    };
  }

  /**
   * Builds an EngineArtifact descriptor from an artifact id, using the genuine
   * SHA-256 digest and byte size recorded at storage time.
   *
   * Returns null when the id is not a registered artifact. Publishing a
   * descriptor with an empty digest and an invented `created_at` would assert
   * provenance the engine cannot actually demonstrate, which is exactly what the
   * anti-fabrication mandate forbids. Callers filter these out of their artifact
   * lists; an engine that needs to report output must register it first with
   * `registerArtifact()`.
   */
  protected describeArtifact(
    id: string,
    type: string,
    artifactPath: string,
    mimeType = 'application/json'
  ): EngineArtifact | null {
    const registered = registeredEvidenceArtifacts.get(id);
    if (!registered?.artifact) {
      return null;
    }
    const { artifact } = registered;
    return {
      id,
      type,
      path: artifact.path || artifactPath,
      sha256: artifact.sha256,
      size: artifact.size_bytes,
      mime_type: artifact.mime_type || mimeType,
      created_at: artifact.created_at,
    };
  }

  /**
   * Registers real engine output as a machine-verifiable evidence artifact with
   * a genuine SHA-256 digest and byte size. Returns null (never a placeholder
   * hash) when there is no content to persist.
   */
  protected async registerOutputArtifact(
    investigationId: string | undefined,
    targetId: string,
    label: string,
    content: string,
    mimeType = 'application/json'
  ): Promise<string | null> {
    if (!investigationId || !content || content.length === 0) return null;
    try {
      const { globalArtifactStorage } = await import('../packages/evidence/src/index.js');
      const { createEvidenceArtifact } = await import('../packages/evidence/src/index.js');
      const filename = `${label}-${Date.now()}.out`;

      // storeSync is used when present so the artifact tree is written eagerly;
      // otherwise fall back to the async store implementation.
      const meta =
        typeof (globalArtifactStorage as any).storeSync === 'function'
          ? (globalArtifactStorage as any).storeSync(investigationId, 'engines', filename, content, mimeType)
          : await globalArtifactStorage.store(investigationId, 'engines', filename, content, mimeType);

      const built = createEvidenceArtifact({
        investigation_id: investigationId,
        target_id: targetId,
        artifact_type: 'ENGINE_OUTPUT' as any,
        producer: this.name,
        producer_version: this.version,
        command: `${this.executable} ${label}`,
        content,
        path: meta.path,
        path_or_reference: meta.path,
        mime_type: mimeType,
      });
      return built.artifact.id;
    } catch {
      return null;
    }
  }

  /**
   * Standard environment information for result provenance.
   */
  protected getEnvironmentInfo(detectedPath?: string | null) {
    return {
      hostname: os.hostname(),
      os: `${os.type()} ${os.release()} (${os.arch()})`,
      node_version: process.version,
      executable_path: detectedPath || null,
    };
  }
}
