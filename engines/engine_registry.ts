/**
 * Engine Registry
 * Intent Security Workbench - Phase 0.1
 *
 * Central source of truth for all security analysis engines and their verified
 * host availability.
 */

import { BaseEngine } from './base_engine.js';
import { EngineAvailability, EngineAvailabilityStatus } from './types.js';
import { TreeSitterEngine } from './placeholders/treesitter.js';
import { SemgrepEngine } from './placeholders/semgrep.js';
import { Z3Engine } from './placeholders/z3.js';
import { AngrEngine } from './placeholders/angr.js';
import { CodeQLEngine } from './placeholders/codeql.js';
import { SlitherEngine } from './placeholders/slither.js';
import { FoundryEngine } from './placeholders/foundry.js';
import { ClarinetEngine } from './placeholders/clarinet.js';
import { SpectralEngine } from './placeholders/spectral.js';
import { GitSourceIntegrityEngine } from './placeholders/git_integrity.js';
import { StaticAnalysisEngine } from './placeholders/static_analysis.js';

export class EngineRegistry {
  private engines: Map<string, BaseEngine> = new Map();

  constructor() {
    this.registerDefaults();
  }

  /**
   * Register standard Phase 0.1 engines and placeholders.
   */
  private registerDefaults(): void {
    this.register(new TreeSitterEngine());
    this.register(new SemgrepEngine());
    this.register(new StaticAnalysisEngine());
    this.register(new Z3Engine());
    this.register(new AngrEngine());
    this.register(new CodeQLEngine());
    this.register(new SlitherEngine());
    this.register(new FoundryEngine());
    this.register(new ClarinetEngine());
    this.register(new SpectralEngine());
    this.register(new GitSourceIntegrityEngine());
  }

  /**
   * Register a new engine instance into the registry.
   */
  register(engine: BaseEngine): void {
    this.engines.set(engine.engine_id, engine);
    // Also index by name if distinct
    if (engine.name && engine.name !== engine.engine_id) {
      this.engines.set(engine.name, engine);
    }
  }

  /**
   * Unregister an engine (useful for test isolation).
   */
  unregister(engine_id: string): boolean {
    const engine = this.engines.get(engine_id);
    if (!engine) return false;
    this.engines.delete(engine.engine_id);
    if (engine.name) this.engines.delete(engine.name);
    return true;
  }

  /**
   * Retrieve an engine by its engine_id or name.
   */
  get(engine_id: string): BaseEngine | undefined {
    return this.engines.get(engine_id);
  }

  /**
   * List all unique registered engines.
   */
  list(): BaseEngine[] {
    const unique = new Map<string, BaseEngine>();
    for (const eng of this.engines.values()) {
      unique.set(eng.engine_id, eng);
    }
    return Array.from(unique.values());
  }

  /**
   * Alias for backward compatibility.
   */
  listEngines(): {
    engine_id: string;
    name: string;
    version: string;
    description: string;
    executable: string;
    capabilities: string[];
    supported_target_types: string[];
    supported_languages: string[];
  }[] {
    return this.list().map(e => ({
      engine_id: e.engine_id,
      name: e.name,
      version: e.version,
      description: e.description,
      executable: e.executable,
      capabilities: e.capabilities,
      supported_target_types: e.supported_target_types,
      supported_languages: e.supported_languages,
    }));
  }

  /**
   * Check real host availability for all registered engines.
   */
  async check_all(): Promise<EngineAvailability[]> {
    const results: EngineAvailability[] = [];
    const engines = this.list();

    for (const engine of engines) {
      const avail = await engine.check_availability();
      results.push(avail);
    }

    return results;
  }

  /**
   * Alias for backward compatibility.
   */
  async checkAllAvailability(): Promise<EngineAvailability[]> {
    return this.check_all();
  }

  /**
   * Check real host availability for a specific engine.
   */
  async check(engine_id: string): Promise<EngineAvailability> {
    const engine = this.get(engine_id);
    if (!engine) {
      return {
        engine_id,
        name: engine_id,
        status: EngineAvailabilityStatus.NOT_INSTALLED,
        executable: 'unknown',
        detected_path: null,
        version: null,
        checked_at: new Date().toISOString(),
        error: `Engine '${engine_id}' is not registered in EngineRegistry.`,
        capabilities: [],
      };
    }

    return await engine.check_availability();
  }
}

export const globalEngineRegistry = new EngineRegistry();
