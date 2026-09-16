import { describe, it, expect } from 'vitest';
import { GitSourceIntegrityEngine, SemgrepEngine, SlitherEngine, EngineRegistry, EngineAvailabilityStatus, EngineResultStatus } from '../../engines/index.js';

describe('Engine Availability & Anti-Fabrication Tests (Phase 0 & Phase 0.1 Requirements)', () => {
  it('should accurately report git engine available on host', async () => {
    const gitEngine = new GitSourceIntegrityEngine();
    const availability = await gitEngine.check_availability();
    expect(availability.status).toBe(EngineAvailabilityStatus.AVAILABLE);
    expect(availability.detected_path).toBeDefined();
  });

  it('should truthfully report uninstalled engines as NOT_INSTALLED rather than fake success', async () => {
    const slither = new SlitherEngine('intent-nonexistent-slither-binary');
    const avail = await slither.check_availability();
    expect(avail.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);
    expect(avail.version).toBeNull();
    expect(avail.detected_path).toBeNull();
    expect(avail.error).toContain('is not installed');
  });

  it('should produce an explicit failure EngineResult when executing an uninstalled engine', async () => {
    const slither = new SlitherEngine('intent-nonexistent-slither-binary');
    const result = await slither.execute('tgt-01', 'ast_rule_scan', {});
    
    expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
    expect(result.exit_code).toBe(127);
    expect(result.findings).toHaveLength(0); // Zero fake findings
    expect(result.error).toContain('ENGINE_UNAVAILABLE');
  });

  it('should truthfully report all registry statuses without fabrication', async () => {
    const registry = new EngineRegistry();
    const checks = await registry.check_all();
    
    const semgrepCheck = checks.find(c => c.engine_id === 'semgrep');
    expect(semgrepCheck?.status).toBe(EngineAvailabilityStatus.AVAILABLE);

    // Any engine lacking a host binary must claim neither a path nor a version.
    for (const check of checks) {
      if (check.status === EngineAvailabilityStatus.NOT_INSTALLED) {
        expect(check.detected_path).toBeNull();
        expect(check.version).toBeNull();
      } else {
        expect(check.detected_path).toBeTruthy();
      }
    }
  });
});
