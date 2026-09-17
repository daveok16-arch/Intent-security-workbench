/**
 * Real Engine Integration Test Suite (Phase 2 / Phase 5)
 *
 * Covers the five engines that were previously placeholders and are now real
 * executors: Slither, CodeQL, Angr, Clarinet and Foundry.
 *
 * Two layers are asserted:
 *   1. Parsers, run against captured fixtures so they are fully host-independent
 *      and pin the anti-fabrication contract (unparseable output => no findings).
 *   2. Real execution, skipped automatically when the engine is not installed,
 *      so a bare host never produces a false failure.
 *
 * Tests must never assert that a tool is absent from the host.
 */

import { describe, it, expect } from 'vitest';
import path from 'path';

import {
  SlitherEngine,
  CodeQLEngine,
  AngrEngine,
  ClarinetEngine,
  FoundryEngine,
  EngineAvailabilityStatus,
  EngineResultStatus,
} from '../../engines/index.js';
import {
  SlitherAnalysisService,
  CodeQLAnalysisService,
} from '../../packages/static-analysis/src/index.js';
import {
  ClarinetAnalysisService,
  AngrAnalysisService,
  FoundryAnalysisService,
} from '../../packages/dynamic-verification/src/index.js';

const rootDir = process.cwd();
// Reuse the fixtures already shipped under tests/fixtures/engines.
const slitherFixture = path.join(rootDir, 'tests', 'fixtures', 'engines', 'slither');
const clarityFixture = path.join(rootDir, 'tests', 'fixtures', 'engines', 'clarinet', 'vulnerable');
const angrFixture = path.join(rootDir, 'tests', 'fixtures', 'engines', 'angr', 'test_crackme');
const vulnerableBinFixture = path.join(rootDir, 'tests', 'fixtures', 'engines', 'angr', 'vulnerable_symbols');
const foundryFixture = path.join(rootDir, 'tests', 'fixtures', 'engines', 'foundry');
const codeqlFixture = path.join(rootDir, 'tests', 'fixtures', 'engines', 'codeql');
const FOUNDRY_FIXTURE_DIR = path.join(
  rootDir,
  'fixtures',
  'dynamic_verification',
  'evm',
  'vulnerable_bola'
);

describe('Real Engine Integrations — Slither, CodeQL, Angr, Clarinet, Foundry', () => {
  // =========================================================================
  // Slither
  // =========================================================================
  describe('Slither engine', () => {
    const service = new SlitherAnalysisService();

    it('parses a genuine Slither JSON envelope into detector results', () => {
      const envelope = JSON.stringify({
        success: true,
        error: null,
        results: {
          detectors: [
            {
              check: 'reentrancy-eth',
              impact: 'High',
              confidence: 'Medium',
              description: 'Reentrancy in Fixture.withdraw()',
              reference: 'https://example.test/reentrancy',
              elements: [
                {
                  type: 'function',
                  name: 'withdraw',
                  source_mapping: {
                    filename_relative: 'Fixture.sol',
                    lines: [12, 13, 14, 15],
                    starting_column: 5,
                  },
                },
              ],
            },
            {
              check: 'tx-origin',
              impact: 'Medium',
              confidence: 'Medium',
              description: 'Fixture.privileged() uses tx.origin for authorization',
              elements: [
                {
                  type: 'function',
                  name: 'privileged',
                  source_mapping: { filename_relative: 'Fixture.sol', lines: [21] },
                },
              ],
            },
          ],
        },
      });

      const parsed = service.parseSlitherOutput(envelope);
      expect(parsed).not.toBeNull();
      expect(parsed!.success).toBe(true);
      expect(parsed!.detectors).toHaveLength(2);
      expect(parsed!.detectors[0].check).toBe('reentrancy-eth');
      expect(parsed!.detectors[0].elements[0].lines).toEqual([12, 13, 14, 15]);
    });

    it('maps Slither impact onto platform severity and attaches CWE ids', () => {
      expect(SlitherAnalysisService.severityFor('High')).toBe('HIGH');
      expect(SlitherAnalysisService.severityFor('Medium')).toBe('MEDIUM');
      expect(SlitherAnalysisService.severityFor('Low')).toBe('LOW');
      expect(SlitherAnalysisService.severityFor('Informational')).toBe('INFO');
      // Unknown impact must degrade to INFO rather than overstate severity.
      expect(SlitherAnalysisService.severityFor('Bogus')).toBe('INFO');

      expect(SlitherAnalysisService.cwesFor('reentrancy-eth')).toContain('CWE-841');
      expect(SlitherAnalysisService.cwesFor('tx-origin')).toContain('CWE-346');
      expect(SlitherAnalysisService.cwesFor('totally-unknown-check')).toEqual([]);
    });

    it('returns null (never fabricated findings) for non-Slither output', () => {
      expect(service.parseSlitherOutput('')).toBeNull();
      expect(service.parseSlitherOutput('error: solc not found')).toBeNull();
      expect(service.parseSlitherOutput('{"unexpected": true}')).toBeNull();
      expect(service.parseSlitherOutput('[1,2,3]')).toBeNull();
    });

    it('reports NOT_INSTALLED with zero findings when the binary is absent', async () => {
      const engine = new SlitherEngine('intent-nonexistent-slither-binary');
      const avail = await engine.check_availability();
      expect(avail.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);
      expect(avail.version).toBeNull();
      expect(avail.detected_path).toBeNull();

      const result = await engine.execute('tgt-x', 'solidity_static_analysis', {});
      expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
      expect(result.exit_code).toBe(127);
      expect(result.findings).toHaveLength(0);
      expect(result.duration_ms).toBe(0);
    });

    it('detects real Solidity flaws on a vulnerable fixture when installed', async () => {
      const engine = new SlitherEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-slither', 'solidity_static_analysis', {
        investigation_id: 'inv-test-slither',
        target_directory: slitherFixture,
        timeout_ms: 300000,
      });

      expect(result.status).toBe(EngineResultStatus.SUCCESS);
      expect(result.exit_code).toBe(0);

      const checks = result.findings.map(f => f.metadata?.detector_id);
      expect(checks).toContain('reentrancy-eth');
      expect(checks).toContain('low-level-calls');

      const reentrancy = result.findings.find(f => f.metadata?.detector_id === 'reentrancy-eth')!;
      expect(reentrancy.severity).toBe('HIGH');
      expect(reentrancy.file).toContain('Reentrancy.sol');
      expect(reentrancy.line_start).toBeGreaterThan(0);
      expect(reentrancy.cwe).toContain('CWE-841');

      // Real output must be persisted as verifiable evidence.
      expect(result.artifacts.length).toBeGreaterThan(0);
      expect(result.artifacts[0].sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(result.artifacts[0].size).toBeGreaterThan(0);
    }, 360000);
  });

  // =========================================================================
  // CodeQL
  // =========================================================================
  describe('CodeQL engine', () => {
    const service = new CodeQLAnalysisService();

    it('parses SARIF into findings using CodeQL security-severity scores', () => {
      const sarif = JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                rules: [
                  {
                    id: 'js/command-line-injection',
                    name: 'js/command-line-injection',
                    properties: { 'security-severity': '9.8', tags: ['external/cwe/cwe-078'] },
                    helpUri: 'https://example.test/cwe78',
                  },
                  {
                    id: 'js/missing-rate-limiting',
                    name: 'js/missing-rate-limiting',
                    properties: { 'security-severity': '7.5' },
                  },
                ],
              },
            },
            results: [
              {
                ruleId: 'js/command-line-injection',
                message: { text: 'This command line depends on a user-provided value.' },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'app.js' },
                      region: { startLine: 10, endLine: 10, snippet: { text: 'exec(cmd)' } },
                    },
                  },
                ],
              },
              {
                ruleId: 'js/missing-rate-limiting',
                message: { text: 'This route handler performs a system command, but is not rate-limited.' },
                locations: [
                  { physicalLocation: { artifactLocation: { uri: 'app.js' }, region: { startLine: 8 } } },
                ],
              },
            ],
          },
        ],
      });

      const findings = service.parseSarif(sarif);
      expect(findings).not.toBeNull();
      expect(findings!).toHaveLength(2);

      const injection = findings!.find(f => f.rule_id === 'js/command-line-injection')!;
      expect(injection.severity).toBe('CRITICAL'); // 9.8
      expect(injection.cwe).toContain('CWE-078');
      expect(injection.file).toBe('app.js');
      expect(injection.line_start).toBe(10);

      const rateLimit = findings!.find(f => f.rule_id === 'js/missing-rate-limiting')!;
      expect(rateLimit.severity).toBe('HIGH'); // 7.5
      expect(rateLimit.cwe).toContain('CWE-770'); // derived from the rule id
    });

    it('returns null (never fabricated findings) for non-SARIF output', () => {
      expect(service.parseSarif('')).toBeNull();
      expect(service.parseSarif('CodeQL: no database found')).toBeNull();
      expect(service.parseSarif('{"version":"2.1.0"}')).toBeNull();
      expect(service.parseSarif('{}')).toBeNull();
    });

    it('detects the language of a source tree from file extensions', () => {
      expect(service.detectLanguage(slitherFixture)).toBeNull(); // only .sol
      expect(service.detectLanguage(path.join(rootDir, 'packages', 'static-analysis', 'src'))).toBe('typescript');
    });

    it('reports NOT_INSTALLED with zero findings when the binary is absent', async () => {
      const engine = new CodeQLEngine('intent-nonexistent-codeql-binary');
      const avail = await engine.check_availability();
      expect(avail.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);

      const result = await engine.execute('tgt-x', 'semantic_analysis', {});
      expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
      expect(result.exit_code).toBe(127);
      expect(result.findings).toHaveLength(0);
    });

    it('finds real vulnerabilities in the shipped JS fixture when installed', async () => {
      const engine = new CodeQLEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-codeql', 'semantic_analysis', {
        investigation_id: 'inv-test-codeql-live',
        target_directory: codeqlFixture,
        timeout_ms: 900000,
      });

      expect(result.status).toBe(EngineResultStatus.SUCCESS);
      const rules = result.findings.map(f => f.metadata?.rule_id);
      expect(rules).toContain('js/command-line-injection');
      expect(rules).toContain('js/path-injection');

      // Severity must come from CodeQL's own security-severity score.
      const injection = result.findings.find(f => f.metadata?.rule_id === 'js/command-line-injection')!;
      expect(injection.severity).toBe('CRITICAL');
      expect(injection.cwe.length).toBeGreaterThan(0);
      expect(result.artifacts.length).toBeGreaterThan(0);
    }, 960000);

    it('fails honestly (no findings) on a tree with no supported source', async () => {
      const engine = new CodeQLEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-codeql', 'semantic_analysis', {
        investigation_id: 'inv-test-codeql',
        target_directory: clarityFixture, // only .clar files
      });

      expect(result.status).toBe(EngineResultStatus.FAILED);
      expect(result.findings).toHaveLength(0);
      expect(result.error).toContain('NO_SUPPORTED_SOURCE');
    }, 120000);
  });

  // =========================================================================
  // Angr
  // =========================================================================
  describe('Angr engine', () => {
    const service = new AngrAnalysisService();

    it('parses analyzer output and resolves call sites', () => {
      const payload = JSON.stringify({
        ok: true,
        angr_version: '9.2.160',
        binary: { path: '/bin/x', arch: 'AMD64', bits: 64, entry: '0x401070', pie: true, nx: true },
        functions: 28,
        imports: ['puts', 'strcpy', 'system'],
        dangerous_imports: ['strcpy', 'system'],
        call_sites: [
          { symbol: 'strcpy', addr: '0x500008' },
          { symbol: 'system', addr: '0x500018' },
        ],
        warnings: [],
      });

      const parsed = service.parseAnalyzerOutput(payload);
      expect(parsed).not.toBeNull();
      expect(parsed!.ok).toBe(true);
      expect(parsed!.functions).toBe(28);
      expect(parsed!.dangerous_imports).toEqual(['strcpy', 'system']);
    });

    it('returns null (never fabricated findings) for non-JSON driver output', () => {
      expect(service.parseAnalyzerOutput('')).toBeNull();
      expect(service.parseAnalyzerOutput('Traceback (most recent call last):')).toBeNull();
      expect(service.parseAnalyzerOutput('{"no_ok_field": true}')).toBeNull();
    });

    it('classifies dangerous libc symbols with CWE ids', () => {
      expect(AngrAnalysisService.isDangerous('strcpy')).toBe(true);
      expect(AngrAnalysisService.isDangerous('system')).toBe(true);
      expect(AngrAnalysisService.isDangerous('printf')).toBe(false);

      expect(AngrAnalysisService.symbolInfo('strcpy')!.cwe).toContain('CWE-120');
      expect(AngrAnalysisService.symbolInfo('system')!.severity).toBe('HIGH');
      expect(AngrAnalysisService.symbolInfo('gets')!.severity).toBe('CRITICAL');
    });

    it('reports NOT_INSTALLED with zero findings when the binary is absent', async () => {
      const engine = new AngrEngine('intent-nonexistent-angr-binary');
      const avail = await engine.check_availability();
      expect(avail.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);

      const result = await engine.execute('tgt-x', 'binary_analysis', {});
      expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
      expect(result.exit_code).toBe(127);
      expect(result.findings).toHaveLength(0);
    });

    it('fails honestly when no binary is supplied', async () => {
      const engine = new AngrEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-angr', 'binary_analysis', {
        investigation_id: 'inv-test-angr',
      });
      expect(result.status).toBe(EngineResultStatus.FAILED);
      expect(result.findings).toHaveLength(0);
      expect(result.error).toContain('ANGR_MISSING_TARGET');
    }, 120000);

    it('recovers CFG facts from the shipped crackme fixture when installed', async () => {
      const engine = new AngrEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-angr', 'binary_analysis', {
        investigation_id: 'inv-test-angr-live',
        binary_path: angrFixture,
        timeout_ms: 240000,
      });

      // The fixture is a real ELF, so analysis must complete rather than error.
      expect(result.status).toBe(EngineResultStatus.SUCCESS);
      expect(result.exit_code).toBe(0);

      // Raw driver output is persisted as verifiable evidence even when the
      // fixture imports no dangerous symbols.
      expect(result.artifacts.length).toBeGreaterThan(0);
      expect(result.artifacts[0].sha256).toMatch(/^[a-f0-9]{64}$/);

      const raw = JSON.parse(result.stdout);
      expect(raw.ok).toBe(true);
      expect(raw.functions).toBeGreaterThan(0);
      expect(raw.binary.arch).toBeTruthy();
    }, 300000);

    it('flags dangerous symbols with call sites on a vulnerable binary', async () => {
      const engine = new AngrEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-angr', 'binary_analysis', {
        investigation_id: 'inv-test-angr-symbols',
        binary_path: vulnerableBinFixture,
        timeout_ms: 240000,
      });

      expect(result.status).toBe(EngineResultStatus.SUCCESS);
      const symbols = result.findings.map(f => f.metadata?.symbol);
      expect(symbols).toContain('strcpy');
      expect(symbols).toContain('system');

      // A resolved call site raises confidence above a bare import.
      const strcpy = result.findings.find(f => f.metadata?.symbol === 'strcpy')!;
      expect(strcpy.metadata?.call_site).toMatch(/^0x/);
      expect(strcpy.confidence).toBe('MEDIUM');
      expect(strcpy.cwe).toContain('CWE-120');
    }, 300000);
  });

  // =========================================================================
  // Clarinet
  // =========================================================================
  describe('Clarinet engine', () => {
    const service = new ClarinetAnalysisService();

    it('parses the Clarinet JSON diagnostics envelope', () => {
      const envelope = JSON.stringify({
        success: true,
        diagnostics: {
          '/tmp/proj/contracts/vault.clar': [
            {
              level: 'Warning',
              message: 'use of potentially unchecked data',
              spans: [{ start_line: 9, start_column: 33, end_line: 9, end_column: 50 }],
              suggestion: null,
            },
            {
              level: 'Note',
              message: 'source of untrusted input here',
              spans: [{ start_line: 7, start_column: 26, end_line: 7, end_column: 31 }],
              suggestion: null,
            },
          ],
        },
        environment: 'onchain',
      });

      const parsed = service.parseClarinetOutput(envelope);
      expect(parsed).not.toBeNull();
      expect(parsed!.success).toBe(true);
      expect(parsed!.diagnostics).toHaveLength(2);
      expect(parsed!.diagnostics[0].level).toBe('Warning');
      expect(parsed!.diagnostics[0].start_line).toBe(9);
      expect(parsed!.diagnostics[1].file).toBe('/tmp/proj/contracts/vault.clar');
    });

    it('maps diagnostic levels onto severity and returns null for foreign output', () => {
      expect(ClarinetAnalysisService.severityFor('Error')).toBe('HIGH');
      expect(ClarinetAnalysisService.severityFor('Warning')).toBe('MEDIUM');
      expect(ClarinetAnalysisService.severityFor('Note')).toBe('INFO');
      expect(ClarinetAnalysisService.severityFor('Bogus')).toBe('INFO');

      expect(service.parseClarinetOutput('')).toBeNull();
      expect(service.parseClarinetOutput('Could not find Clarinet.toml')).toBeNull();
      expect(service.parseClarinetOutput('{"something": 1}')).toBeNull();
    });

    it('reports NOT_INSTALLED with zero findings when the binary is absent', async () => {
      const engine = new ClarinetEngine('intent-nonexistent-clarinet-binary');
      const avail = await engine.check_availability();
      expect(avail.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);

      const result = await engine.execute('tgt-x', 'clarity_check', {
        source_directory: clarityFixture,
      });
      expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
      expect(result.exit_code).toBe(127);
      expect(result.findings).toHaveLength(0);
    });

    it('analyses a bare .clar fixture by scaffolding a project when installed', async () => {
      const engine = new ClarinetEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-clarinet', 'clarity_check', {
        investigation_id: 'inv-test-clarinet',
        source_directory: clarityFixture,
        timeout_ms: 180000,
      });

      expect(result.status).toBe(EngineResultStatus.SUCCESS);
      expect(result.findings.length).toBeGreaterThan(0);
      // Findings must reference the real source file, not the temp scaffold.
      expect(result.findings[0].file).toContain('vault.clar');
    }, 240000);
  });

  // =========================================================================
  // Foundry
  // =========================================================================
  describe('Foundry engine', () => {
    const service = new FoundryAnalysisService();

    it('parses forge test --json into per-test results', () => {
      const forgeOut = JSON.stringify({
        'test/Vault.t.sol:VaultTest': {
          duration: '1ms',
          test_results: {
            'testExploitBOLA()': {
              status: 'Success',
              reason: null,
              kind: { Unit: { gas: 100498 } },
              duration: '161µs',
            },
            'testGuardedPath()': {
              status: 'Failure',
              reason: 'intentional: 1 != 2',
              kind: { Unit: { gas: 12345 } },
            },
          },
          warnings: [],
        },
      });

      const parsed = service.parseForgeOutput(forgeOut);
      expect(parsed).not.toBeNull();
      expect(parsed!.results).toHaveLength(2);
      expect(parsed!.suites).toEqual(['test/Vault.t.sol:VaultTest']);

      const exploit = parsed!.results.find(r => r.test_name === 'testExploitBOLA')!;
      expect(exploit.status).toBe('Success');
      expect(exploit.gas).toBe(100498);

      const guarded = parsed!.results.find(r => r.test_name === 'testGuardedPath')!;
      expect(guarded.status).toBe('Failure');
      expect(guarded.reason).toContain('intentional');
    });

    it('returns null (never fabricated findings) for non-JSON forge output', () => {
      expect(service.parseForgeOutput('')).toBeNull();
      expect(service.parseForgeOutput('Compiling 2 files with Solc 0.8.20')).toBeNull();
      expect(service.parseForgeOutput('{"not":"a suite map"}')).toBeNull();
    });

    it('recognises exploit-asserting test names only', () => {
      expect(FoundryAnalysisService.looksLikeExploitTest('testExploitBOLA')).toBe(true);
      expect(FoundryAnalysisService.looksLikeExploitTest('test_unauthorized_redeem')).toBe(true);
      expect(FoundryAnalysisService.looksLikeExploitTest('testReentrancyAttack')).toBe(true);
      expect(FoundryAnalysisService.looksLikeExploitTest('testDepositSucceeds')).toBe(false);
      expect(FoundryAnalysisService.looksLikeExploitTest('testBalanceOf')).toBe(false);
    });

    it('reports NOT_INSTALLED with zero findings when forge is absent', async () => {
      const engine = new FoundryEngine('intent-nonexistent-forge-binary');
      const avail = await engine.check_availability();
      expect(avail.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);

      const result = await engine.execute('tgt-x', 'forge_test', {});
      expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
      expect(result.exit_code).toBe(127);
      expect(result.findings).toHaveLength(0);
    });

    it('fails honestly when the directory is not a Foundry project', async () => {
      const engine = new FoundryEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-foundry', 'forge_test', {
        investigation_id: 'inv-test-foundry',
        project_directory: slitherFixture, // no foundry.toml/src/test
      });
      expect(result.status).toBe(EngineResultStatus.FAILED);
      expect(result.findings).toHaveLength(0);
      expect(result.error).toContain('NOT_A_FOUNDRY_PROJECT');
    }, 120000);

    it('reproduces a real exploit against the vulnerable EVM fixture when installed', async () => {
      const engine = new FoundryEngine();
      const avail = await engine.check_availability();
      if (avail.status !== EngineAvailabilityStatus.AVAILABLE) return;

      const result = await engine.execute('tgt-foundry', 'forge_test', {
        investigation_id: 'inv-test-foundry-live',
        project_directory: FOUNDRY_FIXTURE_DIR,
        timeout_ms: 600000,
      });

      expect(result.status).toBe(EngineResultStatus.SUCCESS);
      // A passing exploit-named test is the positive reproduction signal.
      const reproduced = result.findings.filter(f => f.metadata?.reproduction === 'exploit test passed');
      expect(reproduced.length).toBeGreaterThan(0);
      expect(result.artifacts.length).toBeGreaterThan(0);
    }, 660000);
  });
});