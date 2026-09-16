/**
 * Static Analysis Engine & BOLA Detection Verification Tests
 * Intent Security Workbench - Phase 2
 *
 * Verifies:
 * 1. Tree-sitter AST parsing, structural analysis, and AST artifact persistence.
 * 2. Semgrep real binary invocation, sandboxing, and output parsing.
 * 3. Controlled BOLA detection:
 *    - Vulnerable fixture generates CANDIDATE finding
 *    - Secure fixture produces zero findings
 * 4. Finding state machine integrity: State strictly CANDIDATE.
 * 5. Evidence artifacts stored with computed SHA-256 checksums.
 * 6. Multi-engine finding correlation and confidence elevation.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import path from 'path';
import fs from 'fs';
import {
  globalTreeSitterService,
  globalSemgrepService,
  globalStaticCorrelationService,
  globalCandidateStore,
  globalSecurityRuleRegistry,
  executeStaticAnalysisPipeline,
} from '../../packages/static-analysis/src/index.js';
import { TreeSitterEngine } from '../../engines/placeholders/treesitter.js';
import { SemgrepEngine } from '../../engines/placeholders/semgrep.js';
import { StaticAnalysisEngine } from '../../engines/placeholders/static_analysis.js';
import {
  FindingStatus,
  Confidence,
  Severity,
} from '../../packages/core/src/index.js';
import {
  globalArtifactStorage,
  verifyArtifactIntegrity,
} from '../../packages/evidence/src/index.js';

describe('Phase 2 — Real Static & Structural Security Analysis', () => {
  const rootDir = process.cwd();
  const vulnFixtureDir = path.join(rootDir, 'fixtures', 'static_analysis', 'bola_vulnerable');
  const secureFixtureDir = path.join(rootDir, 'fixtures', 'static_analysis', 'bola_secure');

  beforeAll(async () => {
    await globalTreeSitterService.init();
  });

  describe('Tree-sitter Structural Analysis Engine', () => {
    it('initializes real tree-sitter parser with precompiled WASM grammars', async () => {
      const initialized = await globalTreeSitterService.init();
      expect(initialized).toBe(true);

      const engine = new TreeSitterEngine();
      const avail = await engine.check_availability();
      expect(avail.status).toBe('AVAILABLE');
      expect(avail.name).toBe('Tree-sitter');
      expect(avail.capabilities).toContain('CST');
    });

    it('parses source file, constructs concrete syntax tree, and persists AST artifact with SHA-256', async () => {
      const vulnFile = path.join(vulnFixtureDir, 'api.js');
      const parseResult = await globalTreeSitterService.parseFile(vulnFile);

      expect(parseResult).toBeDefined();
      expect(parseResult?.language).toBe('javascript');
      expect(parseResult?.node_count).toBeGreaterThan(10);
      expect(parseResult?.root_node.type).toBe('program');
      expect(parseResult?.sha256).toBeDefined();
      expect(parseResult?.sha256.length).toBe(64);

      // Verify AST artifact storage
      const stored = await globalTreeSitterService.storeAstArtifact(
        parseResult!,
        'inv-ts-test',
        'tgt-ts-test',
        'snap-ts-test'
      );
      expect(stored.artifactId).toBeDefined();
      expect(stored.sha256).toBe(parseResult?.sha256);

      // Cryptographic verification
      const verify = await verifyArtifactIntegrity(stored.artifactId);
      expect(verify.verified).toBe(true);
      expect(verify.computed_sha256).toBe(stored.sha256);
    });

    it('identifies structural BOLA candidate in vulnerable fixture via AST queries', async () => {
      const vulnFile = path.join(vulnFixtureDir, 'api.js');
      const candidates = await globalTreeSitterService.analyzeFileForVulnerabilities(
        vulnFile,
        'snap-ts-vuln',
        'inv-ts-vuln',
        'tgt-ts-vuln'
      );

      expect(candidates.length).toBeGreaterThan(0);
      const bolaCandidate = candidates.find(c => c.category === 'BOLA' || c.rule_id === 'INTENT-BOLA-001');
      expect(bolaCandidate).toBeDefined();
      expect(bolaCandidate?.status).toBe(FindingStatus.CANDIDATE);
      expect(bolaCandidate?.severity).toBe(Severity.HIGH);
      expect(bolaCandidate?.engine).toBe('treesitter');
      expect(bolaCandidate?.matched_code).toContain('req.params.id');
    });

    it('does NOT generate BOLA candidate in secure fixture where authorization check exists', async () => {
      const secureFile = path.join(secureFixtureDir, 'api.js');
      const candidates = await globalTreeSitterService.analyzeFileForVulnerabilities(
        secureFile,
        'snap-ts-sec',
        'inv-ts-sec',
        'tgt-ts-sec'
      );

      const bolaCandidates = candidates.filter(c => c.category === 'BOLA' || c.rule_id === 'INTENT-BOLA-001');
      expect(bolaCandidates.length).toBe(0);
    });
  });

  describe('Semgrep Static Analysis Engine', () => {
    it('verifies real semgrep binary presence and checks actual version', async () => {
      const engine = new SemgrepEngine('semgrep');
      const avail = await engine.check_availability();

      expect(avail.status).toBe('AVAILABLE');
      expect(avail.detected_path).toBeTruthy();
      expect(avail.version).toBeTruthy();
      expect(avail.version).toMatch(/1\.\d+\.\d+/);
    });

    it('truthfully reports NOT_INSTALLED when binary is missing (no fake success)', async () => {
      const engine = new SemgrepEngine('semgrep-nonexistent-executable');
      const avail = await engine.check_availability();

      expect(avail.status).toBe('NOT_INSTALLED');
      expect(avail.detected_path).toBeNull();
      expect(avail.error).toContain('not installed');
    });

    it('executes real semgrep scan on vulnerable fixture and captures real process output', async () => {
      const engine = new SemgrepEngine();
      const result = await engine.execute('tgt-sg-vuln', 'scan', {
        investigation_id: 'inv-sg-vuln',
        source_snapshot_id: 'snap-sg-vuln',
        source_directory: vulnFixtureDir,
      });

      expect(result.status).toBe('SUCCESS');
      expect(result.engine_id).toBe('semgrep');
      expect(result.exit_code).toBe(0);
      expect(result.stdout).toBeTruthy();
      expect(result.duration_ms).toBeGreaterThan(0);

      // Verify real Semgrep JSON was parsed into findings
      expect(result.findings.length).toBeGreaterThan(0);
      const bolaFinding = result.findings.find(f => f.category === 'BOLA' || f.id.includes('INTENT-BOLA'));
      expect(bolaFinding).toBeDefined();
      expect(bolaFinding?.file).toContain('api.js');
    });

    it('executes real semgrep scan on secure fixture without generating false BOLA positive', async () => {
      const engine = new SemgrepEngine();
      const result = await engine.execute('tgt-sg-sec', 'scan', {
        investigation_id: 'inv-sg-sec',
        source_snapshot_id: 'snap-sg-sec',
        source_directory: secureFixtureDir,
      });

      expect(result.status).toBe('SUCCESS');
      const bolaFinding = result.findings.find(f => f.title === 'INTENT-BOLA-001' || f.category === 'BOLA');
      expect(bolaFinding).toBeUndefined();
    });
  });

  describe('Multi-Engine Correlation & Pipeline Coordinator', () => {
    it('executes full pipeline, correlates findings, and elevates confidence when corroborated', async () => {
      const execution = await executeStaticAnalysisPipeline(
        'inv-pipeline-test',
        'tgt-pipeline-test',
        'snap-pipeline-test',
        vulnFixtureDir
      );

      expect(execution.treesitter.status).toBe('COMPLETED');
      expect(execution.semgrep.status).toBe('COMPLETED');
      expect(execution.candidates.length).toBeGreaterThan(0);

      // Check finding status is strictly CANDIDATE
      for (const candidate of execution.candidates) {
        expect(candidate.status).toBe(FindingStatus.CANDIDATE);
      }

      // Check corroborated BOLA candidate
      const corroborated = execution.candidates.find(c => c.corroborated);
      expect(corroborated).toBeDefined();
      expect(corroborated?.confidence).toBe(Confidence.HIGH);
      expect(corroborated?.engine).toBe('correlated[treesitter+semgrep]');
    });

    it('ensures CandidateStore strictly enforces initial state and transition rules', () => {
      const candidate = globalCandidateStore.createCandidate({
        investigation_id: 'inv-store-test',
        target_id: 'tgt-store-test',
        source_snapshot_id: 'snap-store-test',
        rule_id: 'INTENT-BOLA-001',
        title: 'Broken Object Level Authorization',
        category: 'BOLA',
        severity: Severity.HIGH,
        confidence: Confidence.MEDIUM,
        confidence_basis: 'Direct object reference without auth check',
        file_path: 'api.js',
        line_start: 10,
        line_end: 20,
        matched_code: 'req.params.id',
        engine: 'treesitter',
        evidence_artifact_ids: ['art-test-1'],
      });

      // Initial state must always be CANDIDATE
      expect(candidate.status).toBe(FindingStatus.CANDIDATE);

      // State machine validation: Invalid direct transition to CONFIRMED or VALIDATED without reproduction
      expect(() => {
        globalCandidateStore.transitionStatus(
          candidate.id,
          FindingStatus.CONFIRMED,
          'Unauthorized manual jump',
          'tester'
        );
      }).toThrow(/Invalid state transition/);

      // Valid transition to REJECTED with justification
      const rejected = globalCandidateStore.transitionStatus(
        candidate.id,
        FindingStatus.REJECTED,
        'False positive identified during manual audit',
        'auditor-alice'
      );
      expect(rejected.status).toBe(FindingStatus.REJECTED);
      expect(rejected.status_history.length).toBe(2);
    });

    it('SecurityRuleRegistry provides versioned, data-driven rules covering diverse categories', () => {
      const rules = globalSecurityRuleRegistry.list();
      expect(rules.length).toBeGreaterThanOrEqual(14);

      const categories = new Set(rules.map(r => r.category));
      expect(categories.has('BOLA')).toBe(true);
      expect(categories.has('ACCESS_CONTROL')).toBe(true);
      expect(categories.has('INJECTION')).toBe(true);
      expect(categories.has('SMART_CONTRACT')).toBe(true);

      const bolaRule = globalSecurityRuleRegistry.get('INTENT-BOLA-001');
      expect(bolaRule).toBeDefined();
      expect(bolaRule?.cwe_ids).toContain('CWE-639');
      expect(bolaRule?.owasp_categories).toContain('API1:2023');
    });
  });
});
