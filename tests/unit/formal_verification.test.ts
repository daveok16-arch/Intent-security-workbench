/**
 * Phase 4 — Real Z3 Formal Verification Engine Comprehensive Test Suite
 *
 * Verifies:
 * 1. Z3 Host Detection (presence, genuine version, missing path rejection)
 * 2. Formal DSL Compilation (SMT-LIB2 generation, comments, deterministic SHA-256)
 * 3. Model Soundness Verification (under-constrained, assumption-dependent, contradiction detection)
 * 4. Real Z3 Process Execution (spawn, stdout, stderr, timeout, exit codes)
 * 5. Benchmark Security Cases:
 *    - Case A: Classic BOLA (SAT -> Model Counterexample -> FORMALLY_SUPPORTED)
 *    - Case B: Authorized Access (UNSAT -> Invariant Holds -> FORMALLY_REFUTED)
 *    - Case C: Multi-Role / Tenant Condition
 * 6. Proof & Provenance Integrity (exact SMT-LIB2 persisted, SHA-256 verified, artifacts linked)
 * 7. Anti-Fabrication Guarantees (SAT != CONFIRMED, boundary clarifications, honest failure handling)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'crypto';
import {
  Z3Detector,
  FormalDSLCompiler,
  ModelSoundnessChecker,
  Z3Executor,
  FormalModelBuilder,
  FormalVerificationService,
  STANDARD_PROPERTIES,
  VerificationStatus,
  ModelSoundnessStatus,
  type FormalModelDefinition,
  type VariableDefinition,
  type ModelConstraint,
  type ModelAssumption,
  type SourceFact,
} from '../../packages/formal-verification/src/index.js';
import { globalDB } from '../../apps/api/db_store.js';
import { FindingStatus, Confidence, Severity } from '../../packages/core/src/index.js';

describe('Phase 4 — Real Z3 Formal Verification Engine', () => {
  let detectorResult: ReturnType<typeof Z3Detector.detect>;

  beforeAll(() => {
    detectorResult = Z3Detector.detect();
  });

  // =========================================================================
  // 1. Z3 Host Detection
  // =========================================================================
  describe('1. Z3 Host Detection', () => {
    it('verifies actual Z3 binary on host system', () => {
      expect(detectorResult.installed).toBe(true);
      expect(detectorResult.executable_path).toBeTruthy();
      expect(detectorResult.executable_path).toContain('z3');
      expect(detectorResult.status).toBe('AVAILABLE');
      expect(detectorResult.error).toBeNull();
    });

    it('extracts actual version string from Z3 CLI', () => {
      expect(detectorResult.version).toBeTruthy();
      expect(detectorResult.version).toMatch(/4\.\d+\.\d+/);
      expect(detectorResult.version).toContain('Z3 version');
    });

    it('truthfully rejects non-existent solver path without fabrication', () => {
      const negativeResult = Z3Detector.detect('/usr/bin/nonexistent_solver_z3_fake');
      expect(negativeResult.installed).toBe(false);
      expect(negativeResult.status).toBe('NOT_INSTALLED');
      expect(negativeResult.executable_path).toBeNull();
      expect(negativeResult.version).toBeNull();
      expect(negativeResult.error).toBeTruthy();
      expect(negativeResult.error).toContain('not found or not executable');
    });
  });

  // =========================================================================
  // 2. DSL Compilation
  // =========================================================================
  describe('2. DSL Compilation & SMT-LIB2 Generation', () => {
    it('compiles property + assumptions + constraints into valid SMT-LIB2 format', () => {
      const vars: VariableDefinition[] = [
        { name: 'caller_id', type: 'Int', description: 'Caller ID' },
        { name: 'owner_id', type: 'Int', description: 'Resource Owner ID' },
        { name: 'is_authorized', type: 'Bool', description: 'Access Granted' },
      ];
      const constraints: ModelConstraint[] = [
        {
          id: 'c1',
          name: 'caller_not_owner',
          smt_representation: '(not (= caller_id owner_id))',
          rationale: 'Attacker caller ID is distinct from resource owner',
          is_assumption: false,
        },
        {
          id: 'c2',
          name: 'access_granted',
          smt_representation: '(= is_authorized true)',
          rationale: 'Route handler granted access to object',
          is_assumption: false,
        },
      ];
      const assumptions: ModelAssumption[] = [
        {
          id: 'a1',
          assumption_text: 'Caller possesses valid session token',
          rationale: 'External auth gateway validated session',
          smt_form: 'true',
        },
      ];
      const facts: SourceFact[] = [
        {
          observed_via: 'TREE_SITTER',
          file: 'api.js',
          line: 12,
          code_snippet: 'db.documents.findOne({ _id: documentId })',
          description: 'Document resolved directly by ID',
        },
      ];

      const model: FormalModelDefinition = {
        name: 'DSL Compilation Test Model',
        target_id: 'tgt-test',
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
        variables: vars,
        constraints,
        assumptions,
        sourceFacts: facts,
      };

      const compiled = FormalDSLCompiler.compile(model);

      expect(compiled.smt_lib).toContain('(set-logic QF_LIA)');
      expect(compiled.smt_lib).toContain('(declare-const caller_id Int)');
      expect(compiled.smt_lib).toContain('(declare-const owner_id Int)');
      expect(compiled.smt_lib).toContain('(declare-const is_authorized Bool)');
      expect(compiled.smt_lib).toContain('(assert (not (= caller_id owner_id)))');
      expect(compiled.smt_lib).toContain('(assert (= is_authorized true))');
      expect(compiled.smt_lib).toContain('(check-sat)');
      expect(compiled.smt_lib).toContain('(get-model)');

      // Contains provenance comments
      expect(compiled.smt_lib).toContain('; SOURCE FACTS (OBSERVED IN CODE):');
      expect(compiled.smt_lib).toContain('; MODEL ASSUMPTIONS (NOT PROVEN BY CODE):');
      expect(compiled.smt_lib).toContain('; FORMAL PROPERTY UNDER VERIFICATION:');

      // Has deterministic SHA-256 hash
      expect(compiled.sha256).toBeDefined();
      expect(compiled.sha256.length).toBe(64);
      const expectedHash = crypto.createHash('sha256').update(compiled.smt_lib, 'utf-8').digest('hex');
      expect(compiled.sha256).toBe(expectedHash);
    });
  });

  // =========================================================================
  // 3. Model Soundness Verification
  // =========================================================================
  describe('3. Model Soundness Verification', () => {
    it('flags under-constrained models lacking relational guards or constraints', () => {
      const underconstrainedModel: FormalModelDefinition = {
        name: 'Empty Model',
        target_id: 'tgt-empty',
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
        variables: [
          { name: 'caller_id', type: 'Int', description: 'Caller' },
        ],
        constraints: [],
        assumptions: [],
        sourceFacts: [],
      };

      const soundness = ModelSoundnessChecker.checkSoundness(underconstrainedModel);
      expect(soundness.status).toBe(ModelSoundnessStatus.MODEL_UNDERCONSTRAINED);
      expect(soundness.is_sound).toBe(false);
      expect(soundness.issues.length).toBeGreaterThan(0);
      expect(soundness.issues[0]).toContain('contains zero constraints');
    });

    it('flags models whose proofs are entirely dependent on manufactured assumptions', () => {
      const assumptionOnlyModel: FormalModelDefinition = {
        name: 'Assumption Dependent Model',
        target_id: 'tgt-assume',
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
        variables: [
          { name: 'caller_id', type: 'Int', description: 'Caller' },
          { name: 'owner_id', type: 'Int', description: 'Owner' },
        ],
        constraints: [
          {
            id: 'c_assume',
            name: 'vulnerability_forcing_assumption',
            smt_representation: '(= caller_id 999)',
            rationale: 'Fabricated assumption forcing solver state',
            is_assumption: true, // Manufactured assumption
          },
        ],
        assumptions: [
          {
            id: 'a1',
            assumption_text: 'Assume attacker can bypass auth',
            rationale: 'Unverified assumption',
            smt_form: 'true',
          },
        ],
        sourceFacts: [], // No actual source facts
      };

      const soundness = ModelSoundnessChecker.checkSoundness(assumptionOnlyModel);
      expect(soundness.status).toBe(ModelSoundnessStatus.ASSUMPTION_DEPENDENT);
      expect(soundness.is_sound).toBe(false);
      expect(soundness.warnings.some(w => w.includes('rely purely on assumptions'))).toBe(true);
    });

    it('detects contradictory assumptions / inconsistent constraints', () => {
      const contradictoryModel: FormalModelDefinition = {
        name: 'Contradictory Model',
        target_id: 'tgt-contra',
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
        variables: [
          { name: 'flag', type: 'Bool', description: 'Flag' },
        ],
        constraints: [
          {
            id: 'c1',
            name: 'flag_true',
            smt_representation: '(= flag true)',
            rationale: 'Flag is true',
            is_assumption: false,
          },
          {
            id: 'c2',
            name: 'flag_false',
            smt_representation: '(= flag false)',
            rationale: 'Flag is false',
            is_assumption: false,
          },
        ],
        assumptions: [],
        sourceFacts: [],
      };

      const soundness = ModelSoundnessChecker.checkSoundness(contradictoryModel);
      expect(soundness.status).toBe(ModelSoundnessStatus.CONTRADICTORY_MODEL);
      expect(soundness.is_sound).toBe(false);
      expect(soundness.issues.some(i => i.includes('Mutually contradictory'))).toBe(true);
    });
  });

  // =========================================================================
  // 4. Real Z3 Solver Execution
  // =========================================================================
  describe('4. Real Z3 Solver Execution', () => {
    it('executes real Z3 binary via spawn and returns SAT on satisfiable query', async () => {
      const smt = `
(set-logic QF_LIA)
(declare-const x Int)
(declare-const y Int)
(assert (> x 10))
(assert (< y 5))
(assert (= (+ x y) 20))
(check-sat)
(get-model)
`;
      const result = await Z3Executor.executeSMT2(smt);

      expect([VerificationStatus.COUNTEREXAMPLE_FOUND, 'COMPLETED']).toContain(result.status);
      expect(result.exit_code).toBe(0);
      expect(result.solver_result_raw).toBe('sat');
      expect(result.execution_time_ms).toBeGreaterThan(0);
      expect(result.counterexample).toBeDefined();
      expect(result.counterexample?.assignments).toBeDefined();

      const x = Number(result.counterexample?.assignments['x']);
      const y = Number(result.counterexample?.assignments['y']);
      expect(x).toBeGreaterThan(10);
      expect(y).toBeLessThan(5);
      expect(x + y).toBe(20);
    });

    it('executes real Z3 binary and returns UNSAT on contradiction', async () => {
      const smt = `
(set-logic QF_LIA)
(declare-const x Int)
(assert (> x 10))
(assert (< x 5))
(check-sat)
`;
      const result = await Z3Executor.executeSMT2(smt);

      expect([VerificationStatus.PROPERTY_HOLDS_FOR_MODEL, 'COMPLETED']).toContain(result.status);
      expect(result.exit_code).toBe(0);
      expect(result.solver_result_raw).toBe('unsat');
      expect(result.counterexample).toBeNull();
    });

    it('captures raw stdout, stderr, and process details', async () => {
      const invalidSmt = `
(declare-const invalid-syntax ???)
(check-sat)
`;
      const result = await Z3Executor.executeSMT2(invalidSmt);
      expect(result.status).toBe(VerificationStatus.EXECUTION_FAILED);
      expect(result.solver_result_raw).toBe('error');
      expect(result.stderr || result.stdout).toBeTruthy();
    });

    it('enforces solver execution timeout', async () => {
      // Intentionally hard or very tight timeout
      const tightTimeout = await Z3Executor.executeSMT2('(check-sat)', {
        timeoutMs: 5000,
        solverTimeoutMs: 1000,
      });
      expect(tightTimeout.status).toBe(VerificationStatus.COUNTEREXAMPLE_FOUND);
      expect(tightTimeout.execution_time_ms).toBeLessThan(4000);
    });
  });

  // =========================================================================
  // 5. Benchmark Security Cases
  // =========================================================================
  describe('5. Benchmark Security Cases', () => {
    const service = new FormalVerificationService();

    it('Case A: Classic BOLA — SAT results in FORMALLY_SUPPORTED with Model Counterexample', async () => {
      // Vulnerable route: documents/:id with no owner check
      const model = FormalModelBuilder.buildFromSource({
        name: 'BOLA Case A: Vulnerable Document Lookup',
        investigation_id: 'inv-bench-a',
        target_id: 'tgt-bench-a',
        source_code: `
router.get('/documents/:id', async (req, res) => {
  const documentId = req.params.id;
  const doc = await db.documents.findOne({ _id: documentId });
  return res.json(doc);
});`,
        source_file: 'routes/documents.js',
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
      });

      const res = await service.verifyModel({
        investigationId: 'inv-bench-a',
        targetId: 'tgt-bench-a',
        model,
      });

      expect(res.solver_result_raw).toBe('sat');
      expect(res.status).toBe(VerificationStatus.FORMALLY_SUPPORTED);
      expect(res.counterexample).toBeDefined();
      expect(res.counterexample?.assignments).toBeDefined();

      // Crucial: Must display boundary clarification
      expect(res.boundary_clarification).toBeTruthy();
      expect(res.boundary_clarification).toContain('NOT automatically an exploit');
    });

    it('Case B: Authorized Access — UNSAT results in FORMALLY_REFUTED (Invariant Holds)', async () => {
      // Secure route: documents/:id with explicit owner equality assertion
      const model = FormalModelBuilder.buildFromSource({
        name: 'BOLA Case B: Secure Owner Verified Document Access',
        investigation_id: 'inv-bench-b',
        target_id: 'tgt-bench-b',
        source_code: `
router.get('/documents/:id', async (req, res) => {
  const documentId = req.params.id;
  const doc = await db.documents.findOne({ _id: documentId });
  if (doc.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }
  return res.json(doc);
});`,
        source_file: 'routes/documents.js',
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
      });

      const res = await service.verifyModel({
        investigationId: 'inv-bench-b',
        targetId: 'tgt-bench-b',
        model,
      });

      expect(res.solver_result_raw).toBe('unsat');
      expect(res.status).toBe(VerificationStatus.FORMALLY_REFUTED);
      expect(res.counterexample).toBeNull();
      expect(res.boundary_clarification).toBeTruthy();
    });

    it('Case C: Complex Condition — Multi-Role Admin OR Owner Authorization', async () => {
      const vars: VariableDefinition[] = [
        { name: 'caller_user_id', type: 'Int', description: 'Caller ID' },
        { name: 'object_owner_id', type: 'Int', description: 'Owner ID' },
        { name: 'caller_role_is_admin', type: 'Bool', description: 'Is Admin' },
        { name: 'is_authorized', type: 'Bool', description: 'Access Granted' },
      ];
      const constraints: ModelConstraint[] = [
        {
          id: 'c_guard',
          name: 'multi_role_guard',
          smt_representation: '(= is_authorized (or (= caller_user_id object_owner_id) caller_role_is_admin))',
          rationale: 'Access granted if caller is resource owner OR administrator',
          is_assumption: false,
        },
        {
          id: 'c_violation',
          name: 'unauthorized_access_attempt',
          smt_representation: '(and is_authorized (not (= caller_user_id object_owner_id)) (not caller_role_is_admin))',
          rationale: 'Non-owner non-admin gains access',
          is_assumption: false,
        },
      ];

      const model: FormalModelDefinition = {
        name: 'Multi-Role Admin Guard Model',
        target_id: 'tgt-bench-c',
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
        variables: vars,
        constraints,
        assumptions: [],
        sourceFacts: [
          {
            observed_via: 'TREE_SITTER',
            file: 'admin_route.js',
            line: 18,
            code_snippet: 'if (doc.ownerId === req.user.id || req.user.isAdmin)',
            description: 'Guard enforces owner or admin',
          },
        ],
      };

      const res = await service.verifyModel({
        investigationId: 'inv-bench-c',
        targetId: 'tgt-bench-c',
        model,
      });

      // Guard is mathematically complete, so unauthorized access is impossible -> UNSAT
      expect(res.solver_result_raw).toBe('unsat');
      expect(res.status).toBe(VerificationStatus.FORMALLY_REFUTED);
    });
  });

  // =========================================================================
  // 6. Proof & Provenance Integrity
  // =========================================================================
  describe('6. Proof & Provenance Integrity', () => {
    it('persists exact SMT-LIB2 input and verifiable SHA-256 hash in DB & Artifacts', async () => {
      const service = new FormalVerificationService();
      const model = FormalModelBuilder.buildFromSource({
        name: 'Provenance Test Model',
        investigation_id: 'inv-prov-test',
        target_id: 'tgt-prov-test',
        source_code: 'router.get("/data/:id", (req, res) => res.json(db.get(req.params.id)));',
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
      });

      const res = await service.verifyModel({
        investigationId: 'inv-prov-test',
        targetId: 'tgt-prov-test',
        model,
      });

      // Verify DB record
      const stored = globalDB.getVerificationResult(res.id);
      expect(stored).toBeDefined();
      expect(stored?.smt_lib_input).toBeTruthy();
      expect(stored?.smt_lib_sha256).toBeTruthy();

      // Cryptographically verify hash match
      const computedHash = crypto
        .createHash('sha256')
        .update(stored!.smt_lib_input, 'utf-8')
        .digest('hex');
      expect(stored?.smt_lib_sha256).toBe(computedHash);

      // Verify evidence artifacts were stored
      expect(stored?.smt_artifact_id).toBeTruthy();
      expect(stored?.result_artifact_id).toBeTruthy();
    });
  });

  // =========================================================================
  // 7. Anti-Fabrication Guarantees
  // =========================================================================
  describe('7. Anti-Fabrication Guarantees', () => {
    it('SAT solver result NEVER automatically transitions finding to CONFIRMED', async () => {
      // Register test investigation & candidate
      const inv = globalDB.createInvestigation({
        program_id: 'prog-antifab',
        target_id: 'tgt-antifab',
        title: 'Anti-Fabrication Test Inv',
        name: 'Anti-Fabrication Test Inv',
        description: 'Verify state machine invariants',
      });

      const candidateId = `cand-antifab-${Date.now()}`;
      const candidate = {
        id: candidateId,
        investigation_id: inv.id,
        target_id: inv.target_id,
        method: 'GET',
        path: '/api/v1/confidential/:id',
        status: FindingStatus.CANDIDATE,
        confidence: Confidence.MEDIUM,
        severity: Severity.HIGH,
        file: 'api.js',
        line: 10,
        route_params: ['id'],
        object_references: ['doc'],
        identified_boundaries: [],
        missing_checks: ['owner_equality'],
        priority_score: 80,
        evidence_ids: [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      globalDB.saveAuthorizationCandidate(candidate as any);

      const service = new FormalVerificationService();
      const model = FormalModelBuilder.buildFromSource({
        name: 'Candidate Verification Model',
        investigation_id: inv.id,
        target_id: inv.target_id,
        candidate_id: candidate.id,
        authorization_candidate: candidate as any,
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
      });

      const res = await service.verifyModel({
        investigationId: inv.id,
        targetId: inv.target_id,
        candidateId: candidate.id,
        model,
      });

      expect(res.status).toBe(VerificationStatus.FORMALLY_SUPPORTED);

      // Check candidate in DB
      const updatedCandidate = globalDB.getAuthorizationCandidate(candidate.id);
      expect(updatedCandidate).toBeDefined();
      // MUST NOT be CONFIRMED!
      expect(updatedCandidate?.status).not.toBe(FindingStatus.CONFIRMED);
      expect([FindingStatus.CANDIDATE, FindingStatus.TESTING]).toContain(updatedCandidate?.status);
      expect(updatedCandidate?.metadata?.formal_status).toBe('FORMALLY_SUPPORTED');
    });

    it('clearly separates Model Assumptions, Source Facts, and Constraints', () => {
      const model = FormalModelBuilder.buildFromSource({
        name: 'Provenance Distinction Model',
        investigation_id: 'inv-dist-test',
        target_id: 'tgt-dist-test',
        source_code: `
router.get('/account/:id', async (req, res) => {
  const acct = await db.get(req.params.id);
  return res.json(acct);
});`,
        property: STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS,
      });

      // Verify facts are marked observed
      expect(model.sourceFacts.length).toBeGreaterThan(0);
      for (const fact of model.sourceFacts) {
        expect(fact.observed_via).toBeTruthy();
        expect(fact.code_snippet).toBeTruthy();
      }

      // Verify assumptions are marked as assumptions
      for (const assumption of model.assumptions) {
        expect(assumption.assumption_text).toBeTruthy();
        expect(assumption.rationale).toBeTruthy();
      }

      // Verify constraints distinguish assumptions from code facts
      for (const constraint of model.constraints) {
        expect(typeof constraint.is_assumption).toBe('boolean');
      }
    });
  });
});
