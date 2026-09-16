import { describe, it, expect } from 'vitest';
import { FindingStatus, validateFindingTransition, VALID_FINDING_TRANSITIONS } from '../../packages/core/src/index.js';

describe('Finding State Machine Strict Transition Tests (Phase 0 Requirement 15 & 16)', () => {
  it('should permit legal initial transitions from CANDIDATE', () => {
    expect(validateFindingTransition(FindingStatus.CANDIDATE, FindingStatus.ANALYZING).allowed).toBe(true);
    expect(validateFindingTransition(FindingStatus.CANDIDATE, FindingStatus.REJECTED).allowed).toBe(true);
    expect(validateFindingTransition(FindingStatus.CANDIDATE, FindingStatus.OUT_OF_SCOPE).allowed).toBe(true);
  });

  it('should reject illegal direct leap from CANDIDATE to CONFIRMED without verification pipeline', () => {
    const check = validateFindingTransition(FindingStatus.CANDIDATE, FindingStatus.CONFIRMED, false);
    expect(check.allowed).toBe(false);
    expect(check.reason).toContain('Illegal state transition');
  });

  it('should reject transition to VALIDATED or CONFIRMED if evidence artifacts are missing', () => {
    // Attempting VALIDATED from REPRODUCED without evidence artifacts
    const withoutEvidence = validateFindingTransition(FindingStatus.REPRODUCED, FindingStatus.VALIDATED, false);
    expect(withoutEvidence.allowed).toBe(false);
    expect(withoutEvidence.reason).toContain('without linked machine-verifiable evidence artifacts');

    // With evidence artifacts, it must be allowed
    const withEvidence = validateFindingTransition(FindingStatus.REPRODUCED, FindingStatus.VALIDATED, true);
    expect(withEvidence.allowed).toBe(true);
  });

  it('should obey the entire progression pipeline', () => {
    expect(validateFindingTransition(FindingStatus.ANALYZING, FindingStatus.VERIFICATION_REQUIRED).allowed).toBe(true);
    expect(validateFindingTransition(FindingStatus.VERIFICATION_REQUIRED, FindingStatus.TESTING).allowed).toBe(true);
    expect(validateFindingTransition(FindingStatus.TESTING, FindingStatus.REPRODUCED).allowed).toBe(true);
    expect(validateFindingTransition(FindingStatus.REPRODUCED, FindingStatus.VALIDATED, true).allowed).toBe(true);
    expect(validateFindingTransition(FindingStatus.VALIDATED, FindingStatus.CONFIRMED, true).allowed).toBe(true);
  });

  it('should enforce that CONFIRMED is a terminal verified state', () => {
    expect(VALID_FINDING_TRANSITIONS[FindingStatus.CONFIRMED]).toEqual([]);
    const attempt = validateFindingTransition(FindingStatus.CONFIRMED, FindingStatus.CANDIDATE);
    expect(attempt.allowed).toBe(false);
  });
});
