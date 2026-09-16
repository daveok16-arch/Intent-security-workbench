/**
 * Research State Machine & Phase Transition Enforcer
 * Phase 6 — AI Security Control Plane Core
 * 
 * Invariants:
 * - Every transition requires explicit prerequisites.
 * - AI cannot skip validation or jump directly to unverified phases.
 * - Transitions to BLOCKED require an explicit blocker code and message.
 */

import { ResearchPhase, ControllerState } from './types.js';

export const PERMITTED_PHASE_TRANSITIONS: Record<ResearchPhase, ResearchPhase[]> = {
  [ResearchPhase.IDLE]: [
    ResearchPhase.UNDERSTANDING_REQUEST,
    ResearchPhase.PLANNING,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.UNDERSTANDING_REQUEST]: [
    ResearchPhase.PLANNING,
    ResearchPhase.POLICY_VALIDATION,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.PLANNING]: [
    ResearchPhase.POLICY_VALIDATION,
    ResearchPhase.SCOPE_VALIDATION,
    ResearchPhase.TARGET_VALIDATION,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.POLICY_VALIDATION]: [
    ResearchPhase.SCOPE_VALIDATION,
    ResearchPhase.TARGET_VALIDATION,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.SCOPE_VALIDATION]: [
    ResearchPhase.TARGET_VALIDATION,
    ResearchPhase.SOURCE_ACQUISITION,
    ResearchPhase.CAPABILITY_ASSESSMENT,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.TARGET_VALIDATION]: [
    ResearchPhase.SOURCE_ACQUISITION,
    ResearchPhase.CAPABILITY_ASSESSMENT,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.SOURCE_ACQUISITION]: [
    ResearchPhase.SOURCE_VERIFICATION,
    ResearchPhase.CAPABILITY_ASSESSMENT,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.SOURCE_VERIFICATION]: [
    ResearchPhase.CAPABILITY_ASSESSMENT,
    ResearchPhase.ANALYSIS_PLANNING,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.CAPABILITY_ASSESSMENT]: [
    ResearchPhase.ANALYSIS_PLANNING,
    ResearchPhase.ANALYSIS_EXECUTION,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.ANALYSIS_PLANNING]: [
    ResearchPhase.ANALYSIS_EXECUTION,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.ANALYSIS_EXECUTION]: [
    ResearchPhase.RESULT_CORRELATION,
    ResearchPhase.HYPOTHESIS_FORMATION,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.RESULT_CORRELATION]: [
    ResearchPhase.HYPOTHESIS_FORMATION,
    ResearchPhase.CORROBORATION,
    ResearchPhase.REPORT_PREPARATION,
    ResearchPhase.COMPLETED,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.HYPOTHESIS_FORMATION]: [
    ResearchPhase.CORROBORATION,
    ResearchPhase.VERIFICATION_REQUESTED,
    ResearchPhase.REPORT_PREPARATION,
    ResearchPhase.COMPLETED,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.CORROBORATION]: [
    ResearchPhase.VERIFICATION_REQUESTED,
    ResearchPhase.IMPACT_VERIFICATION,
    ResearchPhase.REPORT_PREPARATION,
    ResearchPhase.COMPLETED,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.VERIFICATION_REQUESTED]: [
    ResearchPhase.IMPACT_VERIFICATION,
    ResearchPhase.ELIGIBILITY_VERIFICATION,
    ResearchPhase.REPORT_PREPARATION,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.IMPACT_VERIFICATION]: [
    ResearchPhase.ELIGIBILITY_VERIFICATION,
    ResearchPhase.REPORT_PREPARATION,
    ResearchPhase.COMPLETED,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.ELIGIBILITY_VERIFICATION]: [
    ResearchPhase.REPORT_PREPARATION,
    ResearchPhase.COMPLETED,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.REPORT_PREPARATION]: [
    ResearchPhase.COMPLETED,
    ResearchPhase.BLOCKED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.BLOCKED]: [
    ResearchPhase.UNDERSTANDING_REQUEST,
    ResearchPhase.PLANNING,
    ResearchPhase.POLICY_VALIDATION,
    ResearchPhase.SCOPE_VALIDATION,
    ResearchPhase.TARGET_VALIDATION,
    ResearchPhase.SOURCE_ACQUISITION,
    ResearchPhase.CAPABILITY_ASSESSMENT,
    ResearchPhase.ANALYSIS_PLANNING,
    ResearchPhase.ANALYSIS_EXECUTION,
    ResearchPhase.VERIFICATION_REQUESTED,
    ResearchPhase.FAILED,
  ],
  [ResearchPhase.COMPLETED]: [
    ResearchPhase.IDLE,
    ResearchPhase.UNDERSTANDING_REQUEST,
    ResearchPhase.PLANNING,
  ],
  [ResearchPhase.FAILED]: [
    ResearchPhase.IDLE,
    ResearchPhase.UNDERSTANDING_REQUEST,
    ResearchPhase.PLANNING,
  ],
};

export interface TransitionValidationResult {
  allowed: boolean;
  reason?: string;
  missing_prerequisite?: string;
}

/**
 * Validates whether the state transition is permissible given current controller state.
 */
export function validateStateTransition(
  currentState: ControllerState,
  targetPhase: ResearchPhase
): TransitionValidationResult {
  const currentPhase = currentState.current_phase;

  // Identity transition is a no-op and permitted
  if (currentPhase === targetPhase) {
    return { allowed: true };
  }

  // Check graph edge
  const allowedNext = PERMITTED_PHASE_TRANSITIONS[currentPhase] || [];
  if (!allowedNext.includes(targetPhase)) {
    return {
      allowed: false,
      reason: `Illegal phase transition from ${currentPhase} to ${targetPhase}. Permitted transitions: [${allowedNext.join(', ')}]`,
    };
  }

  // Check explicit domain prerequisites:
  switch (targetPhase) {
    case ResearchPhase.SCOPE_VALIDATION:
      if (!currentState.program_id && !currentState.facts.some(f => f.category === 'PROGRAM')) {
        return {
          allowed: false,
          missing_prerequisite: 'PROGRAM_UNIDENTIFIED',
          reason: 'Cannot validate scope without an identified or inspected program.',
        };
      }
      break;

    case ResearchPhase.SOURCE_ACQUISITION:
      // Must not be explicitly blocked by out-of-scope
      if (currentState.blockers.some(b => b.code === 'OUT_OF_SCOPE')) {
        return {
          allowed: false,
          missing_prerequisite: 'SCOPE_AUTHORIZED',
          reason: 'Cannot acquire source for an asset evaluated as OUT_OF_SCOPE.',
        };
      }
      break;

    case ResearchPhase.ANALYSIS_EXECUTION:
      // Must have assessed capabilities
      if (currentState.capability_matrix.length === 0 && !currentState.facts.some(f => f.category === 'CAPABILITY')) {
        return {
          allowed: false,
          missing_prerequisite: 'CAPABILITY_MATRIX',
          reason: 'Cannot execute analysis without an assessed capability matrix.',
        };
      }
      break;

    case ResearchPhase.VERIFICATION_REQUESTED:
      // Must have at least one hypothesis or candidate
      if (currentState.hypotheses.length === 0 && !currentState.facts.some(f => f.category === 'EXECUTION')) {
        return {
          allowed: false,
          missing_prerequisite: 'CANDIDATE_OR_HYPOTHESIS',
          reason: 'Cannot request verification without active hypotheses or execution results.',
        };
      }
      break;

    case ResearchPhase.COMPLETED:
      // Must not have unresolved blockers
      if (currentState.blockers.length > 0) {
        return {
          allowed: false,
          missing_prerequisite: 'BLOCKERS_UNRESOLVED',
          reason: `Cannot mark investigation COMPLETED while active blockers exist: ${currentState.blockers.map(b => b.code).join(', ')}`,
        };
      }
      break;
  }

  return { allowed: true };
}
