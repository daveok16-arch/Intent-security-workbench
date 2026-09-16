/**
 * Deterministic Reproduction Decision Engine
 * Intent Security Workbench - Phase 5
 *
 * Rules:
 * - Candidate: POTENTIAL_BOLA
 * - Formal result: COUNTEREXAMPLE_FOUND / FORMALLY_SUPPORTED
 * - Dynamic execution: SUCCESS
 * - Authorization: ATTACKER_NOT_AUTHORIZED
 * - Protected state: CHANGED
 * -> Result: REPRODUCED
 *
 * State machine discipline:
 * - May permit CANDIDATE -> CORROBORATED
 * - NEVER automatically mark CONFIRMED!
 * - Never transform failure into SAFE unless property explicitly establishes that.
 */

import {
  DynamicReproductionResult,
  AuthorizationStateEvidence,
  StateDiffResult,
  RuntimeExecutionResult,
} from './types.js';

export interface DecisionInputs {
  authorization_state: AuthorizationStateEvidence;
  state_diff: StateDiffResult;
  execution_exit_code: number;
  execution_success: boolean;
  tool_installed: boolean;
  formal_verification_status?: string | null;
  error?: string | null;
}

export interface DecisionEvaluationResult {
  result: DynamicReproductionResult;
  reason: string;
  soundness_notes: string[];
  criteria: {
    tool_installed: boolean;
    attacker_is_unauthorized: boolean;
    execution_succeeded: boolean;
    protected_state_mutated: boolean;
    formal_refuted: boolean;
  };
}

export class ReproductionDecisionEngine {
  /**
   * Deterministically decide whether an authorization security candidate was dynamically reproduced.
   */
  static evaluate(inputs: DecisionInputs): DecisionEvaluationResult {
    const soundness_notes: string[] = [];

    const toolInstalled = !!inputs.tool_installed;
    const attackerNotAuthorized = inputs.authorization_state ? !inputs.authorization_state.caller_authorized : false;
    const executionSucceeded = !!inputs.execution_success && inputs.execution_exit_code === 0;
    const protectedChanged = inputs.state_diff ? !!inputs.state_diff.protected_changed : false;
    const formalRefuted = inputs.formal_verification_status === 'FORMALLY_REFUTED' || inputs.formal_verification_status === 'UNSAT';

    const criteria = {
      tool_installed: toolInstalled,
      attacker_is_unauthorized: attackerNotAuthorized,
      execution_succeeded: executionSucceeded,
      protected_state_mutated: protectedChanged,
      formal_refuted: formalRefuted,
    };

    // 1. Tool availability check
    if (!toolInstalled) {
      return {
        result: 'EXECUTION_FAILED',
        reason: 'Required execution tool is not installed on host. Cannot perform dynamic verification.',
        soundness_notes: ['ENGINE_NOT_INSTALLED'],
        criteria,
      };
    }

    // 2. Execution error check
    if (inputs.error && inputs.execution_exit_code !== 0 && !inputs.execution_success) {
      // If the execution failed due to an expected assertion/revert (e.g. unauthorized revert):
      // Check if the revert was because authorization rejected the call!
      const lowerErr = (inputs.error || '').toLowerCase();
      const isAuthRejection =
        lowerErr.includes('unauthorized') ||
        lowerErr.includes('forbidden') ||
        lowerErr.includes('access denied') ||
        lowerErr.includes('caller is not resource owner') ||
        lowerErr.includes('revert:');

      if (isAuthRejection && inputs.authorization_state && !inputs.authorization_state.caller_authorized) {
        return {
          result: 'NOT_REPRODUCED',
          reason: `Execution properly reverted on unauthorized access: ${inputs.error}`,
          soundness_notes: ['UNAUTHORIZED_CALL_REVERTED_AS_EXPECTED'],
          criteria,
        };
      }

      return {
        result: 'EXECUTION_FAILED',
        reason: `Dynamic execution process failed with exit code ${inputs.execution_exit_code}: ${inputs.error}`,
        soundness_notes: ['PROCESS_EXIT_ERROR'],
        criteria,
      };
    }

    if (!inputs.authorization_state || !inputs.state_diff) {
      return {
        result: 'INCONCLUSIVE',
        reason: 'Missing authorization state or state differential evidence.',
        soundness_notes: ['MISSING_STATE_EVIDENCE'],
        criteria,
      };
    }

    // 3. Authorization state analysis
    const stateUnavailable = inputs.state_diff.status === 'STATE_OBSERVATION_UNAVAILABLE';

    if (attackerNotAuthorized) {
      if (inputs.execution_success && protectedChanged) {
        soundness_notes.push('UNAUTHORIZED_CALLER_MODIFIED_PROTECTED_STATE');
        if (inputs.formal_verification_status === 'FORMALLY_SUPPORTED' || inputs.formal_verification_status === 'COUNTEREXAMPLE_FOUND') {
          soundness_notes.push('ALIGNED_WITH_FORMAL_COUNTEREXAMPLE');
        }

        return {
          result: 'REPRODUCED',
          reason: 'Dynamic exploit witnessed: Authenticated caller lacked authorization, the operation succeeded, and protected state changed.',
          soundness_notes,
          criteria,
        };
      }

      if (!inputs.execution_success) {
        return {
          result: 'NOT_REPRODUCED',
          reason: 'Unauthorized operation was rejected by the target contract/service.',
          soundness_notes: ['CALL_REJECTED'],
          criteria,
        };
      }

      if (!protectedChanged && !stateUnavailable) {
        return {
          result: 'NOT_REPRODUCED',
          reason: 'Operation executed, but protected authorization-critical state remained unchanged.',
          soundness_notes: ['NO_PROTECTED_STATE_DIFF'],
          criteria,
        };
      }

      if (stateUnavailable) {
        return {
          result: 'INCONCLUSIVE',
          reason: 'Operation succeeded for unauthorized caller, but direct state observation was unavailable to confirm state compromise.',
          soundness_notes: ['STATE_UNOBSERVED'],
          criteria,
        };
      }
    } else {
      // Caller was authorized! (e.g. legitimate owner or admin)
      if (inputs.execution_success) {
        return {
          result: 'NOT_REPRODUCED',
          reason: 'Operation succeeded under legitimate authorized permissions (benign authorized baseline).',
          soundness_notes: ['AUTHORIZED_BENIGN_BASELINE'],
          criteria,
        };
      } else {
        return {
          result: 'INCONCLUSIVE',
          reason: 'Authorized operation failed to execute.',
          soundness_notes: ['AUTHORIZED_CALL_FAILED'],
          criteria,
        };
      }
    }

    return {
      result: 'INCONCLUSIVE',
      reason: 'Dynamic verification outcome could not be conclusively determined from captured traces.',
      soundness_notes,
      criteria,
    };
  }
}
