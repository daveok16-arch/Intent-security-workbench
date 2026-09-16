/**
 * Reusable BOLA / Broken Object Level Authorization Verifier
 * Intent Security Workbench - Phase 5
 *
 * Requirements:
 * Input:
 * - OBJECT_ID
 * - AUTHENTICATED_CALLER (attacker)
 * - RESOURCE_OWNER (victim)
 * - PRIVILEGED_OPERATION
 *
 * Establishes:
 * - Attacker != Owner
 * - Attacker lacks required ownership/operator permission
 * while:
 * - The requested operation succeeds
 * - A protected resource changes
 *
 * Operates on normalized authorization model (does NOT hard-code variable names like 'owner').
 */

import {
  AuthorizationStateEvidence,
  DynamicReproductionResult,
  StateDiffResult,
  ExecutionTrace,
} from './types.js';
import { StateDiffer } from './state_diff.js';

export interface BOLAVerificationParams {
  object_id: string;
  authenticated_caller: string;
  resource_owner: string;
  caller_role?: string;
  caller_permissions?: string[];
  privileged_operation: string;
  is_operator_permitted?: boolean;
}

export interface BOLAVerificationOutcome {
  authorization_state: AuthorizationStateEvidence;
  state_diff: StateDiffResult;
  result: DynamicReproductionResult;
  reproduced: boolean;
  reproduction_witness?: {
    caller: string;
    resource_owner: string;
    operation: string;
    object_id: string;
    protected_state_changed: boolean;
  };
  summary: string;
}

export class BOLAVerifier {
  /**
   * Normalize and evaluate the authorization boundary for candidate BOLA.
   */
  static evaluateAuthorization(params: BOLAVerificationParams): AuthorizationStateEvidence {
    const caller = params.authenticated_caller.trim();
    const owner = params.resource_owner.trim();
    const caller_is_owner = caller.toLowerCase() === owner.toLowerCase();
    const has_role = Boolean(params.caller_role && ['admin', 'superadmin', 'operator'].includes(params.caller_role.toLowerCase()));
    const is_operator = Boolean(params.is_operator_permitted);

    // Attacker lacks permission if neither owner nor administrative operator
    const caller_authorized = caller_is_owner || is_operator;

    return {
      caller,
      owner,
      role: params.caller_role || 'standard_user',
      permission: params.caller_permissions?.join(',') || 'read_write',
      caller_is_owner,
      caller_has_role: has_role,
      caller_authorized,
      target_operation: params.privileged_operation,
      resource_id: params.object_id,
    };
  }

  /**
   * Verify whether the dynamic execution outcome establishes a real BOLA reproduction.
   */
  static verifyOutcome(
    params: BOLAVerificationParams,
    executionSuccess: boolean,
    stateBefore: Record<string, any> | null,
    stateAfter: Record<string, any> | null,
    trace?: ExecutionTrace | null
  ): BOLAVerificationOutcome {
    const authState = this.evaluateAuthorization(params);
    const stateDiff = StateDiffer.computeDiff(stateBefore, stateAfter);

    let result: DynamicReproductionResult;
    let summary: string;

    if (!authState.caller_authorized) {
      if (executionSuccess && stateDiff.protected_changed) {
        result = 'REPRODUCED';
        summary = `BOLA Confirmed: Caller '${authState.caller}' lacks ownership of object '${params.object_id}' owned by '${authState.owner}', but operation '${params.privileged_operation}' succeeded and modified protected state (${stateDiff.summary}).`;
        return {
          authorization_state: authState,
          state_diff: stateDiff,
          result,
          reproduced: true,
          reproduction_witness: {
            caller: authState.caller,
            resource_owner: authState.owner,
            operation: authState.target_operation,
            object_id: params.object_id,
            protected_state_changed: true,
          },
          summary,
        };
      }

      if (!executionSuccess) {
        result = 'NOT_REPRODUCED';
        summary = `BOLA Not Reproduced: Privileged operation '${params.privileged_operation}' was rejected when invoked by unauthorized caller '${authState.caller}'.`;
      } else {
        result = 'NOT_REPRODUCED';
        summary = `BOLA Not Reproduced: Operation succeeded, but protected resource state remained unchanged.`;
      }
    } else {
      // Caller was legitimately authorized
      result = 'NOT_REPRODUCED';
      summary = `Benign authorized baseline: Caller '${authState.caller}' is the legitimate owner or operator. Operation success is expected.`;
    }

    return {
      authorization_state: authState,
      state_diff: stateDiff,
      result,
      reproduced: false,
      summary,
    };
  }
}
