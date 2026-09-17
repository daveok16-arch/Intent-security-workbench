/**
 * Policy & Authorization Gate for AI Security Controller
 * Phase 6 — AI Security Control Plane Core
 * 
 * Invariants:
 * - Every security action must pass through this gate.
 * - Out-of-scope targets are strictly BLOCKED.
 * - Destructive or state-changing commands violate sandbox policy and are BLOCKED.
 * - Sensitive actions (dynamic testing, fork reproduction) require explicit policy authorization & user approval.
 */

import { globalDB } from '../../../apps/api/db_store.js';
import {
  ScopeDecisionService,
  ScopeInclusionStatus,
  TargetAuthorizationStatus,
  TargetScopeStatus,
} from '../../core/src/index.js';
import { SandboxSecurityEnforcer } from '../../../sandbox/sandbox_boundary.js';
import { PolicyGateVerdict, UserApprovalRequest } from './types.js';

export interface ActionAuthorizationRequest {
  action: string; // e.g. 'ACQUIRE_SOURCE', 'RUN_STATIC_ANALYSIS', 'RUN_DYNAMIC_VERIFICATION', 'EXECUTE_TOOL'
  program_id?: string;
  target_id?: string;
  command?: string;
  engine_id?: string;
  operation?: string;
  parameters?: Record<string, any>;
  has_user_approval?: boolean;
}

export class PolicyGate {
  /**
   * Authoritatively evaluates whether an action may be executed by the Controller.
   */
  public static evaluateAction(request: ActionAuthorizationRequest): PolicyGateVerdict {
    const checks = {
      target_registered: true,
      scope_permitted: true,
      policy_authorized: true,
      sandbox_safe: true,
      prerequisites_met: true,
    };

    // Set only when a target was supplied AND its scope evaluation returned
    // IN_SCOPE. The sandbox boundary uses this so a command is never validated
    // against an assumed-in-scope target.
    let scopeInScope = false;

    // 1. Target Registration & Scope Evaluation
    // This gate is the last checkpoint before a security action runs, so it must
    // fail closed. An earlier version permitted the action whenever the program
    // was unknown or the program had no scope rules, which meant an
    // unregistered or un-scoped target was silently treated as authorized.
    if (request.target_id) {
      const target = globalDB.getTarget(request.target_id);
      if (!target) {
        return {
          allowed: false,
          code: 'TARGET_NOT_FOUND',
          explanation: `Action blocked: Target with ID '${request.target_id}' is not registered in the workbench database.`,
          requires_user_approval: false,
          checks: { ...checks, target_registered: false },
        };
      }

      // Check scope status if registered
      const targetIdentifier = target.primary_location || target.repository_url || target.contract_address || target.name;
      const programId = request.program_id || target.program_id;

      if (!programId) {
        return {
          allowed: false,
          code: 'SCOPE_UNDETERMINED',
          explanation:
            `Security action blocked: Target '${target.name}' has no associated program, so scope ` +
            `authorization cannot be evaluated. Register the target under a program with scope rules.`,
          requires_user_approval: false,
          checks: { ...checks, scope_permitted: false },
        };
      }

      const program = globalDB.getProgram(programId);
      if (!program) {
        return {
          allowed: false,
          code: 'PROGRAM_NOT_FOUND',
          explanation: `Security action blocked: Program '${programId}' is not registered in the workbench database.`,
          requires_user_approval: false,
          checks: { ...checks, scope_permitted: false },
        };
      }

      const scopeEntries = globalDB.listScopeEntries(programId);
      if (scopeEntries.length === 0) {
        return {
          allowed: false,
          code: 'NO_SCOPE_DEFINED',
          explanation:
            `Security action blocked: Program '${program.name}' defines no scope rules, so no target can ` +
            `be shown to be authorized. Define the program scope before running security actions.`,
          requires_user_approval: false,
          checks: { ...checks, scope_permitted: false },
        };
      }

      const decision = ScopeDecisionService.evaluateScope(scopeEntries, targetIdentifier, target.target_type as any);
      if (decision.decision !== ScopeInclusionStatus.IN_SCOPE) {
        const code = decision.decision === ScopeInclusionStatus.OUT_OF_SCOPE
          ? 'OUT_OF_SCOPE'
          : 'SCOPE_UNDETERMINED';
        return {
          allowed: false,
          code,
          explanation:
            `Security action blocked: Target '${target.name}' (${targetIdentifier}) evaluates to ` +
            `'${decision.decision}' rather than IN_SCOPE. Reason: ${decision.reason || 'no matching scope rule'}.`,
          requires_user_approval: false,
          checks: { ...checks, scope_permitted: false },
        };
      }
      scopeInScope = true;
    }

    // 2. Sandbox Boundary Validation
    if (request.command) {
      const sandboxCheck = SandboxSecurityEnforcer.validateExecutionRequest(request.command, scopeInScope);
      if (!sandboxCheck.allowed) {
        return {
          allowed: false,
          code: 'SANDBOX_VIOLATION',
          explanation: `Sandbox policy violation: ${sandboxCheck.reason}`,
          requires_user_approval: false,
          checks: { ...checks, sandbox_safe: false },
        };
      }
    }

    // 3. Sensitive / State-Changing Operations Approval Gate
    const sensitiveActions = [
      'RUN_DYNAMIC_VERIFICATION',
      'FORK_CREATION',
      'EXTERNAL_NETWORK_INTERACTION',
      'CANDIDATE_EXPLOIT_VERIFICATION',
      'execute_foundry_exploit',
    ];

    const isSensitive = sensitiveActions.includes(request.action) ||
      (request.operation && sensitiveActions.includes(request.operation));

    if (isSensitive) {
      if (!request.has_user_approval) {
        const approvalReq: UserApprovalRequest = {
          id: `appr-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          action: request.action,
          description: `Execution of dynamic verification on target '${request.target_id || 'system'}' using operation '${request.operation || 'test'}'.`,
          target_id: request.target_id,
          sensitive: true,
          required_policy_check: 'EXPLICIT_RESEARCHER_APPROVAL_REQUIRED',
          status: 'PENDING',
          created_at: new Date().toISOString(),
        };

        return {
          allowed: false,
          code: 'APPROVAL_REQUIRED',
          explanation: `Dynamic verification or state-changing action '${request.action}' requires explicit researcher approval before execution.`,
          requires_user_approval: true,
          approval_request: approvalReq,
          checks: { ...checks, policy_authorized: false },
        };
      }
    }

    return {
      allowed: true,
      code: 'AUTHORIZED',
      explanation: 'Action passed all scope, sandbox, and policy invariants.',
      requires_user_approval: false,
      checks,
    };
  }
}
