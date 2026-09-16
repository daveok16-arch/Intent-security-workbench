/**
 * Investigation Gate Enforcement Service for Intent Security Workbench
 * Phase 1 Scope & Target Authorization Subsystem
 *
 * Mandatory pre-flight authorization gate.
 * Blocks any investigation execution if program, target, scope, authorization, or source conditions are not met.
 */

import {
  Program,
  Target,
  InvestigationGateResult,
  InvestigationGateCheck,
  ProgramStatus,
  ProgramFreshnessStatus,
  TargetAuthorizationStatus,
  TargetScopeStatus,
  SourceAcquisitionStatus,
} from './index.js';

export class InvestigationGateService {
  /**
   * Deterministically evaluates whether an investigation against a target is permitted to proceed.
   */
  public static evaluateGate(params: {
    program?: Program | null;
    target?: Target | null;
    requireSourceAcquisition?: boolean;
    strictFreshness?: boolean;
  }): InvestigationGateResult {
    const { program, target, requireSourceAcquisition = true, strictFreshness = true } = params;
    const evaluatedAt = new Date().toISOString();

    const targetAuth = target?.authorization_status || TargetAuthorizationStatus.NOT_EVALUATED;
    const scopeStatus = target?.scope_status || TargetScopeStatus.NOT_EVALUATED;
    const sourceStatus = target?.source_acquisition_status || SourceAcquisitionStatus.SOURCE_NOT_ACQUIRED;

    const checks: InvestigationGateCheck[] = [];

    // 1. Program Existence
    const programExists = !!program;
    checks.push({
      name: 'Program Existence',
      passed: programExists,
      message: programExists ? `Program '${program?.name}' loaded.` : 'No program associated with target.',
    });

    // 2. Program Active
    const programActive = !!program && program.status === ProgramStatus.ACTIVE;
    checks.push({
      name: 'Program Active',
      passed: programActive,
      message: programActive
        ? `Program status is ACTIVE.`
        : `Program status is '${program?.status || 'UNKNOWN'}' (requires ACTIVE).`,
    });

    // 3. Program Policy Freshness
    const freshness = program?.freshness_status || ProgramFreshnessStatus.CURRENT;
    const freshnessPassed = !strictFreshness || (freshness !== ProgramFreshnessStatus.STALE && freshness !== ProgramFreshnessStatus.EXPIRED);
    checks.push({
      name: 'Program Policy Freshness',
      passed: freshnessPassed,
      message: freshnessPassed
        ? `Program policy freshness is ${freshness}.`
        : `Program policy freshness is ${freshness} (requires CURRENT or refreshed policy).`,
    });

    // 4. Target Existence
    const targetExists = !!target;
    checks.push({
      name: 'Target Existence',
      passed: targetExists,
      message: targetExists ? `Target '${target?.name}' loaded.` : 'No target record provided.',
    });

    // 5. Target Authorization
    const authPassed = targetAuth === TargetAuthorizationStatus.AUTHORIZED;
    checks.push({
      name: 'Target Authorization',
      passed: authPassed,
      message: authPassed
        ? 'Target is formally AUTHORIZED for research under program policy.'
        : `Target authorization status is ${targetAuth} (requires AUTHORIZED).`,
    });

    // 6. Target Scope Status
    const scopePassed = scopeStatus === TargetScopeStatus.IN_SCOPE;
    checks.push({
      name: 'Target Scope Status',
      passed: scopePassed,
      message: scopePassed
        ? 'Target is confirmed IN_SCOPE.'
        : `Target scope status is ${scopeStatus} (requires IN_SCOPE).`,
    });

    // 7. Source Code Acquisition
    const sourcePassed = !requireSourceAcquisition || sourceStatus === SourceAcquisitionStatus.SOURCE_ACQUIRED;
    checks.push({
      name: 'Source Code Acquisition',
      passed: sourcePassed,
      message: sourcePassed
        ? `Source status is ${sourceStatus}.`
        : `Source code has not been acquired (status: ${sourceStatus}).`,
    });

    const passed = checks.every(c => c.passed);
    const failedCheck = checks.find(c => !c.passed);
    const reason = passed ? 'AUTHORIZED' : (failedCheck ? failedCheck.message : 'BLOCKED');

    return {
      passed,
      can_proceed: passed,
      allowed: passed,
      reason,
      evaluated_at: evaluatedAt,
      target_authorization: targetAuth,
      scope_status: scopeStatus,
      source_status: sourceStatus,
      policy_status: passed ? 'VALID' : 'BLOCKED',
      checks,
    };
  }
}
