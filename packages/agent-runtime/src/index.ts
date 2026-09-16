/**
 * Agent Runtime & Execution Context
 * Phase 0 Foundational Architecture
 */

import { SandboxExecutionPolicy, DEFAULT_SANDBOX_POLICY, SandboxSecurityEnforcer } from '../../../sandbox/sandbox_boundary.js';

export interface AgentExecutionContext {
  session_id: string;
  user_identifier: string;
  policy: SandboxExecutionPolicy;
}

export class AgentRuntime {
  private context: AgentExecutionContext;

  constructor(context?: Partial<AgentExecutionContext>) {
    this.context = {
      session_id: context?.session_id || `session-${Date.now()}`,
      user_identifier: context?.user_identifier || 'authorized-researcher',
      policy: context?.policy || DEFAULT_SANDBOX_POLICY,
    };
  }

  getContext(): AgentExecutionContext {
    return this.context;
  }

  verifyAuthorization(targetInScope: boolean, command: string): boolean {
    const check = SandboxSecurityEnforcer.validateExecutionRequest(command, targetInScope);
    return check.allowed;
  }
}

export * from './types.js';
export * from './state_machine.js';
export * from './policy_gate.js';
export * from './tools/definitions.js';
export * from './tools/tool_registry.js';
export * from './ai_provider_client.js';
export * from './controller.js';
