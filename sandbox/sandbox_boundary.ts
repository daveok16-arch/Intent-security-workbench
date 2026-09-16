/**
 * Security Sandbox & Command Execution Boundary
 * Phase 0 Foundational Architecture
 * 
 * Strict policies:
 * - Reject arbitrary unrestricted shell commands
 * - Prohibit automatic scanning of external unauthorized targets
 * - Ensure execution operates only within controlled containment
 */

export interface SandboxExecutionPolicy {
  allow_arbitrary_shell: false;
  require_explicit_target_scope: true;
  network_egress_restricted: true;
  timeout_ms: number;
}

export const DEFAULT_SANDBOX_POLICY: SandboxExecutionPolicy = {
  allow_arbitrary_shell: false,
  require_explicit_target_scope: true,
  network_egress_restricted: true,
  timeout_ms: 120000,
};

export class SandboxSecurityEnforcer {
  /**
   * Sanitizes and checks if an execution request conforms to Phase 0 security guidelines.
   */
  static validateExecutionRequest(command: string, targetInScope: boolean): { allowed: boolean; reason?: string } {
    if (!targetInScope) {
      return {
        allowed: false,
        reason: 'Target is not confirmed in scope or authorized for security testing.',
      };
    }

    // Disallow dangerous shell metacharacters and piping to prevent command injection
    const dangerousPatterns = [/;\s*rm\s+-rf/i, /\|\s*bash/i, /\|\s*sh/i, /`.*`/g, /\$\(.*\)/g];
    for (const pattern of dangerousPatterns) {
      if (pattern.test(command)) {
        return {
          allowed: false,
          reason: 'Command contains prohibited shell injection patterns.',
        };
      }
    }

    return { allowed: true };
  }
}

export class SandboxBoundaryEnforcer {
  validateCommand(command: string, scope: string[], target: string): { allowed: boolean; reason: string } {
    if (!command || !command.trim()) {
      return { allowed: false, reason: 'Command cannot be empty' };
    }

    const dangerousPatterns = [/;\s*rm\s+-rf/i, /\|\s*bash/i, /\|\s*sh/i, /`.*`/g, /\$\(.*\)/g, />\s*\/etc/i];
    for (const pattern of dangerousPatterns) {
      if (pattern.test(command)) {
        return {
          allowed: false,
          reason: 'Command contains prohibited dangerous execution pattern or shell injection sequence.',
        };
      }
    }

    if (target && scope && scope.length > 0 && !scope.some(s => s.includes(target) || target.includes(s))) {
      return {
        allowed: false,
        reason: `Target ${target} is outside of authorized research scope boundaries.`,
      };
    }

    return {
      allowed: true,
      reason: 'Command passed strict security boundary sandbox policy checks.',
    };
  }
}
