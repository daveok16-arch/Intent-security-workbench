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

/**
 * Patterns that are never legitimate inside a sandboxed analysis command.
 * This is a defence-in-depth deny-list, not the primary control: the primary
 * control is that engines invoke fixed binaries with typed argument arrays and
 * never interpolate user input into a shell string.
 */
const PROHIBITED_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  // Destructive filesystem operations, anchored to command position or after a
  // separator so a bare `rm -rf /` is caught (the previous regex only matched
  // `; rm -rf` and let `rm -rf --no-preserve-root /` pass).
  { pattern: /(^|[;&|`(]|\s)\s*rm\s+(-\w+\s+)*-\w*r\w*f\w*(\s|$)/i, reason: 'recursive forced delete (rm -rf)' },
  { pattern: /(^|[;&|`(]|\s)\s*rm\s+(-\w+\s+)*-\w*f\w*r\w*(\s|$)/i, reason: 'recursive forced delete (rm -fr)' },
  { pattern: /(^|[;&|`(]|\s)\s*rm\s+[^\n]*--no-preserve-root/i, reason: 'recursive delete with --no-preserve-root' },
  { pattern: /(^|[;&|`(]|\s)\s*mkfs(\.\w+)?\b/i, reason: 'filesystem creation over a device' },
  { pattern: /(^|[;&|`(]|\s)\s*dd\s[^\n]*of=\/dev\//i, reason: 'raw device overwrite' },
  { pattern: /:\s*\(\s*\)\s*\{[\s\S]*\}[\s\S]*;?\s*:/, reason: 'fork bomb' },
  { pattern: /(^|[;&|`(]|\s)\s*shutdown\b|(^|[;&|`(]|\s)\s*reboot\b|(^|[;&|`(]|\s)\s*init\s+0\b/i, reason: 'host shutdown/reboot' },
  // Shell injection primitives
  { pattern: /\|\s*(bash|sh|zsh|dash)\b/i, reason: 'pipe into a shell interpreter' },
  { pattern: /`[^`]*`/, reason: 'backtick command substitution' },
  { pattern: /\$\([^)]*\)/, reason: 'command substitution' },
  { pattern: /[;&|]\s*(curl|wget|nc|ncat|netcat)\b/i, reason: 'network fetch chained into command' },
  { pattern: />\s*\/etc\//i, reason: 'write into /etc' },
  // Privilege escalation
  { pattern: /(^|[;&|`(]|\s)\s*sudo\b/i, reason: 'privilege escalation via sudo' },
  { pattern: /(^|[;&|`(]|\s)\s*chmod\s+[^\n]*\+s\b/i, reason: 'setuid/setgid bit manipulation' },
];

/**
 * Sanitizes and checks if an execution request conforms to Phase 0 security guidelines.
 */
export class SandboxSecurityEnforcer {
  static validateExecutionRequest(command: string, targetInScope: boolean): { allowed: boolean; reason?: string } {
    if (!targetInScope) {
      return {
        allowed: false,
        reason: 'Target is not confirmed in scope or authorized for security testing.',
      };
    }

    if (!command || !command.trim()) {
      return { allowed: false, reason: 'Command cannot be empty.' };
    }

    for (const { pattern, reason } of PROHIBITED_PATTERNS) {
      if (pattern.test(command)) {
        return {
          allowed: false,
          reason: `Command contains a prohibited pattern (${reason}).`,
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

    for (const { pattern, reason } of PROHIBITED_PATTERNS) {
      if (pattern.test(command)) {
        return {
          allowed: false,
          reason: `Command contains prohibited dangerous execution pattern (${reason}).`,
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
