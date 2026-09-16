/**
 * Generic State Differential Abstraction
 * Intent Security Workbench - Phase 5
 *
 * Rules:
 * - Only report values actually observed from actual execution.
 * - Result statuses:
 *   - PROTECTED_STATE_CHANGED
 *   - PROTECTED_STATE_UNCHANGED
 *   - STATE_OBSERVATION_UNAVAILABLE
 * - Do not infer state changes from logs alone when direct state evidence is available.
 */

import { StateDiffResult, StateDiffStatus, StatePropertyDifference } from './types.js';

export class StateDiffer {
  /**
   * Protected field keywords in authorization/vulnerability models:
   * balance, owner, allowance, role, admin, permissions, funds, asset, etc.
   */
  private static readonly PROTECTED_KEYWORDS = [
    'balance',
    'balances',
    'owner',
    'ownership',
    'allowance',
    'role',
    'roles',
    'admin',
    'permission',
    'permissions',
    'funds',
    'vault',
    'token',
    'stx_balance',
    'eth_balance',
    'is_transferred',
    'state',
  ];

  /**
   * Determine if a state property path represents a protected security-relevant attribute.
   */
  static isProtectedProperty(path: string, customProtectedPaths?: string[]): boolean {
    const lower = path.toLowerCase();
    if (customProtectedPaths && customProtectedPaths.some((p) => lower.includes(p.toLowerCase()))) {
      return true;
    }
    return this.PROTECTED_KEYWORDS.some((kw) => lower.includes(kw));
  }

  /**
   * Flatten nested object paths to dot-notation map.
   */
  static flatten(obj: any, prefix = ''): Record<string, any> {
    if (obj === null || obj === undefined) {
      return {};
    }
    if (typeof obj !== 'object' || obj instanceof Date) {
      return { [prefix]: obj };
    }

    const res: Record<string, any> = {};
    for (const [key, val] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
        Object.assign(res, this.flatten(val, fullKey));
      } else {
        res[fullKey] = val;
      }
    }
    return res;
  }

  /**
   * Compare state observed before and after dynamic execution.
   */
  static computeDiff(
    stateBefore: Record<string, any> | null | undefined,
    stateAfter: Record<string, any> | null | undefined,
    options?: {
      protectedPaths?: string[];
    }
  ): StateDiffResult {
    // If either state is unavailable, cannot observe direct state changes
    if (!stateBefore && !stateAfter) {
      return {
        status: 'STATE_OBSERVATION_UNAVAILABLE',
        differences: [],
        protected_changed: false,
        summary: 'Direct state observation was not available in this execution environment.',
      };
    }

    const beforeMap = this.flatten(stateBefore || {});
    const afterMap = this.flatten(stateAfter || {});

    const allKeys = Array.from(new Set([...Object.keys(beforeMap), ...Object.keys(afterMap)])).sort();
    const differences: StatePropertyDifference[] = [];
    let protectedChanged = false;

    for (const key of allKeys) {
      const bVal = beforeMap[key];
      const aVal = afterMap[key];

      const stringifiedB = JSON.stringify(bVal);
      const stringifiedA = JSON.stringify(aVal);

      if (stringifiedB !== stringifiedA) {
        const isProt = this.isProtectedProperty(key, options?.protectedPaths);
        differences.push({
          path: key,
          before: bVal !== undefined ? bVal : null,
          after: aVal !== undefined ? aVal : null,
          is_protected: isProt,
        });

        if (isProt) {
          protectedChanged = true;
        }
      }
    }

    let status: StateDiffStatus;
    let summary: string;

    if (protectedChanged) {
      status = 'PROTECTED_STATE_CHANGED';
      const protDiffs = differences.filter((d) => d.is_protected).map((d) => d.path).join(', ');
      summary = `Protected state changed during execution (${protDiffs}).`;
    } else if (differences.length > 0) {
      status = 'PROTECTED_STATE_UNCHANGED';
      summary = `State changed, but protected authorization-critical values remained unchanged.`;
    } else {
      status = 'PROTECTED_STATE_UNCHANGED';
      summary = `Protected state unchanged: Before and after states are identical.`;
    }

    const keysAdded = differences.filter((d) => d.before === null && d.after !== null).length;
    const keysRemoved = differences.filter((d) => d.before !== null && d.after === null).length;
    const keysModified = differences.filter((d) => d.before !== null && d.after !== null).length;
    const protectedKeysMutated = differences.filter((d) => d.is_protected).length;

    return {
      status,
      differences,
      diffs: differences,
      has_changes: differences.length > 0,
      protected_changed: protectedChanged,
      summary,
      metrics: {
        keys_added: keysAdded,
        keys_removed: keysRemoved,
        keys_modified: keysModified,
        protected_keys_mutated: protectedKeysMutated,
      },
    };
  }
}
