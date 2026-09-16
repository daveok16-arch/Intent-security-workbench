/**
 * Formal Model Builder from Source Analysis & Contract Evidence
 * Intent Security Workbench - Phase 4
 *
 * Bridges empirical static analysis (Tree-sitter, Semgrep, OpenAPI contracts)
 * into formal SMT verification models with strict provenance tracking.
 */

import {
  FormalModelDefinition,
  FormalVariable,
  Constraint,
  ModelAssumption,
  SourceFact,
  SecurityProperty,
  OriginType,
} from './types.js';
import { STANDARD_PROPERTIES } from './properties.js';
import { AuthorizationCandidate, APIEndpoint } from '../../api-analysis/src/types.js';

export interface ModelBuildInput {
  name: string;
  description?: string;
  investigation_id: string;
  target_id: string;
  source_snapshot_id?: string | null;
  candidate_id?: string | null;
  source_code?: string;
  source_file?: string;
  endpoint?: APIEndpoint;
  authorization_candidate?: AuthorizationCandidate;
  property?: SecurityProperty;
}

export class FormalModelBuilder {
  /**
   * Builds a formal verification model from source code and authorization evidence.
   */
  static buildFromSource(input: ModelBuildInput): FormalModelDefinition {
    const file = input.source_file || 'unknown_source.js';
    const code = input.source_code || '';
    const queryProperty = input.property || STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS;

    const variables: FormalVariable[] = [];
    const constraints: Constraint[] = [];
    const assumptions: ModelAssumption[] = [];
    const sourceFacts: SourceFact[] = [];

    // Core Domain Sorts
    const sorts = ['Principal', 'ResourceId', 'TenantId'];

    // 1. Declare Formal Variables with explicit origins
    variables.push({
      name: 'caller',
      type: 'Sort',
      sort_name: 'Principal',
      description: 'The calling principal executing the operation',
      origin: {
        origin_type: 'SOURCE_OBSERVATION',
        source_location: { file, line: 1 },
        symbol: 'caller',
        reason: 'Invocation context principal',
      },
    });

    variables.push({
      name: 'owner',
      type: 'Sort',
      sort_name: 'Principal',
      description: 'The legitimate owner of the requested target resource',
      origin: {
        origin_type: 'SOURCE_OBSERVATION',
        source_location: { file, line: 1 },
        symbol: 'owner',
        reason: 'Resource owner derived from parameter or storage lookup',
      },
    });

    variables.push({
      name: 'is_operator',
      type: 'Bool',
      description: 'Whether the caller has delegated operator permissions',
      origin: {
        origin_type: 'MODEL_ASSUMPTION',
        reason: 'Model assumption of default caller delegation status',
      },
    });

    variables.push({
      name: 'authenticated',
      type: 'Bool',
      description: 'Whether caller identity has been verified by authentication scheme',
      origin: {
        origin_type: 'SOURCE_OBSERVATION',
        source_location: { file, line: 1 },
        reason: 'Authentication middleware or session validity',
      },
    });

    variables.push({
      name: 'is_mutation',
      type: 'Bool',
      description: 'Whether the invoked operation mutates resource state',
      origin: {
        origin_type: 'SOURCE_OBSERVATION',
        source_location: { file, line: 1 },
        reason: 'State mutation operation observed in AST',
      },
    });

    variables.push({
      name: 'reachable',
      type: 'Bool',
      description: 'Reachability of the execution path leading to the resource action',
      origin: {
        origin_type: 'SOURCE_OBSERVATION',
        source_location: { file, line: 1 },
        reason: 'Control flow reachability',
      },
    });

    variables.push({
      name: 'caller_tenant',
      type: 'Sort',
      sort_name: 'TenantId',
      description: 'Tenant organization associated with caller',
      origin: {
        origin_type: 'MODEL_ASSUMPTION',
        reason: 'Multi-tenant context assumption',
      },
    });

    variables.push({
      name: 'resource_tenant',
      type: 'Sort',
      sort_name: 'TenantId',
      description: 'Tenant organization owning the target resource',
      origin: {
        origin_type: 'MODEL_ASSUMPTION',
        reason: 'Multi-tenant context assumption',
      },
    });

    // 2. Scan source code for factual constraints and guards
    const lines = code.split('\n');
    let hasExplicitOwnershipGuard = false;
    let hasRoleCheckOnly = false;
    let hasTenantCheck = false;
    let ownershipGuardLine = -1;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for direct caller-to-owner equality assertion:
      // e.g. assert(caller == owner), if (caller != owner) throw, require(caller == owner)
      if (
        /assert\s*\(\s*caller\s*={2,3}\s*owner\s*\)/i.test(line) ||
        /require\s*\(\s*caller\s*={2,3}\s*owner\s*\)/i.test(line) ||
        /if\s*\(\s*caller\s*!={1,2}\s*owner\s*\)/i.test(line) ||
        /if\s*\(\s*req\.user\.id\s*={2,3}\s*resource\.owner_?id\s*\)/i.test(line) ||
        /doc\.owner_?id\s*!==?\s*req\.user\.id/i.test(line) ||
        /req\.user\.id\s*!==?\s*doc\.owner_?id/i.test(line) ||
        /doc\.owner_?id\s*={2,3}\s*req\.user\.id/i.test(line) ||
        /req\.user\.id\s*={2,3}\s*doc\.owner_?id/i.test(line) ||
        /ensure_owner\s*\(/i.test(line)
      ) {
        hasExplicitOwnershipGuard = true;
        ownershipGuardLine = lineNum;

        sourceFacts.push({
          id: `fact-guard-${lineNum}`,
          description: `Observed direct caller-owner authorization guard: ${line.trim()}`,
          file,
          line: lineNum,
          snippet: line.trim(),
          code_snippet: line.trim(),
          observed_via: 'TREE_SITTER',
        });

        constraints.push({
          id: `c-guard-ownership-${lineNum}`,
          name: 'caller_owner_equality_guard',
          expression: 'caller == owner',
          smt_representation: '(= caller owner)',
          is_assumption: false,
          origin: {
            origin_type: 'SOURCE_OBSERVATION',
            source_location: { file, line: lineNum, snippet: line.trim() },
            source_fact_description: 'Ownership equality check in source guard',
          },
        });
      }

      // Route handler pattern observation
      if (/(router|app)\.(get|post|put|delete|patch)/i.test(line)) {
        sourceFacts.push({
          id: `fact-route-${lineNum}`,
          description: `Observed HTTP endpoint handler: ${line.trim()}`,
          file,
          line: lineNum,
          snippet: line.trim(),
          code_snippet: line.trim(),
          observed_via: 'TREE_SITTER',
        });
      }

      // Database / store pattern observation
      if (/(db|database|repository)\.\w+\.(findOne|findById|get|deleteOne|updateOne)/i.test(line) || /db\.get\(/i.test(line)) {
        sourceFacts.push({
          id: `fact-db-${lineNum}`,
          description: `Observed resource store lookup: ${line.trim()}`,
          file,
          line: lineNum,
          snippet: line.trim(),
          code_snippet: line.trim(),
          observed_via: 'TREE_SITTER',
        });
      }

      // Check for role check (e.g. caller.role == 'admin')
      if (
        /caller\.role\s*={2,3}\s*["']\w+["']/i.test(line) ||
        /user\.role\s*={2,3}\s*["']\w+["']/i.test(line) ||
        /hasRole\s*\(/i.test(line)
      ) {
        hasRoleCheckOnly = true;
        sourceFacts.push({
          id: `fact-role-${lineNum}`,
          description: `Observed role-based check: ${line.trim()} (NOTE: Role checks alone do NOT verify object ownership)`,
          file,
          line: lineNum,
          snippet: line.trim(),
          code_snippet: line.trim(),
          observed_via: 'SEMGREP',
        });
      }

      // Check for tenant equality check
      if (
        /caller\.tenant\s*={2,3}\s*resource\.tenant/i.test(line) ||
        /tenant_id\s*={2,3}\s*req\.user\.tenant_id/i.test(line)
      ) {
        hasTenantCheck = true;
        sourceFacts.push({
          id: `fact-tenant-${lineNum}`,
          description: `Observed tenant isolation check: ${line.trim()}`,
          file,
          line: lineNum,
          snippet: line.trim(),
          code_snippet: line.trim(),
          observed_via: 'TREE_SITTER',
        });

        constraints.push({
          id: `c-guard-tenant-${lineNum}`,
          name: 'tenant_isolation_guard',
          expression: 'caller_tenant == resource_tenant',
          smt_representation: '(= caller_tenant resource_tenant)',
          is_assumption: false,
          origin: {
            origin_type: 'SOURCE_OBSERVATION',
            source_location: { file, line: lineNum, snippet: line.trim() },
          },
        });
      }
    }

    // 3. Add baseline operational assertions (caller authenticated, mutation reachable)
    constraints.push({
      id: 'c-auth-active',
      name: 'caller_authenticated',
      expression: 'authenticated == true',
      smt_representation: 'authenticated',
      is_assumption: false,
      origin: {
        origin_type: 'SOURCE_OBSERVATION',
        source_fact_description: 'Request reaches handler through authenticated route',
      },
    });

    constraints.push({
      id: 'c-mutation-active',
      name: 'state_mutation_operation',
      expression: 'is_mutation == true',
      smt_representation: 'is_mutation',
      is_assumption: false,
      origin: {
        origin_type: 'SOURCE_OBSERVATION',
        source_fact_description: 'Handler performs resource modification or access',
      },
    });

    constraints.push({
      id: 'c-path-reachable',
      name: 'execution_path_reachable',
      expression: 'reachable == true',
      smt_representation: 'reachable',
      is_assumption: false,
      origin: {
        origin_type: 'SOURCE_OBSERVATION',
        source_fact_description: 'Control flow reaches resource operation',
      },
    });

    // Explicit Model Assumption: caller is not a privileged operator unless proven
    assumptions.push({
      id: 'asm-not-operator',
      assumption_text: 'The caller does not hold an authorized operator delegation for this resource.',
      rationale: 'Standard external users do not possess administrator operator exceptions.',
      impact_on_soundness: 'Sound for standard user accounts; if caller were an authorized operator, access would be benign.',
    });

    constraints.push({
      id: 'c-not-operator',
      name: 'caller_not_operator',
      expression: 'is_operator == false',
      smt_representation: '(not is_operator)',
      is_assumption: true,
      origin: {
        origin_type: 'MODEL_ASSUMPTION',
        reason: 'Assumed non-operator caller to test standard access boundaries',
      },
    });

    // 4. Verification Query Property setup
    // For UNAUTHORIZED_OBJECT_ACCESS:
    // We assert (not (= caller owner)) to test if unauthorized access is reachable
    if (queryProperty.name === 'UNAUTHORIZED_OBJECT_ACCESS' || queryProperty.name === 'OWNER_BINDING') {
      constraints.push({
        id: 'c-unauthorized-hypothesis',
        name: 'unauthorized_caller_hypothesis',
        expression: 'caller != owner',
        smt_representation: '(not (= caller owner))',
        is_assumption: true,
        origin: {
          origin_type: 'PROPERTY_INVARIANT',
          reason: 'Testing reachability of unauthorized access where caller is not resource owner',
        },
      });
    } else if (queryProperty.name === 'TENANT_ISOLATION') {
      constraints.push({
        id: 'c-cross-tenant-hypothesis',
        name: 'cross_tenant_hypothesis',
        expression: 'caller_tenant != resource_tenant',
        smt_representation: '(not (= caller_tenant resource_tenant))',
        is_assumption: true,
        origin: {
          origin_type: 'PROPERTY_INVARIANT',
          reason: 'Testing reachability of cross-tenant resource access',
        },
      });
    }

    return {
      name: input.name,
      description: input.description || `Formal model for ${input.name}`,
      target_id: input.target_id,
      investigation_id: input.investigation_id,
      source_snapshot_id: input.source_snapshot_id,
      candidate_id: input.candidate_id,
      sorts,
      variables,
      constraints,
      assumptions,
      sourceFacts,
      source_facts: sourceFacts,
      property: queryProperty,
      query_property: queryProperty,
      query_mode: 'UNAUTHORIZED_ACCESS_REACHABLE',
    };
  }
}
