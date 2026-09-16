/**
 * Formal Property DSL & SMT-LIB2 Compiler
 * Intent Security Workbench - Phase 4
 *
 * Compiles formal security models, variables, constraints, and properties
 * into standardized SMT-LIB2 format accepted by the real Z3 solver.
 *
 * Strict Invariants:
 * - Every variable declaration records its origin in comments.
 * - SOURCE FACTS are strictly distinguished from MODEL ASSUMPTIONS.
 * - SMT-LIB2 formatting is deterministic and reproducible.
 */

import crypto from 'crypto';
import { FormalModelDefinition, Constraint, FormalVariable } from './types.js';

export class FormalDSLCompiler {
  /**
   * Compiles a formal model definition into complete, valid SMT-LIB2 code.
   */
  static compileToSMTLIB2(model: FormalModelDefinition): { smtCode: string; smt_lib: string; sha256: string } {
    const lines: string[] = [];
    const propName = model.query_property?.name || model.property?.name || 'UNAUTHORIZED_OBJECT_ACCESS';
    const propId = model.query_property?.id || model.property?.id || 'AUTH-001';

    // Header with provenance metadata
    lines.push(';; =================================================================');
    lines.push(';; Intent Security Workbench - Phase 4 Formal Verification Model');
    lines.push(`;; Target Model: ${model.name}`);
    lines.push(`;; Investigation ID: ${model.investigation_id || 'N/A'}`);
    lines.push(`;; Target ID: ${model.target_id || 'N/A'}`);
    lines.push(`;; Query Property: ${propName} (${propId})`);
    lines.push(`;; Query Mode: ${model.query_mode || 'UNAUTHORIZED_ACCESS_REACHABLE'}`);
    lines.push(';; =================================================================');
    lines.push(`; FORMAL PROPERTY UNDER VERIFICATION: ${propName}`);

    const hasSorts = (model.sorts && model.sorts.length > 0) || model.variables?.some((v) => v.type === 'Sort');
    if (!hasSorts) {
      lines.push('(set-logic QF_LIA)');
    }

    lines.push('(set-option :produce-models true)');
    lines.push('');

    // Sort declarations
    if (hasSorts) {
      lines.push(';; -----------------------------------------------------------------');
      lines.push(';; Sort / Domain Declarations');
      lines.push(';; -----------------------------------------------------------------');
      const sorts = model.sorts && model.sorts.length > 0 ? model.sorts : ['Principal', 'ResourceId', 'TenantId'];
      for (const sort of sorts) {
        lines.push(`(declare-sort ${sort})`);
      }
      lines.push('');
    }

    // Variable / Constant declarations
    lines.push(';; -----------------------------------------------------------------');
    lines.push(';; Formal Variables & Origins');
    lines.push(';; -----------------------------------------------------------------');
    for (const v of model.variables || []) {
      const originDesc = v.origin?.source_location
        ? `${v.origin.origin_type} from ${v.origin.source_location.file}:${v.origin.source_location.line || 1}`
        : `${v.origin?.origin_type || 'SOURCE_OBSERVATION'} (${v.origin?.reason || v.description || 'modeled variable'})`;

      lines.push(`;; Variable: ${v.name} | Origin: [${originDesc}]`);
      const sortType = v.type === 'Sort' ? (v.sort_name || 'Principal') : v.type;
      lines.push(`(declare-const ${v.name} ${sortType})`);
    }
    lines.push('');

    // Source Facts Constraints
    lines.push(';; -----------------------------------------------------------------');
    lines.push('; SOURCE FACTS (OBSERVED IN CODE):');
    lines.push(';; -----------------------------------------------------------------');
    const sourceConstraints = (model.constraints || []).filter((c) => !c.is_assumption);
    for (const c of sourceConstraints) {
      const loc = c.origin?.source_location
        ? ` at ${c.origin.source_location.file}:${c.origin.source_location.line || 1}`
        : '';
      lines.push(`;; [SOURCE FACT] ${c.name}${loc}: ${c.expression || c.rationale || c.name}`);
      lines.push(`(assert ${c.smt_representation})`);
    }
    lines.push('');

    // Model Assumptions Constraints
    lines.push(';; -----------------------------------------------------------------');
    lines.push('; MODEL ASSUMPTIONS (NOT PROVEN BY CODE):');
    lines.push(';; -----------------------------------------------------------------');
    const assumptionConstraints = (model.constraints || []).filter((c) => c.is_assumption);
    for (const c of assumptionConstraints) {
      lines.push(`;; [MODEL ASSUMPTION] ${c.name}: ${c.expression || c.rationale || c.name}`);
      lines.push(`(assert ${c.smt_representation})`);
    }
    lines.push('');

    // Goal / Query
    lines.push(';; -----------------------------------------------------------------');
    lines.push(';; Formal Verification Query');
    lines.push(';; -----------------------------------------------------------------');
    if (model.query_mode === 'UNAUTHORIZED_ACCESS_REACHABLE') {
      lines.push(';; Query: Does there exist an execution violating authorization?');
      lines.push(';; SAT   => Counterexample found in model (unauthorized state reachable).');
      lines.push(';; UNSAT => Property holds for model (no unauthorized execution).');
      lines.push('(check-sat)');
      lines.push('(get-model)');
    } else {
      lines.push(';; Query: Does the property hold universally?');
      lines.push('(check-sat)');
      lines.push('(get-model)');
    }

    const smtCode = lines.join('\n') + '\n';
    const sha256 = crypto.createHash('sha256').update(smtCode, 'utf8').digest('hex');

    return { smtCode, smt_lib: smtCode, sha256 };
  }

  /**
   * Alias for compileToSMTLIB2 for compatibility with standard compiler interface.
   */
  static compile(model: FormalModelDefinition): { smtCode: string; smt_lib: string; sha256: string } {
    return FormalDSLCompiler.compileToSMTLIB2(model);
  }
}
