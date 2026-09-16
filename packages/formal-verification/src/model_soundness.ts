/**
 * Model Soundness & False-Proof Defense
 * Intent Security Workbench - Phase 4
 *
 * Validates formal verification models prior to solver invocation.
 * Enforces:
 * 1. Well-typedness: Every variable must have a declared type / sort.
 * 2. Symbol resolution: Every identifier in constraints must exist.
 * 3. Source location validity: Valid strings/numbers for locations.
 * 4. Assumption discipline: Assumptions must be explicitly identified.
 * 5. Under-constrained detection: Identifies models missing key domain relations.
 * 6. Assumption dependency: Detects when authorization logic rests solely on assumptions.
 */

import { FormalModelDefinition, ModelSoundnessResult, ModelSoundnessStatus } from './types.js';

export class ModelSoundnessChecker {
  /**
   * Validates model soundness and defense against false proofs.
   */
  static validate(model: FormalModelDefinition): ModelSoundnessResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const definedSymbols = new Set<string>();

    // 1. Variable validation
    if (!model.variables || model.variables.length === 0) {
      errors.push('Formal model contains no variables.');
    }

    for (const v of model.variables || []) {
      if (!v.name || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(v.name)) {
        errors.push(`Invalid variable name '${v.name}'.`);
      }
      if (!v.type) {
        errors.push(`Variable '${v.name}' has no declared type or sort.`);
      }
      if (!v.origin || !v.origin.origin_type) {
        warnings.push(`Variable '${v.name}' has no provenance origin_type recorded.`);
      }
      definedSymbols.add(v.name);
    }

    // Include built-in SMT symbols
    const builtins = new Set([
      'assert', 'check-sat', 'get-model', 'declare-const', 'declare-sort',
      'and', 'or', 'not', '=>', '=', 'distinct', 'ite', 'true', 'false',
      '+', '-', '*', '/', '<=', '>=', '<', '>',
    ]);

    // 2. Constraint validation & symbol resolution
    for (const c of model.constraints || []) {
      if (!c.smt_representation || c.smt_representation.trim().length === 0) {
        errors.push(`Constraint '${c.name}' has empty SMT representation.`);
      }

      // Check parentheses balance in SMT-LIB expression
      let parenBalance = 0;
      for (const char of c.smt_representation) {
        if (char === '(') parenBalance++;
        if (char === ')') parenBalance--;
        if (parenBalance < 0) {
          errors.push(`Unbalanced parentheses in constraint '${c.name}': ${c.smt_representation}`);
          break;
        }
      }
      if (parenBalance !== 0) {
        errors.push(`Mismatched parentheses in constraint '${c.name}': ${c.smt_representation}`);
      }

      // Check symbol references inside smt_representation
      const tokens = c.smt_representation
        .replace(/[()]/g, ' ')
        .split(/\s+/)
        .filter((t) => t.length > 0 && !/^-?\d+$/.test(t));

      for (const token of tokens) {
        if (!builtins.has(token) && !definedSymbols.has(token)) {
          errors.push(`Constraint '${c.name}' references undefined symbol '${token}'.`);
        }
      }

      // Ensure assumptions are explicitly marked
      if (c.origin?.origin_type === 'MODEL_ASSUMPTION' && !c.is_assumption) {
        errors.push(`Constraint '${c.name}' has origin MODEL_ASSUMPTION but is_assumption flag was false.`);
      }
    }

    // 3. Source location validity
    for (const v of model.variables || []) {
      if (v.origin?.source_location) {
        if (!v.origin.source_location.file) {
          errors.push(`Variable '${v.name}' specifies source location with missing file.`);
        }
      }
    }

    // 4. False-Proof Defense: Under-constrained model detection
    // Example: caller and owner exist, but no relationship or security predicate binds them.
    let underconstrained = false;
    const hasCaller = definedSymbols.has('caller') || definedSymbols.has('caller_id');
    const hasOwner = definedSymbols.has('owner') || definedSymbols.has('resource_owner');

    if (hasCaller && hasOwner) {
      const mentionsBoth = (model.constraints || []).some((c) => {
        const text = c.smt_representation;
        return (text.includes('caller') || text.includes('caller_id')) &&
               (text.includes('owner') || text.includes('resource_owner'));
      });

      if (!mentionsBoth) {
        underconstrained = true;
        warnings.push('MODEL_UNDERCONSTRAINED: Model defines caller and owner, but contains no relational constraint or equality guard connecting them.');
      }
    }

    // 5. False-Proof Defense: Assumption-dependent detection
    // If all authorization guards in the model are purely assumptions rather than observed source facts
    let assumptionDependent = false;
    const authConstraints = (model.constraints || []).filter((c) =>
      c.smt_representation.includes('caller') ||
      c.smt_representation.includes('owner') ||
      c.smt_representation.includes('operator') ||
      c.smt_representation.includes('role')
    );

    if (authConstraints.length > 0 && authConstraints.every((c) => c.is_assumption)) {
      assumptionDependent = true;
      warnings.push('ASSUMPTION_DEPENDENT: All authorization constraints in model are unverified assumptions; proof will not reflect actual source behavior.');
    }

    const valid = errors.length === 0;

    return {
      valid,
      underconstrained,
      assumption_dependent: assumptionDependent,
      errors,
      warnings,
    };
  }

  /**
   * Diagnostic check evaluating soundness status of a formal model.
   */
  static checkSoundness(model: FormalModelDefinition): {
    is_sound: boolean;
    status: ModelSoundnessStatus;
    issues: string[];
    warnings: string[];
  } {
    const issues: string[] = [];
    const warnings: string[] = [];

    // 1. Check if model has zero constraints
    if (!model.constraints || model.constraints.length === 0) {
      issues.push('Model contains zero constraints or relations.');
      return {
        is_sound: false,
        status: ModelSoundnessStatus.MODEL_UNDERCONSTRAINED,
        issues,
        warnings,
      };
    }

    // 2. Check for mutually contradictory constraints
    const constraintRepresentations = model.constraints.map((c) => c.smt_representation);
    for (let i = 0; i < constraintRepresentations.length; i++) {
      for (let j = i + 1; j < constraintRepresentations.length; j++) {
        const c1 = constraintRepresentations[i];
        const c2 = constraintRepresentations[j];
        const boolMatch1 = c1.match(/\(=\s+([a-zA-Z_0-9]+)\s+(true|false)\)/);
        const boolMatch2 = c2.match(/\(=\s+([a-zA-Z_0-9]+)\s+(true|false)\)/);
        if (boolMatch1 && boolMatch2 && boolMatch1[1] === boolMatch2[1] && boolMatch1[2] !== boolMatch2[2]) {
          issues.push(
            `Mutually contradictory constraints detected in formal model: ${model.constraints[i].name} and ${model.constraints[j].name}`
          );
          return {
            is_sound: false,
            status: ModelSoundnessStatus.CONTRADICTORY_MODEL,
            issues,
            warnings,
          };
        }
      }
    }

    // 3. Check for assumption dependence
    const hasSourceFacts =
      (model.source_facts && model.source_facts.length > 0) ||
      (model.sourceFacts && model.sourceFacts.length > 0);
    const allAssumptions = model.constraints.every((c) => c.is_assumption);
    if (allAssumptions || (!hasSourceFacts && model.constraints.some((c) => c.is_assumption))) {
      warnings.push('Model constraints rely purely on assumptions without grounded source facts.');
      return {
        is_sound: false,
        status: ModelSoundnessStatus.ASSUMPTION_DEPENDENT,
        issues,
        warnings,
      };
    }

    // 4. General validation
    const validation = ModelSoundnessChecker.validate(model);
    if (!validation.valid) {
      return {
        is_sound: false,
        status: ModelSoundnessStatus.INVALID_SYNTAX,
        issues: validation.errors,
        warnings: validation.warnings,
      };
    }

    if (validation.underconstrained) {
      issues.push('Model contains under-constrained variables.');
      return {
        is_sound: false,
        status: ModelSoundnessStatus.MODEL_UNDERCONSTRAINED,
        issues,
        warnings: validation.warnings,
      };
    }

    return {
      is_sound: true,
      status: ModelSoundnessStatus.SOUND,
      issues,
      warnings,
    };
  }
}
