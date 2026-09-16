/**
 * Authorization Candidate Analyzer & Extensible Boundary Engine
 * Intent Security Workbench - Phase 3
 *
 * Specializes in Object-Level Authorization (OWASP API1 BOLA / IDOR).
 * Combines OpenAPI metadata, AST structure, Semgrep data flow,
 * and boundary inspection to form deterministic candidates with reasoning chains.
 */

import {
  APIContract,
  APIEndpoint,
  AuthorizationBoundary,
  AuthorizationCandidate,
  BoundaryType,
  DeterministicRiskSignal,
  EndpointAuthStatus,
  ParameterIdentifierRole,
  ReasoningChainStep,
} from './types.js';

export interface SourceAnalysisContext {
  file: string;
  sourceCode: string;
  findings?: any[];
  astArtifacts?: any[];
}

export class AuthorizationAnalyzerService {
  /**
   * Scan source code for explicit authorization boundaries.
   */
  detectAuthorizationBoundaries(sourceCode: string, filePath: string): AuthorizationBoundary[] {
    const boundaries: AuthorizationBoundary[] = [];
    const lines = sourceCode.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // 1. Caller == Owner (e.g. caller == owner, msg.sender == owner, user.id === resource.owner_id)
      if (
        /caller\s*==\s*owner/i.test(line) ||
        /msg\.sender\s*==\s*owner/i.test(line) ||
        /user\.id\s*={2,3}\s*resource\.owner/i.test(line) ||
        /req\.user\.id\s*={2,3}\s*\w+\.owner/i.test(line) ||
        /assert\s*\(\s*caller\s*==\s*owner\s*\)/i.test(line) ||
        /require\s*\(\s*caller\s*==\s*owner/i.test(line)
      ) {
        boundaries.push({
          id: `bnd-owner-${lineNum}`,
          boundary_type: BoundaryType.CALLER_EQUALS_OWNER,
          location: { file: filePath, line: lineNum, code_snippet: line.trim() },
          source: 'Ownership Equality Condition',
          evidence: `Direct equality check between invoking caller and resource owner: "${line.trim()}"`,
          confidence_basis: 'Explicit caller-to-owner subject validation statement.',
          satisfies_ownership: true,
        });
      }

      // 2. Tenant isolation check (e.g. caller.tenant_id == resource.tenant_id)
      if (
        /caller\.tenant_id\s*={2,3}\s*resource\.tenant_id/i.test(line) ||
        /user\.tenant_?id\s*={2,3}\s*\w+\.tenant_?id/i.test(line) ||
        /assert\s*\(\s*caller\.tenant_id\s*==\s*resource\.tenant_id\s*\)/i.test(line)
      ) {
        boundaries.push({
          id: `bnd-tenant-${lineNum}`,
          boundary_type: BoundaryType.CALLER_TENANT_EQUALS_RESOURCE_TENANT,
          location: { file: filePath, line: lineNum, code_snippet: line.trim() },
          source: 'Tenant Boundary Assertion',
          evidence: `Multi-tenant boundary enforcement assertion: "${line.trim()}"`,
          confidence_basis: 'Direct tenant scoping comparison prevents cross-tenant access.',
          satisfies_ownership: true,
        });
      }

      // 3. Role check (e.g. caller.role == "depositor", user.role === "admin", hasRole(...))
      // CRITICAL REQUIREMENT: A role check alone does NOT count as ownership authorization!
      if (
        /caller\.role\s*={2,3}\s*["']\w+["']/i.test(line) ||
        /user\.role(s)?\s*={2,3}\s*["']\w+["']/i.test(line) ||
        /roles?\.includes\s*\(/i.test(line) ||
        /hasRole\s*\(/i.test(line) ||
        /requireRole\s*\(/i.test(line) ||
        /checkRole\s*\(/i.test(line) ||
        /inRole\s*\(/i.test(line)
      ) {
        boundaries.push({
          id: `bnd-role-${lineNum}`,
          boundary_type: BoundaryType.ROLE_CHECK,
          location: { file: filePath, line: lineNum, code_snippet: line.trim() },
          source: 'Role-Based Access Control Condition',
          evidence: `Role membership check: "${line.trim()}"`,
          confidence_basis: 'Verifies caller role attribute, but does NOT establish object ownership or tenant isolation.',
          satisfies_ownership: false, // Explicitly false!
        });
      }

      // 4. Permission / ACL Check
      if (/hasPermission\s*\(/i.test(line) || /checkAcl\s*\(/i.test(line) || /canAccess\s*\(/i.test(line)) {
        boundaries.push({
          id: `bnd-acl-${lineNum}`,
          boundary_type: BoundaryType.ACL_CHECK,
          location: { file: filePath, line: lineNum, code_snippet: line.trim() },
          source: 'Access Control List Query',
          evidence: `Permission or ACL evaluation invocation: "${line.trim()}"`,
          confidence_basis: 'Explicit permission evaluator statement.',
          satisfies_ownership: true,
        });
      }

      // 5. Auth Middleware / Decorator
      if (/@authorized/i.test(line) || /@requireAuth/i.test(line) || /authenticateMiddleware/i.test(line)) {
        boundaries.push({
          id: `bnd-mw-${lineNum}`,
          boundary_type: BoundaryType.MIDDLEWARE,
          location: { file: filePath, line: lineNum, code_snippet: line.trim() },
          source: 'Route Middleware / Decorator',
          evidence: `Authentication/authorization middleware gate: "${line.trim()}"`,
          confidence_basis: 'Framework-level handler pipeline middleware.',
          satisfies_ownership: false, // Middleware ensures authentication, rarely object ownership
        });
      }
    }

    return boundaries;
  }

  /**
   * Extracts the route handler body corresponding to a specific endpoint to avoid boundary leakage across routes.
   */
  private extractHandlerBlock(sourceCode: string, endpoint: APIEndpoint): string | null {
    const lines = sourceCode.split('\n');
    const pathPattern = endpoint.path.replace(/\{([^}]+)\}/g, '(:$1|\\{$1\\})');
    const pathRegex = new RegExp(pathPattern, 'i');

    let startLine = -1;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (pathRegex.test(line)) {
        const methodRegex = new RegExp(endpoint.method, 'i');
        if (methodRegex.test(line) || (i > 0 && methodRegex.test(lines[i - 1])) || (i < lines.length - 1 && methodRegex.test(lines[i + 1]))) {
          startLine = i;
          break;
        } else if (startLine === -1) {
          startLine = i;
        }
      }
    }

    if (startLine === -1) return null;

    let endLine = Math.min(lines.length, startLine + 40);
    let openBraces = 0;
    let foundOpen = false;

    for (let j = startLine; j < lines.length; j++) {
      const line = lines[j];
      for (const ch of line) {
        if (ch === '{') {
          openBraces++;
          foundOpen = true;
        } else if (ch === '}') {
          openBraces--;
          if (foundOpen && openBraces <= 0) {
            endLine = j + 1;
            return lines.slice(startLine, endLine).join('\n');
          }
        }
      }
      if (j > startLine && /(app|router)\.(get|post|put|delete|patch)\s*\(/i.test(line)) {
        endLine = j;
        break;
      }
    }

    return lines.slice(startLine, endLine).join('\n');
  }

  /**
   * Analyze an API endpoint in context of contract & source code for authorization vulnerabilities.
   */
  analyzeEndpointAuthorization(
    endpoint: APIEndpoint,
    contract: APIContract,
    sourceContexts: SourceAnalysisContext[],
    investigationId: string,
    targetId: string
  ): AuthorizationCandidate | null {
    // 1. Check if endpoint accepts object identifiers
    const objectIdParams = endpoint.parameters.filter(
      (p) =>
        p.identifier_role === ParameterIdentifierRole.OBJECT_ID ||
        p.identifier_role === ParameterIdentifierRole.RESOURCE_ID ||
        p.identifier_role === ParameterIdentifierRole.OWNER_ID ||
        p.identifier_role === ParameterIdentifierRole.ACCOUNT_ID ||
        p.identifier_role === ParameterIdentifierRole.USER_ID ||
        p.identifier_role === ParameterIdentifierRole.TENANT_ID
    );

    const hasObjectId = objectIdParams.length > 0;
    const isStateMutation = endpoint.is_state_mutation;
    const isAuthenticated = endpoint.auth_status === EndpointAuthStatus.AUTHENTICATED_ENDPOINT;

    // Look for matching source context
    let matchedSource: SourceAnalysisContext | undefined;
    const normalizedPath = endpoint.path.replace(/\{[^}]+\}/g, '').toLowerCase();

    for (const ctx of sourceContexts) {
      if (
        ctx.sourceCode.includes(endpoint.path) ||
        (normalizedPath.length > 2 && ctx.sourceCode.toLowerCase().includes(normalizedPath)) ||
        (endpoint.operation_id && ctx.sourceCode.includes(endpoint.operation_id))
      ) {
        matchedSource = ctx;
        break;
      }
    }

    const detectedBoundaries: AuthorizationBoundary[] = [];
    if (matchedSource) {
      const handlerBlock = this.extractHandlerBlock(matchedSource.sourceCode, endpoint);
      const codeToScan = handlerBlock || matchedSource.sourceCode;
      const bnds = this.detectAuthorizationBoundaries(codeToScan, matchedSource.file);
      detectedBoundaries.push(...bnds);
    } else {
      // If no exact file match, check all loaded source contexts for boundaries
      for (const ctx of sourceContexts) {
        const bnds = this.detectAuthorizationBoundaries(ctx.sourceCode, ctx.file);
        detectedBoundaries.push(...bnds);
      }
    }

    // Check if any boundary satisfies true object ownership or tenant isolation
    const hasOwnershipBoundary = detectedBoundaries.some((b) => b.satisfies_ownership === true);

    // If an ownership boundary is present (e.g. caller == owner or caller.tenant_id == resource.tenant_id),
    // then no BOLA candidate should be generated!
    if (hasOwnershipBoundary) {
      return null;
    }

    // If endpoint has object id AND is state-mutating, or has Semgrep/Tree-sitter findings matching BOLA:
    // Determine if candidate should be formed
    const hasSensitiveKeyword = /vault|deposit|transfer|withdraw|account|balance|delete|destroy|update|burn|admin/i.test(
      `${endpoint.path} ${endpoint.operation_id || ''}`
    );

    // Also check if any Semgrep finding exists in source for BOLA / IDOR
    let semgrepFindingCorroboration: any = null;
    if (matchedSource?.findings) {
      semgrepFindingCorroboration = matchedSource.findings.find(
        (f: any) =>
          f.owasp?.some((o: string) => o.includes('API1') || o.includes('BOLA')) ||
          f.title?.toLowerCase().includes('bola') ||
          f.title?.toLowerCase().includes('idor')
      );
    }

    if (!hasObjectId && !hasSensitiveKeyword && !semgrepFindingCorroboration) {
      return null;
    }

    // Build Deterministic Risk Signals
    const signals: DeterministicRiskSignal[] = [
      {
        code: 'AUTHENTICATED_ENDPOINT',
        name: 'Authenticated Endpoint',
        weight: 15,
        present: isAuthenticated,
        rationale: isAuthenticated
          ? 'Endpoint enforces authentication, establishing legitimate caller context.'
          : 'Endpoint does not declare authentication requirements.',
      },
      {
        code: 'OBJECT_IDENTIFIER',
        name: 'Object Identifier Present',
        weight: 25,
        present: hasObjectId,
        rationale: hasObjectId
          ? `Accepts direct entity identifiers: [${objectIdParams.map((p) => p.name).join(', ')}].`
          : 'No explicit object identifiers detected in parameters.',
      },
      {
        code: 'STATE_MUTATION',
        name: 'State Mutating Operation',
        weight: 20,
        present: isStateMutation,
        rationale: isStateMutation
          ? `HTTP method ${endpoint.method} performs state change on server.`
          : 'HTTP method is idempotent or read-only.',
      },
      {
        code: 'SENSITIVE_RESOURCE',
        name: 'Sensitive Resource Semantics',
        weight: 15,
        present: hasSensitiveKeyword,
        rationale: hasSensitiveKeyword
          ? `URI "${endpoint.path}" involves high-value domain entities.`
          : 'Standard resource category.',
      },
      {
        code: 'USER_CONTROLLED_SOURCE',
        name: 'User-Controlled Key Lookup',
        weight: 15,
        present: hasObjectId,
        rationale: hasObjectId
          ? 'Client-supplied identifier parameter is passed directly to data store lookup.'
          : 'Identifier is derived from session context.',
      },
      {
        code: 'NO_IDENTIFIED_OWNERSHIP_CHECK',
        name: 'Missing Ownership Boundary',
        weight: 25,
        present: !hasOwnershipBoundary,
        rationale: detectedBoundaries.length > 0
          ? 'Found access checks (e.g. role check), but none establish object ownership or tenant isolation.'
          : 'Zero authorization boundaries discovered between caller and resource lookup.',
      },
      {
        code: 'SEMGREP_TAINT_EVIDENCE',
        name: 'Semgrep Taint Corroboration',
        weight: 20,
        present: Boolean(semgrepFindingCorroboration),
        rationale: semgrepFindingCorroboration
          ? `Semgrep rule "${semgrepFindingCorroboration.rule_id}" verified tainted data flow to sensitive sink.`
          : 'No direct static analysis taint finding linked.',
      },
    ];

    const priorityScore = signals.reduce((acc, sig) => (sig.present ? acc + sig.weight : acc), 0);

    // Build Step-by-Step Reasoning Chain
    const reasoningChain: ReasoningChainStep[] = [
      {
        step: 1,
        label: 'Endpoint Definition',
        detail: `${endpoint.method} ${endpoint.path} documented in OpenAPI contract.`,
        status: 'OBSERVED',
      },
      {
        step: 2,
        label: 'Authentication Scheme',
        detail: isAuthenticated
          ? `Secured via ${endpoint.security_requirements.map((s) => s.schemeName).join(', ') || 'Global Security'}.`
          : 'No security requirement defined.',
        status: isAuthenticated ? 'IDENTIFIED' : 'MISSING',
      },
      {
        step: 3,
        label: 'Object Identifier Resolution',
        detail: hasObjectId
          ? `Parameters identifying object: [${objectIdParams.map((p) => `${p.name} (${p.identifier_role})`).join(', ')}].`
          : 'No identifier found in path template.',
        status: hasObjectId ? 'IDENTIFIED' : 'MISSING',
      },
      {
        step: 4,
        label: 'Operation Mutation Type',
        detail: isStateMutation
          ? `${endpoint.method} performs state modification on backend.`
          : 'Read-only access operation.',
        status: isStateMutation ? 'IDENTIFIED' : 'OBSERVED',
      },
      {
        step: 5,
        label: 'User Controlled Key Flow',
        detail: `Caller supplies "${objectIdParams[0]?.name || 'key'}" directly in HTTP request.`,
        status: 'OBSERVED',
      },
      {
        step: 6,
        label: 'Resource Lookup Sink',
        detail: matchedSource ? `Implementation in ${matchedSource.file} queries record.` : 'Source implementation queried.',
        status: 'OBSERVED',
      },
      {
        step: 7,
        label: 'Authorization Boundary Check',
        detail: detectedBoundaries.some((b) => b.boundary_type === BoundaryType.ROLE_CHECK)
          ? 'Role-based check identified; does NOT verify caller is resource owner.'
          : 'NOT IDENTIFIED. No caller == owner or tenant isolation statement detected.',
        status: 'NOT_IDENTIFIED',
      },
      {
        step: 8,
        label: 'Candidate Synthesis',
        detail: 'Synthesized POTENTIAL_BOLA candidate for verification pipeline. Status remains CANDIDATE.',
        status: 'IDENTIFIED',
      },
    ];

    const candId = `cand-auth-${endpoint.id}-${Date.now().toString(36)}`;

    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
    if (priorityScore >= 70) severity = 'HIGH';
    if (priorityScore >= 90) severity = 'CRITICAL';

    return {
      id: candId,
      investigation_id: investigationId,
      target_id: targetId,
      contract_id: contract.id,
      endpoint_id: endpoint.id,
      method: endpoint.method,
      path: endpoint.path,
      title: `[OWASP API1] Potential BOLA / IDOR in ${endpoint.method} ${endpoint.path}`,
      status: 'CANDIDATE', // Invariant: always CANDIDATE in Phase 3
      severity,
      vulnerability_type: 'POTENTIAL_BOLA',
      owasp_category: 'API1:2023-Broken Object Level Authorization',
      parameters: endpoint.parameters,
      identified_boundaries: detectedBoundaries,
      has_ownership_boundary: false,
      risk_signals: signals,
      priority_score: priorityScore,
      reasoning_chain: reasoningChain,
      evidence_artifact_ids: [],
      source_location: matchedSource
        ? {
            file: matchedSource.file,
            line_start: 1,
            line_end: matchedSource.sourceCode.split('\n').length,
          }
        : undefined,
      created_at: new Date().toISOString(),
    };
  }
}

export const globalAuthorizationAnalyzer = new AuthorizationAnalyzerService();
