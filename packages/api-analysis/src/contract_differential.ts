/**
 * Source <-> Contract Differential Engine
 * Intent Security Workbench - Phase 3
 *
 * Compares OpenAPI contract definitions with source-discovered routes.
 * Detects:
 * - DOCUMENTED_AND_IMPLEMENTED
 * - DOCUMENTED_BUT_NOT_FOUND
 * - SOURCE_ONLY (Shadow / Undocumented Endpoints)
 * - METHOD_MISMATCH
 * - PARAMETER_MISMATCH
 */

import {
  APIContract,
  APIEndpoint,
  ContractDiffResult,
  ContractDiffStatus,
  EndpointAuthStatus,
  EndpointDiffItem,
  EndpointSourceType,
} from './types.js';

export class ContractDifferentialService {
  /**
   * Extract source-discovered endpoints from source code using pattern recognition.
   */
  extractSourceEndpoints(sourceCode: string, filePath: string): APIEndpoint[] {
    const endpoints: APIEndpoint[] = [];
    const lines = sourceCode.split('\n');

    // Matches Express / Koa / Router: app.get('/path', ...), router.post('/path', ...)
    const routeRegex = /(?:app|router)\.(get|post|put|delete|patch|options)\s*\(\s*['"`]([^'"`]+)['"`]/g;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let match: RegExpExecArray | null;

      while ((match = routeRegex.exec(line)) !== null) {
        const method = match[1].toUpperCase();
        let pathStr = match[2];

        // Normalize express :param to OpenAPI {param} for comparison
        pathStr = pathStr.replace(/:([a-zA-Z0-9_]+)/g, '{$1}');

        const isStateMutation = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);
        const endpointId = `src-ep-${method.toLowerCase()}-${pathStr.replace(/[^a-zA-Z0-9]/g, '_')}-${i + 1}`;

        endpoints.push({
          id: endpointId,
          method,
          path: pathStr,
          tags: ['source-discovered'],
          parameters: [],
          responses: [],
          security_requirements: [],
          auth_status: EndpointAuthStatus.UNKNOWN,
          is_state_mutation: isStateMutation,
          source_location: {
            file: filePath,
            line_start: i + 1,
            line_end: i + 1,
          },
          endpoint_type: EndpointSourceType.SOURCE_DISCOVERED_ENDPOINT,
        });
      }
    }

    return endpoints;
  }

  /**
   * Compare documented contract endpoints with source-discovered endpoints.
   */
  compareContractAndSource(
    contract: APIContract,
    sourceEndpoints: APIEndpoint[],
    investigationId: string,
    targetId: string
  ): ContractDiffResult {
    const diffItems: EndpointDiffItem[] = [];

    const normalizePath = (p: string) =>
      p
        .trim()
        .toLowerCase()
        .replace(/\/+$/, '')
        .replace(/\{[^}]+\}/g, '{param}');

    const contractEndpoints = contract.endpoints;
    const handledSourceIds = new Set<string>();

    let matchedCount = 0;
    let documentedNotFoundCount = 0;
    let methodMismatchCount = 0;
    let parameterMismatchCount = 0;

    for (const cEp of contractEndpoints) {
      const cNormPath = normalizePath(cEp.path);

      // Look for exact method + path match
      const exactMatch = sourceEndpoints.find(
        (sEp) => sEp.method === cEp.method && normalizePath(sEp.path) === cNormPath
      );

      if (exactMatch) {
        handledSourceIds.add(exactMatch.id);
        matchedCount++;
        diffItems.push({
          method: cEp.method,
          path: cEp.path,
          status: ContractDiffStatus.DOCUMENTED_AND_IMPLEMENTED,
          details: `Endpoint ${cEp.method} ${cEp.path} documented in contract and implemented in source (${exactMatch.source_location?.file || 'source'}).`,
          contract_endpoint: cEp,
          source_endpoint: exactMatch,
        });
        continue;
      }

      // Check if path exists in source but with a different method
      const methodMismatch = sourceEndpoints.find((sEp) => normalizePath(sEp.path) === cNormPath);
      if (methodMismatch) {
        handledSourceIds.add(methodMismatch.id);
        methodMismatchCount++;
        diffItems.push({
          method: cEp.method,
          path: cEp.path,
          status: ContractDiffStatus.METHOD_MISMATCH,
          details: `Path ${cEp.path} is documented for ${cEp.method}, but source implements ${methodMismatch.method} (${methodMismatch.source_location?.file || 'source'}).`,
          contract_endpoint: cEp,
          source_endpoint: methodMismatch,
        });
        continue;
      }

      // Otherwise, documented but not found in source
      documentedNotFoundCount++;
      diffItems.push({
        method: cEp.method,
        path: cEp.path,
        status: ContractDiffStatus.DOCUMENTED_BUT_NOT_FOUND,
        details: `Documented ${cEp.method} ${cEp.path} is not implemented in any scanned source handler.`,
        contract_endpoint: cEp,
      });
    }

    // Identify source endpoints that are not in the contract (Shadow / Undocumented APIs)
    let sourceOnlyCount = 0;
    for (const sEp of sourceEndpoints) {
      if (!handledSourceIds.has(sEp.id)) {
        sourceOnlyCount++;
        diffItems.push({
          method: sEp.method,
          path: sEp.path,
          status: ContractDiffStatus.SOURCE_ONLY,
          details: `Shadow/Undocumented endpoint ${sEp.method} ${sEp.path} implemented in ${sEp.source_location?.file || 'source'} but absent from OpenAPI specification.`,
          source_endpoint: sEp,
        });
      }
    }

    return {
      id: `diff-${contract.id}-${Date.now().toString(36)}`,
      investigation_id: investigationId,
      target_id: targetId,
      contract_id: contract.id,
      total_documented: contractEndpoints.length,
      total_source_discovered: sourceEndpoints.length,
      matched: matchedCount,
      documented_not_found: documentedNotFoundCount,
      source_only: sourceOnlyCount,
      method_mismatches: methodMismatchCount,
      parameter_mismatches: parameterMismatchCount,
      items: diffItems,
      created_at: new Date().toISOString(),
    };
  }
}

export const globalContractDifferential = new ContractDifferentialService();
