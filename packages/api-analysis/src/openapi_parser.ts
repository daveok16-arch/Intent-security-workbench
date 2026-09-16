/**
 * Real OpenAPI 3.x / Swagger 2.0 Parser and Contract Validator
 * Intent Security Workbench - Phase 3
 */

import crypto from 'crypto';
import * as jsYaml from 'js-yaml';
import {
  APIContract,
  APIEndpoint,
  APIParameter,
  ContractValidationIssue,
  EndpointAuthStatus,
  EndpointSourceType,
  ParameterIdentifierRole,
  SecuritySchemeDefinition,
  SecuritySchemeType,
} from './types.js';

export class OpenAPIParserService {
  /**
   * Parse raw specification content (JSON or YAML) and return normalized APIContract.
   */
  parseSpecification(
    rawContent: string,
    specificationPath: string,
    targetId: string,
    investigationId: string,
    sourceSnapshotId?: string
  ): { contract: APIContract; validationIssues: ContractValidationIssue[] } {
    const hash = crypto.createHash('sha256').update(rawContent).digest('hex');
    const validationIssues: ContractValidationIssue[] = [];

    let parsedDoc: any;
    try {
      if (rawContent.trim().startsWith('{')) {
        parsedDoc = JSON.parse(rawContent);
      } else {
        const yamlLoader = typeof (jsYaml as any).load === 'function' 
          ? (jsYaml as any).load 
          : typeof (jsYaml as any).default?.load === 'function'
          ? (jsYaml as any).default.load
          : (jsYaml as any);
        parsedDoc = yamlLoader(rawContent);
      }
    } catch (err: any) {
      validationIssues.push({
        id: `val-syntax-${Date.now()}`,
        code: 'INVALID_SYNTAX',
        message: `Failed to parse specification syntax: ${err.message}`,
        severity: 'ERROR',
        path: specificationPath,
      });

      const fallbackContract: APIContract = {
        id: `contract-${hash.substring(0, 12)}`,
        target_id: targetId,
        investigation_id: investigationId,
        source_snapshot_id: sourceSnapshotId,
        specification_path: specificationPath,
        specification_hash: hash,
        openapi_version: 'UNKNOWN',
        title: 'Malformed Specification',
        server_definitions: [],
        security_schemes: [],
        endpoints: [],
        validation_issues: validationIssues,
        retrieved_at: new Date().toISOString(),
      };
      return { contract: fallbackContract, validationIssues };
    }

    if (!parsedDoc || typeof parsedDoc !== 'object') {
      validationIssues.push({
        id: `val-empty-${Date.now()}`,
        code: 'EMPTY_SPECIFICATION',
        message: 'Specification content does not contain a valid object',
        severity: 'ERROR',
        path: specificationPath,
      });
      const emptyContract: APIContract = {
        id: `contract-${hash.substring(0, 12)}`,
        target_id: targetId,
        investigation_id: investigationId,
        source_snapshot_id: sourceSnapshotId,
        specification_path: specificationPath,
        specification_hash: hash,
        openapi_version: 'UNKNOWN',
        title: 'Empty Specification',
        server_definitions: [],
        security_schemes: [],
        endpoints: [],
        validation_issues: validationIssues,
        retrieved_at: new Date().toISOString(),
      };
      return { contract: emptyContract, validationIssues };
    }

    const openapiVersion = parsedDoc.openapi || (parsedDoc.swagger ? `swagger-${parsedDoc.swagger}` : 'UNKNOWN');
    const info = parsedDoc.info || {};
    const title = info.title || 'Untitled API';
    const description = info.description;

    if (!parsedDoc.openapi && !parsedDoc.swagger) {
      validationIssues.push({
        id: `val-ver-${Date.now()}`,
        code: 'MISSING_OPENAPI_VERSION',
        message: 'Specification root is missing "openapi" or "swagger" version declaration.',
        severity: 'ERROR',
        path: '#',
      });
    }

    // 1. Server Definitions
    const serverDefinitions: Array<{ url: string; description?: string }> = [];
    if (Array.isArray(parsedDoc.servers)) {
      for (const s of parsedDoc.servers) {
        if (s && s.url) {
          serverDefinitions.push({ url: s.url, description: s.description });
        }
      }
    } else if (parsedDoc.host) {
      const scheme = (parsedDoc.schemes && parsedDoc.schemes[0]) || 'https';
      const basePath = parsedDoc.basePath || '';
      serverDefinitions.push({ url: `${scheme}://${parsedDoc.host}${basePath}` });
    }

    // 2. Security Schemes
    const securitySchemes: SecuritySchemeDefinition[] = [];
    const components = parsedDoc.components || {};
    const rawSecSchemes = components.securitySchemes || parsedDoc.securityDefinitions || {};

    for (const [schemeKey, secObj] of Object.entries<any>(rawSecSchemes)) {
      if (!secObj || typeof secObj !== 'object') {
        validationIssues.push({
          id: `val-sec-malformed-${schemeKey}`,
          code: 'MALFORMED_SECURITY_SCHEME',
          message: `Security scheme "${schemeKey}" is malformed or not an object.`,
          severity: 'ERROR',
          path: `#/components/securitySchemes/${schemeKey}`,
        });
        continue;
      }

      let secType = SecuritySchemeType.UNKNOWN;
      const typeLower = (secObj.type || '').toLowerCase();
      const schemeLower = (secObj.scheme || '').toLowerCase();

      if (typeLower === 'http' && schemeLower === 'bearer') {
        secType = SecuritySchemeType.HTTP_BEARER;
      } else if (typeLower === 'http' && schemeLower === 'basic') {
        secType = SecuritySchemeType.HTTP_BASIC;
      } else if (typeLower === 'basic') {
        secType = SecuritySchemeType.HTTP_BASIC;
      } else if (typeLower === 'apikey') {
        secType = SecuritySchemeType.API_KEY;
      } else if (typeLower === 'oauth2') {
        secType = SecuritySchemeType.OAUTH2;
      } else if (typeLower === 'openidconnect') {
        secType = SecuritySchemeType.OPENID_CONNECT;
      }

      securitySchemes.push({
        name: schemeKey,
        type: secType,
        scheme: secObj.scheme,
        bearerFormat: secObj.bearerFormat,
        in: secObj.in,
        flows: secObj.flows,
        scopes: secObj.scopes ? Object.keys(secObj.scopes) : undefined,
        description: secObj.description,
      });
    }

    // Check spec-level default security
    const globalSecurity: Array<{ schemeName: string; scopes: string[] }> = [];
    if (Array.isArray(parsedDoc.security)) {
      for (const secRequirement of parsedDoc.security) {
        for (const [sName, scopes] of Object.entries<any>(secRequirement)) {
          globalSecurity.push({
            schemeName: sName,
            scopes: Array.isArray(scopes) ? scopes : [],
          });
        }
      }
    }

    // 3. Structural Validation: Broken References
    this.detectBrokenReferences(parsedDoc, validationIssues);

    // 4. Endpoints & Operations
    const endpoints: APIEndpoint[] = [];
    const paths = parsedDoc.paths || {};

    const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'trace'];

    for (const [pathStr, pathItem] of Object.entries<any>(paths)) {
      if (!pathItem || typeof pathItem !== 'object') continue;

      // Extract path-level parameters
      const pathLevelParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];

      for (const methodKey of HTTP_METHODS) {
        if (!pathItem[methodKey]) continue;
        const op = pathItem[methodKey];
        const methodUpper = methodKey.toUpperCase();
        const opId = op.operationId;

        if (!opId) {
          validationIssues.push({
            id: `val-opid-${methodUpper}-${pathStr}`,
            code: 'MISSING_OPERATION_ID',
            message: `Endpoint ${methodUpper} ${pathStr} is missing an operationId.`,
            severity: 'INFO',
            path: `#/paths/${pathStr}/${methodKey}/operationId`,
          });
        }

        // Combine parameters (path-level + operation-level)
        const combinedRawParams: any[] = [...pathLevelParams, ...(Array.isArray(op.parameters) ? op.parameters : [])];
        const parameters: APIParameter[] = [];

        // Check path template vs parameters
        const templateVarMatches = pathStr.match(/\{([^}]+)\}/g) || [];
        const templateVarNames = templateVarMatches.map((m) => m.slice(1, -1));

        for (const rawParam of combinedRawParams) {
          // Resolve if $ref
          const p = this.resolveParam(rawParam, parsedDoc);
          if (!p || !p.name) continue;

          const location = (p.in || 'query').toLowerCase() as 'path' | 'query' | 'header' | 'cookie';
          const required = location === 'path' ? true : Boolean(p.required);

          if (location === 'path' && p.required === false) {
            validationIssues.push({
              id: `val-param-path-req-${methodUpper}-${pathStr}-${p.name}`,
              code: 'PATH_PARAMETER_MUST_BE_REQUIRED',
              message: `Path parameter "${p.name}" in ${methodUpper} ${pathStr} must have required: true.`,
              severity: 'WARNING',
              path: `#/paths/${pathStr}/${methodKey}/parameters`,
            });
          }

          const { role, reason } = this.classifyParameter(p.name, location, pathStr, p.schema, p.description);

          parameters.push({
            name: p.name,
            location,
            schema: p.schema,
            required,
            identifier_role: role,
            classification_reason: reason,
          });
        }

        // Check for missing parameters declared in path template
        for (const varName of templateVarNames) {
          const found = parameters.some((param) => param.name === varName && param.location === 'path');
          if (!found) {
            validationIssues.push({
              id: `val-missing-path-param-${methodUpper}-${pathStr}-${varName}`,
              code: 'PATH_VARIABLE_UNDECLARED',
              message: `Path template variable "{${varName}}" in ${methodUpper} ${pathStr} is not defined in parameters list.`,
              severity: 'ERROR',
              path: `#/paths/${pathStr}/${methodKey}`,
            });
          }
        }

        // Security requirements for endpoint
        let endpointSecurity: Array<{ schemeName: string; scopes: string[] }> = [];
        let authStatus = EndpointAuthStatus.UNKNOWN;

        if (Array.isArray(op.security)) {
          if (op.security.length === 0) {
            // Explicitly empty array means PUBLIC endpoint
            authStatus = EndpointAuthStatus.PUBLIC_ENDPOINT;
          } else {
            for (const secReq of op.security) {
              const keys = Object.keys(secReq);
              if (keys.length === 0) {
                // Empty object `{}` in security array denotes public override
                authStatus = EndpointAuthStatus.PUBLIC_ENDPOINT;
              } else {
                for (const [sName, scopes] of Object.entries<any>(secReq)) {
                  endpointSecurity.push({
                    schemeName: sName,
                    scopes: Array.isArray(scopes) ? scopes : [],
                  });
                }
              }
            }
            if (endpointSecurity.length > 0) {
              authStatus = EndpointAuthStatus.AUTHENTICATED_ENDPOINT;
            }
          }
        } else if (globalSecurity.length > 0) {
          endpointSecurity = [...globalSecurity];
          authStatus = EndpointAuthStatus.AUTHENTICATED_ENDPOINT;
        } else {
          authStatus = EndpointAuthStatus.MISSING_SECURITY_DECLARATION;
          validationIssues.push({
            id: `val-sec-missing-${methodUpper}-${pathStr}`,
            code: 'MISSING_SECURITY_DECLARATION',
            message: `Endpoint ${methodUpper} ${pathStr} has no security requirement and no global security scheme declared.`,
            severity: 'INFO',
            path: `#/paths/${pathStr}/${methodKey}/security`,
          });
        }

        // Request Body
        let requestBodyObj: APIEndpoint['request_body'];
        if (op.requestBody) {
          const rb = op.requestBody;
          const contentTypes = rb.content ? Object.keys(rb.content) : [];
          requestBodyObj = {
            description: rb.description,
            required: Boolean(rb.required),
            contentTypes,
            schema: rb.content && contentTypes[0] ? rb.content[contentTypes[0]]?.schema : undefined,
          };
        }

        // State mutation check: POST, PUT, DELETE, PATCH
        const isStateMutation = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(methodUpper);
        if (isStateMutation && !requestBodyObj && parameters.filter((p) => p.location !== 'path').length === 0 && methodUpper !== 'DELETE') {
          validationIssues.push({
            id: `val-undocumented-body-${methodUpper}-${pathStr}`,
            code: 'UNDOCUMENTED_STATE_MUTATION_INPUT',
            message: `State-changing endpoint ${methodUpper} ${pathStr} has no documented requestBody or body parameters.`,
            severity: 'WARNING',
            path: `#/paths/${pathStr}/${methodKey}`,
          });
        }

        // Responses
        const responses: APIEndpoint['responses'] = [];
        if (op.responses && typeof op.responses === 'object') {
          for (const [code, respObj] of Object.entries<any>(op.responses)) {
            responses.push({
              statusCode: code,
              description: (respObj && respObj.description) || '',
              schema: respObj?.content ? Object.values(respObj.content)[0] as any : undefined,
            });
          }
        } else {
          validationIssues.push({
            id: `val-missing-resp-${methodUpper}-${pathStr}`,
            code: 'MISSING_RESPONSES',
            message: `Endpoint ${methodUpper} ${pathStr} does not declare responses.`,
            severity: 'ERROR',
            path: `#/paths/${pathStr}/${methodKey}`,
          });
        }

        const endpointId = `ep-${methodUpper.toLowerCase()}-${pathStr.replace(/[^a-zA-Z0-9]/g, '_')}`;

        endpoints.push({
          id: endpointId,
          method: methodUpper,
          path: pathStr,
          operation_id: opId,
          tags: Array.isArray(op.tags) ? op.tags : [],
          parameters,
          request_body: requestBodyObj,
          responses,
          security_requirements: endpointSecurity,
          auth_status: authStatus,
          is_state_mutation: isStateMutation,
          endpoint_type: EndpointSourceType.DOCUMENTED_ENDPOINT,
        });
      }
    }

    const contract: APIContract = {
      id: `contract-${hash.substring(0, 12)}`,
      target_id: targetId,
      investigation_id: investigationId,
      source_snapshot_id: sourceSnapshotId,
      specification_path: specificationPath,
      specification_hash: hash,
      openapi_version: openapiVersion,
      title,
      description,
      server_definitions: serverDefinitions,
      security_schemes: securitySchemes,
      endpoints,
      validation_issues: validationIssues,
      retrieved_at: new Date().toISOString(),
    };

    return { contract, validationIssues };
  }

  /**
   * Deterministic, contextual parameter classification.
   * Does NOT infer solely from name: inspects location, path template, schema, and description.
   */
  classifyParameter(
    name: string,
    location: 'path' | 'query' | 'header' | 'cookie',
    pathStr: string,
    schema?: Record<string, any>,
    description?: string
  ): { role: ParameterIdentifierRole; reason: string } {
    const lowerName = name.toLowerCase();
    const isPath = location === 'path';
    const schemaFormat = schema?.format || '';
    const descLower = (description || '').toLowerCase();

    // 1. Tenant identifier
    if (lowerName.includes('tenant') || descLower.includes('tenant id') || descLower.includes('organization id')) {
      return {
        role: ParameterIdentifierRole.TENANT_ID,
        reason: `Parameter "${name}" scopes data access to multi-tenant or organizational tenancy boundary (location: ${location}).`,
      };
    }

    // 2. Owner identifier
    if (lowerName === 'owner' || lowerName === 'owner_id' || lowerName === 'ownerid' || descLower.includes('resource owner')) {
      return {
        role: ParameterIdentifierRole.OWNER_ID,
        reason: `Parameter "${name}" explicitly designates ownership subject of the target entity.`,
      };
    }

    // 3. User identifier
    if (lowerName === 'user_id' || lowerName === 'userid' || lowerName === 'user' || descLower.includes('user identifier')) {
      return {
        role: ParameterIdentifierRole.USER_ID,
        reason: `Parameter "${name}" specifies user identity subject (location: ${location}).`,
      };
    }

    // 4. Account identifier
    if (lowerName.includes('account') || descLower.includes('account number') || descLower.includes('financial account')) {
      return {
        role: ParameterIdentifierRole.ACCOUNT_ID,
        reason: `Parameter "${name}" refers to an account instance entity in context of path ${pathStr}.`,
      };
    }

    // 5. Path Object / Resource Identifiers
    // When a parameter is in the path template (e.g. /vaults/{vault_id}, /items/{id}, /documents/{doc_id})
    if (isPath) {
      const segments = pathStr.split('/');
      const varIndex = segments.findIndex((s) => s === `{${name}}`);
      let contextEntity = 'resource';
      if (varIndex > 0) {
        contextEntity = segments[varIndex - 1].replace(/s$/, ''); // e.g. "vaults" -> "vault"
      }

      if (lowerName === 'id' || lowerName.endsWith('_id') || lowerName.endsWith('id')) {
        return {
          role: ParameterIdentifierRole.OBJECT_ID,
          reason: `Path parameter "{${name}}" identifies unique ${contextEntity} object entity in URL hierarchy "${pathStr}".`,
        };
      }

      return {
        role: ParameterIdentifierRole.RESOURCE_ID,
        reason: `Path parameter "{${name}}" serves as direct resource address in URI pattern "${pathStr}".`,
      };
    }

    // 6. Query or body identifier tokens with UUID or ID semantics
    if ((lowerName.endsWith('_id') || lowerName.endsWith('id') || lowerName === 'id') && (schemaFormat === 'uuid' || schema?.type === 'string' || schema?.type === 'integer')) {
      return {
        role: ParameterIdentifierRole.RESOURCE_ID,
        reason: `Identifier parameter "${name}" passed in ${location} matches entity identifier schema (${schema?.type || 'string'}${schemaFormat ? ` / ${schemaFormat}` : ''}).`,
      };
    }

    return {
      role: ParameterIdentifierRole.UNKNOWN,
      reason: `Non-identifier attribute or search filter parameter "${name}" in ${location}.`,
    };
  }

  /**
   * Traverse document to detect broken $ref references.
   */
  private detectBrokenReferences(doc: any, issues: ContractValidationIssue[]) {
    const visited = new Set<any>();

    const checkRefs = (node: any, currentPath: string) => {
      if (!node || typeof node !== 'object' || visited.has(node)) return;
      visited.add(node);

      if (Array.isArray(node)) {
        node.forEach((item, idx) => checkRefs(item, `${currentPath}/${idx}`));
        return;
      }

      for (const [key, value] of Object.entries(node)) {
        if (key === '$ref' && typeof value === 'string') {
          if (value.startsWith('#/')) {
            const parts = value.substring(2).split('/');
            let curr = doc;
            let broken = false;
            for (const p of parts) {
              const decoded = p.replace(/~1/g, '/').replace(/~0/g, '~');
              if (curr && typeof curr === 'object' && decoded in curr) {
                curr = curr[decoded];
              } else {
                broken = true;
                break;
              }
            }
            if (broken) {
              issues.push({
                id: `val-broken-ref-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
                code: 'BROKEN_REFERENCE',
                message: `Broken reference: unable to resolve "${value}".`,
                severity: 'ERROR',
                path: currentPath,
              });
            }
          }
        } else {
          checkRefs(value, `${currentPath}/${key}`);
        }
      }
    };

    checkRefs(doc, '#');
  }

  private resolveParam(param: any, doc: any): any {
    if (param && param.$ref && typeof param.$ref === 'string' && param.$ref.startsWith('#/')) {
      const parts = param.$ref.substring(2).split('/');
      let curr = doc;
      for (const p of parts) {
        if (curr && typeof curr === 'object' && p in curr) {
          curr = curr[p];
        } else {
          return param;
        }
      }
      return curr;
    }
    return param;
  }
}

export const globalOpenAPIParser = new OpenAPIParserService();
