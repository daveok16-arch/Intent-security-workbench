/**
 * API Contract & Authorization Analysis Verification Tests
 * Intent Security Workbench - Phase 3
 *
 * Verifies:
 * 1. OpenAPI 3.x parser: Valid, invalid, and missing specifications.
 * 2. Real Spectral CLI execution, JSON finding parsing, and truthful reporting.
 * 3. Parameter classification & identification reason tracking.
 * 4. State mutation detection.
 * 5. Security scheme extraction and endpoint auth status mapping.
 * 6. Authorization (BOLA) candidate analysis:
 *    - Role checks alone DO NOT count as ownership authorization.
 *    - Direct ownership verification (caller == owner) satisfies ownership and prevents candidate.
 *    - Status strictly remains CANDIDATE (never CONFIRMED).
 * 7. Differential analysis: Documented vs Source-discovered (Shadow APIs).
 * 8. Zero synthetic data fabrication on missing specs (API_SPEC_NOT_FOUND).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import path from 'path';
import fs from 'fs';
import {
  globalOpenAPIParser,
  globalSpectralService,
  globalAuthorizationAnalyzer,
  globalContractDifferential,
  globalAPIAnalysisOrchestrator,
  EndpointAuthStatus,
  ParameterIdentifierRole,
  ContractDiffStatus,
  BoundaryType,
} from '../../packages/api-analysis/src/index.js';

describe('Phase 3 — Real API Contract & Authorization Analysis', () => {
  const rootDir = process.cwd();
  const testWorkspaceDir = path.join(rootDir, 'fixtures', 'api_analysis_test_workspace');
  const openapiYamlPath = path.join(testWorkspaceDir, 'openapi.yaml');
  const serverCodePath = path.join(testWorkspaceDir, 'routes.js');
  let specRawContent: string;

  beforeAll(() => {
    // Create test workspace with real files
    fs.mkdirSync(testWorkspaceDir, { recursive: true });

    // 1. Write a real OpenAPI 3.0.3 specification
    const specContent = `
openapi: "3.0.3"
info:
  title: "Test Store API"
  version: "1.0.0"
  description: "E-Commerce backend API contract"
servers:
  - url: "https://api.store.local/v1"
    description: "Local dev environment"
paths:
  /orders:
    get:
      summary: "List all orders"
      operationId: "listOrders"
      responses:
        "200":
          description: "List of orders"
    post:
      summary: "Create new order"
      operationId: "createOrder"
      responses:
        "201":
          description: "Order created"
  /orders/{orderId}:
    get:
      summary: "Get order by ID"
      operationId: "getOrderById"
      parameters:
        - name: "orderId"
          in: "path"
          required: true
          schema:
            type: "string"
      responses:
        "200":
          description: "Order details"
    delete:
      summary: "Delete order by ID"
      operationId: "deleteOrderById"
      parameters:
        - name: "orderId"
          in: "path"
          required: true
          schema:
            type: "string"
      responses:
        "204":
          description: "Order deleted"
  /users/{userId}/documents/{documentId}:
    put:
      summary: "Update user document"
      operationId: "updateDocument"
      security:
        - BearerAuth: []
      parameters:
        - name: "userId"
          in: "path"
          required: true
          schema:
            type: "string"
        - name: "documentId"
          in: "path"
          required: true
          schema:
            type: "string"
      responses:
        "200":
          description: "Updated"
components:
  securitySchemes:
    BearerAuth:
      type: "http"
      scheme: "bearer"
      bearerFormat: "JWT"
      description: "JWT Bearer authentication"
`;
    specRawContent = specContent.trim();
    fs.writeFileSync(openapiYamlPath, specRawContent);

    // 2. Write source code simulating Express routes
    const routesContent = `
// Routes file
app.get('/orders', async (req, res) => {
  const orders = await db.orders.find();
  res.json(orders);
});

// Vulnerable to BOLA: accepts orderId, has role check, but NO ownership check!
app.delete('/orders/:orderId', async (req, res) => {
  const user = req.user;
  if (!user.roles.includes('user')) {
    return res.status(403).send('Forbidden');
  }
  // Missing: user.id === order.owner_id
  const order = await db.orders.findById(req.params.orderId);
  await order.delete();
  res.status(204).send();
});

// Secure endpoint: explicitly enforces caller == owner
app.put('/users/:userId/documents/:documentId', async (req, res) => {
  const caller = req.user;
  const doc = await db.docs.findById(req.params.documentId);
  if (caller.id !== doc.owner_id) {
    return res.status(403).send('Forbidden');
  }
  await doc.update(req.body);
  res.json(doc);
});

// Shadow API: Exists in source code but NOT in OpenAPI spec!
app.post('/internal/admin/purge-cache', async (req, res) => {
  await cache.flush();
  res.json({ ok: true });
});
`;
    fs.writeFileSync(serverCodePath, routesContent.trim());
  });

  // Test 1: OpenAPI 3.x Parser - Valid specification
  it('parses valid OpenAPI 3.x contract and extracts metadata', () => {
    const { contract } = globalOpenAPIParser.parseSpecification(
      specRawContent,
      openapiYamlPath,
      'target_test_1',
      'inv_test_1'
    );

    expect(contract).toBeDefined();
    expect(contract.title).toBe('Test Store API');
    expect(contract.openapi_version).toBe('3.0.3');
    expect(contract.specification_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(contract.endpoints.length).toBe(5); // GET /orders, POST /orders, GET /orders/{orderId}, DELETE /orders/{orderId}, PUT /users/{userId}/documents/{documentId}
  });

  // Test 2: Parameter Classification & Reason Tracking
  it('correctly classifies object identifiers and records explicit reasoning', () => {
    const { contract } = globalOpenAPIParser.parseSpecification(
      specRawContent,
      openapiYamlPath,
      'target_test_1',
      'inv_test_1'
    );

    const deleteOrderEp = contract.endpoints.find(
      (e) => e.path === '/orders/{orderId}' && e.method === 'DELETE'
    );
    expect(deleteOrderEp).toBeDefined();
    expect(deleteOrderEp!.parameters.length).toBe(1);
    const param = deleteOrderEp!.parameters[0];
    expect(param.name).toBe('orderId');
    expect([ParameterIdentifierRole.RESOURCE_ID, ParameterIdentifierRole.OBJECT_ID]).toContain(param.identifier_role);
    expect(param.classification_reason).toContain('Path parameter');

    const updateDocEp = contract.endpoints.find(
      (e) => e.path === '/users/{userId}/documents/{documentId}' && e.method === 'PUT'
    );
    expect(updateDocEp).toBeDefined();
    const userParam = updateDocEp!.parameters.find((p) => p.name === 'userId');
    const docParam = updateDocEp!.parameters.find((p) => p.name === 'documentId');
    expect(userParam!.identifier_role).toBe(ParameterIdentifierRole.USER_ID);
    expect([ParameterIdentifierRole.RESOURCE_ID, ParameterIdentifierRole.OBJECT_ID]).toContain(docParam!.identifier_role);
  });

  // Test 3: State Mutation Detection
  it('identifies state mutation for POST, PUT, DELETE and read-only for GET', () => {
    const { contract } = globalOpenAPIParser.parseSpecification(
      specRawContent,
      openapiYamlPath,
      'target_test_1',
      'inv_test_1'
    );

    const getEp = contract.endpoints.find((e) => e.path === '/orders' && e.method === 'GET');
    const postEp = contract.endpoints.find((e) => e.path === '/orders' && e.method === 'POST');
    const deleteEp = contract.endpoints.find((e) => e.path === '/orders/{orderId}' && e.method === 'DELETE');

    expect(getEp!.is_state_mutation).toBe(false);
    expect(postEp!.is_state_mutation).toBe(true);
    expect(deleteEp!.is_state_mutation).toBe(true);
  });

  // Test 4: Security Schemes Extraction
  it('extracts security schemes and identifies endpoint auth status', () => {
    const { contract } = globalOpenAPIParser.parseSpecification(
      specRawContent,
      openapiYamlPath,
      'target_test_1',
      'inv_test_1'
    );

    expect(contract.security_schemes.length).toBe(1);
    const scheme = contract.security_schemes[0];
    expect(scheme.name).toBe('BearerAuth');
    expect(scheme.type).toBe('HTTP_BEARER');
    expect(scheme.scheme).toBe('bearer');

    const securedEp = contract.endpoints.find(
      (e) => e.path === '/users/{userId}/documents/{documentId}' && e.method === 'PUT'
    );
    expect(securedEp!.auth_status).toBe(EndpointAuthStatus.AUTHENTICATED_ENDPOINT);
  });

  // Test 5: Missing Specification Handling (No Fabrication Directive)
  it('strictly returns API_SPEC_NOT_FOUND when no specification exists, never fabricating data', async () => {
    const emptyDir = path.join(rootDir, 'fixtures', 'empty_temp_dir');
    fs.mkdirSync(emptyDir, { recursive: true });

    const result = await globalAPIAnalysisOrchestrator.runAnalysis({
      investigationId: 'inv_empty',
      targetId: 'target_empty',
      sourceDir: emptyDir,
    });

    expect(result.status).toBe('API_SPEC_NOT_FOUND');
    expect(result.contract).toBeUndefined();
    expect(result.authorizationCandidates.length).toBe(0);
  });

  // Test 6: Spectral CLI Execution
  it('executes Spectral CLI against OpenAPI specification', async () => {
    const res = await globalSpectralService.lintSpecification(openapiYamlPath);
    expect(res.exit_code).toBeDefined();
    expect(Array.isArray(res.findings)).toBe(true);
  });

  it('resolves the Spectral ruleset from the specification directory, not the process cwd', async () => {
    // Regression: Spectral discovers its ruleset by walking up from the process
    // cwd. Running from the repo root found none and exited 2, discarding the
    // run. The service must anchor the child cwd to the spec directory.
    const specDir = path.join(process.cwd(), 'tests', 'fixtures', 'engines', 'spectral');
    const res = await globalSpectralService.lintSpecification(
      path.join(specDir, 'openapi.yaml')
    );

    expect(res.exit_code).toBe(0);
    expect(res.available).toBe(true);
    expect(res.input_specification).toBe(path.join(specDir, 'openapi.yaml'));

    // The fixture's .spectral.yaml declares operation-description as warn, and
    // the fixture's GET /users has no description, so a real finding must appear.
    const descriptionFinding = res.findings.find(f => f.metadata?.rule_id === 'operation-description');
    expect(descriptionFinding).toBeDefined();
    expect(descriptionFinding!.severity).toBe('MEDIUM');
    expect(descriptionFinding!.line_start).toBeGreaterThan(0);
  });

  it('reports a missing specification without fabricating findings', async () => {
    const res = await globalSpectralService.lintSpecification(
      path.join(process.cwd(), 'tests', 'fixtures', 'engines', 'spectral', 'does-not-exist.yaml')
    );

    expect(res.findings).toHaveLength(0);
    expect(res.exit_code).not.toBe(0);
    expect(res.error).toBeTruthy();
  });

  // Test 7: Full Pipeline & Authorization (BOLA) Analysis & Candidate Invariant
  it('runs orchestrator pipeline, identifies BOLA candidate where role check fails to satisfy ownership, and keeps status CANDIDATE', async () => {
    const result = await globalAPIAnalysisOrchestrator.runAnalysis({
      investigationId: 'inv_test_1',
      targetId: 'target_test_1',
      sourceDir: testWorkspaceDir,
      specificationFilePath: openapiYamlPath,
    });

    expect(result.status).toBe('SUCCESS');
    expect(result.contract).toBeDefined();

    // DELETE /orders/{orderId} accepts orderId, has role check in code, but no ownership check
    const bolaCandidate = result.authorizationCandidates.find(
      (c) => c.method === 'DELETE' && c.path === '/orders/{orderId}'
    );
    expect(bolaCandidate).toBeDefined();

    // Critical Invariant: Status MUST remain CANDIDATE
    expect(bolaCandidate!.status).toBe('CANDIDATE');
    expect(bolaCandidate!.priority_score).toBeGreaterThan(50);

    // Verify boundary check found role check, and marked it as NOT satisfying ownership
    const roleBoundary = bolaCandidate!.identified_boundaries.find(
      (b) => b.boundary_type === BoundaryType.ROLE_CHECK
    );
    expect(roleBoundary).toBeDefined();
    expect(roleBoundary!.satisfies_ownership).toBe(false);

    // Secure route (PUT /users/{userId}/documents/{documentId}) has caller.id !== doc.owner_id
    // It should NOT produce a BOLA candidate!
    const secureCandidate = result.authorizationCandidates.find(
      (c) => c.path === '/users/{userId}/documents/{documentId}'
    );
    expect(secureCandidate).toBeUndefined();
  });

  // Test 8: Source vs Contract Differential (Shadow APIs)
  it('discovers shadow (undocumented) endpoints in source code and reports mismatches', async () => {
    const { contract } = globalOpenAPIParser.parseSpecification(
      specRawContent,
      openapiYamlPath,
      'target_test_1',
      'inv_test_1'
    );

    const sourceContexts = [
      {
        file: serverCodePath,
        sourceCode: fs.readFileSync(serverCodePath, 'utf-8'),
      },
    ];

    const sourceEndpoints = globalContractDifferential.extractSourceEndpoints(
      sourceContexts[0].sourceCode,
      sourceContexts[0].file
    );

    const diff = globalContractDifferential.compareContractAndSource(
      contract,
      sourceEndpoints,
      'inv_test_1',
      'target_test_1'
    );

    expect(diff.total_documented).toBe(5);
    expect(diff.matched).toBeGreaterThanOrEqual(1);

    // Shadow API: POST /internal/admin/purge-cache was discovered in source but not in OpenAPI
    const shadowItem = diff.items.find(
      (i) => i.path.includes('/internal/admin/purge-cache') && i.status === ContractDiffStatus.SOURCE_ONLY
    );
    expect(shadowItem).toBeDefined();
    expect(diff.source_only).toBeGreaterThanOrEqual(1);
  });
});
