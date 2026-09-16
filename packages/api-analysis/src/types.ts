/**
 * API Contract & Authorization Analysis Types
 * Intent Security Workbench - Phase 3
 */

export enum ParameterIdentifierRole {
  OBJECT_ID = 'OBJECT_ID',
  OWNER_ID = 'OWNER_ID',
  TENANT_ID = 'TENANT_ID',
  USER_ID = 'USER_ID',
  ACCOUNT_ID = 'ACCOUNT_ID',
  RESOURCE_ID = 'RESOURCE_ID',
  UNKNOWN = 'UNKNOWN',
}

export enum SecuritySchemeType {
  HTTP_BEARER = 'HTTP_BEARER',
  HTTP_BASIC = 'HTTP_BASIC',
  API_KEY = 'API_KEY',
  OAUTH2 = 'OAUTH2',
  OPENID_CONNECT = 'OPENID_CONNECT',
  UNKNOWN = 'UNKNOWN',
}

export enum EndpointAuthStatus {
  AUTHENTICATED_ENDPOINT = 'AUTHENTICATED_ENDPOINT',
  PUBLIC_ENDPOINT = 'PUBLIC_ENDPOINT',
  MISSING_SECURITY_DECLARATION = 'MISSING_SECURITY_DECLARATION',
  UNKNOWN = 'UNKNOWN',
}

export enum EndpointSourceType {
  DOCUMENTED_ENDPOINT = 'DOCUMENTED_ENDPOINT',
  SOURCE_DISCOVERED_ENDPOINT = 'SOURCE_DISCOVERED_ENDPOINT',
}

export enum ContractDiffStatus {
  DOCUMENTED_AND_IMPLEMENTED = 'DOCUMENTED_AND_IMPLEMENTED',
  DOCUMENTED_BUT_NOT_FOUND = 'DOCUMENTED_BUT_NOT_FOUND',
  SOURCE_ONLY = 'SOURCE_ONLY',
  METHOD_MISMATCH = 'METHOD_MISMATCH',
  PARAMETER_MISMATCH = 'PARAMETER_MISMATCH',
}

export interface SecuritySchemeDefinition {
  name: string;
  type: SecuritySchemeType;
  scheme?: string;
  bearerFormat?: string;
  in?: 'header' | 'query' | 'cookie';
  flows?: Record<string, any>;
  scopes?: string[];
  description?: string;
}

export interface APIParameter {
  name: string;
  location: 'path' | 'query' | 'header' | 'cookie';
  schema?: Record<string, any>;
  required: boolean;
  identifier_role: ParameterIdentifierRole;
  classification_reason: string;
  source_location?: {
    file: string;
    line_start?: number;
    line_end?: number;
  };
}

export interface APIEndpoint {
  id: string;
  method: string; // GET, POST, PUT, DELETE, PATCH, etc.
  path: string; // e.g. /vaults/{vault_id}/deposit
  operation_id?: string;
  tags: string[];
  parameters: APIParameter[];
  request_body?: {
    description?: string;
    required: boolean;
    contentTypes: string[];
    schema?: Record<string, any>;
  };
  responses: Array<{
    statusCode: string;
    description: string;
    schema?: Record<string, any>;
  }>;
  security_requirements: Array<{
    schemeName: string;
    scopes: string[];
  }>;
  auth_status: EndpointAuthStatus;
  is_state_mutation: boolean;
  source_location?: {
    file: string;
    line_start?: number;
    line_end?: number;
  };
  endpoint_type: EndpointSourceType;
}

export interface ContractValidationIssue {
  id: string;
  code: string;
  message: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  path: string;
  source_location?: {
    line?: number;
    column?: number;
  };
}

export interface APIContract {
  id: string;
  target_id: string;
  investigation_id: string;
  source_snapshot_id?: string;
  specification_path: string;
  specification_hash: string;
  openapi_version: string;
  title: string;
  description?: string;
  server_definitions: Array<{ url: string; description?: string }>;
  security_schemes: SecuritySchemeDefinition[];
  endpoints: APIEndpoint[];
  validation_issues: ContractValidationIssue[];
  retrieved_at: string;
}

export enum BoundaryType {
  CALLER_EQUALS_OWNER = 'caller == owner',
  USER_ID_EQUALS_RESOURCE_OWNER = 'user.id == resource.owner_id',
  CALLER_TENANT_EQUALS_RESOURCE_TENANT = 'caller.tenant_id == resource.tenant_id',
  PERMISSION_CHECK = 'permission check',
  ROLE_CHECK = 'role check',
  ACL_CHECK = 'ACL check',
  POLICY_ENGINE = 'policy engine',
  MIDDLEWARE = 'middleware',
  AUTHORIZATION_DECORATOR = 'authorization decorator',
  UNKNOWN = 'unknown',
}

export interface AuthorizationBoundary {
  id: string;
  boundary_type: BoundaryType;
  location: {
    file: string;
    line?: number;
    code_snippet?: string;
  };
  source: string; // e.g. Tree-sitter query, AST node, pattern
  evidence: string;
  confidence_basis: string;
  satisfies_ownership: boolean; // role check does NOT satisfy ownership!
}

export interface DeterministicRiskSignal {
  code: string;
  name: string;
  weight: number;
  present: boolean;
  rationale: string;
}

export interface ReasoningChainStep {
  step: number;
  label: string;
  detail: string;
  status: 'OBSERVED' | 'MISSING' | 'IDENTIFIED' | 'NOT_IDENTIFIED';
}

export interface AuthorizationCandidate {
  id: string;
  investigation_id: string;
  target_id: string;
  contract_id?: string;
  endpoint_id: string;
  method: string;
  path: string;
  title: string;
  status: 'CANDIDATE'; // Phase 3 invariants: Never CONFIRMED
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  vulnerability_type: 'POTENTIAL_BOLA' | 'MISSING_AUTHENTICATION' | 'UNPROTECTED_STATE_MUTATION';
  owasp_category: 'API1:2023-Broken Object Level Authorization' | 'API2:2023-Broken Authentication';
  parameters: APIParameter[];
  identified_boundaries: AuthorizationBoundary[];
  has_ownership_boundary: boolean;
  risk_signals: DeterministicRiskSignal[];
  priority_score: number;
  reasoning_chain: ReasoningChainStep[];
  evidence_artifact_ids: string[];
  source_location?: {
    file: string;
    line_start?: number;
    line_end?: number;
    code_snippet?: string;
  };
  corroborated?: boolean;
  metadata?: Record<string, any>;
  matched_source_snippet?: string;
  file?: string;
  created_at: string;
}

export interface EndpointDiffItem {
  method: string;
  path: string;
  status: ContractDiffStatus;
  details: string;
  contract_endpoint?: APIEndpoint;
  source_endpoint?: APIEndpoint;
}

export interface ContractDiffResult {
  id: string;
  investigation_id: string;
  target_id: string;
  contract_id?: string;
  total_documented: number;
  total_source_discovered: number;
  matched: number;
  documented_not_found: number;
  source_only: number;
  method_mismatches: number;
  parameter_mismatches: number;
  items: EndpointDiffItem[];
  created_at: string;
}
