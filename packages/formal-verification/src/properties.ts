/**
 * Standard Formal Security Properties & DSL Specifications
 * Intent Security Workbench - Phase 4
 *
 * Core authorization properties:
 * 1. OWNER_BINDING: caller == resource.owner (for privileged resource operations)
 * 2. TENANT_ISOLATION: caller.tenant == resource.tenant
 * 3. ROLE_PERMISSION: permission(caller, operation)
 * 4. AUTHENTICATED_OPERATION: authenticated(caller)
 * 5. OPERATOR_EXCEPTION: authorized_operator(caller, operation)
 * 6. STATE_MUTATION_AUTHORIZATION: state_change(resource) -> authorized(caller, resource, operation)
 * 7. UNAUTHORIZED_OBJECT_ACCESS: exists caller, resource such that authenticated(caller) AND caller != resource.owner AND !is_operator AND operation is reachable
 */

import { PropertyCategory, SecurityProperty } from './types.js';

export const STANDARD_PROPERTIES: Record<string, SecurityProperty> = {
  OWNER_BINDING: {
    id: 'PROP-OWNER-BINDING',
    name: 'OWNER_BINDING',
    description: 'For every privileged resource operation, caller == resource.owner unless caller has explicit authorized operator permission.',
    category: PropertyCategory.OBJECT_OWNERSHIP,
    cwe: 'CWE-639',
    source: 'Phase 4 Formal Authorization Specification',
    version: '1.0.0',
  },
  TENANT_ISOLATION: {
    id: 'PROP-TENANT-ISOLATION',
    name: 'TENANT_ISOLATION',
    description: 'Cross-tenant resource access is strictly forbidden; caller.tenant == resource.tenant.',
    category: PropertyCategory.TENANT_ISOLATION,
    cwe: 'CWE-284',
    source: 'Phase 4 Formal Authorization Specification',
    version: '1.0.0',
  },
  ROLE_PERMISSION: {
    id: 'PROP-ROLE-PERMISSION',
    name: 'ROLE_PERMISSION',
    description: 'The caller must hold required role/permission for the invoked operation.',
    category: PropertyCategory.AUTHORIZATION,
    cwe: 'CWE-285',
    source: 'Phase 4 Formal Authorization Specification',
    version: '1.0.0',
  },
  AUTHENTICATED_OPERATION: {
    id: 'PROP-AUTHENTICATED-OPERATION',
    name: 'AUTHENTICATED_OPERATION',
    description: 'Operations modifying or accessing restricted entities require an authenticated caller identity.',
    category: PropertyCategory.ACCESS_CONTROL,
    cwe: 'CWE-306',
    source: 'Phase 4 Formal Authorization Specification',
    version: '1.0.0',
  },
  OPERATOR_EXCEPTION: {
    id: 'PROP-OPERATOR-EXCEPTION',
    name: 'OPERATOR_EXCEPTION',
    description: 'Caller may act on non-owned resource if and only if caller is explicitly designated an authorized operator for the operation.',
    category: PropertyCategory.AUTHORIZATION,
    cwe: 'CWE-639',
    source: 'Phase 4 Formal Authorization Specification',
    version: '1.0.0',
  },
  STATE_MUTATION_AUTHORIZATION: {
    id: 'PROP-STATE-MUTATION-AUTH',
    name: 'STATE_MUTATION_AUTHORIZATION',
    description: 'Any state mutation on a resource entails that caller is authorized (either owner or authorized operator).',
    category: PropertyCategory.STATE_INTEGRITY,
    cwe: 'CWE-862',
    source: 'Phase 4 Formal Authorization Specification',
    version: '1.0.0',
  },
  UNAUTHORIZED_OBJECT_ACCESS: {
    id: 'PROP-BOLA-UNAUTHORIZED-ACCESS',
    name: 'UNAUTHORIZED_OBJECT_ACCESS',
    description: 'Checks whether there exists a model execution where authenticated(caller) AND caller != resource.owner AND !authorized_operator AND operation(resource) is reached.',
    category: PropertyCategory.OBJECT_OWNERSHIP,
    cwe: 'CWE-639', // BOLA / IDOR
    source: 'OWASP API Security Top 10 (API1:2023 - Broken Object Level Authorization)',
    version: '1.0.0',
  },
};

export function getStandardProperty(propertyIdOrName: string): SecurityProperty {
  const upper = propertyIdOrName.toUpperCase();
  if (STANDARD_PROPERTIES[upper]) {
    return STANDARD_PROPERTIES[upper];
  }
  for (const prop of Object.values(STANDARD_PROPERTIES)) {
    if (prop.id === propertyIdOrName || prop.name === upper) {
      return prop;
    }
  }

  // Fallback to custom property
  return {
    id: `PROP-${propertyIdOrName}`,
    name: propertyIdOrName,
    description: `Formal security property: ${propertyIdOrName}`,
    category: PropertyCategory.AUTHORIZATION,
    version: '1.0.0',
  };
}
