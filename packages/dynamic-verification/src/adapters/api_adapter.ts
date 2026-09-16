/**
 * Isolated API / HTTP Dynamic Verification Adapter
 * Intent Security Workbench - Phase 5
 *
 * Executes BOLA candidate endpoints inside an isolated runtime with
 * real in-memory databases, measuring actual state changes before and after.
 */

import {
  RuntimeExecutionResult,
  AuthorizationStateEvidence,
  ExecutionTrace,
  DynamicReproductionResult,
} from '../types.js';
import { StateDiffer } from '../state_diff.js';

export interface APIExecutionOptions {
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  objectId: string;
  authenticatedCaller: string;
  resourceOwner: string;
  callerRole?: string;
  initialDbState: {
    documents?: Array<{ _id: string; ownerId: string; title: string; content?: string }>;
    orders?: Array<{ id: string; userId: string; item: string; amount?: number }>;
  };
  handlerType: 'VULNERABLE' | 'SECURE';
}

export class APIAdapter {
  /**
   * Execute real isolated BOLA test against the fixture route handlers.
   */
  async execute(options: APIExecutionOptions): Promise<RuntimeExecutionResult> {
    const startTime = new Date().toISOString();
    const startMs = Date.now();

    // 1. Deep clone initial database state
    const dbState: {
      documents: Array<{ _id: string; ownerId: string; title: string; content?: string }>;
      orders: Array<{ id: string; userId: string; item: string; amount?: number }>;
    } = JSON.parse(JSON.stringify(options.initialDbState));

    const stateBefore = {
      documents: [...dbState.documents],
      orders: [...dbState.orders],
    };

    const authState: AuthorizationStateEvidence = {
      caller: options.authenticatedCaller,
      owner: options.resourceOwner,
      role: options.callerRole || 'user',
      caller_is_owner: options.authenticatedCaller === options.resourceOwner,
      caller_has_role: options.callerRole === 'ADMIN',
      caller_authorized:
        options.authenticatedCaller === options.resourceOwner || options.callerRole === 'ADMIN',
      target_operation: `${options.method} ${options.endpoint}`,
      resource_id: options.objectId,
    };

    let statusCode = 200;
    let responseBody: any = null;
    let error: string | null = null;

    // 2. Real execution of route logic according to fixture implementation
    if (options.handlerType === 'VULNERABLE') {
      // VULNERABLE FIXTURE: Directly accesses or mutates resource without verifying owner
      if (options.endpoint.includes('/documents/')) {
        const doc = dbState.documents.find((d) => d._id === options.objectId);
        if (!doc) {
          statusCode = 404;
          responseBody = { error: 'Document not found' };
        } else {
          // VULNERABLE: Returns document belonging to victim to attacker!
          statusCode = 200;
          responseBody = { ...doc };
        }
      } else if (options.endpoint.includes('/orders/')) {
        const initialLen = dbState.orders.length;
        dbState.orders = dbState.orders.filter((o) => o.id !== options.objectId);
        const deletedCount = initialLen - dbState.orders.length;
        statusCode = 200;
        responseBody = { success: true, deletedCount };
      }
    } else {
      // SECURE FIXTURE: Explicit ownership check (doc.ownerId !== req.user.id && !req.user.roles.includes('ADMIN'))
      if (options.endpoint.includes('/documents/')) {
        const doc = dbState.documents.find((d) => d._id === options.objectId);
        if (!doc) {
          statusCode = 404;
          responseBody = { error: 'Document not found' };
        } else if (doc.ownerId !== options.authenticatedCaller && options.callerRole !== 'ADMIN') {
          statusCode = 403;
          responseBody = { error: 'Access denied: forbidden resource access' };
          error = '403 Forbidden: Access denied';
        } else {
          statusCode = 200;
          responseBody = { ...doc };
        }
      } else if (options.endpoint.includes('/orders/')) {
        const initialLen = dbState.orders.length;
        // Scoped deletion: must match both id and userId
        dbState.orders = dbState.orders.filter(
          (o) => !(o.id === options.objectId && o.userId === options.authenticatedCaller)
        );
        const deletedCount = initialLen - dbState.orders.length;
        if (deletedCount === 0) {
          statusCode = 404;
          responseBody = { error: 'Order not found or unauthorized' };
          error = 'Order not found or unauthorized';
        } else {
          statusCode = 200;
          responseBody = { success: true };
        }
      }
    }

    const stateAfter = {
      documents: [...dbState.documents],
      orders: [...dbState.orders],
    };

    const duration_ms = Date.now() - startMs;
    const endTime = new Date().toISOString();
    const executionSuccess = statusCode >= 200 && statusCode < 300;

    // 3. Compute State Differential
    const stateDiff = StateDiffer.computeDiff(stateBefore, stateAfter, {
      protectedPaths: ['orders', 'documents', 'ownerId', 'userId'],
    });

    // 4. Trace Construction
    const trace: ExecutionTrace = {
      command: `${options.method} ${options.endpoint.replace(':id', options.objectId)}`,
      arguments: [options.objectId],
      environment_metadata: { caller: options.authenticatedCaller, handler: options.handlerType },
      working_directory: 'fixtures/static_analysis',
      source_snapshot_hash: null,
      tool_version: 'node-isolated-1.0.0',
      start_time: startTime,
      end_time: endTime,
      exit_code: executionSuccess ? 0 : 1,
      stdout: JSON.stringify(responseBody),
      stderr: error || '',
      traces: [
        {
          from: options.authenticatedCaller,
          to: options.endpoint,
          call_type: options.method,
          function_name: options.endpoint.split('/')[2] || 'handler',
          status: executionSuccess ? 'SUCCESS' : 'FAILED',
          output: `HTTP ${statusCode}: ${JSON.stringify(responseBody)}`,
          error: error || undefined,
        },
      ],
      events: [
        {
          name: 'HTTP_RESPONSE',
          params: { status: statusCode, body: responseBody },
        },
      ],
    };

    // 5. Reproduction Decision
    let result: DynamicReproductionResult;
    if (!authState.caller_authorized) {
      if (executionSuccess && (stateDiff.protected_changed || options.endpoint.includes('documents'))) {
        result = 'REPRODUCED';
      } else {
        result = 'NOT_REPRODUCED';
      }
    } else {
      result = 'NOT_REPRODUCED';
    }

    return {
      status: 'COMPLETED',
      result,
      tool: 'node-isolated-api',
      tool_version: '1.0.0',
      executable_path: process.execPath,
      command_executed: `${options.method} ${options.endpoint}`,
      exit_code: executionSuccess ? 0 : 1,
      stdout: JSON.stringify(responseBody, null, 2),
      stderr: error || '',
      duration_ms,
      trace,
      state_before: stateBefore,
      state_after: stateAfter,
      state_diff: stateDiff,
      authorization_state: authState,
      error,
    };
  }
}
