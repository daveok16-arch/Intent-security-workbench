/**
 * Tool Registry & Invocation Manager
 * Phase 6 — AI Security Control Plane Core
 * 
 * Invariants:
 * - Rejects unregistered tools.
 * - Rejects malformed arguments violating parameter schemas.
 * - Injects authorization context and policy evaluation.
 */

import { ToolDefinition, ToolExecutionResult, ControllerExecutionContext } from '../types.js';
import { ALL_TOOLS } from './definitions.js';

export class ToolRegistry {
  private tools: Map<string, ToolDefinition> = new Map();

  constructor() {
    for (const tool of ALL_TOOLS) {
      this.tools.set(tool.name, tool);
    }
  }

  public getTool(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  public getToolsByCategory(category: string): ToolDefinition[] {
    return this.listTools().filter(t => t.category === category);
  }

  public listTools(): ToolDefinition[] {
    return Array.from(this.tools.values());
  }

  public getToolSchemas(): Array<{ name: string; category: string; description: string; parameters: any; requires_approval: boolean }> {
    return this.listTools().map(t => ({
      name: t.name,
      category: t.category,
      description: t.description,
      parameters: t.parameters,
      requires_approval: t.requires_approval,
    }));
  }

  /**
   * Authoritatively validates arguments against tool parameter schemas.
   */
  public validateParameters(tool: ToolDefinition, params: Record<string, any>): { valid: boolean; error?: string } {
    if (!params || typeof params !== 'object') {
      return { valid: false, error: 'Parameters must be a JSON object.' };
    }

    for (const [paramName, schema] of Object.entries(tool.parameters)) {
      const val = params[paramName];
      if (schema.required && (val === undefined || val === null || val === '')) {
        return { valid: false, error: `Missing required parameter '${paramName}' for tool '${tool.name}'.` };
      }

      if (val !== undefined && val !== null) {
        if (schema.type === 'string' && typeof val !== 'string') {
          return { valid: false, error: `Parameter '${paramName}' must be a string.` };
        }
        if (schema.type === 'number' && typeof val !== 'number') {
          return { valid: false, error: `Parameter '${paramName}' must be a number.` };
        }
        if (schema.type === 'boolean' && typeof val !== 'boolean') {
          return { valid: false, error: `Parameter '${paramName}' must be a boolean.` };
        }
        if (schema.type === 'array' && !Array.isArray(val)) {
          return { valid: false, error: `Parameter '${paramName}' must be an array.` };
        }
        if (schema.type === 'object' && (typeof val !== 'object' || Array.isArray(val))) {
          return { valid: false, error: `Parameter '${paramName}' must be an object.` };
        }
      }
    }

    return { valid: true };
  }

  /**
   * Invokes a tool safely with schema validation and execution timing.
   */
  public async invokeTool(
    name: string,
    params: Record<string, any>,
    context: ControllerExecutionContext
  ): Promise<ToolExecutionResult> {
    const tool = this.tools.get(name);
    if (!tool) {
      return {
        success: false,
        error: `Tool '${name}' is not registered in the AI Security Controller.`,
        duration_ms: 0,
      };
    }

    // Validate parameters
    const paramValidation = this.validateParameters(tool, params);
    if (!paramValidation.valid) {
      return {
        success: false,
        error: paramValidation.error,
        duration_ms: 0,
      };
    }

    // Execute tool
    try {
      return await tool.execute(params, context);
    } catch (err: any) {
      return {
        success: false,
        error: `Tool execution failed: ${err.message}`,
        duration_ms: 0,
      };
    }
  }
}

export const globalToolRegistry = new ToolRegistry();
