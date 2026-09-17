/**
 * AI Security Controller Orchestration Engine
 * Phase 6 — AI Security Control Plane Core
 * 
 * Strict Invariants:
 * - Controls existing Workbench capabilities through typed, permissioned tools.
 * - Rejects arbitrary DB queries, shell calls, or finding state manipulations.
 * - Explicitly distinguishes verified FACTS from HYPOTHESES.
 * - Enforces deterministic research phase transitions and halts at approval gates.
 */

import { globalDB } from '../../../apps/api/db_store.js';
import { globalJobOrchestrator } from '../../orchestrator/src/index.js';
import {
  ControllerState,
  ResearchPhase,
  ResearchFact,
  ResearchHypothesis,
  ResearchUnknown,
  ResearchPlan,
  ResearchPlanStep,
  ResearchDecision,
  ResearchBlocker,
  UserApprovalRequest,
  ControllerEventType,
  ControllerExecutionContext,
  CapabilityMatrixEntry,
} from './types.js';
import { validateStateTransition } from './state_machine.js';
import { globalToolRegistry } from './tools/tool_registry.js';
import { globalAIProviderClient } from './ai_provider_client.js';

export type EventListener = (event: { type: ControllerEventType | string; data: any; timestamp: string }) => void;

export class AISecurityController {
  private states: Map<string, ControllerState> = new Map();
  private approvedActions: Set<string> = new Set();
  private eventListeners: Set<EventListener> = new Set();

  constructor() {
    // Listen to background job updates to correlate execution
    globalJobOrchestrator.subscribe((event) => {
      this.handleJobOrchestratorEvent(event);
    });
  }

  public addEventListener(listener: EventListener): () => void {
    this.eventListeners.add(listener);
    return () => this.eventListeners.delete(listener);
  }

  private emitEvent(type: ControllerEventType | string, data: any): void {
    const payload = {
      type,
      data,
      timestamp: new Date().toISOString(),
    };
    for (const listener of this.eventListeners) {
      try {
        listener(payload);
      } catch (err) {
        console.error('[AISecurityController] Error in event listener:', err);
      }
    }
  }

  private handleJobOrchestratorEvent(jobEvent: any): void {
    if (!jobEvent?.job) return;
    const invId = jobEvent.job.investigation_id;
    if (!invId) return;

    const state = this.states.get(invId);
    if (!state) return;

    if (jobEvent.type === 'job_completed') {
      const fact: ResearchFact = {
        id: `fact-job-${Date.now()}`,
        category: 'EXECUTION',
        statement: `Job '${jobEvent.job.id}' (${jobEvent.job.engine} / ${jobEvent.job.operation}) completed with exit code ${jobEvent.job.exit_code}.`,
        source: 'JobOrchestrator',
        verified_at: new Date().toISOString(),
        confidence: 1.0,
      };
      state.facts.push(fact);
      this.emitEvent(ControllerEventType.ANALYSIS_COMPLETED, { investigation_id: invId, job: jobEvent.job });
    } else if (jobEvent.type === 'job_failed') {
      const blocker: ResearchBlocker = {
        id: `block-job-${Date.now()}`,
        phase: state.current_phase,
        code: 'ENGINE_EXECUTION_FAILED',
        message: `Job '${jobEvent.job.id}' failed: ${jobEvent.job.error || 'Unknown execution failure'}`,
        resolution_hint: 'Inspect engine stderr artifact or select an alternative applicable engine.',
        blocking_entity_id: jobEvent.job.id,
        timestamp: new Date().toISOString(),
      };
      state.blockers.push(blocker);
      this.emitEvent(ControllerEventType.ACTION_BLOCKED, { investigation_id: invId, blocker });
    }
  }

  /**
   * Initializes or updates an investigation research objective.
   */
  public async executeObjective(params: {
    objective: string;
    program_id?: string;
    target_id?: string;
    investigation_id?: string;
    auto_advance?: boolean;
  }): Promise<ControllerState> {
    const requestedId = params.investigation_id || `inv-ai-${Date.now()}`;
    let state = this.states.get(requestedId);
    // Resolved after any store-assigned id is adopted; used by the auto-advance loop.
    let invId = requestedId;

    if (!state) {
      // Find or establish investigation
      let existingInv = globalDB.getInvestigation(requestedId);
      if (!existingInv && params.program_id && params.target_id) {
        existingInv = globalDB.createInvestigation({
          program_id: params.program_id,
          target_id: params.target_id,
          title: `Autonomous Research: ${params.objective.substring(0, 60)}`,
          description: params.objective,
          status: 'ACTIVE' as any,
        });
      }

      // The store assigns its own id. Adopt it so controller state, dispatched
      // jobs and evidence all reference the persisted investigation rather than
      // a synthetic id that does not exist in the database.
      invId = existingInv?.id || requestedId;

      const plan = this.generateInitialPlan(params.objective, params.program_id, params.target_id);

      state = {
        investigation_id: invId,
        session_id: `session-${Date.now()}`,
        program_id: params.program_id || existingInv?.program_id,
        target_id: params.target_id || existingInv?.target_id,
        current_phase: ResearchPhase.UNDERSTANDING_REQUEST,
        current_objective: params.objective,
        current_activity: 'Analyzing objective and generating structured plan...',
        plan,
        facts: [],
        hypotheses: [],
        unknowns: [],
        evidence_refs: [],
        decisions: [
          {
            id: `dec-${Date.now()}`,
            phase: ResearchPhase.UNDERSTANDING_REQUEST,
            decision: 'Initialized autonomous security research session.',
            reason: 'User provided objective: ' + params.objective,
            timestamp: new Date().toISOString(),
          },
        ],
        blockers: [],
        approvals: [],
        active_jobs: [],
        capability_matrix: [],
        progress_percentage: 10,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      // Keep the requested alias resolvable so callers that passed an explicit
      // id (or none) can still fetch state by it.
      this.states.set(invId, state);
      if (requestedId !== invId) {
        this.states.set(requestedId, state);
      }
      this.emitEvent(ControllerEventType.CONTROLLER_PHASE_CHANGED, { investigation_id: invId, phase: state.current_phase });
    } else {
      state.current_objective = params.objective;
      state.updated_at = new Date().toISOString();
    }

    // Auto-detect pasted bounty guidelines or policies
    const isGuidelinesText =
      params.objective.includes('in-scope') ||
      params.objective.includes('In-Scope') ||
      params.objective.includes('out-of-scope') ||
      params.objective.includes('Out-of-Scope') ||
      params.objective.includes('safe harbor') ||
      params.objective.includes('Safe Harbor') ||
      params.objective.includes('# Scope') ||
      (params.objective.length > 150 && (params.objective.includes('github.com') || params.objective.includes('0x')));

    if (isGuidelinesText && (!state.program_id || !state.target_id)) {
      try {
        state.current_activity = 'Compiling unstructured bounty guidelines into policy & scope rules...';
        const compileResult = await globalToolRegistry.invokeTool(
          'compileProgramPolicyAndScope',
          { guidelines_text: params.objective, program_id: state.program_id },
          {
            session_id: state.session_id,
            investigation_id: invId,
            is_approved: () => true,
          }
        );

        if (compileResult.success && compileResult.data?.program) {
          state.program_id = compileResult.data.program.id;
          if (compileResult.facts_established) {
            state.facts.push(...compileResult.facts_established);
          }
          if (compileResult.data.unknowns_identified) {
            for (const u of compileResult.data.unknowns_identified) {
              const unk: ResearchUnknown = {
                id: `unk-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
                question: u.question,
                context: u.context,
                impact: u.impact,
                status: 'UNRESOLVED',
                created_at: new Date().toISOString(),
              };
              state.unknowns.push(unk);
              this.emitEvent(ControllerEventType.UNKNOWN_IDENTIFIED, { investigation_id: invId, unknown: unk });
            }
          }
          if (!state.target_id) {
            const targets = globalDB.listTargets().filter(t => t.program_id === state.program_id);
            if (targets.length > 0) {
              state.target_id = targets[0].id;
            }
          }
          this.emitEvent(ControllerEventType.POLICY_COMPILED, { investigation_id: invId, program: compileResult.data.program });
        }
      } catch (err: any) {
        console.warn(`[AISecurityController] Guidelines compilation warning: ${err.message}`);
      }
    }

    if (params.auto_advance) {
      // Step until paused, blocked, or completed
      let iterations = 0;
      const maxIterations = 8;
      while (
        iterations < maxIterations &&
        state.current_phase !== ResearchPhase.BLOCKED &&
        state.current_phase !== ResearchPhase.COMPLETED &&
        state.current_phase !== ResearchPhase.FAILED &&
        state.approvals.filter(a => a.status === 'PENDING').length === 0
      ) {
        iterations++;
        await this.step(invId);
      }
    }

    return state;
  }

  /**
   * Performs a single discrete step in the research plan.
   */
  public async step(investigation_id: string): Promise<ControllerState> {
    const state = this.states.get(investigation_id);
    if (!state) {
      throw new Error(`Investigation state '${investigation_id}' not found.`);
    }

    // If there is an unresolved pending approval, we cannot proceed
    const pendingApproval = state.approvals.find(a => a.status === 'PENDING');
    if (pendingApproval) {
      state.current_phase = ResearchPhase.BLOCKED;
      state.current_activity = `Waiting for researcher approval on action: ${pendingApproval.action}`;
      return state;
    }

    const program = state.program_id ? globalDB.getProgram(state.program_id) : undefined;
    const target = state.target_id ? globalDB.getTarget(state.target_id) : undefined;

    // Reason on current context
    const reasoningContext = {
      objective: state.current_objective,
      phase: state.current_phase,
      program,
      target,
      facts: state.facts,
      hypotheses: state.hypotheses,
      unknowns: state.unknowns,
      capability_matrix: state.capability_matrix,
      blockers: state.blockers,
      available_tools: globalToolRegistry.getToolSchemas(),
    };

    const reasoning = await globalAIProviderClient.reason(reasoningContext);

    // Record decisions
    for (const dec of reasoning.decisions) {
      state.decisions.push({
        id: `dec-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        phase: state.current_phase,
        decision: dec,
        reason: reasoning.explanation,
        timestamp: new Date().toISOString(),
      });
      this.emitEvent(ControllerEventType.CONTROLLER_DECISION_MADE, { investigation_id, decision: dec });
    }

    // Record any new unknowns
    if (reasoning.new_unknowns) {
      for (const u of reasoning.new_unknowns) {
        if (!state.unknowns.some(existing => existing.question === u.question)) {
          const newUnk: ResearchUnknown = {
            id: `unk-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            question: u.question,
            context: u.context,
            impact: u.impact,
            status: 'UNRESOLVED',
            created_at: new Date().toISOString(),
          };
          state.unknowns.push(newUnk);
          this.emitEvent(ControllerEventType.UNKNOWN_IDENTIFIED, { investigation_id, unknown: newUnk });
        }
      }
    }

    // Resolve any identified unknowns
    if (reasoning.resolved_unknowns) {
      for (const res of reasoning.resolved_unknowns) {
        const match = state.unknowns.find(u => u.id === res.unknown_id || u.question.includes(res.unknown_id));
        if (match && match.status === 'UNRESOLVED') {
          match.status = 'RESOLVED';
          match.resolved_at = new Date().toISOString();
          match.resolution_summary = res.resolution_summary;
          if (res.fact_statement) {
            const fact: ResearchFact = {
              id: `fact-unk-res-${Date.now()}`,
              category: 'EXECUTION',
              statement: res.fact_statement,
              source: 'UnknownResolution',
              verified_at: new Date().toISOString(),
              confidence: 1.0,
            };
            state.facts.push(fact);
            match.resolution_fact_id = fact.id;
          }
          this.emitEvent(ControllerEventType.UNKNOWN_RESOLVED, { investigation_id, unknown: match });
        }
      }
    }

    // Record any new hypotheses
    if (reasoning.new_hypotheses) {
      for (const h of reasoning.new_hypotheses) {
        state.hypotheses.push({
          id: `hyp-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          title: h.title,
          premise: h.premise,
          target_id: state.target_id || '',
          supporting_fact_ids: state.facts.map(f => f.id),
          severity: h.severity || 'MEDIUM',
          confidence: h.confidence || 'MEDIUM',
          status: 'ACTIVE',
          requires_verification: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });
        this.emitEvent(ControllerEventType.CANDIDATE_DISCOVERED, { investigation_id, hypothesis: h });
      }
    }

    // Execute suggested tool calls
    const executionContext: ControllerExecutionContext = {
      session_id: state.session_id,
      investigation_id,
      program_id: state.program_id,
      target_id: state.target_id,
      is_approved: (action: string) => this.approvedActions.has(`${investigation_id}:${action}`),
    };

    for (const call of reasoning.suggested_tool_calls) {
      state.current_activity = `Executing tool ${call.tool}...`;
      const result = await globalToolRegistry.invokeTool(call.tool, call.parameters, executionContext);

      if (result.success) {
        // Collect facts
        if (result.facts_established) {
          state.facts.push(...result.facts_established);
        }

        // Special tool side effects
        if (call.tool === 'inspectTargetCapability' && result.data?.matrix) {
          state.capability_matrix = result.data.matrix;
          this.emitEvent(ControllerEventType.CAPABILITY_ASSESSED, { investigation_id, matrix: result.data.matrix });
        } else if (call.tool === 'acquireTargetSource' && result.data?.snapshot) {
          this.emitEvent(ControllerEventType.TARGET_ACQUIRED, { investigation_id, snapshot: result.data.snapshot });
        } else if (call.tool === 'verifySourceIntegrity') {
          this.emitEvent(ControllerEventType.SOURCE_VERIFIED, { investigation_id, data: result.data });
        } else if (call.tool === 'evaluateScope') {
          this.emitEvent(ControllerEventType.SCOPE_VERIFIED, { investigation_id, decision: result.data });
        } else if (call.tool === 'validateProgramPolicy') {
          this.emitEvent(ControllerEventType.PROGRAM_VERIFIED, { investigation_id, policy: result.data });
        } else if (call.tool === 'createAnalysisJob' && result.data?.job_id) {
          state.active_jobs.push(result.data.job_id);
          this.emitEvent(ControllerEventType.ANALYSIS_STARTED, { investigation_id, job_id: result.data.job_id });
        } else if (call.tool === 'compileProgramPolicyAndScope' && result.data?.program) {
          state.program_id = result.data.program.id;
          if (result.data.unknowns_identified) {
            for (const u of result.data.unknowns_identified) {
              if (!state.unknowns.some(existing => existing.question === u.question)) {
                const unk: ResearchUnknown = {
                  id: `unk-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
                  question: u.question,
                  context: u.context,
                  impact: u.impact,
                  status: 'UNRESOLVED',
                  created_at: new Date().toISOString(),
                };
                state.unknowns.push(unk);
                this.emitEvent(ControllerEventType.UNKNOWN_IDENTIFIED, { investigation_id, unknown: unk });
              }
            }
          }
          if (!state.target_id && result.data.targets_created > 0) {
            const targets = globalDB.listTargets().filter(t => t.program_id === state.program_id);
            if (targets.length > 0) {
              state.target_id = targets[0].id;
            }
          }
          this.emitEvent(ControllerEventType.POLICY_COMPILED, { investigation_id, program: result.data.program });
        } else if (call.tool === 'executeFoundryPoC' || call.tool === 'requestVerification') {
          this.emitEvent(ControllerEventType.VERIFICATION_COMPLETED, { investigation_id, data: result.data });
        }
      } else {
        // Handle failure
        if (result.code === 'APPROVAL_REQUIRED' || result.error?.includes('requires explicit researcher approval')) {
          const approvalReq: UserApprovalRequest = {
            id: `appr-${Date.now()}`,
            action: call.tool,
            description: `Tool '${call.tool}' with params ${JSON.stringify(call.parameters)} requires authorization.`,
            target_id: state.target_id,
            sensitive: true,
            required_policy_check: 'RESEARCHER_APPROVAL',
            status: 'PENDING',
            created_at: new Date().toISOString(),
          };
          state.approvals.push(approvalReq);
          state.current_phase = ResearchPhase.BLOCKED;
          state.current_activity = `Paused: Researcher approval required for ${call.tool}.`;
          this.emitEvent(ControllerEventType.USER_APPROVAL_REQUESTED, { investigation_id, approval: approvalReq });
          return state;
        }

        const blocker: ResearchBlocker = {
          id: `block-${Date.now()}`,
          phase: state.current_phase,
          code: result.code || 'TOOL_EXECUTION_FAILED',
          message: result.error || 'Unknown tool failure',
          resolution_hint: 'Review parameters or check underlying engine installation.',
          timestamp: new Date().toISOString(),
        };
        state.blockers.push(blocker);
        state.current_phase = ResearchPhase.BLOCKED;
        state.current_activity = `Blocked: ${blocker.message}`;
        this.emitEvent(ControllerEventType.ACTION_BLOCKED, { investigation_id, blocker });
        return state;
      }
    }

    // Advance phase if recommended
    if (reasoning.next_phase && reasoning.next_phase !== state.current_phase) {
      const validation = validateStateTransition(state, reasoning.next_phase);
      if (validation.allowed) {
        state.current_phase = reasoning.next_phase;
        this.emitEvent(ControllerEventType.CONTROLLER_PHASE_CHANGED, { investigation_id, phase: state.current_phase });
      } else {
        const blocker: ResearchBlocker = {
          id: `block-trans-${Date.now()}`,
          phase: state.current_phase,
          code: validation.missing_prerequisite || 'TRANSITION_PREREQUISITE_MISSING',
          message: validation.reason || 'Phase transition prerequisite not satisfied.',
          resolution_hint: 'Fulfill earlier stages before attempting transition.',
          timestamp: new Date().toISOString(),
        };
        state.blockers.push(blocker);
        state.current_phase = ResearchPhase.BLOCKED;
        this.emitEvent(ControllerEventType.ACTION_BLOCKED, { investigation_id, blocker });
      }
    }

    // Update progress percentage
    state.progress_percentage = this.calculateProgress(state);
    state.current_activity = reasoning.explanation;
    state.updated_at = new Date().toISOString();

    return state;
  }

  /**
   * Resolves a pending user approval request.
   */
  public async approveAction(
    investigation_id: string,
    approval_id: string,
    approved: boolean,
    reason?: string
  ): Promise<ControllerState> {
    const state = this.states.get(investigation_id);
    if (!state) {
      throw new Error(`Investigation state '${investigation_id}' not found.`);
    }

    const req = state.approvals.find(a => a.id === approval_id);
    if (!req) {
      throw new Error(`Approval request '${approval_id}' not found.`);
    }

    req.status = approved ? 'APPROVED' : 'REJECTED';
    req.resolved_at = new Date().toISOString();
    req.resolution_reason = reason || (approved ? 'Authorized by researcher.' : 'Rejected by researcher.');

    if (approved) {
      this.approvedActions.add(`${investigation_id}:${req.action}`);
      // Remove BLOCKED if it was due to this approval
      state.blockers = state.blockers.filter(b => b.code !== 'APPROVAL_REQUIRED');
      if (state.current_phase === ResearchPhase.BLOCKED) {
        state.current_phase = ResearchPhase.VERIFICATION_REQUESTED;
      }
    } else {
      state.blockers.push({
        id: `block-rej-${Date.now()}`,
        phase: state.current_phase,
        code: 'RESEARCHER_REJECTED',
        message: `Action '${req.action}' rejected by researcher: ${req.resolution_reason}`,
        resolution_hint: 'Action will not be executed. Investigation proceeds without this test.',
        timestamp: new Date().toISOString(),
      });
      state.current_phase = ResearchPhase.BLOCKED;
    }

    this.emitEvent(ControllerEventType.USER_APPROVAL_RESOLVED, { investigation_id, approval: req });
    return state;
  }

  public getState(investigation_id: string): ControllerState | undefined {
    return this.states.get(investigation_id);
  }

  public getAllStates(): ControllerState[] {
    // One state may be registered under both its canonical id and the caller's
    // requested alias; deduplicate by state identity so callers see each
    // investigation exactly once.
    const seen = new Set<ControllerState>();
    const unique: ControllerState[] = [];
    for (const state of this.states.values()) {
      if (seen.has(state)) continue;
      seen.add(state);
      unique.push(state);
    }
    return unique;
  }

  private generateInitialPlan(objective: string, programId?: string, targetId?: string): ResearchPlan {
    const steps: ResearchPlanStep[] = [
      {
        id: 'step-1',
        order: 1,
        phase: ResearchPhase.POLICY_VALIDATION,
        title: 'Program Intelligence & Policy Validation',
        description: 'Inspect program testing rules, safe-harbor constraints, and policy freshness.',
        status: 'PENDING',
        prerequisite_steps: [],
        executed_tools: ['getProgram', 'validateProgramPolicy'],
      },
      {
        id: 'step-2',
        order: 2,
        phase: ResearchPhase.SCOPE_VALIDATION,
        title: 'Target Scope Authorization',
        description: 'Verify target asset against program scope rules to ensure IN_SCOPE authorization.',
        status: 'PENDING',
        prerequisite_steps: ['step-1'],
        executed_tools: ['evaluateScope', 'explainScopeDecision'],
      },
      {
        id: 'step-3',
        order: 3,
        phase: ResearchPhase.SOURCE_ACQUISITION,
        title: 'Sandboxed Source Acquisition',
        description: 'Acquire repository code into sandbox storage and compute deterministic tree SHA-256.',
        status: 'PENDING',
        prerequisite_steps: ['step-2'],
        executed_tools: ['acquireTargetSource', 'verifySourceIntegrity'],
      },
      {
        id: 'step-4',
        order: 4,
        phase: ResearchPhase.CAPABILITY_ASSESSMENT,
        title: 'Engine Capability Assessment',
        description: 'Assess target technology and build capability matrix of applicable installed tools.',
        status: 'PENDING',
        prerequisite_steps: ['step-3'],
        executed_tools: ['inspectTargetCapability', 'listEngines'],
      },
      {
        id: 'step-5',
        order: 5,
        phase: ResearchPhase.ANALYSIS_PLANNING,
        title: 'Formulate Analysis Plan',
        description: 'Select static rules, AST queries, and vulnerability patterns.',
        status: 'PENDING',
        prerequisite_steps: ['step-4'],
        executed_tools: ['createAnalysisJob'],
      },
      {
        id: 'step-6',
        order: 6,
        phase: ResearchPhase.ANALYSIS_EXECUTION,
        title: 'Orchestrated Engine Execution',
        description: 'Dispatch asynchronous analysis jobs and collect machine-readable artifacts.',
        status: 'PENDING',
        prerequisite_steps: ['step-5'],
        executed_tools: ['getJobStatus', 'getJobResult'],
      },
      {
        id: 'step-7',
        order: 7,
        phase: ResearchPhase.HYPOTHESIS_FORMATION,
        title: 'Hypothesis Formation & Verification Readiness',
        description: 'Correlate outputs into vulnerability hypotheses; prepare for authorized corroboration.',
        status: 'PENDING',
        prerequisite_steps: ['step-6'],
        executed_tools: ['listCandidates', 'requestVerification'],
      },
    ];

    return {
      id: `plan-${Date.now()}`,
      objective,
      steps,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
  }

  private calculateProgress(state: ControllerState): number {
    switch (state.current_phase) {
      case ResearchPhase.IDLE: return 0;
      case ResearchPhase.UNDERSTANDING_REQUEST: return 10;
      case ResearchPhase.PLANNING: return 20;
      case ResearchPhase.POLICY_VALIDATION: return 30;
      case ResearchPhase.SCOPE_VALIDATION: return 40;
      case ResearchPhase.TARGET_VALIDATION: return 50;
      case ResearchPhase.SOURCE_ACQUISITION: return 60;
      case ResearchPhase.SOURCE_VERIFICATION: return 70;
      case ResearchPhase.CAPABILITY_ASSESSMENT: return 80;
      case ResearchPhase.ANALYSIS_PLANNING: return 85;
      case ResearchPhase.ANALYSIS_EXECUTION: return 90;
      case ResearchPhase.RESULT_CORRELATION: return 92;
      case ResearchPhase.HYPOTHESIS_FORMATION: return 95;
      case ResearchPhase.CORROBORATION: return 97;
      case ResearchPhase.VERIFICATION_REQUESTED: return 98;
      case ResearchPhase.COMPLETED: return 100;
      case ResearchPhase.BLOCKED: return Math.max(state.progress_percentage, 10);
      case ResearchPhase.FAILED: return 0;
      default: return 50;
    }
  }
}

export const globalAISecurityController = new AISecurityController();
