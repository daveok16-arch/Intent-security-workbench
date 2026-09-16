import React, { useState, useEffect, useCallback } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import {
  ControllerState,
  ResearchPhase,
  ResearchFact,
  ResearchHypothesis,
  UserApprovalRequest,
  ResearchPlanStep,
  ResearchDecision,
  CapabilityMatrixEntry,
} from '../types.js';
import {
  Bot,
  Play,
  RotateCw,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Database,
  Cpu,
  Lock,
  FileSearch,
  Sparkles,
  Info,
  Clock,
  Layers,
  ChevronRight,
  Check,
  X,
  Send,
  HelpCircle,
  Activity,
  Compass,
} from 'lucide-react';

export const AiControllerView: React.FC = () => {
  const { targets, programs, investigations, selectedInvestigationId, setSelectedInvestigationId } = useWorkbench();

  const [states, setStates] = useState<ControllerState[]>([]);
  const [activeState, setActiveState] = useState<ControllerState | null>(null);
  const [loading, setLoading] = useState(false);
  const [stepping, setStepping] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // New Objective Form
  const [showNewModal, setShowNewModal] = useState(false);
  const [targetId, setTargetId] = useState('');
  const [objective, setObjective] = useState('');
  const [autoAdvance, setAutoAdvance] = useState(true);

  // Approval rejection modal/input
  const [rejectingApprovalId, setRejectingApprovalId] = useState<string | null>(null);
  const [rejectionReason, setRejectionReason] = useState('');

  // Active sub-tab in Controller view
  const [activeTab, setActiveTab] = useState<'overview' | 'facts_hypotheses' | 'plan' | 'matrix' | 'decisions'>('overview');

  // Fetch all controller states
  const fetchStates = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/ai/controller/states');
      if (res.ok) {
        const data = await res.json();
        setStates(data);
        if (data.length > 0 && !activeState) {
          // If there is an investigation selected in context, prefer that
          const match = selectedInvestigationId ? data.find((s: ControllerState) => s.investigation_id === selectedInvestigationId) : null;
          setActiveState(match || data[0]);
        } else if (activeState) {
          // Refresh active state
          const updated = data.find((s: ControllerState) => s.investigation_id === activeState.investigation_id);
          if (updated) setActiveState(updated);
        }
      }
    } catch (err: any) {
      console.error('Failed to fetch controller states:', err);
    }
  }, [activeState, selectedInvestigationId]);

  useEffect(() => {
    fetchStates();
    const interval = setInterval(fetchStates, 3000);
    return () => clearInterval(interval);
  }, [fetchStates]);

  // Handle Objective submission
  const handleSubmitObjective = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!objective.trim()) {
      setError('Please provide a research objective.');
      return;
    }

    setLoading(true);
    setError(null);

    const selectedTarget = targets.find(t => t.id === targetId);

    try {
      const res = await fetch('/api/v1/ai/controller/objective', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          objective: objective.trim(),
          target_id: targetId || undefined,
          program_id: selectedTarget?.program_id || undefined,
          investigation_id: selectedInvestigationId || undefined,
          auto_advance: autoAdvance,
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Failed to submit objective');
      }

      const newState: ControllerState = await res.json();
      setActiveState(newState);
      setShowNewModal(false);
      setObjective('');
      await fetchStates();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Step discrete action
  const handleStep = async () => {
    if (!activeState) return;
    setStepping(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/ai/controller/step/${activeState.investigation_id}`, {
        method: 'POST',
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Step failed');
      }
      const updatedState = await res.json();
      setActiveState(updatedState);
      await fetchStates();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setStepping(false);
    }
  };

  // Handle Approval Resolution
  const handleResolveApproval = async (approvalId: string, approved: boolean, reason?: string) => {
    if (!activeState) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/ai/controller/approve/${activeState.investigation_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          approval_id: approvalId,
          approved,
          reason,
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Failed to resolve approval');
      }

      const updatedState = await res.json();
      setActiveState(updatedState);
      setRejectingApprovalId(null);
      setRejectionReason('');
      await fetchStates();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getPhaseBadge = (phase: ResearchPhase) => {
    switch (phase) {
      case ResearchPhase.COMPLETED:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case ResearchPhase.BLOCKED:
      case ResearchPhase.FAILED:
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case ResearchPhase.VERIFICATION_REQUESTED:
      case ResearchPhase.IMPACT_VERIFICATION:
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      default:
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
    }
  };

  const pendingApprovals = activeState?.approvals.filter(a => a.status === 'PENDING') || [];

  return (
    <div id="ai-security-controller-view" className="space-y-6">
      {/* Header & Session Control */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <Bot className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-semibold text-white tracking-tight">AI Security Control Plane</h1>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Orchestrator Core
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Deterministic autonomous security researcher invoking verified Workbench capabilities.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {states.length > 0 && (
            <select
              id="select-controller-session"
              value={activeState?.investigation_id || ''}
              onChange={(e) => {
                const s = states.find(st => st.investigation_id === e.target.value);
                if (s) {
                  setActiveState(s);
                  setSelectedInvestigationId(s.investigation_id);
                }
              }}
              className="bg-[#141414] border border-white/10 text-xs text-slate-200 rounded-md px-3 py-2 focus:outline-none focus:border-emerald-500"
            >
              {states.map(st => (
                <option key={st.investigation_id} value={st.investigation_id}>
                  {st.investigation_id} ({st.current_phase})
                </option>
              ))}
            </select>
          )}

          {activeState && (
            <button
              id="btn-step-controller"
              onClick={handleStep}
              disabled={stepping || activeState.current_phase === ResearchPhase.COMPLETED || pendingApprovals.length > 0}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium border transition cursor-pointer ${
                pendingApprovals.length > 0
                  ? 'bg-amber-500/10 text-amber-300 border-amber-500/30 opacity-60 cursor-not-allowed'
                  : 'bg-white/5 hover:bg-white/10 text-white border-white/10'
              }`}
            >
              {stepping ? <RotateCw className="h-3.5 w-3.5 animate-spin text-emerald-400" /> : <Play className="h-3.5 w-3.5 text-emerald-400" />}
              <span>Step Controller</span>
            </button>
          )}

          <button
            id="btn-new-ai-objective"
            onClick={() => setShowNewModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-md text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition cursor-pointer"
          >
            <Sparkles className="h-3.5 w-3.5" />
            <span>New Research Objective</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-md text-xs text-rose-300 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Active Controller State Overview Card */}
      {activeState ? (
        <div className="space-y-6">
          <div className="bg-[#121212] border border-white/10 rounded-xl p-5 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`text-[11px] font-mono px-2.5 py-0.5 rounded-full border ${getPhaseBadge(activeState.current_phase)}`}>
                    {activeState.current_phase}
                  </span>
                  <span className="text-xs text-slate-500 font-mono">ID: {activeState.investigation_id}</span>
                </div>
                <h2 className="text-base font-semibold text-white tracking-tight">{activeState.current_objective}</h2>
              </div>

              <div className="flex items-center gap-4 text-right">
                <div>
                  <div className="text-[10px] text-slate-400 uppercase font-mono">Progress</div>
                  <div className="text-sm font-semibold text-emerald-400 font-mono">{activeState.progress_percentage}%</div>
                </div>
                <div className="w-32 bg-white/5 h-2 rounded-full overflow-hidden border border-white/10">
                  <div
                    className="bg-emerald-500 h-full rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(100, Math.max(5, activeState.progress_percentage))}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Current Activity Message */}
            <div className="bg-black/40 border border-white/5 rounded-lg p-3 text-xs flex items-start gap-2.5">
              <Activity className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="text-slate-400 font-mono text-[11px] uppercase tracking-wider">Current Activity:</span>
                <p className="text-slate-200">{activeState.current_activity}</p>
              </div>
            </div>

            {/* Sub-navigation tabs */}
            <div className="flex items-center gap-2 border-b border-white/10 pt-2">
              <button
                onClick={() => setActiveTab('overview')}
                className={`pb-2 px-3 text-xs font-medium border-b-2 transition ${
                  activeTab === 'overview' ? 'border-emerald-500 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Overview & Status
              </button>
              <button
                onClick={() => setActiveTab('facts_hypotheses')}
                className={`pb-2 px-3 text-xs font-medium border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'facts_hypotheses' ? 'border-emerald-500 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>Facts vs. Hypotheses</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-emerald-500/20 text-emerald-300 rounded-full font-mono">
                  {activeState.facts.length} / {activeState.hypotheses.length}
                </span>
              </button>
              <button
                onClick={() => setActiveTab('plan')}
                className={`pb-2 px-3 text-xs font-medium border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'plan' ? 'border-emerald-500 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>Research Plan</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-white/10 text-slate-300 rounded-full font-mono">
                  {activeState.plan?.steps.length || 0}
                </span>
              </button>
              <button
                onClick={() => setActiveTab('matrix')}
                className={`pb-2 px-3 text-xs font-medium border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'matrix' ? 'border-emerald-500 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>Capability Matrix</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-white/10 text-slate-300 rounded-full font-mono">
                  {activeState.capability_matrix.length}
                </span>
              </button>
              <button
                onClick={() => setActiveTab('decisions')}
                className={`pb-2 px-3 text-xs font-medium border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'decisions' ? 'border-emerald-500 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>Decisions Audit Log</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-white/10 text-slate-300 rounded-full font-mono">
                  {activeState.decisions.length}
                </span>
              </button>
            </div>
          </div>

          {/* Pending Human-in-the-Loop Approvals Alert */}
          {pendingApprovals.length > 0 && (
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-5 space-y-4">
              <div className="flex items-center gap-2.5 text-amber-400">
                <ShieldAlert className="h-5 w-5" />
                <h3 className="text-sm font-semibold tracking-tight">Researcher Authorization Required</h3>
              </div>
              <p className="text-xs text-amber-200/80 leading-relaxed">
                The AI Security Controller has proposed sensitive verification or state transitions that require human sign-off.
                Execution is safely paused until an authorized researcher approves or rejects each action.
              </p>

              <div className="space-y-3 pt-1">
                {pendingApprovals.map((req) => (
                  <div key={req.id} className="bg-black/50 border border-amber-500/20 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-amber-300 uppercase">{req.action}</span>
                        <span className="text-[10px] px-1.5 py-0.5 bg-amber-500/20 text-amber-200 rounded font-mono">
                          {req.required_policy_check}
                        </span>
                      </div>
                      <p className="text-slate-300">{req.description}</p>
                      <div className="text-[11px] text-slate-500 font-mono">Requested at: {new Date(req.created_at).toLocaleTimeString()}</div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleResolveApproval(req.id, true)}
                        disabled={loading}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition cursor-pointer"
                      >
                        <Check className="h-3.5 w-3.5" />
                        <span>Authorize Action</span>
                      </button>

                      <button
                        onClick={() => setRejectingApprovalId(req.id)}
                        disabled={loading}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-rose-600/80 hover:bg-rose-600 text-white transition cursor-pointer"
                      >
                        <X className="h-3.5 w-3.5" />
                        <span>Reject</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {rejectingApprovalId && (
                <div className="bg-black/70 border border-rose-500/30 rounded-lg p-4 space-y-3">
                  <div className="text-xs font-semibold text-rose-300">Provide Rejection Reason</div>
                  <input
                    type="text"
                    value={rejectionReason}
                    onChange={(e) => setRejectionReason(e.target.value)}
                    placeholder="e.g. Target contract not redeployed yet; dynamic probe prohibited on staging"
                    className="w-full bg-[#161616] border border-white/10 rounded-md px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-rose-500"
                  />
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => setRejectingApprovalId(null)}
                      className="px-3 py-1 text-xs text-slate-400 hover:text-white"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => handleResolveApproval(rejectingApprovalId, false, rejectionReason)}
                      className="px-3 py-1 bg-rose-600 text-white text-xs rounded font-medium hover:bg-rose-500"
                    >
                      Confirm Rejection
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 1: Overview & Status */}
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Research Pipeline Card */}
              <div className="lg:col-span-2 bg-[#121212] border border-white/10 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">Execution State Machine</h3>
                  <span className="text-xs text-slate-500 font-mono">Deterministic Phase Engine</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                  {[
                    { phase: ResearchPhase.POLICY_VALIDATION, label: 'Policy Check', icon: ShieldCheck },
                    { phase: ResearchPhase.SCOPE_VALIDATION, label: 'Scope Check', icon: Compass },
                    { phase: ResearchPhase.SOURCE_ACQUISITION, label: 'Source Sandbox', icon: Database },
                    { phase: ResearchPhase.CAPABILITY_ASSESSMENT, label: 'Tool Capability', icon: Cpu },
                    { phase: ResearchPhase.ANALYSIS_EXECUTION, label: 'Engine Scans', icon: FileSearch },
                    { phase: ResearchPhase.HYPOTHESIS_FORMATION, label: 'Hypotheses', icon: Sparkles },
                    { phase: ResearchPhase.VERIFICATION_REQUESTED, label: 'Verification Gate', icon: Lock },
                    { phase: ResearchPhase.COMPLETED, label: 'Report Ready', icon: CheckCircle2 },
                  ].map((p, idx) => {
                    const Icon = p.icon;
                    const isCurrent = activeState.current_phase === p.phase;
                    const isPassed = activeState.decisions.some(d => d.phase === p.phase);
                    return (
                      <div
                        key={p.phase}
                        className={`p-3 rounded-lg border text-xs flex flex-col gap-1.5 transition ${
                          isCurrent
                            ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
                            : isPassed
                            ? 'bg-white/5 border-white/10 text-slate-300'
                            : 'bg-black/20 border-white/5 text-slate-600'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] text-slate-500">0{idx + 1}</span>
                          <Icon className={`h-4 w-4 ${isCurrent ? 'text-emerald-400 animate-pulse' : isPassed ? 'text-slate-400' : 'text-slate-700'}`} />
                        </div>
                        <span className="font-medium">{p.label}</span>
                      </div>
                    );
                  })}
                </div>

                {/* Blockers */}
                {activeState.blockers.length > 0 && (
                  <div className="mt-4 p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg space-y-2">
                    <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold">
                      <AlertTriangle className="h-4 w-4" />
                      <span>Active Research Blockers ({activeState.blockers.length})</span>
                    </div>
                    {activeState.blockers.map((b) => (
                      <div key={b.id} className="text-xs text-rose-200/90 pl-6 space-y-0.5">
                        <div className="font-mono font-bold text-[11px] text-rose-300">{b.code}: {b.message}</div>
                        <div className="text-slate-400 text-[11px]">Hint: {b.resolution_hint}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Research Metrics & Environment */}
              <div className="bg-[#121212] border border-white/10 rounded-xl p-5 space-y-4">
                <h3 className="text-sm font-semibold text-white">Target & Environment</h3>

                <div className="space-y-3 text-xs">
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Target ID</span>
                    <span className="font-mono text-slate-200">{activeState.target_id || 'Global'}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Program ID</span>
                    <span className="font-mono text-slate-200">{activeState.program_id || 'Default Safe Harbor'}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Established Facts</span>
                    <span className="font-mono font-semibold text-emerald-400">{activeState.facts.length}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Active Hypotheses</span>
                    <span className="font-mono font-semibold text-purple-400">{activeState.hypotheses.length}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Recorded Decisions</span>
                    <span className="font-mono text-slate-200">{activeState.decisions.length}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400">Created At</span>
                    <span className="font-mono text-slate-400">{new Date(activeState.created_at).toLocaleTimeString()}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Facts vs Hypotheses Dual Panel */}
          {activeTab === 'facts_hypotheses' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Facts (Ground Truth) */}
              <div className="bg-[#121212] border border-white/10 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                    <h3 className="text-sm font-semibold text-white">Ground-Truth Facts</h3>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    100% Cryptographically Verified
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Established by sandbox executions, scope evaluations, and SHA-256 evidence integrity checks.
                </p>

                <div className="space-y-2.5 max-h-[480px] overflow-y-auto pr-1">
                  {activeState.facts.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-500 border border-dashed border-white/5 rounded-lg">
                      No facts established yet. Step the controller to begin validation.
                    </div>
                  ) : (
                    activeState.facts.map((fact) => (
                      <div key={fact.id} className="p-3 bg-black/40 border border-white/5 rounded-lg space-y-1.5 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 bg-emerald-500/10 text-emerald-400 rounded">
                            {fact.category}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">Source: {fact.source}</span>
                        </div>
                        <p className="text-slate-200 leading-relaxed">{fact.statement}</p>
                        <div className="text-[10px] text-slate-500 font-mono">
                          Verified at: {new Date(fact.verified_at).toLocaleTimeString()}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Hypotheses (Unproven Candidates) */}
              <div className="bg-[#121212] border border-white/10 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-purple-400" />
                    <h3 className="text-sm font-semibold text-white">Research Hypotheses</h3>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    Unverified Reasoning
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  AI security conjectures requiring dynamic reproduction or formal SMT proof before acceptance.
                </p>

                <div className="space-y-2.5 max-h-[480px] overflow-y-auto pr-1">
                  {activeState.hypotheses.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-500 border border-dashed border-white/5 rounded-lg">
                      No hypotheses formed yet. Engines must finish correlation before generating hypotheses.
                    </div>
                  ) : (
                    activeState.hypotheses.map((hyp) => (
                      <div key={hyp.id} className="p-3 bg-black/40 border border-white/5 rounded-lg space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-200">{hyp.title}</span>
                          <span className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded ${
                            hyp.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                          }`}>
                            {hyp.severity || 'MEDIUM'}
                          </span>
                        </div>
                        <p className="text-slate-300 leading-relaxed">{hyp.premise}</p>
                        <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-white/5">
                          <span>Status: {hyp.status}</span>
                          <span className="text-purple-400">Requires Verification: {hyp.requires_verification ? 'YES' : 'NO'}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Research Plan */}
          {activeTab === 'plan' && (
            <div className="bg-[#121212] border border-white/10 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white">Structured Research Plan</h3>
                <span className="text-xs text-slate-500 font-mono">Objective Execution Pipeline</span>
              </div>

              <div className="space-y-3">
                {activeState.plan?.steps.map((step) => {
                  const isCurrent = activeState.current_phase === step.phase;
                  return (
                    <div
                      key={step.id}
                      className={`p-4 rounded-lg border text-xs space-y-2 transition ${
                        isCurrent
                          ? 'bg-emerald-500/5 border-emerald-500/30 text-white'
                          : step.status === 'COMPLETED'
                          ? 'bg-black/30 border-white/10 text-slate-300'
                          : 'bg-black/20 border-white/5 text-slate-400'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          <span className="font-mono text-slate-500 text-[11px]">Step {step.order}</span>
                          <span className="font-semibold text-white">{step.title}</span>
                          <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-white/5 border border-white/10 text-slate-300">
                            {step.phase}
                          </span>
                        </div>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                          step.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-white/5 text-slate-400'
                        }`}>
                          {step.status}
                        </span>
                      </div>
                      <p className="text-slate-300 leading-relaxed">{step.description}</p>
                      <div className="flex items-center gap-2 pt-1">
                        <span className="text-[11px] text-slate-500 font-mono">Tools:</span>
                        <div className="flex flex-wrap gap-1.5">
                          {step.executed_tools.map((tool) => (
                            <span key={tool} className="text-[10px] font-mono bg-white/5 px-2 py-0.5 rounded text-emerald-400 border border-white/5">
                              {tool}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Tab 4: Capability Matrix */}
          {activeTab === 'matrix' && (
            <div className="bg-[#121212] border border-white/10 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white">Engine Capability Matrix</h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Installed security analysis engines mapped against target technology and execution constraints.
                  </p>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-black/40 text-[11px] font-mono text-slate-400 uppercase border-b border-white/10">
                    <tr>
                      <th className="p-3">Engine</th>
                      <th className="p-3">Ecosystem</th>
                      <th className="p-3">Applicability</th>
                      <th className="p-3">Host Installation</th>
                      <th className="p-3">Evaluation Rationale</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 font-mono">
                    {activeState.capability_matrix.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="p-6 text-center text-slate-500">
                          Capability matrix not assessed yet. Step the controller through CAPABILITY_ASSESSMENT.
                        </td>
                      </tr>
                    ) : (
                      activeState.capability_matrix.map((entry) => (
                        <tr key={entry.engine_id} className="hover:bg-white/5 transition">
                          <td className="p-3 font-semibold text-white">{entry.name}</td>
                          <td className="p-3 text-slate-400">{entry.ecosystem}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] ${
                              entry.applicable ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400'
                            }`}>
                              {entry.applicable ? 'APPLICABLE' : 'NOT_APPLICABLE'}
                            </span>
                          </td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] ${
                              entry.installed ? 'bg-blue-500/20 text-blue-300' : 'bg-rose-500/20 text-rose-300'
                            }`}>
                              {entry.installed ? 'INSTALLED' : 'MISSING'}
                            </span>
                          </td>
                          <td className="p-3 text-slate-400 text-xs font-sans">{entry.reason}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab 5: Decisions Audit Log */}
          {activeTab === 'decisions' && (
            <div className="bg-[#121212] border border-white/10 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white">Autonomous Decision Audit Log</h3>
                <span className="text-xs text-slate-500 font-mono">{activeState.decisions.length} Decisions</span>
              </div>

              <div className="space-y-3">
                {activeState.decisions.map((dec) => (
                  <div key={dec.id} className="p-3.5 bg-black/40 border border-white/5 rounded-lg space-y-1.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-emerald-400">{dec.decision}</span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {new Date(dec.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="text-slate-300">{dec.reason}</p>
                    <div className="text-[10px] text-slate-500 font-mono">Phase: {dec.phase}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Empty State */
        <div className="bg-[#121212] border border-white/10 rounded-xl p-12 text-center space-y-4">
          <Bot className="h-12 w-12 text-emerald-500/60 mx-auto" />
          <div className="space-y-1">
            <h3 className="text-base font-semibold text-white">No Active AI Controller Session</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Initialize a new autonomous security research objective to orchestrate scanners, verify source integrity, and test vulnerability hypotheses.
            </p>
          </div>
          <button
            onClick={() => setShowNewModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition"
          >
            <Sparkles className="h-4 w-4" />
            <span>Launch Research Objective</span>
          </button>
        </div>
      )}

      {/* New Research Objective Modal */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-[#141414] border border-white/10 rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <Bot className="h-5 w-5 text-emerald-400" />
                <h3 className="text-sm font-semibold text-white">Submit Research Objective</h3>
              </div>
              <button onClick={() => setShowNewModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleSubmitObjective} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1.5">Select Target (Optional)</label>
                <select
                  value={targetId}
                  onChange={(e) => setTargetId(e.target.value)}
                  className="w-full bg-[#181818] border border-white/10 rounded-md px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500"
                >
                  <option value="">None / New Global Investigation</option>
                  {targets.map(t => (
                    <option key={t.id} value={t.id}>
                      {t.name} ({t.ecosystem})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1.5">Research Objective</label>
                <textarea
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  rows={4}
                  placeholder="e.g. Audit smart contract for reentrancy and unauthorized asset drains, verify scope compliance, and execute formal SMT proofs."
                  className="w-full bg-[#181818] border border-white/10 rounded-md p-3 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="auto-advance-chk"
                  checked={autoAdvance}
                  onChange={(e) => setAutoAdvance(e.target.checked)}
                  className="rounded border-white/10 bg-[#181818] text-emerald-500 focus:ring-0"
                />
                <label htmlFor="auto-advance-chk" className="text-slate-300 cursor-pointer">
                  Auto-advance through safe phases until approval or completion
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
                  className="px-4 py-2 text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-md transition cursor-pointer"
                >
                  {loading ? <RotateCw className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                  <span>Start Autonomous Research</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
