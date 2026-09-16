import React, { useState } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { InvestigationStatus, Severity } from '../types.js';
import {
  Search, Plus, Trash2, ListTodo, FileCheck,
  AlertTriangle, Play, ShieldCheck, ShieldAlert, CheckCircle2, AlertCircle, Bot
} from 'lucide-react';

export const InvestigationsView: React.FC = () => {
  const {
    investigations,
    programs,
    targets,
    jobs,
    evidence,
    findings,
    selectedInvestigationId,
    setSelectedInvestigationId,
    createInvestigation,
    updateInvestigationStatus,
    deleteInvestigation,
    createJob,
    runJob,
    createFinding,
    setActiveTab,
    evaluateInvestigationGate,
  } = useWorkbench();

  const [showModal, setShowModal] = useState(false);
  const [showJobModal, setShowJobModal] = useState(false);
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [showGateModal, setShowGateModal] = useState(false);
  const [gateResult, setGateResult] = useState<any>(null);
  const [checkingGate, setCheckingGate] = useState(false);

  const [programId, setProgramId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  // Quick job form
  const [jobEngine, setJobEngine] = useState('git-source-integrity');
  const [jobOp, setJobOp] = useState('verify_commit');

  // Quick finding form
  const [fndTitle, setFndTitle] = useState('');
  const [fndCategory, setFndCategory] = useState('SMART_CONTRACT');
  const [fndSeverity, setFndSeverity] = useState<Severity>(Severity.HIGH);
  const [fndSteps, setFndSteps] = useState('');

  const activeInv = investigations.find(i => i.id === selectedInvestigationId) || investigations[0];

  const handleCreateInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!programId || !targetId || !title.trim()) {
      setFormError('Program, Target, and Title are required.');
      return;
    }

    try {
      setFormError(null);
      const inv = await createInvestigation({
        program_id: programId,
        target_id: targetId,
        title: title.trim(),
        description: description.trim(),
        status: InvestigationStatus.ACTIVE,
      });
      setSelectedInvestigationId(inv.id);
      setTitle('');
      setDescription('');
      setShowModal(false);
    } catch (err: any) {
      setFormError(err.message || 'Failed to create investigation');
    }
  };

  const handleCreateJob = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeInv) return;

    try {
      const job = await createJob({
        investigation_id: activeInv.id,
        target_id: activeInv.target_id,
        engine: jobEngine,
        operation: jobOp,
      });
      setShowJobModal(false);
      // Auto run
      await runJob(job.id);
    } catch (err: any) {
      alert(err.message || 'Failed to trigger job');
    }
  };

  const handleCreateFinding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeInv || !fndTitle.trim()) return;

    try {
      await createFinding({
        investigation_id: activeInv.id,
        target_id: activeInv.target_id,
        title: fndTitle.trim(),
        category: fndCategory,
        severity: fndSeverity,
        reproduction_steps: fndSteps.trim(),
      });
      setFndTitle('');
      setFndSteps('');
      setShowFindingModal(false);
    } catch (err: any) {
      alert(err.message || 'Failed to create candidate finding');
    }
  };

  const filteredTargets = targets.filter(t => !programId || t.program_id === programId);

  return (
    <div id="investigations-view" className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase font-mono flex items-center gap-2">
            <Search className="w-4 h-4 text-emerald-500" />
            Security Investigations Workspace
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Active audit sessions linking targets, background execution jobs, evidence artifacts, and candidate findings.
          </p>
        </div>
        <button
          onClick={() => {
            if (programs.length > 0 && !programId) setProgramId(programs[0].id);
            if (targets.length > 0 && !targetId) setTargetId(targets[0].id);
            setShowModal(true);
          }}
          disabled={targets.length === 0}
          className="bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-mono font-semibold px-3.5 py-1.5 rounded flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer self-start"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>INITIALIZE INVESTIGATION</span>
        </button>
      </div>

      {investigations.length === 0 ? (
        <div className="py-16 text-center rounded-lg border border-dashed border-white/10 bg-[#0D0D0D]">
          <Search className="w-10 h-10 text-slate-600 mx-auto mb-2" />
          <p className="text-sm font-mono text-slate-400">No active investigations found.</p>
          <p className="text-xs font-mono text-slate-600 mt-1">
            Create an investigation to coordinate engine execution and track findings state.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* Left Col: Investigation Selector */}
          <div className="lg:col-span-1 space-y-2">
            <div className="text-[10px] font-mono font-bold uppercase tracking-[0.2em] text-slate-500 px-1">
              Active Sessions ({investigations.length})
            </div>
            <div className="space-y-1.5 max-h-[600px] overflow-y-auto">
              {investigations.map((inv) => {
                const isSelected = activeInv?.id === inv.id;
                const tgt = targets.find(t => t.id === inv.target_id);
                return (
                  <div
                    key={inv.id}
                    onClick={() => setSelectedInvestigationId(inv.id)}
                    className={`p-3 rounded-lg border font-mono text-xs cursor-pointer transition ${
                      isSelected
                        ? 'bg-white/5 border-emerald-500/50 text-white'
                        : 'bg-[#0D0D0D] border-white/5 text-slate-400 hover:bg-white/5 hover:text-white'
                    }`}
                  >
                    <div className="font-semibold truncate">{inv.title}</div>
                    <div className="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
                      <span className="truncate">{tgt?.name || 'Target'}</span>
                      <span className="px-1.5 py-0.2 rounded bg-black/40 text-slate-400 border border-white/5">
                        {inv.status}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right 3 Cols: Active Investigation Workspace */}
          {activeInv && (
            <div className="lg:col-span-3 rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-5 font-mono">
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-white/10 gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-semibold text-white">{activeInv.title}</h2>
                    <span className="text-[10px] px-2 py-0.5 rounded border border-emerald-500/30 text-emerald-400 bg-emerald-500/10">
                      {activeInv.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{activeInv.description || 'No description provided.'}</p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={async () => {
                      if (!activeInv) return;
                      try {
                        setCheckingGate(true);
                        const res = await evaluateInvestigationGate(activeInv.id);
                        setGateResult(res);
                        setShowGateModal(true);
                      } catch (err: any) {
                        alert(`Pre-flight check error: ${err.message}`);
                      } finally {
                        setCheckingGate(false);
                      }
                    }}
                    disabled={checkingGate}
                    className="text-[11px] px-2.5 py-1 rounded border border-emerald-500/40 bg-emerald-950/40 hover:bg-emerald-900/50 text-emerald-300 transition cursor-pointer flex items-center gap-1"
                  >
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    <span>{checkingGate ? 'Checking Gate...' : 'Pre-Flight Gate'}</span>
                  </button>
                  <button
                    onClick={() => {
                      setSelectedInvestigationId(activeInv.id);
                      setActiveTab('ai_controller');
                    }}
                    className="text-[11px] px-2.5 py-1 rounded border border-purple-500/40 bg-purple-950/40 hover:bg-purple-900/50 text-purple-300 transition cursor-pointer flex items-center gap-1"
                  >
                    <Bot className="w-3.5 h-3.5 text-purple-400" />
                    <span>AI Control Plane</span>
                  </button>
                  <button
                    onClick={() => updateInvestigationStatus(activeInv.id, InvestigationStatus.COMPLETED)}
                    className="text-[11px] px-2.5 py-1 rounded border border-white/10 bg-white/5 hover:bg-white/10 text-slate-300 transition cursor-pointer"
                  >
                    Mark Completed
                  </button>
                  <button
                    onClick={() => deleteInvestigation(activeInv.id)}
                    className="text-[11px] p-1.5 text-slate-500 hover:text-rose-400 transition cursor-pointer"
                    title="Delete Investigation"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Target Authorization Status Banner */}
              {(() => {
                const target = targets.find(t => t.id === activeInv.target_id);
                const program = programs.find(p => p.id === activeInv.program_id);
                const isAuthorized = target?.authorization_status === 'AUTHORIZED';
                const isBlocked = target?.authorization_status === 'NOT_AUTHORIZED';
                const isUnknown = !isAuthorized && !isBlocked;

                return (
                  <div className={`p-3 rounded-lg border font-mono text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                    isAuthorized
                      ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                      : isBlocked
                      ? 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                      : 'bg-amber-950/30 border-amber-500/40 text-amber-300'
                  }`}>
                    <div className="flex items-center gap-2.5">
                      {isAuthorized ? (
                        <span className="px-2.5 py-1 rounded bg-emerald-500/20 border border-emerald-500/50 text-emerald-400 font-bold tracking-wider">
                          AUTHORIZED
                        </span>
                      ) : isBlocked ? (
                        <span className="px-2.5 py-1 rounded bg-rose-500/20 border border-rose-500/50 text-rose-400 font-bold tracking-wider">
                          BLOCKED
                        </span>
                      ) : (
                        <span className="px-2.5 py-1 rounded bg-amber-500/20 border border-amber-500/50 text-amber-400 font-bold tracking-wider">
                          UNKNOWN
                        </span>
                      )}
                      <div>
                        <div className="font-semibold text-white">
                          Target: {target?.name || activeInv.target_id} ({program?.name || activeInv.program_id})
                        </div>
                        <div className="text-[11px] opacity-80 mt-0.5">
                          {isAuthorized
                            ? 'Target is verified in-scope. Operations permitted under program authorization.'
                            : isBlocked
                            ? 'Target is out-of-scope or forbidden. Analysis against this external target must NOT proceed.'
                            : 'Authorization has not been established. UNKNOWN must NOT automatically become IN_SCOPE.'}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-start sm:self-auto shrink-0">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-black/40 border border-white/10 text-slate-300">
                        Scope: {target?.scope_status || 'NOT_EVALUATED'}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-black/40 border border-white/10 text-slate-300">
                        Source: {target?.source_acquisition_status || 'NOT_ACQUIRED'}
                      </span>
                    </div>
                  </div>
                );
              })()}

              {/* Investigation Sub-sections */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* 1. Linked Jobs */}
                <div className="bg-black/30 p-4 rounded border border-white/5 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                      <ListTodo className="w-3.5 h-3.5 text-sky-400" />
                      Analysis Jobs ({jobs.filter(j => j.investigation_id === activeInv.id).length})
                    </span>
                    <button
                      onClick={() => setShowJobModal(true)}
                      className="text-[10px] text-emerald-400 hover:underline cursor-pointer"
                    >
                      + Run Job
                    </button>
                  </div>

                  <div className="space-y-1.5 mt-2 max-h-48 overflow-y-auto">
                    {jobs.filter(j => j.investigation_id === activeInv.id).length === 0 ? (
                      <div className="text-[11px] text-slate-600 italic py-2">No jobs executed yet.</div>
                    ) : (
                      jobs.filter(j => j.investigation_id === activeInv.id).map(j => (
                        <div key={j.id} className="p-2 rounded bg-black/40 border border-white/5 flex items-center justify-between text-[11px]">
                          <span className="truncate text-slate-300">{j.engine}</span>
                          <span className={`text-[10px] px-1.5 rounded ${
                            j.status === 'COMPLETED' ? 'text-emerald-400 bg-emerald-950/60' :
                            j.status === 'RUNNING' ? 'text-sky-400 bg-sky-950/60' :
                            j.status === 'FAILED' ? 'text-rose-400 bg-rose-950/60' : 'text-slate-400 bg-slate-800'
                          }`}>
                            {j.status}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* 2. Linked Evidence */}
                <div className="bg-black/30 p-4 rounded border border-white/5 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                      <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
                      Evidence Artifacts ({evidence.filter(e => e.investigation_id === activeInv.id).length})
                    </span>
                    <button
                      onClick={() => setActiveTab('evidence')}
                      className="text-[10px] text-emerald-400 hover:underline cursor-pointer"
                    >
                      Locker
                    </button>
                  </div>

                  <div className="space-y-1.5 mt-2 max-h-48 overflow-y-auto">
                    {evidence.filter(e => e.investigation_id === activeInv.id).length === 0 ? (
                      <div className="text-[11px] text-slate-600 italic py-2">No artifacts stored.</div>
                    ) : (
                      evidence.filter(e => e.investigation_id === activeInv.id).map(e => (
                        <div key={e.id} className="p-2 rounded bg-black/40 border border-white/5 text-[11px] space-y-0.5">
                          <div className="flex items-center justify-between text-slate-300">
                            <span className="truncate">{e.producer}</span>
                            <span className="text-[10px] text-emerald-400">{e.byte_size}B</span>
                          </div>
                          <div className="text-[10px] text-slate-500 truncate font-mono">
                            SHA: {e.sha256.substring(0, 16)}...
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* 3. Candidate Findings */}
                <div className="bg-black/30 p-4 rounded border border-white/5 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      Findings Pipeline ({findings.filter(f => f.investigation_id === activeInv.id).length})
                    </span>
                    <button
                      onClick={() => setShowFindingModal(true)}
                      className="text-[10px] text-emerald-400 hover:underline cursor-pointer"
                    >
                      + Candidate
                    </button>
                  </div>

                  <div className="space-y-1.5 mt-2 max-h-48 overflow-y-auto">
                    {findings.filter(f => f.investigation_id === activeInv.id).length === 0 ? (
                      <div className="text-[11px] text-slate-600 italic py-2">No candidate findings.</div>
                    ) : (
                      findings.filter(f => f.investigation_id === activeInv.id).map(f => (
                        <div
                          key={f.id}
                          onClick={() => setActiveTab('findings')}
                          className="p-2 rounded bg-black/40 border border-white/5 flex items-center justify-between text-[11px] cursor-pointer hover:border-white/20"
                        >
                          <span className="truncate text-slate-300">{f.title}</span>
                          <span className="text-[10px] px-1.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/50">
                            {f.status}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Modal: New Investigation */}
      {showModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 font-mono">
          <div className="bg-[#0D0D0D] border border-white/10 rounded-lg p-6 w-full max-w-lg space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                <Search className="w-4 h-4 text-emerald-500" />
                Initialize Security Investigation
              </h2>
              <button onClick={() => setShowModal(false)} className="text-slate-500 hover:text-white cursor-pointer">
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-2.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateInvestigation} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Bounty Program *</label>
                <select
                  value={programId}
                  onChange={(e) => {
                    setProgramId(e.target.value);
                    const matchingTgt = targets.find(t => t.program_id === e.target.value);
                    if (matchingTgt) setTargetId(matchingTgt.id);
                  }}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                >
                  {programs.map((p) => (
                    <option key={p.id} value={p.id}>{p.name} ({p.platform})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Target Asset *</label>
                <select
                  value={targetId}
                  onChange={(e) => setTargetId(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                >
                  {filteredTargets.map((t) => (
                    <option key={t.id} value={t.id}>{t.name} [{t.ecosystem}]</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Investigation Moniker / Title *</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Reentrancy in Liquidity Pool Minting"
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Research Hypothesis / Notes</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Details regarding target logic to verify..."
                  rows={3}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-3 py-1.5 rounded border border-white/10 bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-black font-semibold cursor-pointer"
                >
                  Start Investigation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Run Job */}
      {showJobModal && activeInv && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 font-mono">
          <div className="bg-[#0D0D0D] border border-white/10 rounded-lg p-6 w-full max-w-md space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                <Play className="w-4 h-4 text-sky-400" />
                Dispatch Background Analysis Job
              </h2>
              <button onClick={() => setShowJobModal(false)} className="text-slate-500 hover:text-white cursor-pointer">
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateJob} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Engine</label>
                <select
                  value={jobEngine}
                  onChange={(e) => setJobEngine(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                >
                  <option value="git-source-integrity">git-source-integrity (Host Verified)</option>
                  <option value="semgrep-static-analyzer">semgrep-static-analyzer (Not Installed)</option>
                  <option value="slither-solidity-analyzer">slither-solidity-analyzer (Not Installed)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Operation</label>
                <input
                  type="text"
                  value={jobOp}
                  onChange={(e) => setJobOp(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowJobModal(false)}
                  className="px-3 py-1.5 rounded border border-white/10 bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-white font-semibold cursor-pointer"
                >
                  Queue & Run Job
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: New Candidate Finding */}
      {showFindingModal && activeInv && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 font-mono">
          <div className="bg-[#0D0D0D] border border-white/10 rounded-lg p-6 w-full max-w-md space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Register Candidate Finding
              </h2>
              <button onClick={() => setShowFindingModal(false)} className="text-slate-500 hover:text-white cursor-pointer">
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateFinding} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Finding Title *</label>
                <input
                  type="text"
                  value={fndTitle}
                  onChange={(e) => setFndTitle(e.target.value)}
                  placeholder="e.g. Unbounded loop denial of service"
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Category</label>
                  <select
                    value={fndCategory}
                    onChange={(e) => setFndCategory(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  >
                    <option value="SMART_CONTRACT">Smart Contract Logic</option>
                    <option value="CRYPTO_LOGIC">Cryptographic / Math</option>
                    <option value="ACCESS_CONTROL">Access Control</option>
                    <option value="WEB_SECURITY">Web / API Security</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={fndSeverity}
                    onChange={(e) => setFndSeverity(e.target.value as Severity)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  >
                    <option value={Severity.CRITICAL}>Critical</option>
                    <option value={Severity.HIGH}>High</option>
                    <option value={Severity.MEDIUM}>Medium</option>
                    <option value={Severity.LOW}>Low</option>
                    <option value={Severity.INFO}>Info</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Reproduction Notes / Initial Steps</label>
                <textarea
                  value={fndSteps}
                  onChange={(e) => setFndSteps(e.target.value)}
                  rows={2}
                  placeholder="Steps to reproduce locally..."
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowFindingModal(false)}
                  className="px-3 py-1.5 rounded border border-white/10 bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white font-semibold cursor-pointer"
                >
                  Add Candidate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Pre-Flight Investigation Gate Modal */}
      {showGateModal && gateResult && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 font-mono">
          <div className="bg-[#111] border border-white/10 rounded-lg max-w-xl w-full p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-2">
                {gateResult.gate?.passed ? (
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                ) : (
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                )}
                <span>Pre-Flight Investigation Gate Verification</span>
              </h2>
              <button
                onClick={() => setShowGateModal(false)}
                className="text-slate-500 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between bg-black/40 p-2.5 rounded border border-white/5">
                <span className="text-slate-400">Gate Authorization Status:</span>
                <span
                  className={`font-semibold px-2 py-0.5 rounded text-[10px] ${
                    gateResult.gate?.passed
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : 'bg-rose-950 text-rose-400 border border-rose-800'
                  }`}
                >
                  {gateResult.gate?.passed ? 'PASSED (CLEAR FOR RESEARCH)' : 'BLOCKED (AUTHORIZATION / SOURCE REQUIRED)'}
                </span>
              </div>

              <div className="space-y-2">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Gate Checkpoints:</div>
                <div className="space-y-1.5">
                  {gateResult.gate?.checks?.map((chk: any, idx: number) => (
                    <div
                      key={idx}
                      className={`p-2 rounded border flex items-start justify-between gap-2 text-[11px] ${
                        chk.passed
                          ? 'bg-emerald-950/20 border-emerald-800/30 text-emerald-300'
                          : 'bg-rose-950/20 border-rose-800/30 text-rose-300'
                      }`}
                    >
                      <div className="flex items-start gap-1.5">
                        {chk.passed ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        ) : (
                          <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                        )}
                        <div>
                          <div className="font-semibold text-white">{chk.name}</div>
                          <div className="text-[10px] opacity-80 mt-0.5">{chk.message}</div>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono shrink-0">
                        {chk.passed ? 'PASS' : 'FAIL'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-black/30 p-2.5 rounded text-[10px] text-slate-400 space-y-1">
                <div className="flex justify-between">
                  <span>Policy Freshness:</span>
                  <span className="text-slate-200">{gateResult.gate?.policy_status}</span>
                </div>
                <div className="flex justify-between">
                  <span>Evaluated At:</span>
                  <span className="text-slate-200">{new Date(gateResult.gate?.evaluated_at).toLocaleString()}</span>
                </div>
              </div>
            </div>

            <button
              onClick={() => setShowGateModal(false)}
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-semibold py-2 rounded transition cursor-pointer"
            >
              Acknowledge Pre-Flight Check
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
