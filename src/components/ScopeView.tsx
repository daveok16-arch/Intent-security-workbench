import React, { useState, useEffect, useCallback } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import {
  ScopeEntry,
  ScopeAssetType,
  ScopeInclusionStatus,
  TargetScopeStatus,
  TargetAuthorizationStatus,
} from '../types.js';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Plus,
  Trash2,
  Filter,
  Search,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Globe,
  Binary,
  Layers,
  Sparkles,
} from 'lucide-react';

export const ScopeView: React.FC = () => {
  const { programs, targets } = useWorkbench();

  const [selectedProgramId, setSelectedProgramId] = useState<string>('ALL');
  const [scopeEntries, setScopeEntries] = useState<ScopeEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);

  // Form State
  const [progId, setProgId] = useState('');
  const [pattern, setPattern] = useState('');
  const [assetType, setAssetType] = useState<ScopeAssetType>(ScopeAssetType.REPOSITORY);
  const [inclusionStatus, setInclusionStatus] = useState<ScopeInclusionStatus>(ScopeInclusionStatus.IN_SCOPE);
  const [restrictions, setRestrictions] = useState('');
  const [notes, setNotes] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Interactive Scope Evaluator
  const [evalTestTarget, setEvalTestTarget] = useState('');
  const [evalProgramId, setEvalProgramId] = useState('');
  const [evaluating, setEvaluating] = useState(false);
  const [evalResult, setEvalResult] = useState<any | null>(null);

  const fetchEntries = useCallback(async () => {
    try {
      setLoading(true);
      const url = selectedProgramId === 'ALL'
        ? '/api/scope'
        : `/api/scope?program_id=${encodeURIComponent(selectedProgramId)}`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setScopeEntries(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error('Failed to load scope entries:', err);
    } finally {
      setLoading(false);
    }
  }, [selectedProgramId]);

  useEffect(() => {
    fetchEntries();
  }, [fetchEntries]);

  useEffect(() => {
    if (programs.length > 0 && !progId) {
      setProgId(programs[0].id);
    }
    if (programs.length > 0 && !evalProgramId) {
      setEvalProgramId(programs[0].id);
    }
  }, [programs, progId, evalProgramId]);

  const handleCreateEntry = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!progId) {
      setFormError('Program selection is required.');
      return;
    }
    if (!pattern.trim()) {
      setFormError('Pattern or asset identifier is required.');
      return;
    }

    try {
      setSubmitting(true);
      setFormError(null);
      const res = await fetch('/api/scope', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          program_id: progId,
          pattern: pattern.trim(),
          asset_type: assetType,
          inclusion_status: inclusionStatus,
          restrictions: restrictions.split('\n').map(r => r.trim()).filter(Boolean),
          notes: notes.trim() || undefined,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to create scope entry');
      }

      setPattern('');
      setRestrictions('');
      setNotes('');
      setShowAddModal(false);
      fetchEntries();
    } catch (err: any) {
      setFormError(err.message || 'Failed to create scope entry');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteEntry = async (id: string) => {
    if (!confirm('Are you sure you want to delete this scope rule?')) return;
    try {
      const res = await fetch(`/api/scope/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setScopeEntries(prev => prev.filter(e => e.id !== id));
      }
    } catch (err) {
      console.error('Failed to delete scope entry:', err);
    }
  };

  const handleRunEvaluation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!evalProgramId || !evalTestTarget.trim()) return;

    try {
      setEvaluating(true);
      setEvalResult(null);

      // Check if this matches a registered target ID or URL
      const matchingTarget = targets.find(t => t.id === evalTestTarget.trim() || t.repository_url === evalTestTarget.trim() || t.contract_address === evalTestTarget.trim());
      
      let res;
      if (matchingTarget) {
        res = await fetch(`/api/targets/${matchingTarget.id}/scope/evaluate`, { method: 'POST' });
      } else {
        // Evaluate custom test candidate by registering an ephemeral check via direct endpoint or target query
        // Find if target exists
        const matched = targets.find(t => t.program_id === evalProgramId);
        if (matched) {
          res = await fetch(`/api/targets/${matched.id}/scope/evaluate`, { method: 'POST' });
        } else {
          // Fallback evaluation report
          setEvalResult({
            decision: ScopeInclusionStatus.UNKNOWN,
            reason: `No registered targets in program '${evalProgramId}' to anchor authorization. Target must be formally registered.`,
            provenance: { evaluator_version: '1.0.0-phase1' },
          });
          return;
        }
      }

      if (res && res.ok) {
        const data = await res.json();
        setEvalResult(data.evaluation);
      } else {
        const errData = await res?.json().catch(() => ({}));
        setEvalResult({
          decision: ScopeInclusionStatus.UNKNOWN,
          reason: errData?.error || 'Evaluation endpoint error',
        });
      }
    } catch (err: any) {
      setEvalResult({
        decision: ScopeInclusionStatus.UNKNOWN,
        reason: `Evaluation request failed: ${err.message}`,
      });
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div id="scope-view" className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase font-mono flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            Program Scope & Authorization Rules
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Deterministic scope boundary evaluation. Targets must be affirmatively in-scope before research operations proceed.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start">
          <button
            onClick={() => setShowAddModal(true)}
            disabled={programs.length === 0}
            className="bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-mono font-semibold px-3.5 py-1.5 rounded flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>ADD SCOPE RULE</span>
          </button>
        </div>
      </div>

      {/* Program Filter & Fast Scope Evaluator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Filter Bar */}
        <div className="lg:col-span-2 bg-[#0D0D0D] border border-white/10 rounded-lg p-4 font-mono space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-slate-300 font-semibold uppercase tracking-wider">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <span>Scope Registry Filter</span>
            </div>
            <span className="text-[11px] text-slate-500">
              {scopeEntries.length} Rule{scopeEntries.length === 1 ? '' : 's'} Loaded
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setSelectedProgramId('ALL')}
              className={`text-xs px-2.5 py-1 rounded border transition cursor-pointer ${
                selectedProgramId === 'ALL'
                  ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400 font-semibold'
                  : 'bg-black/30 border-white/10 text-slate-400 hover:text-white'
              }`}
            >
              All Programs ({programs.length})
            </button>
            {programs.map(p => (
              <button
                key={p.id}
                onClick={() => setSelectedProgramId(p.id)}
                className={`text-xs px-2.5 py-1 rounded border transition cursor-pointer truncate max-w-xs ${
                  selectedProgramId === p.id
                    ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400 font-semibold'
                    : 'bg-black/30 border-white/10 text-slate-400 hover:text-white'
                }`}
              >
                {p.name}
              </button>
            ))}
          </div>
        </div>

        {/* Quick Evaluator Box */}
        <div className="bg-[#0D0D0D] border border-white/10 rounded-lg p-4 font-mono space-y-3">
          <div className="text-xs text-slate-300 font-semibold uppercase tracking-wider flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Scope Test Harness</span>
          </div>
          <form onSubmit={handleRunEvaluation} className="space-y-2">
            <select
              value={evalProgramId}
              onChange={(e) => setEvalProgramId(e.target.value)}
              className="w-full bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-white outline-none focus:border-cyan-500"
            >
              {programs.map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            <input
              type="text"
              value={evalTestTarget}
              onChange={(e) => setEvalTestTarget(e.target.value)}
              placeholder="e.g. contracts/Vault.sol or target ID"
              className="w-full bg-black/40 border border-white/10 rounded px-2.5 py-1 text-xs text-white outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={evaluating || !evalTestTarget.trim()}
              className="w-full bg-cyan-600/30 hover:bg-cyan-600/50 border border-cyan-500/40 text-cyan-200 text-xs py-1 rounded transition font-semibold disabled:opacity-50 cursor-pointer"
            >
              {evaluating ? 'Evaluating...' : 'Test Scope Determinism'}
            </button>
          </form>

          {evalResult && (
            <div className={`p-2.5 rounded border text-[11px] space-y-1 ${
              evalResult.decision === ScopeInclusionStatus.IN_SCOPE
                ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                : evalResult.decision === ScopeInclusionStatus.OUT_OF_SCOPE
                ? 'bg-rose-950/40 border-rose-800/60 text-rose-300'
                : 'bg-amber-950/40 border-amber-800/60 text-amber-300'
            }`}>
              <div className="font-semibold flex items-center justify-between">
                <span>DECISION: {evalResult.decision}</span>
                <span className="text-[10px] opacity-75">v{evalResult.evaluator_version || '1.0.0'}</span>
              </div>
              <div className="text-[10px] opacity-90">{evalResult.reason}</div>
            </div>
          )}
        </div>
      </div>

      {/* Scope Table */}
      {loading ? (
        <div className="py-12 text-center text-xs font-mono text-slate-500">
          Loading scope rules...
        </div>
      ) : scopeEntries.length === 0 ? (
        <div className="py-16 text-center rounded-lg border border-dashed border-white/10 bg-[#0D0D0D] font-mono">
          <ShieldAlert className="w-10 h-10 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-400">No scope rules found.</p>
          <p className="text-xs text-slate-600 mt-1">
            {selectedProgramId === 'ALL'
              ? 'Define explicit scope rules or register programs with scope definitions.'
              : 'This program has no granular scope entries. Register rules to authorize targets.'}
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-white/10 bg-[#0D0D0D] overflow-hidden font-mono text-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 bg-black/40 text-[11px] text-slate-400 uppercase tracking-wider">
                  <th className="py-2.5 px-3.5">Status</th>
                  <th className="py-2.5 px-3.5">Pattern / Identifier</th>
                  <th className="py-2.5 px-3.5">Asset Type</th>
                  <th className="py-2.5 px-3.5">Program</th>
                  <th className="py-2.5 px-3.5">Restrictions</th>
                  <th className="py-2.5 px-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300">
                {scopeEntries.map((entry) => {
                  const prog = programs.find(p => p.id === entry.program_id);
                  const isInScope = entry.inclusion_status === ScopeInclusionStatus.IN_SCOPE;

                  return (
                    <tr key={entry.id} className="hover:bg-white/[0.02] transition">
                      <td className="py-2.5 px-3.5 whitespace-nowrap">
                        {isInScope ? (
                          <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                            <ShieldCheck className="w-3 h-3" />
                            IN_SCOPE
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400">
                            <ShieldAlert className="w-3 h-3" />
                            OUT_OF_SCOPE
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3.5 font-semibold text-white">
                        <span className="bg-black/40 px-1.5 py-0.5 rounded border border-white/5">
                          {entry.asset_identifier || (entry as any).pattern || '—'}
                        </span>
                        {entry.notes && (
                          <div className="text-[10px] text-slate-500 font-normal mt-0.5">
                            {entry.notes}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 px-3.5">
                        <span className="text-[10px] text-slate-400 bg-white/5 px-1.5 py-0.5 rounded border border-white/5">
                          {entry.asset_type}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 text-slate-400 truncate max-w-xs">
                        {prog?.name || entry.program_id}
                      </td>
                      <td className="py-2.5 px-3.5 text-slate-400">
                        {entry.restrictions && entry.restrictions.length > 0 ? (
                          <span className="text-[10px] text-amber-400/90">
                            {entry.restrictions.join(', ')}
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3.5 text-right">
                        <button
                          onClick={() => handleDeleteEntry(entry.id)}
                          className="text-slate-500 hover:text-rose-400 transition p-1 cursor-pointer"
                          title="Delete Rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Add Scope Entry Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#0D0D0D] border border-white/10 rounded-lg p-6 w-full max-w-lg space-y-4 font-mono">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                Register Program Scope Rule
              </h2>
              <button onClick={() => setShowAddModal(false)} className="text-slate-500 hover:text-white cursor-pointer">
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-2.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateEntry} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Associated Program *</label>
                <select
                  value={progId}
                  onChange={(e) => setProgId(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                >
                  {programs.map(p => (
                    <option key={p.id} value={p.id}>{p.name} ({p.platform})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Pattern or Asset Identifier *</label>
                <input
                  type="text"
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="e.g. github.com/org/repo, contracts/**, 0x1234... or *.example.com"
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Asset Type</label>
                  <select
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value as ScopeAssetType)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  >
                    <option value={ScopeAssetType.REPOSITORY}>Repository</option>
                    <option value={ScopeAssetType.SMART_CONTRACT}>Smart Contract</option>
                    <option value={ScopeAssetType.CONTRACT}>Contract</option>
                    <option value={ScopeAssetType.URL}>URL</option>
                    <option value={ScopeAssetType.DOMAIN}>Domain</option>
                    <option value={ScopeAssetType.API}>API</option>
                    <option value={ScopeAssetType.TOKEN}>Token</option>
                    <option value={ScopeAssetType.CHAIN}>Chain</option>
                    <option value={ScopeAssetType.OTHER}>Other</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Inclusion Status</label>
                  <select
                    value={inclusionStatus}
                    onChange={(e) => setInclusionStatus(e.target.value as ScopeInclusionStatus)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  >
                    <option value={ScopeInclusionStatus.IN_SCOPE}>IN_SCOPE (Authorized)</option>
                    <option value={ScopeInclusionStatus.OUT_OF_SCOPE}>OUT_OF_SCOPE (Forbidden)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Restrictions (one per line, optional)</label>
                <textarea
                  value={restrictions}
                  onChange={(e) => setRestrictions(e.target.value)}
                  placeholder="e.g. No automated DoS&#10;No mainnet fund drain without simulation"
                  rows={2}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Notes / Description (optional)</label>
                <input
                  type="text"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g. Core automated market maker pool contracts"
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded border border-white/10 bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-3.5 py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-black font-semibold disabled:opacity-50 cursor-pointer"
                >
                  {submitting ? 'Saving...' : 'Register Scope Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
