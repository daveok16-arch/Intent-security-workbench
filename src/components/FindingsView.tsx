import React, { useState } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { FindingStatus, Severity } from '../types.js';
import {
  AlertTriangle, CheckCircle2, ShieldCheck, ArrowRight,
  Clock, FileCheck, AlertCircle
} from 'lucide-react';

const STATUS_PROGRESSION: FindingStatus[] = [
  FindingStatus.CANDIDATE,
  FindingStatus.ANALYZING,
  FindingStatus.VERIFICATION_REQUIRED,
  FindingStatus.TESTING,
  FindingStatus.REPRODUCED,
  FindingStatus.VALIDATED,
  FindingStatus.CONFIRMED,
];

export const FindingsView: React.FC = () => {
  const {
    findings,
    evidence,
    targets,
    transitionFinding,
    linkEvidenceToFinding
  } = useWorkbench();

  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [transitionReason, setTransitionReason] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [linkingEvidenceId, setLinkingEvidenceId] = useState('');

  const selectedFinding = findings.find(f => f.id === selectedFindingId) || findings[0];

  const handleTransition = async (targetStatus: FindingStatus) => {
    if (!selectedFinding) return;

    try {
      setErrorMsg(null);
      await transitionFinding(selectedFinding.id, targetStatus, transitionReason.trim() || `Advancing state to ${targetStatus}`);
      setTransitionReason('');
    } catch (err: any) {
      setErrorMsg(err.message || 'State machine transition rejected');
    }
  };

  const handleLinkEvidence = async () => {
    if (!selectedFinding || !linkingEvidenceId) return;

    try {
      setErrorMsg(null);
      await linkEvidenceToFinding(selectedFinding.id, linkingEvidenceId);
      setLinkingEvidenceId('');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to link evidence');
    }
  };

  return (
    <div id="findings-view" className="space-y-6 font-mono">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-emerald-500" />
            10-State Findings Pipeline & Verification Machine
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Strict formal state transitions with zero synthetic confirmations. Machine-verifiable SHA-256 evidence is mandatory before validating.
          </p>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="py-16 text-center rounded-lg border border-dashed border-white/10 bg-[#0D0D0D]">
          <AlertTriangle className="w-10 h-10 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-400">No candidate findings registered.</p>
          <p className="text-xs text-slate-600 mt-1">
            Create candidate findings inside an active investigation workspace to begin the verification pipeline.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Left Col: Finding List */}
          <div className="lg:col-span-1 space-y-2">
            <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 px-1">
              Registered Findings ({findings.length})
            </div>
            <div className="space-y-1.5 max-h-[600px] overflow-y-auto">
              {findings.map((fnd) => {
                const isSelected = selectedFinding?.id === fnd.id;
                const tgt = targets.find(t => t.id === fnd.target_id);

                return (
                  <div
                    key={fnd.id}
                    onClick={() => {
                      setSelectedFindingId(fnd.id);
                      setErrorMsg(null);
                    }}
                    className={`p-3 rounded-lg border text-xs cursor-pointer transition ${
                      isSelected
                        ? 'bg-white/5 border-emerald-500/50 text-white'
                        : 'bg-[#0D0D0D] border-white/5 text-slate-400 hover:bg-white/5 hover:text-white'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-200 truncate">{fnd.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold ${
                        fnd.severity === Severity.CRITICAL ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60' :
                        fnd.severity === Severity.HIGH ? 'bg-orange-950/80 text-orange-300 border border-orange-800/60' :
                        'bg-amber-950/80 text-amber-300 border border-amber-800/60'
                      }`}>
                        {fnd.severity}
                      </span>
                    </div>

                    <div className="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
                      <span className="truncate">Tgt: {tgt?.name || fnd.target_id}</span>
                      <span className="text-emerald-400 font-semibold">{fnd.status}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right 2 Cols: State Transition Controls & Provenance Timeline */}
          {selectedFinding && (
            <div className="lg:col-span-2 rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-white/10 gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-white">{selectedFinding.title}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded border border-emerald-500/30 text-emerald-400 bg-emerald-500/10">
                      {selectedFinding.status}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    Category: <span className="text-slate-300">{selectedFinding.category}</span> | Linked Artifacts: <span className="text-emerald-400 font-semibold">{selectedFinding.evidence_artifact_ids.length}</span>
                  </div>
                </div>
              </div>

              {/* Visual Pipeline Progression Ribbon */}
              <div className="bg-black/30 p-3.5 rounded border border-white/5 space-y-2">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-bold">
                  Verification Lifecycle Sequence
                </span>
                <div className="flex items-center gap-1 overflow-x-auto py-1">
                  {STATUS_PROGRESSION.map((step, idx) => {
                    const isCurrent = selectedFinding.status === step;
                    const isPassed = STATUS_PROGRESSION.indexOf(selectedFinding.status) > idx;

                    return (
                      <React.Fragment key={step}>
                        <div className={`px-2 py-1 rounded text-[10px] whitespace-nowrap font-mono transition ${
                          isCurrent ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 font-bold' :
                          isPassed ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-800/40' :
                          'bg-black/40 text-slate-500 border border-white/5'
                        }`}>
                          {isPassed && '✓ '}
                          {step}
                        </div>
                        {idx < STATUS_PROGRESSION.length - 1 && (
                          <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                        )}
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>

              {/* State Machine Transition Action Panel */}
              <div className="bg-black/30 p-4 rounded border border-white/5 space-y-3">
                <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                  <span>Advance Verification State</span>
                  <span className="text-[10px] text-slate-500 font-normal">State transition rules enforced</span>
                </div>

                {errorMsg && (
                  <div className="p-2.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-start gap-2">
                    <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>{errorMsg}</span>
                  </div>
                )}

                <div className="space-y-2">
                  <label className="block text-[11px] text-slate-400">Transition Rationale / Audit Justification:</label>
                  <input
                    type="text"
                    value={transitionReason}
                    onChange={(e) => setTransitionReason(e.target.value)}
                    placeholder="e.g. Test reproduction harness produced expected state divergence..."
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white text-xs focus:border-emerald-500 outline-none"
                  />
                </div>

                <div className="flex flex-wrap gap-2 pt-1">
                  {selectedFinding.status === FindingStatus.CANDIDATE && (
                    <button
                      onClick={() => handleTransition(FindingStatus.ANALYZING)}
                      className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-slate-200 rounded text-xs border border-white/10 transition cursor-pointer"
                    >
                      Start Analysis →
                    </button>
                  )}
                  {selectedFinding.status === FindingStatus.ANALYZING && (
                    <button
                      onClick={() => handleTransition(FindingStatus.VERIFICATION_REQUIRED)}
                      className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-slate-200 rounded text-xs border border-white/10 transition cursor-pointer"
                    >
                      Require Verification →
                    </button>
                  )}
                  {selectedFinding.status === FindingStatus.VERIFICATION_REQUIRED && (
                    <button
                      onClick={() => handleTransition(FindingStatus.TESTING)}
                      className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-slate-200 rounded text-xs border border-white/10 transition cursor-pointer"
                    >
                      Begin Testing →
                    </button>
                  )}
                  {selectedFinding.status === FindingStatus.TESTING && (
                    <button
                      onClick={() => handleTransition(FindingStatus.REPRODUCED)}
                      className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-slate-200 rounded text-xs border border-white/10 transition cursor-pointer"
                    >
                      Mark Reproduced →
                    </button>
                  )}
                  {selectedFinding.status === FindingStatus.REPRODUCED && (
                    <button
                      onClick={() => handleTransition(FindingStatus.VALIDATED)}
                      className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold transition cursor-pointer flex items-center gap-1.5"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Validate Finding (Requires Evidence) →</span>
                    </button>
                  )}
                  {selectedFinding.status === FindingStatus.VALIDATED && (
                    <button
                      onClick={() => handleTransition(FindingStatus.CONFIRMED)}
                      className="px-3.5 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded text-xs transition cursor-pointer flex items-center gap-1.5"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Confirm Vulnerability (Terminal) →</span>
                    </button>
                  )}

                  {/* Terminal / Negative State Options */}
                  {selectedFinding.status !== FindingStatus.CONFIRMED && (
                    <>
                      <button
                        onClick={() => handleTransition(FindingStatus.REJECTED)}
                        className="px-2.5 py-1.5 bg-black/40 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 rounded text-xs border border-white/10 transition cursor-pointer"
                      >
                        Reject
                      </button>
                      <button
                        onClick={() => handleTransition(FindingStatus.OUT_OF_SCOPE)}
                        className="px-2.5 py-1.5 bg-black/40 hover:bg-white/5 text-slate-400 rounded text-xs border border-white/10 transition cursor-pointer"
                      >
                        Out of Scope
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Linked Evidence Artifacts Manager */}
              <div className="bg-black/30 p-4 rounded border border-white/5 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                    <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
                    Machine-Verifiable Evidence Linkages ({selectedFinding.evidence_artifact_ids.length})
                  </span>
                </div>

                {selectedFinding.evidence_artifact_ids.length === 0 ? (
                  <div className="p-3 bg-amber-950/30 border border-amber-800/50 rounded text-xs text-amber-300/90 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>No evidence artifacts linked. Transitions to VALIDATED or CONFIRMED are blocked by rule.</span>
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {selectedFinding.evidence_artifact_ids.map(artId => {
                      const art = evidence.find(e => e.id === artId);
                      return (
                        <div key={artId} className="p-2.5 bg-black rounded border border-white/10 text-xs flex items-center justify-between">
                          <div>
                            <span className="text-slate-200 font-semibold">{art?.producer || artId}</span>
                            <div className="text-[10px] text-slate-500">SHA-256: {art?.sha256 || 'Unknown'}</div>
                          </div>
                          <span className="text-[10px] px-2 py-0.5 rounded border border-emerald-500/30 text-emerald-400 bg-emerald-500/10">
                            LINKED PROOF
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* Link another artifact dropdown */}
                {evidence.length > 0 && (
                  <div className="flex items-center gap-2 pt-1">
                    <select
                      value={linkingEvidenceId}
                      onChange={(e) => setLinkingEvidenceId(e.target.value)}
                      className="flex-1 bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white text-xs focus:border-emerald-500 outline-none"
                    >
                      <option value="">Select an evidence artifact to link...</option>
                      {evidence.map(e => (
                        <option key={e.id} value={e.id}>
                          [{e.artifact_type}] {e.producer} ({e.sha256.substring(0, 12)}...)
                        </option>
                      ))}
                    </select>
                    <button
                      onClick={handleLinkEvidence}
                      disabled={!linkingEvidenceId}
                      className="px-3.5 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded text-xs disabled:opacity-50 cursor-pointer"
                    >
                      Link Evidence
                    </button>
                  </div>
                )}
              </div>

              {/* State History Audit Log */}
              <div className="space-y-2">
                <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  <span>State History Audit Trail</span>
                </div>
                <div className="bg-black rounded border border-white/10 p-3 max-h-48 overflow-y-auto space-y-2 text-[11px]">
                  {selectedFinding.state_history.map((hist, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-black/40 border border-white/5 space-y-1">
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="text-emerald-400 font-semibold">
                          {hist.from_status ? `${hist.from_status} → ${hist.to_status}` : `Initial: ${hist.to_status}`}
                        </span>
                        <span className="text-slate-500">{new Date(hist.timestamp).toLocaleString()}</span>
                      </div>
                      <p className="text-slate-300 text-[11px]">{hist.reason}</p>
                      <div className="text-[10px] text-slate-500">Actor: {hist.actor}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
