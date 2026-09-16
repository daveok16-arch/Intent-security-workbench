import React, { useState } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import {
  TargetType,
  Ecosystem,
  SourceAcquisitionStatus,
  TargetAuthorizationStatus,
  TargetScopeStatus,
} from '../types.js';
import {
  Crosshair,
  Plus,
  Trash2,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  GitBranch,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  FileCode,
  DownloadCloud,
  Check,
} from 'lucide-react';

export const TargetsView: React.FC = () => {
  const {
    targets,
    programs,
    createTarget,
    deleteTarget,
    evaluateTargetScope,
    acquireTargetSource,
    verifyTargetSource,
  } = useWorkbench();

  const [showModal, setShowModal] = useState(false);
  const [programId, setProgramId] = useState('');
  const [name, setName] = useState('');
  const [targetType, setTargetType] = useState<TargetType>(TargetType.SMART_CONTRACT);
  const [ecosystem, setEcosystem] = useState<Ecosystem>(Ecosystem.EVM);
  const [repoUrl, setRepoUrl] = useState('');
  const [commitHash, setCommitHash] = useState('');
  const [branch, setBranch] = useState('main');
  const [contractAddress, setContractAddress] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);
  const [evalResultModal, setEvalResultModal] = useState<{ targetId: string; data: any } | null>(null);
  const [verifyResultModal, setVerifyResultModal] = useState<{ targetId: string; data: any } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!programId) {
      setFormError('Please select a program.');
      return;
    }
    if (!name.trim()) {
      setFormError('Target name is required.');
      return;
    }

    try {
      setSubmitting(true);
      setFormError(null);
      await createTarget({
        program_id: programId,
        name: name.trim(),
        target_type: targetType,
        ecosystem,
        repository_url: repoUrl.trim() || undefined,
        commit_hash: commitHash.trim() || undefined,
        branch: branch.trim() || undefined,
        contract_address: contractAddress.trim() || undefined,
        deployment: contractAddress.trim() ? { address: contractAddress.trim() } : {},
      });

      setName('');
      setRepoUrl('');
      setCommitHash('');
      setContractAddress('');
      setShowModal(false);
    } catch (err: any) {
      setFormError(err.message || 'Failed to create target');
    } finally {
      setSubmitting(false);
    }
  };

  const handleEvaluateScope = async (targetId: string) => {
    try {
      setActionLoadingId(targetId);
      const res = await evaluateTargetScope(targetId);
      setEvalResultModal({ targetId, data: res.evaluation });
    } catch (err: any) {
      alert(`Scope evaluation error: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleAcquireSource = async (targetId: string) => {
    try {
      setActionLoadingId(targetId);
      const res = await acquireTargetSource(targetId);
      if (!res.result.success) {
        alert(`Source acquisition failed: ${res.result.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      alert(`Source acquisition error: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleVerifyIntegrity = async (targetId: string) => {
    try {
      setActionLoadingId(targetId);
      const res = await verifyTargetSource(targetId);
      setVerifyResultModal({ targetId, data: res });
    } catch (err: any) {
      alert(`Verification error: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  };

  return (
    <div id="targets-view" className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase font-mono flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-emerald-500" />
            Target Acquisition & Scope Evaluation
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Deterministic scope boundary evaluation, sandboxed Git repository acquisition, and immutable SHA-256 tree snapshots.
          </p>
        </div>
        <button
          onClick={() => {
            if (programs.length > 0 && !programId) setProgramId(programs[0].id);
            setShowModal(true);
          }}
          disabled={programs.length === 0}
          className="bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-mono font-semibold px-3.5 py-1.5 rounded flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer self-start"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>REGISTER TARGET</span>
        </button>
      </div>

      {programs.length === 0 && (
        <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded text-xs font-mono text-amber-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>You must create at least one Program before registering targets.</span>
        </div>
      )}

      {targets.length === 0 ? (
        <div className="py-16 text-center rounded-lg border border-dashed border-white/10 bg-[#0D0D0D]">
          <Crosshair className="w-10 h-10 text-slate-600 mx-auto mb-2" />
          <p className="text-sm font-mono text-slate-400">No targets registered.</p>
          <p className="text-xs font-mono text-slate-600 mt-1">
            Define specific smart contracts, repositories, or assets to analyze under authorized programs.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {targets.map((tgt) => {
            const prog = programs.find((p) => p.id === tgt.program_id);
            const isLoading = actionLoadingId === tgt.id;

            return (
              <div
                key={tgt.id}
                className="rounded-lg border border-white/10 bg-[#0D0D0D] p-5 space-y-3.5 font-mono"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-white">{tgt.name}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-sky-950/60 text-sky-400 border border-sky-800/50">
                        {tgt.ecosystem}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-700">
                        {tgt.target_type}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">
                      Program: <span className="text-slate-300">{prog?.name || tgt.program_id}</span>
                    </div>
                  </div>
                  <button
                    onClick={() => deleteTarget(tgt.id)}
                    className="text-slate-500 hover:text-rose-400 transition p-1 cursor-pointer"
                    title="Delete Target"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>

                {/* Scope & Authorization Status Badges */}
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="bg-black/40 p-2.5 rounded border border-white/5 space-y-1">
                    <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Scope Decision</span>
                    {tgt.scope_status === TargetScopeStatus.IN_SCOPE ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        IN SCOPE
                      </span>
                    ) : tgt.scope_status === TargetScopeStatus.OUT_OF_SCOPE ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-rose-400">
                        <ShieldAlert className="w-3.5 h-3.5" />
                        OUT OF SCOPE
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-amber-400">
                        <ShieldQuestion className="w-3.5 h-3.5" />
                        UNKNOWN
                      </span>
                    )}
                  </div>

                  <div className="bg-black/40 p-2.5 rounded border border-white/5 space-y-1">
                    <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Authorization</span>
                    {tgt.authorization_status === TargetAuthorizationStatus.AUTHORIZED ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                        <Check className="w-3.5 h-3.5" />
                        AUTHORIZED
                      </span>
                    ) : tgt.authorization_status === TargetAuthorizationStatus.NOT_AUTHORIZED ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-rose-400">
                        <AlertCircle className="w-3.5 h-3.5" />
                        NOT AUTHORIZED
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-slate-400">
                        PENDING
                      </span>
                    )}
                  </div>
                </div>

                {/* Target Coordinates */}
                <div className="bg-black/30 p-3 rounded border border-white/5 space-y-1.5 text-[11px]">
                  {tgt.repository_url && (
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Repository:</span>
                      <span className="text-slate-300 truncate max-w-[200px]" title={tgt.repository_url}>
                        {tgt.repository_url}
                      </span>
                    </div>
                  )}
                  {tgt.contract_address && (
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Contract:</span>
                      <span className="text-slate-300 font-mono text-[10px]">{tgt.contract_address}</span>
                    </div>
                  )}
                  {tgt.commit_hash && (
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Commit SHA:</span>
                      <span className="text-emerald-400 font-mono text-[10px]">
                        {tgt.commit_hash.substring(0, 10)}...
                      </span>
                    </div>
                  )}
                  {tgt.source_hash && (
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Tree SHA-256:</span>
                      <span className="text-sky-400 font-mono text-[10px]">
                        {tgt.source_hash.substring(0, 12)}...
                      </span>
                    </div>
                  )}
                </div>

                {/* Actions Row */}
                <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-white/5">
                  <button
                    onClick={() => handleEvaluateScope(tgt.id)}
                    disabled={isLoading}
                    className="flex-1 bg-white/5 hover:bg-white/10 text-slate-300 text-[11px] font-mono py-1.5 px-2 rounded border border-white/10 flex items-center justify-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                  >
                    <ShieldCheck className="w-3 h-3 text-emerald-400" />
                    <span>Evaluate Scope</span>
                  </button>

                  {tgt.repository_url && (
                    <button
                      onClick={() => handleAcquireSource(tgt.id)}
                      disabled={isLoading}
                      className="flex-1 bg-emerald-950/40 hover:bg-emerald-900/50 text-emerald-300 text-[11px] font-mono py-1.5 px-2 rounded border border-emerald-800/40 flex items-center justify-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                    >
                      {isLoading ? (
                        <RefreshCw className="w-3 h-3 animate-spin" />
                      ) : (
                        <DownloadCloud className="w-3 h-3" />
                      )}
                      <span>Acquire Git</span>
                    </button>
                  )}

                  {tgt.source_hash && (
                    <button
                      onClick={() => handleVerifyIntegrity(tgt.id)}
                      disabled={isLoading}
                      className="bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white text-[11px] font-mono p-1.5 rounded border border-white/10 transition cursor-pointer"
                      title="Verify Tree SHA-256 Digest"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5 text-sky-400" />
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Scope Decision Result Modal */}
      {evalResultModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 font-mono">
          <div className="bg-[#111] border border-white/10 rounded-lg max-w-lg w-full p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                Deterministic Scope Decision
              </h2>
              <button
                onClick={() => setEvalResultModal(null)}
                className="text-slate-500 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between bg-black/40 p-2 rounded">
                <span className="text-slate-400">Decision Result:</span>
                <span
                  className={`font-semibold px-2 py-0.5 rounded text-[10px] ${
                    evalResultModal.data.decision === 'IN_SCOPE'
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : evalResultModal.data.decision === 'OUT_OF_SCOPE'
                      ? 'bg-rose-950 text-rose-400 border border-rose-800'
                      : 'bg-amber-950 text-amber-400 border border-amber-800'
                  }`}
                >
                  {evalResultModal.data.decision}
                </span>
              </div>

              <div className="bg-black/40 p-2.5 rounded space-y-1">
                <span className="text-slate-400 block text-[11px]">Evaluation Reason:</span>
                <p className="text-slate-200 text-[11px] leading-relaxed">{evalResultModal.data.reason}</p>
              </div>

              {evalResultModal.data.matched_scope_entry && (
                <div className="bg-black/40 p-2.5 rounded space-y-1">
                  <span className="text-slate-400 block text-[11px]">Matched Scope Rule:</span>
                  <p className="text-emerald-400 text-[11px]">
                    {evalResultModal.data.matched_scope_entry.asset_identifier} (
                    {evalResultModal.data.matched_scope_entry.asset_type})
                  </p>
                </div>
              )}

              <div className="text-[10px] text-slate-500 pt-2 flex justify-between">
                <span>Evaluator: {evalResultModal.data.evaluator_version}</span>
                <span>Policy Version: {evalResultModal.data.policy_version}</span>
              </div>
            </div>

            <button
              onClick={() => setEvalResultModal(null)}
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-semibold py-2 rounded transition cursor-pointer"
            >
              Acknowledge Decision
            </button>
          </div>
        </div>
      )}

      {/* Verify Tree SHA Result Modal */}
      {verifyResultModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 font-mono">
          <div className="bg-[#111] border border-white/10 rounded-lg max-w-lg w-full p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-sky-400" />
                Cryptographic Tree Integrity Report
              </h2>
              <button
                onClick={() => setVerifyResultModal(null)}
                className="text-slate-500 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between bg-black/40 p-2 rounded">
                <span className="text-slate-400">Integrity State:</span>
                <span
                  className={`font-semibold px-2 py-0.5 rounded text-[10px] ${
                    verifyResultModal.data.verified
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : 'bg-rose-950 text-rose-400 border border-rose-800'
                  }`}
                >
                  {verifyResultModal.data.verified ? 'PASSED (MATCH)' : 'MISMATCH / MISSING'}
                </span>
              </div>

              <div className="bg-black/40 p-2.5 rounded space-y-1">
                <span className="text-slate-400 block text-[10px]">Expected SHA-256:</span>
                <span className="text-sky-300 font-mono text-[10px] break-all">
                  {verifyResultModal.data.expected_hash || '(none)'}
                </span>
              </div>

              <div className="bg-black/40 p-2.5 rounded space-y-1">
                <span className="text-slate-400 block text-[10px]">Actual Calculated SHA-256:</span>
                <span className="text-emerald-300 font-mono text-[10px] break-all">
                  {verifyResultModal.data.actual_hash || '(none)'}
                </span>
              </div>

              {verifyResultModal.data.error && (
                <div className="bg-rose-950/40 p-2.5 rounded border border-rose-800/40 text-rose-300 text-[11px]">
                  {verifyResultModal.data.error}
                </div>
              )}
            </div>

            <button
              onClick={() => setVerifyResultModal(null)}
              className="w-full bg-white/10 hover:bg-white/20 text-white text-xs font-semibold py-2 rounded transition cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* Target Registration Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 font-mono">
          <div className="bg-[#111] border border-white/10 rounded-lg max-w-lg w-full p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-emerald-500" />
                Register Research Target
              </h2>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-500 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-2.5 bg-rose-950/50 border border-rose-800/50 rounded text-rose-300 text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Associated Bounty Program *</label>
                <select
                  value={programId}
                  onChange={(e) => setProgramId(e.target.value)}
                  className="w-full bg-black/50 border border-white/10 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-emerald-500 text-xs"
                >
                  {programs.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.platform})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Target Name *</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Uniswap V3 Pool Contract"
                  className="w-full bg-black/50 border border-white/10 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-emerald-500 text-xs"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Target Type</label>
                  <select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value as TargetType)}
                    className="w-full bg-black/50 border border-white/10 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-emerald-500 text-xs"
                  >
                    <option value={TargetType.SMART_CONTRACT}>SMART_CONTRACT</option>
                    <option value={TargetType.REPOSITORY}>REPOSITORY</option>
                    <option value={TargetType.DEPLOYED_SYSTEM}>DEPLOYED_SYSTEM</option>
                    <option value={TargetType.BINARY}>BINARY</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Ecosystem</label>
                  <select
                    value={ecosystem}
                    onChange={(e) => setEcosystem(e.target.value as Ecosystem)}
                    className="w-full bg-black/50 border border-white/10 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-emerald-500 text-xs"
                  >
                    <option value={Ecosystem.EVM}>EVM (Solidity/Vyper)</option>
                    <option value={Ecosystem.SOLANA}>Solana (Anchor/Rust)</option>
                    <option value={Ecosystem.CLARITY}>Clarity (Stacks)</option>
                    <option value={Ecosystem.MOVE}>Move (Aptos/Sui)</option>
                    <option value={Ecosystem.COSMWASM}>CosmWasm</option>
                    <option value={Ecosystem.WEB_APP}>Web / API Service</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Git Repository URL</label>
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/org/repo.git"
                  className="w-full bg-black/50 border border-white/10 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-emerald-500 text-xs"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Commit SHA / Tag</label>
                  <input
                    type="text"
                    value={commitHash}
                    onChange={(e) => setCommitHash(e.target.value)}
                    placeholder="e.g. 7b8f9e0... or v1.0.0"
                    className="w-full bg-black/50 border border-white/10 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-emerald-500 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Branch</label>
                  <input
                    type="text"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    placeholder="main"
                    className="w-full bg-black/50 border border-white/10 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-emerald-500 text-xs"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Contract / Deployment Address</label>
                <input
                  type="text"
                  value={contractAddress}
                  onChange={(e) => setContractAddress(e.target.value)}
                  placeholder="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"
                  className="w-full bg-black/50 border border-white/10 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-emerald-500 text-xs"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-3 py-1.5 rounded text-slate-400 hover:text-white transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="bg-emerald-500 hover:bg-emerald-400 text-black font-semibold px-4 py-1.5 rounded transition disabled:opacity-50 cursor-pointer"
                >
                  {submitting ? 'Registering...' : 'Register Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
