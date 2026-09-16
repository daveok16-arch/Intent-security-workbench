import React, { useState } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { BountyPlatform, ProgramStatus } from '../types.js';
import { FolderLock, Plus, Trash2, Globe, Clock, ShieldCheck, AlertCircle, ExternalLink, ShieldAlert, FileText } from 'lucide-react';

export const ProgramsView: React.FC = () => {
  const { programs, createProgram, deleteProgram } = useWorkbench();
  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState('');
  const [platform, setPlatform] = useState<BountyPlatform>(BountyPlatform.IMMUNEFI);
  const [status, setStatus] = useState<ProgramStatus>(ProgramStatus.ACTIVE);
  const [externalId, setExternalId] = useState('');
  const [programUrl, setProgramUrl] = useState('');
  const [policyVersion, setPolicyVersion] = useState('1.0.0');
  const [scopeInput, setScopeInput] = useState('');
  const [exclusionsInput, setExclusionsInput] = useState('');
  const [testingRulesInput, setTestingRulesInput] = useState('');
  const [techInput, setTechInput] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setFormError('Program name is required.');
      return;
    }

    try {
      setSubmitting(true);
      setFormError(null);
      await createProgram({
        name: name.trim(),
        platform,
        status,
        external_identifier: externalId.trim(),
        program_url: programUrl.trim() || undefined,
        source_reference: programUrl.trim() || undefined,
        policy_version: policyVersion.trim() || '1.0.0',
        scope: scopeInput.split('\n').map(s => s.trim()).filter(Boolean),
        exclusions: exclusionsInput.split('\n').map(e => e.trim()).filter(Boolean),
        testing_rules: testingRulesInput.split('\n').map(r => r.trim()).filter(Boolean),
        technology: techInput.split(',').map(t => t.trim()).filter(Boolean),
        last_verified_at: new Date().toISOString(),
      });

      setName('');
      setExternalId('');
      setProgramUrl('');
      setPolicyVersion('1.0.0');
      setScopeInput('');
      setExclusionsInput('');
      setTestingRulesInput('');
      setShowModal(false);
    } catch (err: any) {
      setFormError(err.message || 'Failed to create program');
    } finally {
      setSubmitting(false);
    }
  };

  const getStatusBadge = (progStatus?: ProgramStatus | string) => {
    switch (progStatus) {
      case ProgramStatus.ACTIVE:
      case 'ACTIVE':
        return (
          <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold border border-emerald-500/30 text-emerald-400 bg-emerald-500/10 inline-flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            ACTIVE
          </span>
        );
      case ProgramStatus.INACTIVE:
      case 'INACTIVE':
        return (
          <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold border border-amber-500/30 text-amber-400 bg-amber-500/10 inline-flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            INACTIVE
          </span>
        );
      case ProgramStatus.ARCHIVED:
      case 'ARCHIVED':
        return (
          <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold border border-slate-500/30 text-slate-400 bg-slate-500/10 inline-flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
            ARCHIVED
          </span>
        );
      default:
        return (
          <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold border border-rose-500/30 text-rose-400 bg-rose-500/10 inline-flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
            UNKNOWN
          </span>
        );
    }
  };

  return (
    <div id="programs-view" className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase font-mono flex items-center gap-2">
            <FolderLock className="w-4 h-4 text-emerald-500" />
            Bounty Programs & Scope Registry
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Modular multi-platform adapters for Immunefi, HackenProof, Cantina, HackerOne, and Custom authorizations.
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-mono px-3.5 py-1.5 rounded font-semibold flex items-center gap-1.5 transition cursor-pointer self-start"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>INITIALIZE PROGRAM</span>
        </button>
      </div>

      {/* Program List */}
      {programs.length === 0 ? (
        <div className="py-16 text-center rounded-lg border border-dashed border-white/10 bg-[#0D0D0D]">
          <FolderLock className="w-10 h-10 text-slate-600 mx-auto mb-2" />
          <p className="text-sm font-mono text-slate-400">No bounty programs configured.</p>
          <p className="text-xs font-mono text-slate-600 mt-1">
            Add a program to establish scope boundaries and authorized targets.
          </p>
          <button
            onClick={() => setShowModal(true)}
            className="mt-4 inline-flex items-center gap-1.5 bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-mono font-semibold px-3.5 py-1.5 rounded transition cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Register First Program</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {programs.map((prog) => (
            <div key={prog.id} className="rounded-lg border border-white/10 bg-[#0D0D0D] p-5 space-y-3.5 font-mono">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-semibold text-white">{prog.name}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded border border-white/10 text-slate-300 bg-white/5">
                      {prog.platform}
                    </span>
                    {getStatusBadge(prog.status)}
                  </div>
                  {prog.external_identifier && (
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      ID: {prog.external_identifier}
                    </div>
                  )}
                </div>
                <button
                  onClick={() => deleteProgram(prog.id)}
                  className="text-slate-500 hover:text-rose-400 transition p-1 cursor-pointer"
                  title="Delete Program"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>

              {/* Policy & Verification Metadata */}
              <div className="bg-black/30 p-2.5 rounded border border-white/5 grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-slate-500 text-[10px] block">Policy Version</span>
                  <span className="text-slate-300 font-medium">{prog.policy_version || 'v1.0.0'}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">Last Verified</span>
                  <span className="text-slate-300">
                    {prog.last_verified_at ? new Date(prog.last_verified_at).toLocaleString() : (prog.retrieved_at ? new Date(prog.retrieved_at).toLocaleString() : 'Not verified')}
                  </span>
                </div>
              </div>

              {/* Source & Program URL */}
              {(prog.program_url || prog.source_reference) && (
                <div className="text-[11px] flex items-center justify-between text-slate-400 bg-black/20 px-2.5 py-1.5 rounded border border-white/5">
                  <span className="text-slate-500 text-[10px]">Source:</span>
                  <a
                    href={prog.program_url || prog.source_reference}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sky-400 hover:underline flex items-center gap-1 truncate max-w-[240px]"
                  >
                    <span>{prog.program_url || prog.source_reference}</span>
                    <ExternalLink className="w-3 h-3 shrink-0" />
                  </a>
                </div>
              )}

              {/* Scope & Exclusions summary */}
              <div className="space-y-2 text-[11px]">
                <div>
                  <span className="text-slate-400 font-medium">In-Scope Assets ({Array.isArray(prog.scope) ? prog.scope.length : 0}):</span>
                  <div className="mt-1 bg-black/30 p-2.5 rounded border border-white/5 text-slate-300 max-h-20 overflow-y-auto space-y-0.5">
                    {Array.isArray(prog.scope) && prog.scope.length > 0 ? (
                      prog.scope.map((s, idx) => (
                        <div key={idx} className="truncate">
                          • {typeof s === 'string' ? s : (s as any).asset_identifier || JSON.stringify(s)}
                        </div>
                      ))
                    ) : (
                      <span className="text-slate-600 italic">No scope items defined</span>
                    )}
                  </div>
                </div>

                {prog.exclusions && prog.exclusions.length > 0 && (
                  <div>
                    <span className="text-rose-400/90 font-medium">Exclusions ({prog.exclusions.length}):</span>
                    <div className="mt-1 bg-black/30 p-2.5 rounded border border-white/5 text-rose-300/80 max-h-16 overflow-y-auto space-y-0.5">
                      {prog.exclusions.map((e, idx) => <div key={idx} className="truncate">• {e}</div>)}
                    </div>
                  </div>
                )}

                {prog.testing_rules && prog.testing_rules.length > 0 && (
                  <div>
                    <span className="text-amber-400/90 font-medium">Restrictions & Rules ({prog.testing_rules.length}):</span>
                    <div className="mt-1 bg-black/30 p-2.5 rounded border border-white/5 text-amber-300/80 max-h-16 overflow-y-auto space-y-0.5">
                      {prog.testing_rules.map((r, idx) => <div key={idx} className="truncate">• {r}</div>)}
                    </div>
                  </div>
                )}
              </div>

              {/* Tech Tags */}
              <div className="flex flex-wrap gap-1 pt-2 border-t border-white/5">
                {prog.technology?.map((tech, idx) => (
                  <span key={idx} className="text-[10px] bg-black/40 border border-white/5 text-slate-400 px-1.5 py-0.5 rounded">
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#0D0D0D] border border-white/10 rounded-lg p-6 w-full max-w-lg space-y-4 font-mono max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                <FolderLock className="w-4 h-4 text-emerald-500" />
                Register Bounty Program
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

            <form onSubmit={handleSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Program Name *</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Uniswap V4 Bug Bounty"
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Platform</label>
                  <select
                    value={platform}
                    onChange={(e) => setPlatform(e.target.value as BountyPlatform)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  >
                    <option value={BountyPlatform.IMMUNEFI}>Immunefi</option>
                    <option value={BountyPlatform.HACKENPROOF}>HackenProof</option>
                    <option value={BountyPlatform.CANTINA}>Cantina</option>
                    <option value={BountyPlatform.HACKERONE}>HackerOne</option>
                    <option value={BountyPlatform.CUSTOM}>Custom / Private</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Status</label>
                  <select
                    value={status}
                    onChange={(e) => setStatus(e.target.value as ProgramStatus)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  >
                    <option value={ProgramStatus.ACTIVE}>ACTIVE</option>
                    <option value={ProgramStatus.INACTIVE}>INACTIVE</option>
                    <option value={ProgramStatus.ARCHIVED}>ARCHIVED</option>
                    <option value={ProgramStatus.UNKNOWN}>UNKNOWN</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">External Identifier / Slug</label>
                  <input
                    type="text"
                    value={externalId}
                    onChange={(e) => setExternalId(e.target.value)}
                    placeholder="e.g. uniswap-v4"
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Policy Version</label>
                  <input
                    type="text"
                    value={policyVersion}
                    onChange={(e) => setPolicyVersion(e.target.value)}
                    placeholder="e.g. 1.0.0"
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Source / Program URL</label>
                <input
                  type="text"
                  value={programUrl}
                  onChange={(e) => setProgramUrl(e.target.value)}
                  placeholder="https://immunefi.com/bounty/uniswap-v4"
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">In-Scope Assets (one per line)</label>
                <textarea
                  value={scopeInput}
                  onChange={(e) => setScopeInput(e.target.value)}
                  placeholder="contracts/PoolManager.sol&#10;0x1234567890abcdef..."
                  rows={3}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Exclusions (one per line)</label>
                <textarea
                  value={exclusionsInput}
                  onChange={(e) => setExclusionsInput(e.target.value)}
                  placeholder="Third-party oracle downtime&#10;Front-end spoofing..."
                  rows={2}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Testing Restrictions & Rules (one per line)</label>
                <textarea
                  value={testingRulesInput}
                  onChange={(e) => setTestingRulesInput(e.target.value)}
                  placeholder="No denial of service on mainnet&#10;No automated fuzzing on production RPC"
                  rows={2}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Technologies (comma-separated)</label>
                <input
                  type="text"
                  value={techInput}
                  onChange={(e) => setTechInput(e.target.value)}
                  placeholder="Solidity, Foundry, EVM"
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
                  disabled={submitting}
                  className="px-3.5 py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-black font-semibold disabled:opacity-50 cursor-pointer"
                >
                  {submitting ? 'Creating...' : 'Create Program'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
