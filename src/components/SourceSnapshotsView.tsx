import React, { useState, useEffect, useCallback } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { SourceSnapshot } from '../types.js';
import {
  FolderGit2,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  GitCommit,
  Hash,
  Clock,
  HardDrive,
  Copy,
  Check,
  ShieldCheck,
  ExternalLink,
} from 'lucide-react';

export const SourceSnapshotsView: React.FC = () => {
  const { targets, verifyTargetSource } = useWorkbench();

  const [snapshots, setSnapshots] = useState<SourceSnapshot[]>([]);
  const [loading, setLoading] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationResults, setVerificationResults] = useState<Record<string, any>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchSnapshots = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/source/snapshots');
      if (res.ok) {
        const data = await res.json();
        setSnapshots(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error('Failed to load source snapshots:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSnapshots();
  }, [fetchSnapshots]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleVerify = async (snapshot: SourceSnapshot) => {
    try {
      setVerifyingId(snapshot.id);
      const res = await verifyTargetSource(snapshot.target_id);
      setVerificationResults(prev => ({
        ...prev,
        [snapshot.id]: res,
      }));
    } catch (err: any) {
      setVerificationResults(prev => ({
        ...prev,
        [snapshot.id]: {
          verified: false,
          error: err.message,
        },
      }));
    } finally {
      setVerifyingId(null);
    }
  };

  return (
    <div id="source-snapshots-view" className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase font-mono flex items-center gap-2">
            <FolderGit2 className="w-4 h-4 text-emerald-500" />
            Source Snapshots & Tree Provenance
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Cryptographically anchored source code snapshots with deterministic SHA-256 tree hashing and audit event tracking.
          </p>
        </div>
        <button
          onClick={fetchSnapshots}
          disabled={loading}
          className="bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-mono px-3 py-1.5 rounded border border-white/10 flex items-center gap-1.5 transition cursor-pointer self-start"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>REFRESH</span>
        </button>
      </div>

      {/* Snapshots List */}
      {loading && snapshots.length === 0 ? (
        <div className="py-16 text-center text-xs font-mono text-slate-500">
          Loading source snapshots from evidence archive...
        </div>
      ) : snapshots.length === 0 ? (
        <div className="py-16 text-center rounded-lg border border-dashed border-white/10 bg-[#0D0D0D] font-mono">
          <FolderGit2 className="w-10 h-10 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-400">No source snapshots acquired yet.</p>
          <p className="text-xs text-slate-600 mt-1">
            Navigate to Targets and execute "ACQUIRE SOURCE" to clone and compute SHA-256 tree digests.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {snapshots.map((snap) => {
            const tgt = targets.find(t => t.id === snap.target_id);
            const isVerifying = verifyingId === snap.id;
            const vResult = verificationResults[snap.id];

            return (
              <div
                key={snap.id}
                className="bg-[#0D0D0D] border border-white/10 rounded-lg p-5 space-y-4 font-mono text-xs"
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/5 pb-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-white">{snap.id}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                      {snap.provider} v{snap.provider_version || '1.0'}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      Target: <span className="text-slate-300 font-semibold">{tgt?.name || snap.target_id}</span>
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleVerify(snap)}
                      disabled={isVerifying}
                      className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2.5 py-1 rounded text-[11px] font-semibold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3 h-3 ${isVerifying ? 'animate-spin' : ''}`} />
                      <span>{isVerifying ? 'Verifying Tree...' : 'Verify Cryptographic Integrity'}</span>
                    </button>
                  </div>
                </div>

                {/* Details Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {/* SHA-256 Tree Hash */}
                  <div className="bg-black/30 p-2.5 rounded border border-white/5 space-y-1">
                    <div className="flex items-center justify-between text-[10px] text-slate-500 uppercase tracking-wider">
                      <span className="flex items-center gap-1">
                        <Hash className="w-3 h-3 text-emerald-500" />
                        Source Tree SHA-256
                      </span>
                      <button
                        onClick={() => handleCopy(snap.source_hash, `hash-${snap.id}`)}
                        className="text-slate-500 hover:text-white cursor-pointer"
                        title="Copy Hash"
                      >
                        {copiedId === `hash-${snap.id}` ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                    <div className="font-mono text-[11px] text-emerald-400 break-all select-all">
                      {snap.source_hash || 'Pending Calculation'}
                    </div>
                  </div>

                  {/* Commit SHA */}
                  <div className="bg-black/30 p-2.5 rounded border border-white/5 space-y-1">
                    <div className="flex items-center justify-between text-[10px] text-slate-500 uppercase tracking-wider">
                      <span className="flex items-center gap-1">
                        <GitCommit className="w-3 h-3 text-sky-400" />
                        Resolved Commit SHA
                      </span>
                      {snap.resolved_commit_sha && (
                        <button
                          onClick={() => handleCopy(snap.resolved_commit_sha!, `commit-${snap.id}`)}
                          className="text-slate-500 hover:text-white cursor-pointer"
                          title="Copy Commit SHA"
                        >
                          {copiedId === `commit-${snap.id}` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      )}
                    </div>
                    <div className="font-mono text-[11px] text-sky-400 break-all select-all">
                      {snap.resolved_commit_sha || snap.commit_hash || 'HEAD / Unresolved'}
                    </div>
                  </div>

                  {/* Repository URL */}
                  <div className="bg-black/30 p-2.5 rounded border border-white/5 space-y-1">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
                      <HardDrive className="w-3 h-3 text-amber-400" />
                      Repository Source
                    </div>
                    <div className="font-mono text-[11px] text-slate-300 truncate" title={snap.repository_url}>
                      {snap.repository_url || 'Local Workspace'}
                    </div>
                  </div>
                </div>

                {/* Storage & Metadata Footer */}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-white/5 text-[11px] text-slate-500">
                  <div className="flex items-center gap-4">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      Acquired: {snap.acquired_at ? new Date(snap.acquired_at).toLocaleString() : '—'}
                    </span>
                    {snap.storage_path && (
                      <span className="truncate max-w-sm" title={snap.storage_path}>
                        Path: <span className="text-slate-400">{snap.storage_path}</span>
                      </span>
                    )}
                  </div>

                  {/* Live Verification Status Pill */}
                  {vResult && (
                    <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold ${
                      vResult.verified
                        ? 'bg-emerald-950/60 border border-emerald-700/60 text-emerald-300'
                        : 'bg-rose-950/60 border border-rose-700/60 text-rose-300'
                    }`}>
                      {vResult.verified ? (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          <span>INTEGRITY VERIFIED: EXACT SHA-256 MATCH</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="w-3 h-3 text-rose-400" />
                          <span>INTEGRITY MISMATCH: {vResult.error || 'HASH DRIFT DETECTED'}</span>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
