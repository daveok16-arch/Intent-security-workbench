import React, { useState } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { Cpu, CheckCircle2, XCircle, RefreshCw, Terminal, AlertCircle, AlertTriangle, ShieldCheck, Binary } from 'lucide-react';
import { EngineAvailabilityStatus } from '../types.js';

export const EnginesView: React.FC = () => {
  const { engines, refreshAll, checkEngine, checkAllEngines, loading } = useWorkbench();
  const [checkingEngineId, setCheckingEngineId] = useState<string | null>(null);
  const [isCheckingAll, setIsCheckingAll] = useState<boolean>(false);

  const handleCheckAll = async () => {
    setIsCheckingAll(true);
    try {
      await checkAllEngines();
    } catch (err) {
      console.error('Failed to check all engines:', err);
    } finally {
      setIsCheckingAll(false);
    }
  };

  const handleCheckSingle = async (engineId: string) => {
    setCheckingEngineId(engineId);
    try {
      await checkEngine(engineId);
    } catch (err) {
      console.error(`Failed to check engine ${engineId}:`, err);
    } finally {
      setCheckingEngineId(null);
    }
  };

  const availableCount = engines.filter(
    e => e.availability?.status === EngineAvailabilityStatus.AVAILABLE || (e.availability as any)?.available === true
  ).length;

  return (
    <div id="engines-view" className="space-y-6 font-mono">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase flex items-center gap-2">
            <Cpu className="w-4 h-4 text-emerald-500" />
            Truthful Engine Registry & Binary Abstraction Layer
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time host PATH detection, binary execution verification, and strict anti-fabrication isolation.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            id="btn-check-all-engines"
            onClick={handleCheckAll}
            disabled={loading || isCheckingAll}
            className="bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-semibold px-3.5 py-1.5 rounded flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isCheckingAll || loading ? 'animate-spin' : ''}`} />
            <span>CHECK ALL AVAILABILITY</span>
          </button>
        </div>
      </div>

      {/* Engine Invariant Banner */}
      <div className="p-4 bg-black/40 border border-white/10 rounded-lg text-xs text-slate-300 space-y-2">
        <div className="flex items-center justify-between">
          <div className="font-semibold text-emerald-400 flex items-center gap-2">
            <Terminal className="w-4 h-4" />
            <span>Phase 0.1 Invariant: Ground-Truth Engine Isolation</span>
          </div>
          <div className="text-[11px] text-slate-400">
            Available on host: <strong className="text-emerald-400">{availableCount}</strong> / {engines.length}
          </div>
        </div>
        <p className="text-slate-400 text-[11px] leading-relaxed">
          Engines marked <strong className="text-rose-400">NOT_INSTALLED</strong> or <strong className="text-amber-400">UNAVAILABLE</strong> lack verified host executables. The engine framework strictly refuses to execute synthetic scans, mock AST queries, or simulated vulnerabilities for missing tools.
        </p>
      </div>

      {/* Engines Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {engines.map((eng) => {
          const avail = eng.availability;
          const status = avail?.status || ((avail as any)?.available ? EngineAvailabilityStatus.AVAILABLE : EngineAvailabilityStatus.NOT_INSTALLED);
          const isChecking = checkingEngineId === eng.engine_id;

          return (
            <div
              key={eng.engine_id || eng.name}
              id={`engine-card-${eng.engine_id || eng.name}`}
              className="rounded-lg border border-white/10 bg-[#0D0D0D] p-5 flex flex-col justify-between space-y-4"
            >
              <div className="space-y-3">
                {/* Engine Header */}
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-semibold text-white">{eng.name}</span>
                      <span className="text-[10px] text-slate-500 font-mono">({eng.engine_id})</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{eng.description}</p>
                  </div>

                  {/* Status Badge */}
                  {status === EngineAvailabilityStatus.AVAILABLE ? (
                    <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60 font-semibold shrink-0">
                      <CheckCircle2 className="w-3 h-3" />
                      AVAILABLE
                    </span>
                  ) : status === EngineAvailabilityStatus.BROKEN ? (
                    <span className="inline-flex items-center gap-1 text-[10px] text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/60 font-semibold shrink-0">
                      <AlertTriangle className="w-3 h-3" />
                      BROKEN
                    </span>
                  ) : status === EngineAvailabilityStatus.UNAVAILABLE ? (
                    <span className="inline-flex items-center gap-1 text-[10px] text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800/60 font-semibold shrink-0">
                      <AlertCircle className="w-3 h-3" />
                      UNAVAILABLE
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[10px] text-rose-400 bg-rose-950/50 px-2 py-0.5 rounded border border-rose-800/50 font-semibold shrink-0">
                      <XCircle className="w-3 h-3" />
                      NOT INSTALLED
                    </span>
                  )}
                </div>

                {/* Capabilities Badges */}
                {eng.capabilities && Array.isArray(eng.capabilities) && eng.capabilities.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {eng.capabilities.map((cap) => (
                      <span
                        key={cap}
                        className="text-[9px] bg-white/5 text-slate-300 px-1.5 py-0.5 rounded border border-white/5 font-mono"
                      >
                        {cap}
                      </span>
                    ))}
                  </div>
                )}

                {/* Verification Box */}
                <div className="bg-black/40 p-2.5 rounded border border-white/5 space-y-1.5 text-[11px]">
                  <div className="flex justify-between items-center text-slate-500">
                    <span>Executable:</span>
                    <span className="text-slate-300 font-mono font-semibold">{eng.executable}</span>
                  </div>

                  <div className="flex justify-between items-center text-slate-500">
                    <span>Resolved Path:</span>
                    <span className={avail?.detected_path ? 'text-emerald-400 truncate max-w-[170px]' : 'text-slate-500'}>
                      {avail?.detected_path || '(none on PATH)'}
                    </span>
                  </div>

                  <div className="flex justify-between items-center text-slate-500">
                    <span>Detected Version:</span>
                    <span className={avail?.version ? 'text-sky-300 font-semibold truncate max-w-[170px]' : 'text-slate-500'}>
                      {avail?.version || '-'}
                    </span>
                  </div>

                  {avail?.error && (
                    <div className="pt-1 text-[10px] text-rose-400 border-t border-white/5">
                      <span className="font-semibold">Reason:</span> {avail.error}
                    </div>
                  )}
                </div>

                {/* Supported Target Types & Languages */}
                <div className="space-y-1 text-[10px] text-slate-500">
                  {eng.supported_languages && eng.supported_languages.length > 0 && (
                    <div>
                      Languages: <span className="text-slate-400">{eng.supported_languages.join(', ')}</span>
                    </div>
                  )}
                  {eng.supported_target_types && eng.supported_target_types.length > 0 && (
                    <div>
                      Target Types: <span className="text-slate-400">{eng.supported_target_types.join(', ')}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Card Footer & Action */}
              <div className="pt-3 border-t border-white/5 flex items-center justify-between">
                <span className="text-[9px] text-slate-500">
                  Checked: {avail?.checked_at ? new Date(avail.checked_at).toLocaleTimeString() : 'Never'}
                </span>
                <button
                  id={`btn-check-${eng.engine_id}`}
                  onClick={() => handleCheckSingle(eng.engine_id)}
                  disabled={isChecking || loading}
                  className="text-[10px] bg-white/5 hover:bg-white/10 text-slate-300 px-2.5 py-1 rounded border border-white/10 flex items-center gap-1 transition disabled:opacity-50 cursor-pointer"
                >
                  <RefreshCw className={`w-2.5 h-2.5 ${isChecking ? 'animate-spin' : ''}`} />
                  <span>Re-check Binary</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
