import React from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';

/** Maps a diagnostics entry to a lamp colour and label suffix. */
function serviceLamp(entry: unknown): { color: string; label: string } {
  if (entry === undefined || entry === null || entry === '') {
    return { color: 'bg-slate-500', label: 'UNKNOWN' };
  }
  const status = typeof entry === 'string' ? entry : (entry as any)?.status;
  if (status === undefined || status === null || status === '') {
    return { color: 'bg-slate-500', label: 'UNKNOWN' };
  }
  const normalized = String(status).toUpperCase();
  if (normalized === 'OK' || normalized === 'CONNECTED' || normalized === 'HEALTHY' || normalized === 'READY') {
    return { color: 'bg-emerald-500', label: normalized };
  }
  if (normalized === 'NOT_CONFIGURED' || normalized === 'DISABLED' || normalized === 'IN_MEMORY') {
    return { color: 'bg-slate-500', label: normalized };
  }
  return { color: 'bg-rose-500', label: normalized };
}

export const Footer: React.FC = () => {
  const { wsConnected, systemStatus, buildInfo, diagnostics } = useWorkbench();

  const dbEntry = diagnostics?.diagnostics?.database ?? diagnostics?.database;
  const db = serviceLamp(dbEntry);

  return (
    <footer id="app-footer" className="flex h-8 items-center justify-between border-t border-white/10 bg-[#0A0A0A] px-6 text-[10px] font-mono text-slate-500 select-none shrink-0">
      <div className="flex items-center gap-4">
        <span>STORAGE: {diagnostics ? 'EVIDENCE_LOCKER' : 'UNKNOWN'}</span>
        <span className="hidden sm:inline text-white/10">|</span>
        <span>ENV: {diagnostics ? 'RESEARCH_WORKBENCH' : 'UNKNOWN'}</span>
        <span className="hidden sm:inline text-white/10">|</span>
        {/* Reported by the backend. Never a hardcoded release string. */}
        <span>VER: {buildInfo?.api_version ?? 'unknown'}</span>
      </div>

      <div className="flex items-center gap-5">
        <span className="flex items-center gap-1.5" title={db.label}>
          <span className={`h-1.5 w-1.5 rounded-full ${db.color}`}></span>
          <span className="text-slate-400">DATABASE{diagnostics ? `: ${db.label}` : ''}</span>
        </span>
        <span className="flex items-center gap-1.5">
          {/* Only green when the backend has actually confirmed worker state. */}
          <span className={`h-1.5 w-1.5 rounded-full ${
            !systemStatus ? 'bg-slate-500' : systemStatus.jobs_running ? 'bg-sky-400 animate-pulse' : 'bg-emerald-500'
          }`}></span>
          <span className="text-slate-400">WORKER_0{systemStatus ? '' : ': UNKNOWN'}</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className={`h-1.5 w-1.5 rounded-full ${wsConnected ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`}></span>
          <span className={wsConnected ? 'text-emerald-500' : 'text-rose-500'}>WS_GATEWAY</span>
        </span>
      </div>
    </footer>
  );
};
