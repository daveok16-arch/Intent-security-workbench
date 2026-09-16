import React from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { RefreshCw } from 'lucide-react';

export const Header: React.FC = () => {
  const { wsConnected, systemStatus, refreshAll, loading, engines } = useWorkbench();

  return (
    <header id="app-header" className="flex h-14 items-center justify-between border-b border-white/10 bg-[#0D0D0D] px-6 select-none shrink-0">
      <div className="flex items-center gap-4">
        <div className="flex h-8 w-8 items-center justify-center rounded bg-emerald-500 font-bold text-black text-sm tracking-tighter">
          I
        </div>
        <h1 className="text-sm font-semibold tracking-widest text-white flex items-center gap-2">
          INTENT <span className="text-emerald-500">SECURITY</span> WORKBENCH
          <span className="ml-2 rounded border border-emerald-500/30 px-1.5 py-0.5 text-[10px] text-emerald-500 font-mono tracking-normal">
            WORKBENCH
          </span>
        </h1>
      </div>

      <div className="flex items-center gap-6 text-[11px] font-mono uppercase tracking-wider">
        <div className="flex items-center gap-2">
          <div className={`h-1.5 w-1.5 rounded-full ${wsConnected ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`} />
          <span className={wsConnected ? 'text-emerald-500 font-medium' : 'text-rose-400 font-medium'}>
            API: {wsConnected ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        <div className="flex items-center gap-2 text-slate-400">
          <div className={`h-1.5 w-1.5 rounded-full ${systemStatus?.jobs_running ? 'bg-sky-400 animate-pulse' : 'bg-emerald-500'}`} />
          <span>WORKER: {systemStatus?.jobs_running ? `${systemStatus.jobs_running} RUNNING` : 'READY'}</span>
        </div>

        <div className="flex items-center gap-2 text-slate-400">
          <div className={`h-1.5 w-1.5 rounded-full ${engines.some(e => e.availability?.status === 'AVAILABLE' || (e.availability as any)?.available) ? 'bg-emerald-500' : 'bg-amber-500'}`} />
          <span>
            ENGINES: {engines.filter(e => e.availability?.status === 'AVAILABLE' || (e.availability as any)?.available).length}/{engines.length || 11}
          </span>
        </div>

        <div className="h-4 w-px bg-white/10" />

        <button
          id="btn-refresh-telemetry"
          onClick={() => refreshAll()}
          disabled={loading}
          className="flex items-center gap-1.5 rounded border border-white/10 bg-white/5 hover:bg-white/10 text-slate-300 px-2.5 py-1 text-[11px] font-mono transition disabled:opacity-50 cursor-pointer"
          title="Refresh All State"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
          <span>SYNC</span>
        </button>
      </div>
    </header>
  );
};
