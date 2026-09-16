import React from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';

export const Footer: React.FC = () => {
  const { wsConnected, systemStatus } = useWorkbench();

  return (
    <footer id="app-footer" className="flex h-8 items-center justify-between border-t border-white/10 bg-[#0A0A0A] px-6 text-[10px] font-mono text-slate-500 select-none shrink-0">
      <div className="flex items-center gap-4">
        <span>STORAGE: EVIDENCE_LOCKER</span>
        <span className="hidden sm:inline text-white/10">|</span>
        <span>ENV: RESEARCH_WORKBENCH</span>
        <span className="hidden sm:inline text-white/10">|</span>
        <span>VER: 2.0.0</span>
      </div>

      <div className="flex items-center gap-5">
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
          <span className="text-slate-400">DATABASE</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className={`h-1.5 w-1.5 rounded-full ${systemStatus?.jobs_running ? 'bg-sky-400 animate-pulse' : 'bg-emerald-500'}`}></span>
          <span className="text-slate-400">WORKER_0</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className={`h-1.5 w-1.5 rounded-full ${wsConnected ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`}></span>
          <span className={wsConnected ? 'text-emerald-500' : 'text-rose-500'}>WS_GATEWAY</span>
        </span>
      </div>
    </footer>
  );
};
