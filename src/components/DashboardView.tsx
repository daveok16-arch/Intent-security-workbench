import React from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import {
  FolderLock,
  Crosshair,
  Search,
  ListTodo,
  FileCheck,
  AlertTriangle,
  Cpu,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertCircle
} from 'lucide-react';

export const DashboardView: React.FC = () => {
  const {
    programs,
    targets,
    investigations,
    jobs,
    evidence,
    findings,
    engines,
    setActiveTab,
    liveNotifications,
    setSelectedInvestigationId
  } = useWorkbench();

  return (
    <div id="dashboard-view" className="space-y-6">
      {/* 3-column layout matching Design HTML */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Columns: Main Workbench Overview */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active Investigations Section */}
          <section className="rounded-lg border border-white/5 bg-[#0D0D0D] p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-500 font-mono">
                Active Investigations
              </h2>
              <button
                onClick={() => setActiveTab('investigations')}
                className="text-[11px] font-mono font-medium text-emerald-500 hover:underline cursor-pointer"
              >
                + INITIALIZE INVESTIGATION
              </button>
            </div>

            {investigations.length === 0 ? (
              <div className="flex h-48 items-center justify-center border border-dashed border-white/10 rounded-md bg-black/20">
                <div className="text-center p-4">
                  <p className="text-sm text-slate-500 font-mono">No active investigations found.</p>
                  <p className="mt-1 text-[11px] text-slate-600 font-mono">
                    Phase 0: Foundation established. Create an investigation to begin.
                  </p>
                  <button
                    onClick={() => setActiveTab('programs')}
                    className="mt-3 inline-flex items-center gap-1.5 rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] font-mono text-emerald-400 hover:bg-emerald-500/20 transition cursor-pointer"
                  >
                    <span>Configure Program Scope</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                {investigations.slice(0, 4).map((inv) => {
                  const prog = programs.find(p => p.id === inv.program_id);
                  const tgt = targets.find(t => t.id === inv.target_id);
                  const invJobs = jobs.filter(j => j.investigation_id === inv.id);
                  const invFindings = findings.filter(f => f.investigation_id === inv.id);

                  return (
                    <div
                      key={inv.id}
                      onClick={() => {
                        setSelectedInvestigationId(inv.id);
                        setActiveTab('investigations');
                      }}
                      className="p-3 bg-black/20 hover:bg-white/5 border border-white/5 rounded-md flex items-center justify-between transition cursor-pointer font-mono"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-medium text-white">{inv.title}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-white/5 text-slate-400 border border-white/10">
                            {inv.status}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 flex items-center gap-2">
                          <span>{prog?.name || inv.program_id}</span>
                          <span>/</span>
                          <span>{tgt?.name || inv.target_id}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-4 text-right">
                        <div className="text-[11px] text-slate-500">
                          <div>{invJobs.length} Jobs</div>
                          <div className="text-emerald-400/90">{invFindings.length} Findings</div>
                        </div>
                        <ArrowRight className="w-4 h-4 text-slate-500" />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* Foundational Domain State Metrics Section */}
          <section className="rounded-lg border border-white/5 bg-[#0D0D0D] p-6">
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-4 font-mono">
              Foundational Domain State
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <div
                onClick={() => setActiveTab('programs')}
                className="rounded border border-white/5 p-3.5 bg-black/20 hover:bg-white/[0.02] transition cursor-pointer font-mono"
              >
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">PROGRAMS</div>
                <div className="mt-1 text-2xl font-light text-white">{programs.length}</div>
                <div className="text-[10px] text-slate-500 mt-1">Multi-platform</div>
              </div>

              <div
                onClick={() => setActiveTab('targets')}
                className="rounded border border-white/5 p-3.5 bg-black/20 hover:bg-white/[0.02] transition cursor-pointer font-mono"
              >
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">TARGETS</div>
                <div className="mt-1 text-2xl font-light text-white">{targets.length}</div>
                <div className="text-[10px] text-slate-500 mt-1">EVM/Rust/Clarity</div>
              </div>

              <div
                onClick={() => setActiveTab('investigations')}
                className="rounded border border-white/5 p-3.5 bg-black/20 hover:bg-white/[0.02] transition cursor-pointer font-mono"
              >
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">SESSIONS</div>
                <div className="mt-1 text-2xl font-light text-white">{investigations.length}</div>
                <div className="text-[10px] text-slate-500 mt-1">Investigations</div>
              </div>

              <div
                onClick={() => setActiveTab('jobs')}
                className="rounded border border-white/5 p-3.5 bg-black/20 hover:bg-white/[0.02] transition cursor-pointer font-mono"
              >
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">JOBS</div>
                <div className="mt-1 text-2xl font-light text-sky-400">{jobs.length}</div>
                <div className="text-[10px] text-slate-500 mt-1">{jobs.filter(j => j.status === 'RUNNING').length} running</div>
              </div>

              <div
                onClick={() => setActiveTab('evidence')}
                className="rounded border border-white/5 p-3.5 bg-black/20 hover:bg-white/[0.02] transition cursor-pointer font-mono"
              >
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">EVIDENCE</div>
                <div className="mt-1 text-2xl font-light text-emerald-400">{evidence.length}</div>
                <div className="text-[10px] text-slate-500 mt-1">SHA-256 locked</div>
              </div>

              <div
                onClick={() => setActiveTab('findings')}
                className="rounded border border-white/5 p-3.5 bg-black/20 hover:bg-white/[0.02] transition cursor-pointer font-mono"
              >
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">FINDINGS</div>
                <div className="mt-1 text-2xl font-light text-amber-400">{findings.length}</div>
                <div className="text-[10px] text-slate-500 mt-1">{findings.filter(f => f.status === 'CONFIRMED').length} confirmed</div>
              </div>
            </div>
          </section>

          {/* Engine Status Panel */}
          <section id="engine-status-panel" className="rounded-lg border border-white/5 bg-[#0D0D0D] p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400 font-mono flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-500" />
                ENGINE STATUS
              </h2>
              <button
                id="btn-view-engine-registry"
                onClick={() => setActiveTab('engines')}
                className="text-[11px] font-mono text-emerald-500 hover:underline cursor-pointer"
              >
                Inspect All Engines →
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono">
              {engines.map((eng) => {
                const status = eng.availability?.status || 'NOT_INSTALLED';
                const isAvailable = status === 'AVAILABLE';
                const isNotInstalled = status === 'NOT_INSTALLED';
                const isBroken = status === 'BROKEN';

                return (
                  <div
                    key={eng.engine_id || eng.name}
                    id={`engine-card-${eng.engine_id}`}
                    className="p-3 bg-black/20 border border-white/5 rounded space-y-1.5 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-slate-200">{eng.name}</span>
                      {isAvailable ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-400 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-800/40">
                          <CheckCircle2 className="w-3 h-3" />
                          AVAILABLE
                        </span>
                      ) : isNotInstalled ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold text-slate-400 bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
                          <XCircle className="w-3 h-3 text-slate-500" />
                          NOT INSTALLED
                        </span>
                      ) : isBroken ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold text-amber-400 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-800/40">
                          <AlertTriangle className="w-3 h-3" />
                          BROKEN
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold text-rose-400 bg-rose-950/40 px-1.5 py-0.5 rounded border border-rose-800/40">
                          <AlertCircle className="w-3 h-3" />
                          UNAVAILABLE
                        </span>
                      )}
                    </div>
                    <p className="text-[10px] text-slate-500 leading-tight truncate">
                      {isAvailable
                        ? `v${eng.availability.version || 'unknown'} (${eng.availability.detected_path || 'PATH'})`
                        : `Executable: ${eng.executable} (missing on host PATH)`}
                    </p>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        {/* Right Column: Orchestrator Log & Live Telemetry Stream */}
        <div className="space-y-6">
          <section className="h-full rounded-lg border border-white/5 bg-[#0D0D0D] flex flex-col min-h-[460px]">
            <div className="border-b border-white/5 p-4 flex items-center justify-between">
              <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 font-mono">
                Orchestrator Log
              </h2>
              <span className="text-[10px] text-emerald-500 font-mono flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                LIVE_WS
              </span>
            </div>

            <div className="flex-1 p-4 font-mono text-[11px] leading-relaxed text-slate-400 overflow-y-auto space-y-2 max-h-[560px]">
              {liveNotifications.length === 0 ? (
                <div className="py-8 text-center text-slate-500 space-y-2">
                  <div className="text-slate-400">Gateway stream connected.</div>
                  <div className="text-[10px] text-slate-600">
                    Awaiting live pipeline telemetry and job worker events...
                  </div>
                </div>
              ) : (
                liveNotifications.map((notif) => (
                  <div key={notif.id} className="text-slate-300 border-l border-emerald-500/40 pl-2 py-0.5">
                    <span className="text-emerald-400/90 text-[10px]">[{notif.timestamp}]</span>{' '}
                    <span className="text-emerald-300 font-medium">[{notif.type}]</span>: {notif.message}
                  </div>
                ))
              )}

              <div className="mt-4 flex gap-1 items-center">
                <span className="text-emerald-500 animate-pulse font-bold">_</span>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};
