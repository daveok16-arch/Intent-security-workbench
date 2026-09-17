import React from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { TabType } from '../types.js';
import {
  LayoutDashboard,
  FolderLock,
  Crosshair,
  Search,
  ListTodo,
  FileCheck,
  AlertTriangle,
  Cpu,
  Settings,
  ShieldCheck,
  FolderGit2,
  Network,
  Bot,
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const { activeTab, setActiveTab, programs, targets, investigations, jobs, evidence, findings, engines, systemStatus } = useWorkbench();

  const coreNav: { id: TabType; label: string; icon: React.FC<{ className?: string }>; count?: number }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'ai_controller', label: 'AI Control Plane', icon: Bot },
    { id: 'programs', label: 'Programs', icon: FolderLock, count: programs.length },
    { id: 'scope', label: 'Scope Rules', icon: ShieldCheck },
    { id: 'targets', label: 'Targets', icon: Crosshair, count: targets.length },
    { id: 'source_snapshots', label: 'Source Snapshots', icon: FolderGit2 },
    { id: 'investigations', label: 'Investigations', icon: Search, count: investigations.length },
    { id: 'api_security', label: 'API Security', icon: Network },
    { id: 'jobs', label: 'Job Orchestrator', icon: ListTodo, count: jobs.length },
  ];

  const artifactNav: { id: TabType; label: string; icon: React.FC<{ className?: string }>; count?: number }[] = [
    { id: 'evidence', label: 'Evidence Archive', icon: FileCheck, count: evidence.length },
    { id: 'findings', label: 'Finding Registry', icon: AlertTriangle, count: findings.length },
  ];

  const systemNav: { id: TabType; label: string; icon: React.FC<{ className?: string }> }[] = [
    { id: 'engines', label: 'Engine Registry', icon: Cpu },
    { id: 'settings', label: 'Sandbox Policy', icon: Settings },
  ];

  const runningJobCount = jobs.filter(j => j.status === 'RUNNING').length;
  const queuedJobCount = jobs.filter(j => j.status === 'QUEUED').length;

  return (
    <nav id="app-sidebar" className="w-56 border-r border-white/10 bg-[#0D0D0D] p-4 flex flex-col gap-1 select-none shrink-0 overflow-y-auto">
      <div className="mb-2 px-2 text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 font-mono">
        Core Workbench
      </div>
      <div className="space-y-1">
        {coreNav.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              id={`nav-item-${item.id}`}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between gap-3 rounded-md px-3 py-2 text-xs transition text-left cursor-pointer ${
                isActive
                  ? 'bg-white/5 text-white font-medium shadow-inner'
                  : 'text-slate-400 hover:bg-white/5 hover:text-white'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`h-4 w-4 ${isActive ? 'text-emerald-500' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.count !== undefined && item.count > 0 && (
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                  isActive ? 'bg-emerald-500/20 text-emerald-300' : 'bg-black/40 text-slate-400'
                }`}>
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="my-3 px-2 text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 font-mono">
        Artifacts
      </div>
      <div className="space-y-1">
        {artifactNav.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              id={`nav-item-${item.id}`}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between gap-3 rounded-md px-3 py-2 text-xs transition text-left cursor-pointer ${
                isActive
                  ? 'bg-white/5 text-white font-medium'
                  : 'text-slate-400 hover:bg-white/5 hover:text-white'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`h-4 w-4 ${isActive ? 'text-emerald-500' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.count !== undefined && item.count > 0 && (
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                  isActive ? 'bg-emerald-500/20 text-emerald-300' : 'bg-black/40 text-slate-400'
                }`}>
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="my-3 px-2 text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 font-mono">
        Engines & Control
      </div>
      <div className="space-y-1">
        {systemNav.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              id={`nav-item-${item.id}`}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 rounded-md px-3 py-2 text-xs transition text-left cursor-pointer ${
                isActive
                  ? 'bg-white/5 text-white font-medium'
                  : 'text-slate-400 hover:bg-white/5 hover:text-white'
              }`}
            >
              <Icon className={`h-4 w-4 ${isActive ? 'text-emerald-500' : 'text-slate-400'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>

      {/* Bottom telemetry card. Reports real job counts: a "load" percentage
          derived from running/total-ever-created jobs was neither load nor
          meaningful, and clamping it to a 50% floor invented utilisation. */}
      <div className="mt-auto pt-4">
        <div className="rounded bg-black/40 border border-white/5 p-2.5 font-mono">
          <div className="flex justify-between text-[10px] font-bold uppercase text-slate-500">
            <span>Job Queue</span>
            <span className={runningJobCount > 0 ? 'text-emerald-400' : 'text-slate-400'}>
              {runningJobCount} Running / {queuedJobCount} Queued
            </span>
          </div>
          <div className="mt-1.5 h-1 w-full bg-black rounded-full overflow-hidden">
            <div
              className="h-1 bg-emerald-500 transition-all duration-300 rounded-full"
              style={{ width: `${runningJobCount > 0 ? 100 : 0}%` }}
            />
          </div>
        </div>
      </div>
    </nav>
  );
};
