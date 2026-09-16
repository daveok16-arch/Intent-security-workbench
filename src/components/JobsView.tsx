import React, { useState, useEffect } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { JobStatus } from '../types.js';
import { ListTodo, Play, XCircle, RefreshCw, Terminal } from 'lucide-react';

export const JobsView: React.FC = () => {
  const { jobs, investigations, targets, runJob, cancelJob } = useWorkbench();
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [jobLogs, setJobLogs] = useState<{ id: string; timestamp: string; level: string; message: string }[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);

  const selectedJob = jobs.find(j => j.id === selectedJobId) || jobs[0];

  useEffect(() => {
    if (selectedJob) {
      fetchLogs(selectedJob.id);
    }
  }, [selectedJob?.id]);

  const fetchLogs = async (jobId: string) => {
    try {
      setLoadingLogs(true);
      const res = await fetch(`/api/jobs/${jobId}/logs`);
      if (res.ok) {
        const logs = await res.json();
        setJobLogs(logs);
      }
    } catch {
      // ignore
    } finally {
      setLoadingLogs(false);
    }
  };

  return (
    <div id="jobs-view" className="space-y-6 font-mono">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase flex items-center gap-2">
            <ListTodo className="w-4 h-4 text-emerald-500" />
            Background Job Orchestrator
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Asynchronous task queue with persistent stdout/stderr evidence capture, retry policies, and execution timestamps.
          </p>
        </div>
      </div>

      {jobs.length === 0 ? (
        <div className="py-16 text-center rounded-lg border border-dashed border-white/10 bg-[#0D0D0D]">
          <ListTodo className="w-10 h-10 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-400">No background jobs queued.</p>
          <p className="text-xs text-slate-600 mt-1">
            Dispatch analysis jobs from active investigations to run verified tools.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Left Col: Job List */}
          <div className="lg:col-span-1 space-y-2">
            <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 px-1">
              Job Queue ({jobs.length})
            </div>
            <div className="space-y-1.5 max-h-[600px] overflow-y-auto">
              {jobs.map((job) => {
                const isSelected = selectedJob?.id === job.id;

                return (
                  <div
                    key={job.id}
                    onClick={() => {
                      setSelectedJobId(job.id);
                      fetchLogs(job.id);
                    }}
                    className={`p-3 rounded-lg border text-xs cursor-pointer transition ${
                      isSelected
                        ? 'bg-white/5 border-emerald-500/50 text-white'
                        : 'bg-[#0D0D0D] border-white/5 text-slate-400 hover:bg-white/5 hover:text-white'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-200 truncate">{job.engine}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold ${
                        job.status === JobStatus.COMPLETED ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60' :
                        job.status === JobStatus.RUNNING ? 'bg-sky-950/80 text-sky-400 animate-pulse border border-sky-800/60' :
                        job.status === JobStatus.FAILED ? 'bg-rose-950/80 text-rose-400 border border-rose-800/60' :
                        'bg-black/40 text-slate-400 border border-white/10'
                      }`}>
                        {job.status}
                      </span>
                    </div>

                    <div className="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
                      <span className="truncate">Op: {job.operation}</span>
                      <span>{new Date(job.created_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right 2 Cols: Job Details & Real Live Logs */}
          {selectedJob && (
            <div className="lg:col-span-2 rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-white/10 gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">Job ID:</span>
                    <span className="text-xs font-semibold text-slate-200">{selectedJob.id}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    Engine: <span className="text-emerald-400">{selectedJob.engine}</span> | Op: <span className="text-slate-300">{selectedJob.operation}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {selectedJob.status === JobStatus.QUEUED && (
                    <button
                      onClick={() => runJob(selectedJob.id)}
                      className="px-3 py-1 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded text-xs flex items-center gap-1.5 transition cursor-pointer"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Execute</span>
                    </button>
                  )}
                  {selectedJob.status === JobStatus.RUNNING && (
                    <button
                      onClick={() => cancelJob(selectedJob.id)}
                      className="px-3 py-1 bg-rose-900/80 hover:bg-rose-800 text-rose-200 rounded text-xs flex items-center gap-1.5 transition border border-rose-700 cursor-pointer"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Cancel</span>
                    </button>
                  )}
                  <button
                    onClick={() => fetchLogs(selectedJob.id)}
                    className="p-1 text-slate-500 hover:text-slate-200 transition cursor-pointer"
                    title="Refresh Logs"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${loadingLogs ? 'animate-spin text-emerald-400' : ''}`} />
                  </button>
                </div>
              </div>

              {/* Execution telemetry */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                <div className="bg-black/30 p-2.5 rounded border border-white/5">
                  <span className="text-slate-500 text-[10px] block">Status</span>
                  <span className="font-semibold text-slate-200">{selectedJob.status}</span>
                </div>
                <div className="bg-black/30 p-2.5 rounded border border-white/5">
                  <span className="text-slate-500 text-[10px] block">Exit Code</span>
                  <span className={selectedJob.exit_code === 0 ? 'text-emerald-400 font-semibold' : 'text-slate-300'}>
                    {selectedJob.exit_code !== undefined ? selectedJob.exit_code : 'N/A'}
                  </span>
                </div>
                <div className="bg-black/30 p-2.5 rounded border border-white/5">
                  <span className="text-slate-500 text-[10px] block">Retries</span>
                  <span className="text-slate-300">{selectedJob.retry_count} / {selectedJob.max_retries}</span>
                </div>
                <div className="bg-black/30 p-2.5 rounded border border-white/5">
                  <span className="text-slate-500 text-[10px] block">Evidence Output</span>
                  <span className="text-emerald-400 text-[10px] truncate block">
                    {selectedJob.stdout_artifact_id || 'None'}
                  </span>
                </div>
              </div>

              {selectedJob.error && (
                <div className="p-3 bg-rose-950/60 border border-rose-800 rounded text-xs text-rose-300">
                  <span className="font-semibold">Execution Failure:</span> {selectedJob.error}
                </div>
              )}

              {/* Console Output Log Box */}
              <div className="space-y-1.5">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-500" />
                  <span>Execution Standard Stream Log</span>
                </div>
                <div className="bg-black rounded border border-white/10 p-3.5 h-64 overflow-y-auto font-mono text-[11px] text-slate-300 space-y-1">
                  {jobLogs.length === 0 ? (
                    <div className="text-slate-600 italic py-4 text-center">No logs emitted for this job.</div>
                  ) : (
                    jobLogs.map((log) => (
                      <div key={log.id} className="flex items-start gap-2 leading-relaxed">
                        <span className="text-slate-600 text-[10px] shrink-0">[{log.timestamp}]</span>
                        <span className={`text-[10px] px-1 rounded shrink-0 ${
                          log.level === 'ERROR' ? 'bg-rose-950 text-rose-400' :
                          log.level === 'WARN' ? 'bg-amber-950 text-amber-400' : 'bg-white/10 text-slate-400'
                        }`}>
                          {log.level}
                        </span>
                        <span className="break-all text-slate-300">{log.message}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
