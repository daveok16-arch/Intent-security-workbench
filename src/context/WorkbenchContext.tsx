/**
 * Workbench Context & Real-Time WebSocket Client
 * Phase 0 Foundational Architecture
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import {
  Program, Target, Investigation, AnalysisJob, EvidenceArtifact, Finding,
  EngineItem, SystemStatus, TabType, FindingStatus, InvestigationStatus, SourceAcquisitionStatus
} from '../types.js';

interface WorkbenchContextType {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  selectedInvestigationId: string | null;
  setSelectedInvestigationId: (id: string | null) => void;
  
  programs: Program[];
  targets: Target[];
  investigations: Investigation[];
  jobs: AnalysisJob[];
  evidence: EvidenceArtifact[];
  findings: Finding[];
  engines: EngineItem[];
  systemStatus: SystemStatus | null;
  wsConnected: boolean;
  liveNotifications: { id: string; type: string; message: string; timestamp: string }[];
  
  loading: boolean;
  error: string | null;
  
  // Actions
  refreshAll: () => Promise<void>;
  createProgram: (data: any) => Promise<Program>;
  deleteProgram: (id: string) => Promise<void>;
  createTarget: (data: any) => Promise<Target>;
  updateTargetSourceStatus: (id: string, status: SourceAcquisitionStatus, hash?: string) => Promise<void>;
  deleteTarget: (id: string) => Promise<void>;
  createInvestigation: (data: any) => Promise<Investigation>;
  updateInvestigationStatus: (id: string, status: InvestigationStatus) => Promise<void>;
  deleteInvestigation: (id: string) => Promise<void>;
  createJob: (data: any) => Promise<AnalysisJob>;
  runJob: (id: string) => Promise<void>;
  cancelJob: (id: string) => Promise<void>;
  storeEvidence: (data: any) => Promise<EvidenceArtifact>;
  verifyEvidence: (id: string) => Promise<any>;
  createFinding: (data: any) => Promise<Finding>;
  transitionFinding: (id: string, targetStatus: FindingStatus, reason: string) => Promise<Finding>;
  linkEvidenceToFinding: (findingId: string, evidenceId: string) => Promise<void>;
  checkEngine: (engineId: string) => Promise<any>;
  checkAllEngines: () => Promise<any>;
  getProvenanceGraph: (investigationId: string) => Promise<any>;
  getFindingProvenance: (findingId: string) => Promise<any>;
  listInvestigationEvents: (investigationId: string) => Promise<any>;
  evaluateTargetScope: (targetId: string) => Promise<any>;
  acquireTargetSource: (targetId: string, options?: any) => Promise<any>;
  verifyTargetSource: (targetId: string) => Promise<any>;
  evaluateInvestigationGate: (investigationId: string) => Promise<any>;
}

const WorkbenchContext = createContext<WorkbenchContextType | undefined>(undefined);

export const WorkbenchProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string | null>(null);

  const [programs, setPrograms] = useState<Program[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [evidence, setEvidence] = useState<EvidenceArtifact[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [engines, setEngines] = useState<EngineItem[]>([]);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [liveNotifications, setLiveNotifications] = useState<{ id: string; type: string; message: string; timestamp: string }[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const addNotification = useCallback((type: string, message: string) => {
    const id = `notif-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    setLiveNotifications(prev => [{ id, type, message, timestamp: new Date().toLocaleTimeString() }, ...prev.slice(0, 24)]);
  }, []);

  const refreshAll = useCallback(async () => {
    try {
      setLoading(true);
      const [progRes, tgtRes, invRes, jobsRes, evRes, fndRes, engRes, statRes] = await Promise.all([
        fetch('/api/programs').then(r => r.json()),
        fetch('/api/targets').then(r => r.json()),
        fetch('/api/investigations').then(r => r.json()),
        fetch('/api/jobs').then(r => r.json()),
        fetch('/api/evidence').then(r => r.json()),
        fetch('/api/findings').then(r => r.json()),
        fetch('/api/engines').then(r => r.json()),
        fetch('/api/system/status').then(r => r.json()),
      ]);

      if (Array.isArray(progRes)) setPrograms(progRes);
      if (Array.isArray(tgtRes)) setTargets(tgtRes);
      if (Array.isArray(invRes)) setInvestigations(invRes);
      if (Array.isArray(jobsRes)) setJobs(jobsRes);
      if (Array.isArray(evRes)) setEvidence(evRes);
      if (Array.isArray(fndRes)) setFindings(fndRes);
      if (Array.isArray(engRes)) setEngines(engRes);
      if (statRes && typeof statRes === 'object') setSystemStatus(statRes);

      setError(null);
    } catch (err: any) {
      console.error('Failed to load workbench state:', err);
      setError('Failed to connect to backend server. Make sure server is running.');
    } finally {
      setLoading(false);
    }
  }, []);

  // WebSocket Connection
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    let socket: WebSocket | null = null;
    let reconnectTimeout: any = null;

    function connect() {
      try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
          setWsConnected(true);
          addNotification('SYSTEM', 'Real-time WebSocket event stream connected.');
        };

        socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'job_created' || data.type === 'job_queued') {
              addNotification('JOB_QUEUED', `Job ${data.payload.job.id} queued for engine ${data.payload.job.engine}`);
              refreshAll();
            } else if (data.type === 'job_started') {
              addNotification('JOB_STARTED', `Job ${data.payload.job.id} execution started on worker.`);
              refreshAll();
            } else if (data.type === 'job_completed') {
              addNotification('JOB_COMPLETED', `Job ${data.payload.job.id} finished with exit code 0.`);
              refreshAll();
            } else if (data.type === 'job_failed') {
              addNotification('JOB_FAILED', `Job ${data.payload.job.id} failed: ${data.payload.job.error || 'error'}`);
              refreshAll();
            } else if (data.type === 'evidence_created') {
              addNotification('EVIDENCE_LOCKER', `New artifact stored: SHA-256 ${data.payload.sha256.substring(0, 12)}...`);
              refreshAll();
            } else if (data.type === 'finding_updated' || data.type === 'finding_created') {
              addNotification('FINDING_STATE', `Finding ${data.payload.title} state: ${data.payload.status}`);
              refreshAll();
            } else if (data.type === 'investigation_status_changed') {
              addNotification('INVESTIGATION', `Investigation status updated: ${data.payload.status}`);
              refreshAll();
            }
          } catch {
            // malformed
          }
        };

        socket.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connect, 3000);
        };

        socket.onerror = () => {
          setWsConnected(false);
        };
      } catch {
        reconnectTimeout = setTimeout(connect, 3000);
      }
    }

    connect();
    refreshAll();

    return () => {
      if (socket) socket.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, [refreshAll, addNotification]);

  // Actions
  const createProgram = async (data: any): Promise<Program> => {
    const res = await fetch('/api/programs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to create program');
    }
    const prog = await res.json();
    await refreshAll();
    return prog;
  };

  const deleteProgram = async (id: string) => {
    const res = await fetch(`/api/programs/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete program');
    await refreshAll();
  };

  const createTarget = async (data: any): Promise<Target> => {
    const res = await fetch('/api/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to create target');
    }
    const tgt = await res.json();
    await refreshAll();
    return tgt;
  };

  const updateTargetSourceStatus = async (id: string, status: SourceAcquisitionStatus, hash?: string) => {
    const res = await fetch(`/api/targets/${id}/source-status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, source_hash: hash }),
    });
    if (!res.ok) throw new Error('Failed to update target source status');
    await refreshAll();
  };

  const deleteTarget = async (id: string) => {
    const res = await fetch(`/api/targets/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete target');
    await refreshAll();
  };

  const createInvestigation = async (data: any): Promise<Investigation> => {
    const res = await fetch('/api/investigations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to create investigation');
    }
    const inv = await res.json();
    await refreshAll();
    return inv;
  };

  const updateInvestigationStatus = async (id: string, status: InvestigationStatus) => {
    const res = await fetch(`/api/investigations/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error('Failed to update investigation status');
    await refreshAll();
  };

  const deleteInvestigation = async (id: string) => {
    const res = await fetch(`/api/investigations/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete investigation');
    await refreshAll();
  };

  const createJob = async (data: any): Promise<AnalysisJob> => {
    const res = await fetch('/api/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to create job');
    }
    const job = await res.json();
    await refreshAll();
    return job;
  };

  const runJob = async (id: string) => {
    const res = await fetch(`/api/jobs/${id}/run`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to trigger job execution');
    }
    await refreshAll();
  };

  const cancelJob = async (id: string) => {
    const res = await fetch(`/api/jobs/${id}/cancel`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to cancel job');
    }
    await refreshAll();
  };

  const storeEvidence = async (data: any): Promise<EvidenceArtifact> => {
    const res = await fetch('/api/evidence', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to store evidence');
    }
    const art = await res.json();
    await refreshAll();
    return art;
  };

  const verifyEvidence = async (id: string) => {
    const res = await fetch(`/api/v1/evidence/${id}/integrity`);
    if (!res.ok) throw new Error('Verification failed');
    return await res.json();
  };

  const getProvenanceGraph = async (investigationId: string) => {
    const res = await fetch(`/api/v1/investigations/${investigationId}/provenance`);
    if (!res.ok) throw new Error('Failed to load provenance graph');
    return await res.json();
  };

  const getFindingProvenance = async (findingId: string) => {
    const res = await fetch(`/api/v1/findings/${findingId}/provenance`);
    if (!res.ok) throw new Error('Failed to load finding provenance chain');
    return await res.json();
  };

  const listInvestigationEvents = async (investigationId: string) => {
    const res = await fetch(`/api/v1/investigations/${investigationId}/events`);
    if (!res.ok) throw new Error('Failed to load events');
    return await res.json();
  };

  const createFinding = async (data: any): Promise<Finding> => {
    const res = await fetch('/api/findings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to create candidate finding');
    }
    const fnd = await res.json();
    await refreshAll();
    return fnd;
  };

  const transitionFinding = async (id: string, targetStatus: FindingStatus, reason: string): Promise<Finding> => {
    const res = await fetch(`/api/findings/${id}/transition`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_status: targetStatus, reason }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'State machine transition rejected');
    }
    const fnd = await res.json();
    await refreshAll();
    return fnd;
  };

  const linkEvidenceToFinding = async (findingId: string, evidenceId: string) => {
    const res = await fetch(`/api/findings/${findingId}/link-evidence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ evidence_id: evidenceId }),
    });
    if (!res.ok) throw new Error('Failed to link evidence to finding');
    await refreshAll();
  };

  const checkEngine = async (engineId: string) => {
    const res = await fetch(`/api/v1/engines/${engineId}/check`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`Failed to check engine ${engineId}`);
    const data = await res.json();
    await refreshAll();
    return data;
  };

  const checkAllEngines = async () => {
    const res = await fetch('/api/v1/engines/check', {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to check all engines');
    const data = await res.json();
    await refreshAll();
    return data;
  };

  const evaluateTargetScope = async (targetId: string) => {
    const res = await fetch(`/api/v1/targets/${targetId}/scope/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to evaluate scope');
    }
    const data = await res.json();
    await refreshAll();
    return data;
  };

  const acquireTargetSource = async (targetId: string, options?: any) => {
    const res = await fetch(`/api/v1/targets/${targetId}/source/acquire`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options || {}),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to acquire source repository');
    }
    const data = await res.json();
    await refreshAll();
    return data;
  };

  const verifyTargetSource = async (targetId: string) => {
    const res = await fetch(`/api/v1/targets/${targetId}/source/verify`);
    if (!res.ok) throw new Error('Failed to verify source integrity');
    return await res.json();
  };

  const evaluateInvestigationGate = async (investigationId: string) => {
    const res = await fetch(`/api/v1/investigations/${investigationId}/gate`);
    if (!res.ok) throw new Error('Failed to evaluate investigation pre-flight gate');
    return await res.json();
  };

  return (
    <WorkbenchContext.Provider
      value={{
        activeTab,
        setActiveTab,
        selectedInvestigationId,
        setSelectedInvestigationId,
        programs,
        targets,
        investigations,
        jobs,
        evidence,
        findings,
        engines,
        systemStatus,
        wsConnected,
        liveNotifications,
        loading,
        error,
        refreshAll,
        createProgram,
        deleteProgram,
        createTarget,
        updateTargetSourceStatus,
        deleteTarget,
        createInvestigation,
        updateInvestigationStatus,
        deleteInvestigation,
        createJob,
        runJob,
        cancelJob,
        storeEvidence,
        verifyEvidence,
        createFinding,
        transitionFinding,
        linkEvidenceToFinding,
        checkEngine,
        checkAllEngines,
        getProvenanceGraph,
        getFindingProvenance,
        listInvestigationEvents,
        evaluateTargetScope,
        acquireTargetSource,
        verifyTargetSource,
        evaluateInvestigationGate,
      }}
    >
      {children}
    </WorkbenchContext.Provider>
  );
};

export const useWorkbench = () => {
  const context = useContext(WorkbenchContext);
  if (!context) throw new Error('useWorkbench must be used within a WorkbenchProvider');
  return context;
};
