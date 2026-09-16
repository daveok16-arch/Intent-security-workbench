import React, { useState, useEffect } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { ArtifactType, ProvenanceGraph, ProvenanceNode, ProvenanceEdge } from '../types.js';
import { ProvenanceGraphFlow } from './ProvenanceGraphFlow.js';
import {
  FileCheck,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Plus,
  Key,
  GitBranch,
  Network,
  History,
  Terminal,
  Download,
  AlertTriangle,
  FolderGit2,
  Activity,
  Layers,
  Search,
} from 'lucide-react';

export const EvidenceView: React.FC = () => {
  const {
    evidence,
    investigations,
    targets,
    findings,
    verifyEvidence,
    storeEvidence,
    getProvenanceGraph,
    listInvestigationEvents,
  } = useWorkbench();

  const [activeTab, setActiveTab] = useState<'locker' | 'provenance' | 'events'>('locker');
  const [selectedArtifactId, setSelectedArtifactId] = useState<string | null>(null);
  const [selectedInvId, setSelectedInvId] = useState<string>(investigations[0]?.id || '');
  const [verificationResult, setVerificationResult] = useState<{ [id: string]: { valid: boolean; status?: string; actual_sha256?: string; expected_sha256?: string; error?: string } }>({});
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);

  // Provenance graph state
  const [graphData, setGraphData] = useState<ProvenanceGraph | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [selectedGraphNode, setSelectedGraphNode] = useState<ProvenanceNode | null>(null);

  // Events state
  const [eventsList, setEventsList] = useState<any[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);

  // Filter / Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');

  // Form for manual evidence submission
  const [invId, setInvId] = useState(investigations[0]?.id || '');
  const [artType, setArtType] = useState<ArtifactType>(ArtifactType.EXECUTION_TRACE);
  const [producer, setProducer] = useState('');
  const [producerVersion, setProducerVersion] = useState('');
  const [cmd, setCmd] = useState('');
  const [content, setContent] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Set initial selected investigation when list loads
  useEffect(() => {
    if (!selectedInvId && investigations.length > 0) {
      setSelectedInvId(investigations[0].id);
      setInvId(investigations[0].id);
    }
  }, [investigations, selectedInvId]);

  // Load provenance graph when tab is active
  useEffect(() => {
    if (activeTab === 'provenance' && selectedInvId) {
      setGraphLoading(true);
      getProvenanceGraph(selectedInvId)
        .then((res: ProvenanceGraph) => {
          setGraphData(res);
          setGraphLoading(false);
        })
        .catch(() => {
          setGraphData(null);
          setGraphLoading(false);
        });
    }
  }, [activeTab, selectedInvId, getProvenanceGraph]);

  // Load events when tab is active
  useEffect(() => {
    if (activeTab === 'events' && selectedInvId) {
      setEventsLoading(true);
      listInvestigationEvents(selectedInvId)
        .then((res: any[]) => {
          setEventsList(res);
          setEventsLoading(false);
        })
        .catch(() => {
          setEventsList([]);
          setEventsLoading(false);
        });
    }
  }, [activeTab, selectedInvId, listInvestigationEvents]);

  const filteredEvidence = evidence.filter((art) => {
    const matchesInv = !selectedInvId || art.investigation_id === selectedInvId;
    const matchesSearch =
      !searchQuery ||
      art.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      art.producer.toLowerCase().includes(searchQuery.toLowerCase()) ||
      art.sha256.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (art.command && art.command.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = typeFilter === 'ALL' || art.artifact_type === typeFilter;
    return matchesInv && matchesSearch && matchesType;
  });

  const selectedArtifact = evidence.find((e) => e.id === selectedArtifactId) || filteredEvidence[0];

  const handleVerify = async (artifactId: string) => {
    try {
      setVerifyingId(artifactId);
      const res = await verifyEvidence(artifactId);
      setVerificationResult((prev) => ({ ...prev, [artifactId]: res }));
    } catch (err: any) {
      alert('Verification failed: ' + err.message);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleManualAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!invId || !content.trim()) return;

    try {
      setSubmitting(true);
      const inv = investigations.find((i) => i.id === invId);
      await storeEvidence({
        investigation_id: invId,
        target_id: inv?.target_id,
        artifact_type: artType,
        producer: producer.trim(),
        producer_version: producerVersion.trim() || '1.0.0',
        command: cmd.trim(),
        content: content.trim(),
        path: `evidence/${Date.now()}_manual.log`,
      });
      setContent('');
      setShowAddModal(false);
    } catch (err: any) {
      alert('Failed to store artifact: ' + err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div id="evidence-view" className="space-y-6 font-mono">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold tracking-widest text-white uppercase flex items-center gap-2">
            <FileCheck className="w-4 h-4 text-emerald-500" />
            Cryptographic Evidence & Provenance Subsystem
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Immutable SHA-256 hashed artifacts, raw process execution logs, and deterministic chain-of-custody graphs.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start">
          {investigations.length > 0 && (
            <select
              value={selectedInvId}
              onChange={(e) => setSelectedInvId(e.target.value)}
              className="bg-black/60 border border-white/10 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:border-emerald-500 outline-none"
            >
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.title.length > 25 ? `${inv.title.substring(0, 25)}...` : inv.title}
                </option>
              ))}
            </select>
          )}

          <button
            onClick={() => {
              if (investigations.length > 0 && !invId) setInvId(investigations[0].id);
              setShowAddModal(true);
            }}
            disabled={investigations.length === 0}
            className="bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-semibold px-3 py-1.5 rounded flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>STORE ARTIFACT</span>
          </button>
        </div>
      </div>

      {/* Subsystem Navigation Tabs */}
      <div className="flex border-b border-white/10 text-xs">
        <button
          onClick={() => setActiveTab('locker')}
          className={`px-4 py-2 font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'locker'
              ? 'border-emerald-500 text-emerald-400 bg-white/5'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Evidence Locker ({filteredEvidence.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('provenance')}
          className={`px-4 py-2 font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'provenance'
              ? 'border-emerald-500 text-emerald-400 bg-white/5'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Provenance Graph</span>
        </button>

        <button
          onClick={() => setActiveTab('events')}
          className={`px-4 py-2 font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'events'
              ? 'border-emerald-500 text-emerald-400 bg-white/5'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <History className="w-3.5 h-3.5" />
          <span>Immutable Audit Events</span>
        </button>
      </div>

      {/* ========================================================= */}
      {/* TAB 1: EVIDENCE LOCKER */}
      {/* ========================================================= */}
      {activeTab === 'locker' && (
        <>
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row items-center gap-3 bg-[#0D0D0D] p-3 rounded-lg border border-white/5 text-xs">
            <div className="relative flex-1 w-full">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search artifacts by ID, producer, command, or SHA-256..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded pl-8 pr-3 py-1.5 text-white placeholder-slate-600 focus:border-emerald-500 outline-none text-xs"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-slate-500 text-[11px]">Type:</span>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="bg-black/40 border border-white/10 rounded px-2.5 py-1.5 text-slate-300 text-xs focus:border-emerald-500 outline-none"
              >
                <option value="ALL">All Types</option>
                <option value="ENGINE_STDOUT">Engine Stdout</option>
                <option value="ENGINE_STDERR">Engine Stderr</option>
                <option value="ENGINE_RESULT">Engine Result</option>
                <option value="EXECUTION_TRACE">Execution Trace</option>
                <option value="SOURCE">Source Snapshot</option>
                <option value="TEST_OUTPUT">Test Output</option>
              </select>
            </div>
          </div>

          {filteredEvidence.length === 0 ? (
            <div className="py-16 text-center rounded-lg border border-dashed border-white/10 bg-[#0D0D0D]">
              <FileCheck className="w-10 h-10 text-slate-600 mx-auto mb-2" />
              <p className="text-sm text-slate-400">No evidence recorded.</p>
              <p className="text-xs text-slate-600 mt-1">
                Execute engine jobs or upload reproduction logs to populate verified evidence.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Left Col: Artifact List */}
              <div className="lg:col-span-1 space-y-2">
                <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 px-1 flex justify-between items-center">
                  <span>Artifacts ({filteredEvidence.length})</span>
                  <span className="text-[9px] text-slate-600">Strict Ground Truth</span>
                </div>
                <div className="space-y-1.5 max-h-[600px] overflow-y-auto">
                  {filteredEvidence.map((art) => {
                    const isSelected = selectedArtifact?.id === art.id;
                    const vRes = verificationResult[art.id];

                    return (
                      <div
                        key={art.id}
                        onClick={() => setSelectedArtifactId(art.id)}
                        className={`p-3 rounded-lg border text-xs cursor-pointer transition ${
                          isSelected
                            ? 'bg-white/5 border-emerald-500/50 text-white'
                            : 'bg-[#0D0D0D] border-white/5 text-slate-400 hover:bg-white/5 hover:text-white'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-200 truncate">{art.producer}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-black/40 text-slate-400 border border-white/5">
                            {art.size_bytes || art.byte_size || 0} B
                          </span>
                        </div>

                        <div className="text-[10px] text-slate-500 mt-1 truncate">
                          SHA: {art.sha256.substring(0, 16)}...
                        </div>

                        <div className="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
                          <span className="text-emerald-400 font-mono text-[10px]">{art.artifact_type}</span>
                          {vRes && (
                            <span
                              className={`text-[10px] ${
                                vRes.valid ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'
                              }`}
                            >
                              {vRes.valid ? '✓ VALID' : '✗ TAMPER'}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Right 2 Cols: Selected Artifact Details & Real Hash Verification */}
              {selectedArtifact && (
                <div className="lg:col-span-2 rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-white/10 gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-500">Artifact ID:</span>
                        <span className="text-xs font-semibold text-slate-200">{selectedArtifact.id}</span>
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5">
                        Type: <span className="text-emerald-400">{selectedArtifact.artifact_type}</span> | Size:{' '}
                        <span className="text-slate-300">{selectedArtifact.size_bytes || selectedArtifact.byte_size} bytes</span> | MIME:{' '}
                        <span className="text-slate-300">{selectedArtifact.mime_type || 'text/plain'}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleVerify(selectedArtifact.id)}
                        disabled={verifyingId === selectedArtifact.id}
                        className="px-3.5 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded text-xs flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>{verifyingId === selectedArtifact.id ? 'Reading bytes...' : 'Verify Cryptographic SHA-256'}</span>
                      </button>
                    </div>
                  </div>

                  {/* SHA-256 Provenance Box */}
                  <div className="bg-black/30 p-3.5 rounded border border-white/5 space-y-2 text-xs">
                    <div className="text-slate-400 text-[11px]">
                      <span className="text-slate-500 uppercase tracking-wider text-[10px] font-bold">
                        Calculated SHA-256 Byte Digest:
                      </span>
                      <div className="mt-1 bg-black p-2.5 rounded text-emerald-400 font-mono text-[11px] break-all border border-white/10">
                        {selectedArtifact.sha256}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                      <div>
                        <span className="text-slate-500">Producer Tool:</span>
                        <span className="text-slate-300 ml-1">
                          {selectedArtifact.producer} (v{selectedArtifact.producer_version || '1.0.0'})
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Storage Path:</span>
                        <span className="text-slate-300 ml-1 truncate font-mono text-[10px]">
                          {selectedArtifact.path || selectedArtifact.path_or_reference}
                        </span>
                      </div>
                    </div>

                    {selectedArtifact.command && (
                      <div className="text-[11px] pt-1">
                        <span className="text-slate-500">Executed Command:</span>
                        <div className="mt-0.5 bg-black p-2 rounded text-sky-300 font-mono text-[10px] border border-white/5 break-all">
                          {selectedArtifact.command}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Verification Status Banner */}
                  {verificationResult[selectedArtifact.id] && (
                    <div
                      className={`p-3 rounded border text-xs flex items-center gap-2 ${
                        verificationResult[selectedArtifact.id].valid
                          ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                          : 'bg-rose-950/60 border-rose-800 text-rose-300'
                      }`}
                    >
                      {verificationResult[selectedArtifact.id].valid ? (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                          <div>
                            <div className="font-semibold">Cryptographic Integrity PASSED</div>
                            <div className="text-[10px] opacity-80">
                              Actual file bytes on disk produce exact matching SHA-256 hash. Zero tampering.
                            </div>
                          </div>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                          <div>
                            <div className="font-semibold">INTEGRITY COMPROMISED / TAMPER DETECTED</div>
                            <div className="text-[10px] opacity-80">
                              Calculated byte digest on storage does not match recorded signature.
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  )}

                  {/* Raw Payload Preview */}
                  <div className="space-y-1.5">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center justify-between">
                      <span>Artifact Content Preview</span>
                      <a
                        href={`/api/evidence/${selectedArtifact.id}/download`}
                        download
                        className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 text-[10px]"
                      >
                        <Download className="w-3 h-3" />
                        <span>Download Raw File</span>
                      </a>
                    </div>
                    <div className="bg-black rounded border border-white/10 p-3.5 h-48 overflow-y-auto font-mono text-[11px] text-slate-300 whitespace-pre-wrap">
                      {selectedArtifact.content_preview || 'No content preview stored.'}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ========================================================= */}
      {/* TAB 2: PROVENANCE GRAPH */}
      {/* ========================================================= */}
      {activeTab === 'provenance' && (
        <div className="space-y-4">
          <div className="bg-[#0D0D0D] p-4 rounded-lg border border-white/10">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xs font-bold uppercase tracking-widest text-slate-200 flex items-center gap-2">
                  <Network className="w-4 h-4 text-emerald-500" />
                  Investigation Provenance Graph
                </h2>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Visual relationship network connecting Investigation, Target, Source Snapshots, Analysis Jobs, Engines, Audit Events, Artifacts, and Findings.
                </p>
              </div>

              {graphData && (
                <div className="text-[10px] text-slate-500">
                  Nodes: <span className="text-emerald-400">{graphData.nodes.length}</span> | Edges:{' '}
                  <span className="text-emerald-400">{graphData.edges.length}</span>
                </div>
              )}
            </div>

            {graphLoading ? (
              <div className="py-20 text-center text-slate-500 text-xs">Loading provenance topology...</div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Visual Graph Panel (React Flow) */}
                <div className="lg:col-span-2">
                  <ProvenanceGraphFlow
                    graph={graphData}
                    onNodeSelect={setSelectedGraphNode}
                    selectedNodeId={selectedGraphNode?.id || null}
                  />

                  {graphData && graphData.edges.length > 0 && (
                    <div className="mt-3 p-3 bg-black rounded border border-white/10">
                      <div className="text-[9px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">
                        Recorded Directed Relationships ({graphData.edges.length})
                      </div>
                      <div className="space-y-1 max-h-24 overflow-y-auto text-[10px] text-slate-400 font-mono">
                        {graphData.edges.map((edge) => (
                          <div key={edge.id} className="flex items-center gap-2">
                            <span className="text-slate-300 truncate max-w-[140px]">{edge.source}</span>
                            <span className="text-emerald-500">--[{edge.relationship}]--&gt;</span>
                            <span className="text-slate-300 truncate max-w-[140px]">{edge.target}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Node Inspector Drawer */}
                <div className="bg-[#111] rounded border border-white/10 p-4 space-y-3">
                  <div className="text-xs font-bold uppercase tracking-widest text-slate-300 border-b border-white/10 pb-2">
                    Node Inspector
                  </div>

                  {selectedGraphNode ? (
                    <div className="space-y-3 text-xs">
                      <div>
                        <span className="text-slate-500 text-[10px]">Type:</span>
                        <div className="text-emerald-400 font-semibold">{selectedGraphNode.type}</div>
                      </div>
                      <div>
                        <span className="text-slate-500 text-[10px]">Node ID:</span>
                        <div className="text-slate-200 break-all font-mono text-[11px]">{selectedGraphNode.id}</div>
                      </div>
                      <div>
                        <span className="text-slate-500 text-[10px]">Label:</span>
                        <div className="text-slate-200">{selectedGraphNode.label}</div>
                      </div>

                      <div className="pt-2 border-t border-white/10">
                        <span className="text-slate-500 text-[10px] uppercase font-bold">Node Metadata:</span>
                        <pre className="mt-1 bg-black p-2 rounded text-[10px] text-slate-300 overflow-x-auto border border-white/5">
                          {JSON.stringify(selectedGraphNode.data, null, 2)}
                        </pre>
                      </div>
                    </div>
                  ) : (
                    <div className="py-12 text-center text-slate-600 text-xs">
                      Click any node in the graph to inspect metadata and provenance connections.
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================= */}
      {/* TAB 3: IMMUTABLE AUDIT EVENTS */}
      {/* ========================================================= */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          <div className="bg-[#0D0D0D] p-4 rounded-lg border border-white/10">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xs font-bold uppercase tracking-widest text-slate-200 flex items-center gap-2">
                  <History className="w-4 h-4 text-emerald-500" />
                  Append-Only Audit Trail
                </h2>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Non-repudiable log of system operations, engine dispatches, and artifact creations.
                </p>
              </div>
            </div>

            {eventsLoading ? (
              <div className="py-20 text-center text-slate-500 text-xs">Loading event audit log...</div>
            ) : eventsList.length === 0 ? (
              <div className="py-16 text-center text-slate-500 text-xs">
                No audit events recorded for this investigation yet.
              </div>
            ) : (
              <div className="space-y-2">
                {eventsList.map((ev) => (
                  <div
                    key={ev.id}
                    className="p-3 bg-black/40 border border-white/5 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-emerald-400 font-bold">{ev.event_type}</span>
                        <span className="text-slate-600">|</span>
                        <span className="text-slate-300 font-semibold">{ev.producer}</span>
                        <span className="text-slate-500 text-[10px]">(v{ev.producer_version})</span>
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        Actor: <span className="text-slate-400">{ev.actor}</span> | Event ID:{' '}
                        <span className="font-mono text-slate-400">{ev.id}</span>
                      </div>
                    </div>

                    <div className="text-[11px] text-slate-500 shrink-0 font-mono">
                      {new Date(ev.timestamp).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modal: Upload Proof Artifact */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 font-mono">
          <div className="bg-[#0D0D0D] border border-white/10 rounded-lg p-6 w-full max-w-lg space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                <Key className="w-4 h-4 text-emerald-500" />
                Store Evidence Artifact
              </h2>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-500 hover:text-white cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleManualAdd} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Investigation *</label>
                <select
                  value={invId}
                  onChange={(e) => setInvId(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                >
                  {investigations.map((i) => (
                    <option key={i.id} value={i.id}>
                      {i.title}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Artifact Type</label>
                  <select
                    value={artType}
                    onChange={(e) => setArtType(e.target.value as ArtifactType)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  >
                    <option value={ArtifactType.EXECUTION_TRACE}>Execution Trace</option>
                    <option value={ArtifactType.ENGINE_STDOUT}>Engine Stdout</option>
                    <option value={ArtifactType.ENGINE_STDERR}>Engine Stderr</option>
                    <option value={ArtifactType.TEST_OUTPUT}>Test Output</option>
                    <option value={ArtifactType.SOURCE}>Source Snapshot</option>
                    <option value={ArtifactType.REPORT}>Report / Audit File</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Producer Engine / Tool</label>
                  <input
                    type="text"
                    value={producer}
                    onChange={(e) => setProducer(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Producer Version</label>
                  <input
                    type="text"
                    value={producerVersion}
                    onChange={(e) => setProducerVersion(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Command Executed</label>
                  <input
                    type="text"
                    value={cmd}
                    onChange={(e) => setCmd(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Raw Payload / Test Log Output *</label>
                <textarea
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  placeholder="Paste raw execution output or reproduction script..."
                  rows={4}
                  className="w-full bg-black/40 border border-white/10 rounded px-3 py-1.5 text-white focus:border-emerald-500 outline-none"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded border border-white/10 bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-3.5 py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-black font-semibold disabled:opacity-50 cursor-pointer"
                >
                  {submitting ? 'Writing to disk & hashing...' : 'Write & Compute SHA-256'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
