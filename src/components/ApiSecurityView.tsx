/**
 * API Security & Authorization Analysis View
 * Intent Security Workbench - Phase 3
 *
 * Dedicated workspace for:
 * - OpenAPI Contract inspection
 * - Spectral CLI linting results
 * - Object-Level Authorization (BOLA/IDOR) candidate ledger
 * - Interactive BOLA Reasoning Chain visualizer
 * - Contract <-> Source Differential (Shadow APIs, mismatches)
 * - Verifiable evidence and provenance artifacts
 */

import React, { useState, useEffect } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import {
  APIContract,
  APIEndpoint,
  AuthorizationCandidate,
  ContractDiffResult,
  ContractDiffStatus,
  EndpointAuthStatus,
  ParameterIdentifierRole,
} from '../types.js';
import {
  Network,
  ShieldAlert,
  ShieldCheck,
  FileCode,
  Layers,
  ArrowRightLeft,
  FileCheck,
  AlertTriangle,
  Play,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Key,
  Database,
  ArrowRight,
  Info,
  Filter,
  ExternalLink,
} from 'lucide-react';

export const ApiSecurityView: React.FC = () => {
  const { investigations, selectedInvestigationId, setSelectedInvestigationId } = useWorkbench();

  const [activeSubTab, setActiveSubTab] = useState<
    'overview' | 'endpoints' | 'auth' | 'authorization' | 'issues' | 'diff' | 'evidence'
  >('overview');

  const [contracts, setContracts] = useState<APIContract[]>([]);
  const [selectedContract, setSelectedContract] = useState<APIContract | null>(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState<APIEndpoint | null>(null);
  const [authCandidates, setAuthCandidates] = useState<AuthorizationCandidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<AuthorizationCandidate | null>(null);
  const [contractDiff, setContractDiff] = useState<ContractDiffResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [runningAnalysis, setRunningAnalysis] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [methodFilter, setMethodFilter] = useState<string>('ALL');
  const [authFilter, setAuthFilter] = useState<string>('ALL');

  const currentInvestigationId = selectedInvestigationId || (investigations[0]?.id ?? '');

  const loadData = async (invId: string) => {
    if (!invId) return;
    setLoading(true);
    try {
      // 1. Fetch Contracts
      const resContracts = await fetch(`/api/v1/investigations/${invId}/api-contracts`);
      if (resContracts.ok) {
        const cData: APIContract[] = await resContracts.json();
        setContracts(cData);
        if (cData.length > 0) {
          setSelectedContract(cData[0]);
        } else {
          setSelectedContract(null);
        }
      }

      // 2. Fetch Authorization Candidates
      const resAuth = await fetch(`/api/v1/investigations/${invId}/authorization-candidates`);
      if (resAuth.ok) {
        const aData: AuthorizationCandidate[] = await resAuth.json();
        setAuthCandidates(aData);
        if (aData.length > 0) {
          setSelectedCandidate(aData[0]);
        } else {
          setSelectedCandidate(null);
        }
      }

      // 3. Fetch Contract Diff
      const resDiff = await fetch(`/api/v1/investigations/${invId}/contract-diff`);
      if (resDiff.ok) {
        const dData: ContractDiffResult = await resDiff.json();
        setContractDiff(dData);
      } else {
        setContractDiff(null);
      }
    } catch (err: any) {
      console.error('Failed loading API Security data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (currentInvestigationId) {
      loadData(currentInvestigationId);
    }
  }, [currentInvestigationId]);

  const handleRunAnalysis = async () => {
    if (!currentInvestigationId) return;
    setRunningAnalysis(true);
    setStatusMessage('Executing API Contract & Authorization Analysis pipeline...');
    try {
      const res = await fetch(`/api/v1/investigations/${currentInvestigationId}/analysis/api`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      const data = await res.json();
      if (!res.ok) {
        if (data.status === 'API_SPEC_NOT_FOUND' || data.error === 'API_SPEC_NOT_FOUND') {
          setStatusMessage('Notice: API_SPEC_NOT_FOUND. No OpenAPI specification was discovered in target repository. No synthetic data was generated.');
        } else {
          setStatusMessage(`Analysis failed: ${data.error || 'Server error'}`);
        }
      } else {
        setStatusMessage(data.message || 'API Analysis completed successfully.');
        await loadData(currentInvestigationId);
      }
    } catch (err: any) {
      setStatusMessage(`Analysis request error: ${err.message}`);
    } finally {
      setRunningAnalysis(false);
    }
  };

  const filteredEndpoints = (selectedContract?.endpoints || []).filter((ep) => {
    if (methodFilter !== 'ALL' && ep.method !== methodFilter) return false;
    if (authFilter !== 'ALL' && ep.auth_status !== authFilter) return false;
    return true;
  });

  return (
    <div id="api-security-workspace" className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <Network className="w-6 h-6 text-emerald-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">API Contract & Authorization Analysis</h1>
            <span className="px-2 py-0.5 text-[10px] font-mono uppercase rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Phase 3 Live
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real OpenAPI contract parsing, Stoplight Spectral CLI validation, BOLA candidate synthesis, and differential tracking.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Investigation Selector */}
          <select
            id="api-investigation-select"
            value={currentInvestigationId}
            onChange={(e) => setSelectedInvestigationId(e.target.value)}
            className="bg-[#141414] border border-white/10 rounded-md px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-emerald-500/50"
          >
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.name} ({inv.id.substring(0, 8)})
              </option>
            ))}
            {investigations.length === 0 && <option value="">(No investigations created)</option>}
          </select>

          <button
            id="btn-run-api-analysis"
            onClick={handleRunAnalysis}
            disabled={runningAnalysis || !currentInvestigationId}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-md text-xs font-medium transition disabled:opacity-50 cursor-pointer"
          >
            <Play className={`w-3.5 h-3.5 ${runningAnalysis ? 'animate-spin' : ''}`} />
            {runningAnalysis ? 'Analyzing...' : 'Run API Analysis'}
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 bg-white/5 border border-white/10 rounded-md text-xs text-slate-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{statusMessage}</span>
          </div>
          <button onClick={() => setStatusMessage(null)} className="text-slate-500 hover:text-white text-xs">
            Dismiss
          </button>
        </div>
      )}

      {/* Primary Tab Navigation */}
      <div className="flex border-b border-white/10 gap-2 overflow-x-auto">
        {[
          { id: 'overview', label: 'Overview', icon: Layers },
          { id: 'endpoints', label: `Endpoints (${selectedContract?.endpoints.length || 0})`, icon: FileCode },
          { id: 'auth', label: 'Authentication Schemes', icon: Key },
          { id: 'authorization', label: `Authorization Candidates (${authCandidates.length})`, icon: ShieldAlert },
          { id: 'issues', label: `Contract Issues (${selectedContract?.validation_issues.length || 0})`, icon: AlertTriangle },
          { id: 'diff', label: 'Source ↔ Contract', icon: ArrowRightLeft },
          { id: 'evidence', label: 'Evidence & Provenance', icon: FileCheck },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeSubTab === 'overview' && (
        <div className="space-y-6">
          {/* Key Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-[#111111] border border-white/10 rounded-lg">
              <div className="text-[11px] font-mono uppercase text-slate-500 tracking-wider">Documented Endpoints</div>
              <div className="text-2xl font-bold text-white mt-1.5">{selectedContract?.endpoints.length || 0}</div>
              <div className="text-[11px] text-slate-400 mt-1">OpenAPI 3.x contract</div>
            </div>

            <div className="p-4 bg-[#111111] border border-white/10 rounded-lg">
              <div className="text-[11px] font-mono uppercase text-slate-500 tracking-wider">Security Schemes</div>
              <div className="text-2xl font-bold text-emerald-400 mt-1.5">
                {selectedContract?.security_schemes.length || 0}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">Bearer / OAuth2 / API Key</div>
            </div>

            <div className="p-4 bg-[#111111] border border-white/10 rounded-lg">
              <div className="text-[11px] font-mono uppercase text-slate-500 tracking-wider">BOLA Candidates</div>
              <div className="text-2xl font-bold text-amber-400 mt-1.5">{authCandidates.length}</div>
              <div className="text-[11px] text-slate-400 mt-1">Status: CANDIDATE strictly</div>
            </div>

            <div className="p-4 bg-[#111111] border border-white/10 rounded-lg">
              <div className="text-[11px] font-mono uppercase text-slate-500 tracking-wider">Contract Issues</div>
              <div className="text-2xl font-bold text-rose-400 mt-1.5">
                {selectedContract?.validation_issues.length || 0}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">Structural & Lint findings</div>
            </div>
          </div>

          {/* Active Contract Metadata */}
          {selectedContract ? (
            <div className="p-5 bg-[#111111] border border-white/10 rounded-lg space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white">{selectedContract.title}</h3>
                  <p className="text-xs text-slate-400 mt-0.5">{selectedContract.description || 'No description provided in specification.'}</p>
                </div>
                <span className="px-2.5 py-1 text-xs font-mono rounded bg-white/5 border border-white/10 text-slate-300">
                  Version: {selectedContract.openapi_version}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-2.5 bg-[#0C0C0C] border border-white/5 rounded">
                  <span className="text-slate-500 block">Specification Path:</span>
                  <span className="text-slate-200 break-all">{selectedContract.specification_path}</span>
                </div>
                <div className="p-2.5 bg-[#0C0C0C] border border-white/5 rounded">
                  <span className="text-slate-500 block">SHA-256 Digest:</span>
                  <span className="text-emerald-400 break-all">{selectedContract.specification_hash}</span>
                </div>
              </div>

              {selectedContract.server_definitions.length > 0 && (
                <div className="text-xs">
                  <span className="text-slate-400 font-medium">Configured Base Servers:</span>
                  <div className="flex flex-wrap gap-2 mt-1.5">
                    {selectedContract.server_definitions.map((s, idx) => (
                      <span key={idx} className="px-2 py-1 bg-[#161616] border border-white/5 rounded font-mono text-slate-300">
                        {s.url} {s.description && `(${s.description})`}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center bg-[#111111] border border-white/10 rounded-lg text-slate-500 text-xs">
              No API contract loaded. Run analysis or select an investigation with an OpenAPI document.
            </div>
          )}
        </div>
      )}

      {/* TAB 2: ENDPOINTS TABLE */}
      {activeSubTab === 'endpoints' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-[#111111] border border-white/10 rounded-lg text-xs">
            <div className="flex items-center gap-3">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400">Method:</span>
                <select
                  value={methodFilter}
                  onChange={(e) => setMethodFilter(e.target.value)}
                  className="bg-[#181818] border border-white/10 rounded px-2 py-1 text-slate-200"
                >
                  <option value="ALL">All Methods</option>
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-slate-400">Auth:</span>
                <select
                  value={authFilter}
                  onChange={(e) => setAuthFilter(e.target.value)}
                  className="bg-[#181818] border border-white/10 rounded px-2 py-1 text-slate-200"
                >
                  <option value="ALL">All Statuses</option>
                  <option value={EndpointAuthStatus.AUTHENTICATED_ENDPOINT}>Authenticated</option>
                  <option value={EndpointAuthStatus.PUBLIC_ENDPOINT}>Public</option>
                  <option value={EndpointAuthStatus.MISSING_SECURITY_DECLARATION}>Missing Declaration</option>
                </select>
              </div>
            </div>

            <div className="text-slate-500 font-mono">
              Showing {filteredEndpoints.length} of {selectedContract?.endpoints.length || 0} endpoints
            </div>
          </div>

          {/* Endpoints Table */}
          <div className="border border-white/10 rounded-lg overflow-hidden bg-[#111111]">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-white/5 border-b border-white/10 text-slate-400 font-mono uppercase text-[10px]">
                  <th className="p-3">Method</th>
                  <th className="p-3">Path</th>
                  <th className="p-3">Authentication</th>
                  <th className="p-3">Object ID</th>
                  <th className="p-3">Mutation</th>
                  <th className="p-3">Operation ID</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredEndpoints.map((ep) => {
                  const methodColors: Record<string, string> = {
                    GET: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
                    POST: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
                    PUT: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
                    DELETE: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
                    PATCH: 'text-violet-400 bg-violet-500/10 border-violet-500/20',
                  };

                  const objParams = ep.parameters.filter((p) => p.identifier_role !== ParameterIdentifierRole.UNKNOWN);

                  return (
                    <tr
                      key={ep.id}
                      onClick={() => setSelectedEndpoint(ep)}
                      className={`hover:bg-white/[0.03] transition cursor-pointer ${
                        selectedEndpoint?.id === ep.id ? 'bg-white/[0.05]' : ''
                      }`}
                    >
                      <td className="p-3 font-mono">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${methodColors[ep.method] || 'text-slate-300'}`}>
                          {ep.method}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-slate-200">{ep.path}</td>
                      <td className="p-3">
                        {ep.auth_status === EndpointAuthStatus.AUTHENTICATED_ENDPOINT ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Authenticated
                          </span>
                        ) : ep.auth_status === EndpointAuthStatus.PUBLIC_ENDPOINT ? (
                          <span className="inline-flex items-center gap-1 text-sky-400">
                            <Info className="w-3.5 h-3.5" /> Public
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-amber-400">
                            <AlertTriangle className="w-3.5 h-3.5" /> Undeclared
                          </span>
                        )}
                      </td>
                      <td className="p-3 font-mono">
                        {objParams.length > 0 ? (
                          <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
                            {objParams.map((p) => p.name).join(', ')}
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="p-3">
                        {ep.is_state_mutation ? (
                          <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono text-[10px]">
                            MUTATION
                          </span>
                        ) : (
                          <span className="text-slate-500 font-mono text-[10px]">READ_ONLY</span>
                        )}
                      </td>
                      <td className="p-3 text-slate-400 font-mono text-[11px]">{ep.operation_id || '—'}</td>
                      <td className="p-3 text-right">
                        <button className="text-xs text-emerald-400 hover:underline">Inspect</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Endpoint Inspector Drawer */}
          {selectedEndpoint && (
            <div className="p-5 bg-[#141414] border border-white/10 rounded-lg space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    {selectedEndpoint.method}
                  </span>
                  <h4 className="text-sm font-mono font-semibold text-white">{selectedEndpoint.path}</h4>
                </div>
                <button
                  onClick={() => setSelectedEndpoint(null)}
                  className="text-xs text-slate-500 hover:text-white cursor-pointer"
                >
                  Close
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Parameters Breakdown */}
                <div className="space-y-2">
                  <h5 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">Parameters</h5>
                  {selectedEndpoint.parameters.length === 0 ? (
                    <p className="text-xs text-slate-500">No parameters documented.</p>
                  ) : (
                    <div className="space-y-2">
                      {selectedEndpoint.parameters.map((p, idx) => (
                        <div key={idx} className="p-2.5 bg-[#0D0D0D] border border-white/5 rounded text-xs">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-emerald-300 font-bold">{p.name}</span>
                            <span className="px-1.5 py-0.5 text-[10px] rounded bg-white/5 text-slate-400 font-mono">
                              in: {p.location} | {p.required ? 'required' : 'optional'}
                            </span>
                          </div>
                          <div className="mt-1 text-[11px] text-amber-300/80 font-mono">
                            Role: {p.identifier_role}
                          </div>
                          <div className="mt-0.5 text-[11px] text-slate-400">
                            {p.classification_reason}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Responses & Security */}
                <div className="space-y-4">
                  <div>
                    <h5 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">Security Requirements</h5>
                    <div className="mt-1.5 space-y-1">
                      {selectedEndpoint.security_requirements.length === 0 ? (
                        <span className="text-xs text-slate-500">No specific operation security requirement.</span>
                      ) : (
                        selectedEndpoint.security_requirements.map((s, idx) => (
                          <div key={idx} className="text-xs font-mono text-slate-300">
                            Scheme: <span className="text-emerald-400">{s.schemeName}</span> {s.scopes.length > 0 && `(Scopes: ${s.scopes.join(', ')})`}
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div>
                    <h5 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">Documented Responses</h5>
                    <div className="mt-1.5 flex flex-wrap gap-2">
                      {selectedEndpoint.responses.map((r, idx) => (
                        <span key={idx} className="px-2 py-1 bg-[#0D0D0D] border border-white/5 rounded text-xs font-mono text-slate-300">
                          {r.statusCode}: {r.description || 'No description'}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: AUTHENTICATION SCHEMES */}
      {activeSubTab === 'auth' && (
        <div className="space-y-6">
          <div className="p-4 bg-white/5 border border-white/10 rounded-lg text-xs text-slate-300 flex items-start gap-3">
            <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-white">Contract-Level Authentication Rule:</span>
              <p className="mt-0.5 text-slate-400">
                Missing OpenAPI security metadata is treated as a contract-level candidate. It is NOT automatically treated as proof of an exploitable vulnerability.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(selectedContract?.security_schemes || []).map((sec, idx) => (
              <div key={idx} className="p-4 bg-[#111111] border border-white/10 rounded-lg space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white font-mono text-sm">{sec.name}</span>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono text-[10px]">
                    {sec.type}
                  </span>
                </div>
                <p className="text-slate-400">{sec.description || 'No description provided.'}</p>
                {sec.scheme && (
                  <div className="font-mono text-slate-500">
                    Scheme: <span className="text-slate-300">{sec.scheme}</span>
                  </div>
                )}
                {sec.bearerFormat && (
                  <div className="font-mono text-slate-500">
                    Bearer Format: <span className="text-slate-300">{sec.bearerFormat}</span>
                  </div>
                )}
                {sec.in && (
                  <div className="font-mono text-slate-500">
                    Location: <span className="text-slate-300">{sec.in}</span>
                  </div>
                )}
              </div>
            ))}
            {(selectedContract?.security_schemes || []).length === 0 && (
              <div className="col-span-2 p-8 text-center bg-[#111111] border border-white/10 rounded-lg text-slate-500 text-xs">
                No security schemes defined in contract components/securitySchemes.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: AUTHORIZATION (BOLA) CANDIDATES & REASONING CHAIN */}
      {activeSubTab === 'authorization' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Candidates List */}
          <div className="lg:col-span-5 space-y-3">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              BOLA Candidates ({authCandidates.length})
            </h4>

            {authCandidates.length === 0 ? (
              <div className="p-6 bg-[#111111] border border-white/10 rounded-lg text-center text-xs text-slate-500">
                Zero BOLA candidates identified. (Endpoints either do not accept object identifiers or secure ownership/tenant isolation boundaries are verified in code).
              </div>
            ) : (
              authCandidates.map((cand) => {
                const isSelected = selectedCandidate?.id === cand.id;
                return (
                  <div
                    key={cand.id}
                    onClick={() => setSelectedCandidate(cand)}
                    className={`p-4 rounded-lg border transition cursor-pointer ${
                      isSelected
                        ? 'bg-amber-500/5 border-amber-500/50 shadow-sm'
                        : 'bg-[#111111] border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-white">
                        {cand.method} {cand.path}
                      </span>
                      <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold">
                        {cand.status}
                      </span>
                    </div>

                    <div className="mt-1.5 text-xs text-slate-300 font-medium">{cand.title}</div>

                    <div className="mt-3 flex items-center justify-between text-[11px] text-slate-400 border-t border-white/5 pt-2">
                      <span>Priority: <strong className="text-amber-400">{cand.priority_score}</strong></span>
                      <span>Boundaries: <strong className="text-slate-200">{cand.identified_boundaries.length}</strong></span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Right Column: Reasoning Chain & Details */}
          <div className="lg:col-span-7">
            {selectedCandidate ? (
              <div className="p-5 bg-[#111111] border border-white/10 rounded-lg space-y-6">
                <div className="border-b border-white/10 pb-4">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-amber-400" />
                    <h3 className="text-base font-bold text-white">{selectedCandidate.title}</h3>
                  </div>
                  <div className="flex items-center gap-3 mt-2 text-xs font-mono text-slate-400">
                    <span>OWASP: {selectedCandidate.owasp_category}</span>
                    <span>•</span>
                    <span>Status: <span className="text-amber-400 font-bold">{selectedCandidate.status}</span></span>
                  </div>
                </div>

                {/* BOLA Reasoning Chain Visualization */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono mb-3">
                    BOLA Deterministic Reasoning Chain
                  </h4>
                  <div className="space-y-2">
                    {selectedCandidate.reasoning_chain.map((step) => {
                      let badgeColor = 'bg-white/5 text-slate-400 border-white/10';
                      if (step.status === 'IDENTIFIED') badgeColor = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
                      else if (step.status === 'NOT_IDENTIFIED') badgeColor = 'bg-rose-500/10 text-rose-400 border-rose-500/20';
                      else if (step.status === 'MISSING') badgeColor = 'bg-amber-500/10 text-amber-400 border-amber-500/20';

                      return (
                        <div key={step.step} className="p-3 bg-[#0D0D0D] border border-white/5 rounded-md flex items-start gap-3 text-xs">
                          <div className="w-5 h-5 rounded-full bg-white/10 text-slate-300 flex items-center justify-center font-mono font-bold text-[10px] shrink-0 mt-0.5">
                            {step.step}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-white">{step.label}</span>
                              <span className={`px-1.5 py-0.5 text-[10px] font-mono rounded border ${badgeColor}`}>
                                {step.status}
                              </span>
                            </div>
                            <p className="text-slate-400 text-[11px] mt-0.5">{step.detail}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Identified Authorization Boundaries */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono mb-2">
                    Identified Authorization Boundaries
                  </h4>
                  {selectedCandidate.identified_boundaries.length === 0 ? (
                    <div className="p-3 bg-[#0D0D0D] border border-white/5 rounded text-xs text-rose-400 flex items-center gap-2">
                      <XCircle className="w-4 h-4" />
                      Zero access control boundaries detected in source code.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {selectedCandidate.identified_boundaries.map((b, idx) => (
                        <div key={idx} className="p-3 bg-[#0D0D0D] border border-white/5 rounded text-xs space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-emerald-400 font-bold">{b.boundary_type}</span>
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${b.satisfies_ownership ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'}`}>
                              {b.satisfies_ownership ? 'Satisfies Ownership' : 'DOES NOT Satisfy Ownership'}
                            </span>
                          </div>
                          <div className="font-mono text-slate-300 bg-black/40 p-1.5 rounded">{b.location.code_snippet}</div>
                          <p className="text-[11px] text-slate-400">{b.evidence}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Deterministic Risk Signals */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono mb-2">
                    Deterministic Risk Signals
                  </h4>
                  <div className="space-y-1.5">
                    {selectedCandidate.risk_signals.map((sig, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-[#0D0D0D] border border-white/5 rounded text-xs">
                        <div className="flex items-center gap-2">
                          {sig.present ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                          )}
                          <span className={sig.present ? 'text-white font-medium' : 'text-slate-500 line-through'}>
                            {sig.name} (+{sig.weight}pts)
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-400 max-w-xs truncate text-right">
                          {sig.rationale}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center bg-[#111111] border border-white/10 rounded-lg text-slate-500 text-xs">
                Select an authorization candidate to inspect its BOLA reasoning chain.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: CONTRACT ISSUES */}
      {activeSubTab === 'issues' && (
        <div className="space-y-4">
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
            Contract Issues & Spectral Lint Findings ({selectedContract?.validation_issues.length || 0})
          </h4>

          {(selectedContract?.validation_issues || []).length === 0 ? (
            <div className="p-8 text-center bg-[#111111] border border-white/10 rounded-lg text-slate-500 text-xs">
              No validation issues detected in OpenAPI contract.
            </div>
          ) : (
            <div className="space-y-2">
              {selectedContract?.validation_issues.map((issue) => {
                let badge = 'text-amber-400 bg-amber-500/10 border-amber-500/20';
                if (issue.severity === 'ERROR') badge = 'text-rose-400 bg-rose-500/10 border-rose-500/20';
                if (issue.severity === 'INFO') badge = 'text-sky-400 bg-sky-500/10 border-sky-500/20';

                return (
                  <div key={issue.id} className="p-3 bg-[#111111] border border-white/10 rounded-lg flex items-start gap-3 text-xs">
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-white">{issue.code}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${badge}`}>
                          {issue.severity}
                        </span>
                      </div>
                      <p className="text-slate-300 mt-1">{issue.message}</p>
                      <div className="font-mono text-slate-500 text-[11px] mt-1">Path: {issue.path}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 6: SOURCE <-> CONTRACT DIFFERENTIAL */}
      {activeSubTab === 'diff' && (
        <div className="space-y-6">
          {contractDiff ? (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <div className="p-3.5 bg-[#111111] border border-white/10 rounded-lg">
                  <span className="text-slate-500 font-mono text-[10px] uppercase">Matched</span>
                  <div className="text-xl font-bold text-emerald-400 mt-1">{contractDiff.matched}</div>
                  <div className="text-slate-400 mt-0.5">Documented & Implemented</div>
                </div>

                <div className="p-3.5 bg-[#111111] border border-white/10 rounded-lg">
                  <span className="text-slate-500 font-mono text-[10px] uppercase">Documented Only</span>
                  <div className="text-xl font-bold text-amber-400 mt-1">{contractDiff.documented_not_found}</div>
                  <div className="text-slate-400 mt-0.5">Missing in Source Code</div>
                </div>

                <div className="p-3.5 bg-[#111111] border border-white/10 rounded-lg">
                  <span className="text-slate-500 font-mono text-[10px] uppercase">Source Only (Shadow)</span>
                  <div className="text-xl font-bold text-rose-400 mt-1">{contractDiff.source_only}</div>
                  <div className="text-slate-400 mt-0.5">Undocumented Endpoints</div>
                </div>

                <div className="p-3.5 bg-[#111111] border border-white/10 rounded-lg">
                  <span className="text-slate-500 font-mono text-[10px] uppercase">Method Mismatches</span>
                  <div className="text-xl font-bold text-violet-400 mt-1">{contractDiff.method_mismatches}</div>
                  <div className="text-slate-400 mt-0.5">Method disagreement</div>
                </div>
              </div>

              {/* Items List */}
              <div className="space-y-2">
                {contractDiff.items.map((item, idx) => {
                  let statusBadge = 'text-slate-400 bg-white/5 border-white/10';
                  if (item.status === ContractDiffStatus.DOCUMENTED_AND_IMPLEMENTED) {
                    statusBadge = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
                  } else if (item.status === ContractDiffStatus.SOURCE_ONLY) {
                    statusBadge = 'text-rose-400 bg-rose-500/10 border-rose-500/20';
                  } else if (item.status === ContractDiffStatus.METHOD_MISMATCH) {
                    statusBadge = 'text-violet-400 bg-violet-500/10 border-violet-500/20';
                  } else if (item.status === ContractDiffStatus.DOCUMENTED_BUT_NOT_FOUND) {
                    statusBadge = 'text-amber-400 bg-amber-500/10 border-amber-500/20';
                  }

                  return (
                    <div key={idx} className="p-3.5 bg-[#111111] border border-white/10 rounded-lg flex items-center justify-between text-xs">
                      <div className="flex items-center gap-3">
                        <span className="font-mono font-bold text-white px-2 py-0.5 bg-white/5 rounded border border-white/10">
                          {item.method}
                        </span>
                        <div>
                          <div className="font-mono text-slate-200">{item.path}</div>
                          <div className="text-slate-400 text-[11px] mt-0.5">{item.details}</div>
                        </div>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${statusBadge}`}>
                        {item.status}
                      </span>
                    </div>
                  );
                })}
              </div>
            </>
          ) : (
            <div className="p-8 text-center bg-[#111111] border border-white/10 rounded-lg text-slate-500 text-xs">
              No contract differential analysis generated. Run API Analysis to compare contract with source code.
            </div>
          )}
        </div>
      )}

      {/* TAB 7: EVIDENCE & PROVENANCE */}
      {activeSubTab === 'evidence' && (
        <div className="space-y-4">
          <div className="p-4 bg-white/5 border border-white/10 rounded-lg text-xs text-slate-300">
            <span className="font-semibold text-white">Immutable Evidence Chain:</span>
            <p className="mt-1 text-slate-400">
              All parsed specifications, Spectral CLI raw execution outputs, and authorization evaluations are sealed with SHA-256 digests in the evidence locker.
            </p>
          </div>

          <div className="p-4 bg-[#111111] border border-white/10 rounded-lg space-y-3 text-xs">
            <div className="flex items-center justify-between border-b border-white/5 pb-2">
              <span className="text-slate-400 font-mono">OpenAPI Specification Artifact:</span>
              <span className="text-emerald-400 font-mono">{selectedContract?.specification_hash || '(none)'}</span>
            </div>
            <div className="flex items-center justify-between border-b border-white/5 pb-2">
              <span className="text-slate-400 font-mono">Retrieved At:</span>
              <span className="text-slate-300 font-mono">{selectedContract?.retrieved_at || '(none)'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400 font-mono">Source Snapshot:</span>
              <span className="text-slate-300 font-mono">{selectedContract?.source_snapshot_id || 'Direct Workspace'}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
