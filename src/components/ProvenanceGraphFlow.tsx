import React, { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  MarkerType,
  BackgroundVariant,
  Node,
  Edge,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ProvenanceGraph, ProvenanceNode } from '../types.js';

interface ProvenanceGraphFlowProps {
  graph: ProvenanceGraph | null;
  onNodeSelect: (node: ProvenanceNode) => void;
  selectedNodeId: string | null;
}

// Custom node component for Intent Security Workbench monospace aesthetic
const CustomProvenanceNode: React.FC<{ data: any; id: string; selected?: boolean }> = ({ data, selected }) => {
  const { type, label, details, isSelected } = data;

  const styleConfig: Record<string, { border: string; bg: string; text: string; badge: string }> = {
    Investigation: { border: 'border-sky-500', bg: 'bg-sky-950/40', text: 'text-sky-300', badge: 'bg-sky-500/20 text-sky-400' },
    Target: { border: 'border-indigo-500', bg: 'bg-indigo-950/40', text: 'text-indigo-300', badge: 'bg-indigo-500/20 text-indigo-400' },
    SourceSnapshot: { border: 'border-amber-500', bg: 'bg-amber-950/40', text: 'text-amber-300', badge: 'bg-amber-500/20 text-amber-400' },
    Source: { border: 'border-amber-500', bg: 'bg-amber-950/40', text: 'text-amber-300', badge: 'bg-amber-500/20 text-amber-400' },
    AnalysisJob: { border: 'border-purple-500', bg: 'bg-purple-950/40', text: 'text-purple-300', badge: 'bg-purple-500/20 text-purple-400' },
    Job: { border: 'border-purple-500', bg: 'bg-purple-950/40', text: 'text-purple-300', badge: 'bg-purple-500/20 text-purple-400' },
    Engine: { border: 'border-blue-500', bg: 'bg-blue-950/40', text: 'text-blue-300', badge: 'bg-blue-500/20 text-blue-400' },
    EvidenceEvent: { border: 'border-teal-500', bg: 'bg-teal-950/40', text: 'text-teal-300', badge: 'bg-teal-500/20 text-teal-400' },
    EvidenceArtifact: { border: 'border-emerald-500', bg: 'bg-emerald-950/40', text: 'text-emerald-300', badge: 'bg-emerald-500/20 text-emerald-400' },
    Artifact: { border: 'border-emerald-500', bg: 'bg-emerald-950/40', text: 'text-emerald-300', badge: 'bg-emerald-500/20 text-emerald-400' },
    Finding: { border: 'border-rose-500', bg: 'bg-rose-950/40', text: 'text-rose-300', badge: 'bg-rose-500/20 text-rose-400' },
  };

  const currentStyle = styleConfig[type] || { border: 'border-slate-700', bg: 'bg-slate-900/40', text: 'text-slate-300', badge: 'bg-slate-800 text-slate-400' };

  // Format display type per prompt: Investigation, Target, Source, Job, Engine, Artifact, Finding
  let displayType = type;
  if (type === 'SourceSnapshot') displayType = 'Source';
  if (type === 'AnalysisJob') displayType = 'Job';
  if (type === 'EvidenceArtifact') displayType = 'Artifact';

  return (
    <div
      className={`p-3 rounded border text-xs font-mono min-w-[190px] max-w-[240px] shadow-lg transition ${currentStyle.bg} ${currentStyle.border} ${
        isSelected || selected ? 'ring-2 ring-white ring-offset-2 ring-offset-black scale-105' : 'hover:border-white/50'
      }`}
    >
      <Handle type="target" position={Position.Left} className="!bg-slate-500 !w-2 !h-2" />
      <div className="flex items-center justify-between gap-1 mb-1">
        <span className={`text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded font-bold ${currentStyle.badge}`}>
          {displayType}
        </span>
        {details?.sha256 && (
          <span className="text-[9px] text-slate-400 font-mono" title={details.sha256}>
            {details.sha256.substring(0, 8)}...
          </span>
        )}
      </div>

      <div className={`font-semibold text-[11px] truncate ${currentStyle.text}`}>
        {label}
      </div>

      {details?.command && (
        <div className="text-[9px] text-slate-400 truncate mt-1 bg-black/60 px-1 py-0.5 rounded font-mono border border-white/5">
          $ {details.command}
        </div>
      )}

      {details?.producer && (
        <div className="text-[9px] text-slate-500 mt-0.5">
          {details.producer} {details.producer_version ? `(v${details.producer_version})` : ''}
        </div>
      )}

      <Handle type="source" position={Position.Right} className="!bg-slate-500 !w-2 !h-2" />
    </div>
  );
};

const nodeTypes = {
  custom: CustomProvenanceNode,
};

export const ProvenanceGraphFlow: React.FC<ProvenanceGraphFlowProps> = ({
  graph,
  onNodeSelect,
  selectedNodeId,
}) => {
  // Check if graph has actual evidence or stored entities
  const hasEvidence = useMemo(() => {
    if (!graph || !graph.nodes || graph.nodes.length === 0) return false;
    // An investigation with no evidence or jobs has only the investigation node itself
    const evidenceNodes = graph.nodes.filter(n =>
      n.type === 'EvidenceArtifact' ||
      n.type === 'Artifact' ||
      n.type === 'EvidenceEvent' ||
      n.type === 'AnalysisJob' ||
      n.type === 'Job' ||
      n.type === 'SourceSnapshot' ||
      n.type === 'Source'
    );
    return evidenceNodes.length > 0;
  }, [graph]);

  const { nodes, edges } = useMemo(() => {
    if (!graph || !hasEvidence) return { nodes: [], edges: [] };

    // Layout nodes into clean deterministic columns by layer
    const layerIndices: Record<string, number> = {
      Investigation: 0,
      Target: 1,
      AnalysisJob: 1,
      Job: 1,
      SourceSnapshot: 2,
      Source: 2,
      Engine: 2,
      EvidenceEvent: 3,
      EvidenceArtifact: 3,
      Artifact: 3,
      Finding: 4,
    };

    const layerYCounts: Record<number, number> = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
    const columnWidth = 260;
    const rowHeight = 110;

    const flowNodes: Node[] = graph.nodes.map((n) => {
      const col = layerIndices[n.type] ?? 2;
      const row = layerYCounts[col] || 0;
      layerYCounts[col] = (layerYCounts[col] || 0) + 1;

      const isSelected = n.id === selectedNodeId;

      return {
        id: n.id,
        type: 'custom',
        position: { x: 30 + col * columnWidth, y: 30 + row * rowHeight },
        data: {
          type: n.type,
          label: n.label,
          details: n.data,
          isSelected,
          rawNode: n,
        },
      };
    });

    const flowEdges: Edge[] = graph.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.relationship || e.label || '',
      type: 'smoothstep',
      animated: false,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: '#64748b',
        width: 15,
        height: 15,
      },
      style: {
        stroke: '#475569',
        strokeWidth: 1.5,
      },
      labelStyle: {
        fill: '#94a3b8',
        fontSize: 9,
        fontFamily: 'monospace',
        fontWeight: 600,
      },
      labelBgStyle: {
        fill: '#09090b',
        fillOpacity: 0.9,
        rx: 3,
        ry: 3,
      },
    }));

    return { nodes: flowNodes, edges: flowEdges };
  }, [graph, hasEvidence, selectedNodeId]);

  if (!hasEvidence) {
    return (
      <div className="py-24 text-center rounded-lg border border-dashed border-white/10 bg-[#09090b] font-mono">
        <p className="text-sm font-semibold text-slate-300">No evidence recorded.</p>
        <p className="text-xs text-slate-500 mt-1">
          This investigation does not currently have any stored artifacts, jobs, or evidence events.
        </p>
      </div>
    );
  }

  return (
    <div className="w-full h-[520px] rounded-lg border border-white/10 bg-[#09090b] overflow-hidden relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, node) => {
          if (node.data?.rawNode) {
            onNodeSelect(node.data.rawNode as ProvenanceNode);
          }
        }}
        fitView
        minZoom={0.2}
        maxZoom={1.5}
        defaultEdgeOptions={{ type: 'smoothstep' }}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#27272a" />
        <Controls className="!bg-[#18181b] !border-white/10 !text-white [&>button]:!border-white/10 [&>button]:!bg-[#18181b] [&>button]:!text-white hover:[&>button]:!bg-white/10" />
        <MiniMap
          className="!bg-[#09090b] !border-white/10"
          nodeColor={(n: any) => {
            const t = n.data?.type;
            if (t === 'Investigation') return '#38bdf8';
            if (t === 'Target') return '#818cf8';
            if (t === 'SourceSnapshot' || t === 'Source') return '#fbbf24';
            if (t === 'AnalysisJob' || t === 'Job') return '#c084fc';
            if (t === 'Engine') return '#60a5fa';
            if (t === 'EvidenceArtifact' || t === 'Artifact') return '#34d399';
            if (t === 'Finding') return '#f43f5e';
            return '#64748b';
          }}
          maskColor="rgba(0, 0, 0, 0.7)"
        />
      </ReactFlow>
    </div>
  );
};
