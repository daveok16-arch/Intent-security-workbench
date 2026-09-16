import React from 'react';
import { WorkbenchProvider, useWorkbench } from './context/WorkbenchContext.js';
import { Header } from './components/Header.js';
import { Sidebar } from './components/Sidebar.js';
import { Footer } from './components/Footer.js';
import { DashboardView } from './components/DashboardView.js';
import { ProgramsView } from './components/ProgramsView.js';
import { ScopeView } from './components/ScopeView.js';
import { TargetsView } from './components/TargetsView.js';
import { SourceSnapshotsView } from './components/SourceSnapshotsView.js';
import { InvestigationsView } from './components/InvestigationsView.js';
import { JobsView } from './components/JobsView.js';
import { EvidenceView } from './components/EvidenceView.js';
import { FindingsView } from './components/FindingsView.js';
import { EnginesView } from './components/EnginesView.js';
import { SettingsView } from './components/SettingsView.js';
import { ApiSecurityView } from './components/ApiSecurityView.js';
import { AiControllerView } from './components/AiControllerView.js';

const WorkbenchContent: React.FC = () => {
  const { activeTab } = useWorkbench();

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0A0A0A] text-slate-300 overflow-hidden select-text">
      <Header />
      <div className="flex-1 flex min-h-0 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#0A0A0A]">
          <div className="max-w-7xl mx-auto">
            {activeTab === 'dashboard' && <DashboardView />}
            {activeTab === 'ai_controller' && <AiControllerView />}
            {activeTab === 'programs' && <ProgramsView />}
            {activeTab === 'scope' && <ScopeView />}
            {activeTab === 'targets' && <TargetsView />}
            {activeTab === 'source_snapshots' && <SourceSnapshotsView />}
            {activeTab === 'investigations' && <InvestigationsView />}
            {activeTab === 'api_security' && <ApiSecurityView />}
            {activeTab === 'jobs' && <JobsView />}
            {activeTab === 'evidence' && <EvidenceView />}
            {activeTab === 'findings' && <FindingsView />}
            {activeTab === 'engines' && <EnginesView />}
            {activeTab === 'settings' && <SettingsView />}
          </div>
        </main>
      </div>
      <Footer />
    </div>
  );
};

export default function App() {
  return (
    <WorkbenchProvider>
      <div className="h-screen w-screen flex flex-col font-sans bg-[#0A0A0A] antialiased selection:bg-emerald-500/30 selection:text-emerald-200">
        <WorkbenchContent />
      </div>
    </WorkbenchProvider>
  );
}
