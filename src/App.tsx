/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Header, ActiveTab } from './components/Header';
import { RepoExplorer } from './components/RepoExplorer';
import { EvaluationLab } from './components/EvaluationLab';
import { TcpDesyncVisualizer } from './components/TcpDesyncVisualizer';
import { ArchitectureView } from './components/ArchitectureView';
import { TerminalConsole } from './components/TerminalConsole';
import { GitPushModal } from './components/GitPushModal';
import { ShieldCheck } from 'lucide-react';
import { downloadRepoZip } from './utils/zipExporter';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('explorer');
  const [isGitModalOpen, setIsGitModalOpen] = useState(false);
  const [activeFile, setActiveFile] = useState<string>('README.md');

  const handleOpenFile = (path: string) => {
    setActiveFile(path);
    setActiveTab('explorer');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased selection:bg-cyan-500/30 selection:text-white">
      {/* Top Navigation Bar */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenGitModal={() => setIsGitModalOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'explorer' && <RepoExplorer activeFile={activeFile} />}
        {activeTab === 'evaluation' && <EvaluationLab />}
        {activeTab === 'desync' && <TcpDesyncVisualizer />}
        {activeTab === 'architecture' && <ArchitectureView onOpenFile={handleOpenFile} />}
        {activeTab === 'terminal' && <TerminalConsole />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 text-xs text-slate-500 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2 text-slate-400">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>
              Six Eyes - Autonomous eBPF TCP Sequence Desync & DPI Evasion Framework (v10.0)
            </span>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => setIsGitModalOpen(true)}
              className="hover:text-slate-300 transition-colors cursor-pointer"
            >
              Push to GitHub
            </button>
            <span>•</span>
            <button
              onClick={() => downloadRepoZip()}
              className="hover:text-cyan-400 transition-colors cursor-pointer"
            >
              Download .ZIP
            </button>
            <span>•</span>
            <button
              onClick={() => setActiveTab('architecture')}
              className="hover:text-slate-300 transition-colors cursor-pointer"
            >
              Six Eyes Architecture & Lore
            </button>
          </div>
        </div>
      </footer>

      {/* Push to GitHub Modal */}
      <GitPushModal
        isOpen={isGitModalOpen}
        onClose={() => setIsGitModalOpen(false)}
      />
    </div>
  );
}
