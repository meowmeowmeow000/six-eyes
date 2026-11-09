/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  FolderGit2,
  Cpu,
  Activity,
  Layers,
  Terminal,
  Download,
  Share2,
  Check,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';
import { downloadRepoZip } from '../utils/zipExporter';

export type ActiveTab = 'explorer' | 'evaluation' | 'desync' | 'architecture' | 'terminal';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  onOpenGitModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onOpenGitModal,
}) => {
  const [downloading, setDownloading] = useState(false);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [downloaded, setDownloaded] = useState(false);

  const handleDownloadZip = async () => {
    try {
      setDownloading(true);
      setDownloadProgress(10);
      await downloadRepoZip((p) => setDownloadProgress(p));
      setDownloaded(true);
      setTimeout(() => setDownloaded(false), 3000);
    } catch (err) {
      console.error('Download failed:', err);
    } finally {
      setDownloading(false);
    }
  };

  const navItems: { id: ActiveTab; label: string; icon: React.ReactNode; badge?: string }[] = [
    {
      id: 'explorer',
      label: 'Repository Explorer',
      icon: <FolderGit2 className="w-4 h-4" />,
      badge: '17 files',
    },
    {
      id: 'evaluation',
      label: 'DPI Evasion & Fingerprint Lab',
      icon: <Activity className="w-4 h-4" />,
      badge: 'Auditor',
    },
    {
      id: 'desync',
      label: 'eBPF TCP Desync',
      icon: <Cpu className="w-4 h-4" />,
      badge: 'v10 Kernel',
    },
    {
      id: 'architecture',
      label: 'Six Eyes Architecture & Lore',
      icon: <Layers className="w-4 h-4" />,
      badge: 'v10 Modular',
    },
    {
      id: 'terminal',
      label: 'CLI Workbench',
      icon: <Terminal className="w-4 h-4" />,
      badge: 'make/bpftool',
    },
  ];

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40 text-slate-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Top bar */}
        <div className="flex items-center justify-between py-3.5 border-b border-slate-800/60">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 via-indigo-600 to-purple-600 p-0.5 shadow-lg shadow-indigo-500/20 flex items-center justify-center">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                  <span>six-eyes</span>
                  <span className="text-slate-500">/</span>
                  <span className="text-cyan-400">six-eyes</span>
                </h1>
                <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Public
                </span>
                <span className="hidden sm:inline-flex px-2 py-0.5 rounded-full text-[11px] font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
                  v10.0-rc1
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Autonomous eBPF TCP Sequence Desynchronization & DPI Evasion Daemon (Six Eyes v10)
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2.5">
            <button
              onClick={onOpenGitModal}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 hover:border-slate-600 transition-colors cursor-pointer shadow-sm"
              title="View instructions to push to your connected GitHub account"
            >
              <Share2 className="w-3.5 h-3.5 text-indigo-400" />
              <span>Push to GitHub</span>
            </button>

            <button
              onClick={handleDownloadZip}
              disabled={downloading}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-md shadow-cyan-500/20 transition-all cursor-pointer disabled:opacity-50"
            >
              {downloaded ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-300" />
                  <span>Downloaded!</span>
                </>
              ) : downloading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/40 border-t-white rounded-full animate-spin" />
                  <span>Packaging ({downloadProgress}%)</span>
                </>
              ) : (
                <>
                  <Download className="w-3.5 h-3.5" />
                  <span>Download ZIP</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex space-x-1 sm:space-x-2 py-2 overflow-x-auto scrollbar-none" aria-label="Tabs">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all cursor-pointer ${
                  isActive
                    ? 'bg-slate-800 text-cyan-300 shadow-sm border border-slate-700/80'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
                {item.badge && (
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded ${
                      isActive
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                        : 'bg-slate-800/80 text-slate-400'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
