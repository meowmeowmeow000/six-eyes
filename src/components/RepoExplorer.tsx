/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  FileText,
  FileCode,
  Folder,
  FolderOpen,
  Copy,
  Check,
  Search,
  ExternalLink,
  Code2,
  Terminal,
  FileCheck2,
  ArrowRight,
  GitBranch,
} from 'lucide-react';
import { REPO_FILES, RepoFile } from '../data/repoFiles';

interface RepoExplorerProps {
  activeFile?: string;
  onSelectFileForTerminal?: (filePath: string) => void;
}

export const RepoExplorer: React.FC<RepoExplorerProps> = ({
  activeFile,
  onSelectFileForTerminal,
}) => {
  const [selectedFilePath, setSelectedFilePath] = useState<string>(activeFile || 'README.md');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [copied, setCopied] = useState(false);
  const [expandedFolders, setExpandedFolders] = useState<Record<string, boolean>>({
    'pkg': true,
    'pkg/bpf': true,
    'cmd': true,
    'cmd/daemon': true,
    'pkg/desync': true,
    'pkg/proxy': true,
    'pkg/config': true,
    'scanner': true,
    'configs': true,
    '.github': true,
    '.github/workflows': true,
  });

  // Sync when activeFile prop changes
  React.useEffect(() => {
    if (activeFile) {
      setSelectedFilePath(activeFile);
    }
  }, [activeFile]);

  const selectedFile = useMemo(() => {
    return REPO_FILES.find((f) => f.path === selectedFilePath) || REPO_FILES[0];
  }, [selectedFilePath]);

  const filteredFiles = useMemo(() => {
    return REPO_FILES.filter((file) => {
      const matchesSearch =
        file.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
        file.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesCategory = categoryFilter === 'all' || file.category === categoryFilter;
      return matchesSearch && matchesCategory;
    });
  }, [searchQuery, categoryFilter]);

  const handleCopy = () => {
    if (selectedFile) {
      navigator.clipboard.writeText(selectedFile.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const toggleFolder = (folder: string) => {
    setExpandedFolders((prev) => ({
      ...prev,
      [folder]: !prev[folder],
    }));
  };

  const getLanguageColor = (lang: string) => {
    switch (lang) {
      case 'c':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
      case 'go':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20';
      case 'python':
        return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
      case 'javascript':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'makefile':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
      case 'yaml':
        return 'text-purple-400 bg-purple-500/10 border-purple-500/20';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
    }
  };

  const lines = useMemo(() => {
    return selectedFile.content.split('\n');
  }, [selectedFile]);

  return (
    <div className="space-y-4">
      {/* Repository Meta Banner */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <GitBranch className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-semibold text-slate-200">main</span>
              <span className="text-slate-500 text-xs">/</span>
              <span className="text-xs text-slate-400">commit 148ace8</span>
              <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                17 files verified
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              feat(core): initialize six-eyes v10 autonomous eBPF DPI evasion daemon (pkg/bpf + Go daemon + Scapy cartographer)
            </p>
          </div>
        </div>

        {/* Quick Filter Categories */}
        <div className="flex flex-wrap items-center gap-1.5">
          {[
            { id: 'all', label: 'All Files' },
            { id: 'ebpf', label: 'eBPF (C)' },
            { id: 'daemon', label: 'Go Daemon' },
            { id: 'scanner', label: 'Python Scanner' },
            { id: 'edge', label: 'Cloudflare' },
            { id: 'config', label: 'Configs & CI' },
          ].map((cat) => (
            <button
              key={cat.id}
              onClick={() => setCategoryFilter(cat.id)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                categoryFilter === cat.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 border border-slate-700/60'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Explorer Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Pane: File Tree */}
        <div className="lg:col-span-4 bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-[700px]">
          {/* Search box */}
          <div className="p-3 border-b border-slate-800 bg-slate-950/40">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search repository files..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-900 border border-slate-700/80 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
              />
            </div>
          </div>

          {/* Files List */}
          <div className="flex-1 overflow-y-auto p-2 space-y-1">
            {filteredFiles.map((file) => {
              const isSelected = selectedFilePath === file.path;
              return (
                <button
                  key={file.path}
                  onClick={() => setSelectedFilePath(file.path)}
                  className={`w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono flex items-center justify-between group transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 font-medium'
                      : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                  }`}
                >
                  <div className="flex items-center space-x-2 truncate pr-2">
                    <FileCode
                      className={`w-4 h-4 shrink-0 ${
                        isSelected ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-400'
                      }`}
                    />
                    <span className="truncate">{file.path}</span>
                  </div>
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded border uppercase shrink-0 ${getLanguageColor(
                      file.language
                    )}`}
                  >
                    {file.language}
                  </span>
                </button>
              );
            })}

            {filteredFiles.length === 0 && (
              <div className="p-6 text-center text-slate-500 text-xs">
                No files match "{searchQuery}"
              </div>
            )}
          </div>

          {/* Directory Summary Footer */}
          <div className="p-2.5 bg-slate-950/60 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>{REPO_FILES.length} repository files</span>
            <span className="font-mono text-emerald-400">git clean & validated</span>
          </div>
        </div>

        {/* Right Pane: Code Viewer */}
        <div className="lg:col-span-8 bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-[700px]">
          {/* File Header */}
          <div className="p-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
            <div className="flex items-center space-x-2.5 truncate">
              <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
              <div className="truncate">
                <span className="text-xs font-mono font-semibold text-white">{selectedFile.path}</span>
                <span className="mx-2 text-slate-600">|</span>
                <span className="text-[11px] text-slate-400">{selectedFile.size}</span>
                <span className="mx-2 text-slate-600">|</span>
                <span className="text-[11px] text-slate-400">{lines.length} lines</span>
              </div>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              <button
                onClick={handleCopy}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
                title="Copy entire code to clipboard"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Description bar */}
          <div className="px-4 py-2 bg-slate-900/90 border-b border-slate-800/80 text-xs text-slate-400 flex items-center gap-2">
            <span className="text-indigo-400 font-semibold shrink-0">Component:</span>
            <span className="truncate">{selectedFile.description}</span>
          </div>

          {/* Code content with line numbers */}
          <div className="flex-1 overflow-auto bg-slate-950 font-mono text-xs p-4 selection:bg-cyan-500/30 selection:text-white">
            <table className="w-full border-collapse">
              <tbody>
                {lines.map((line, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="w-12 text-right pr-4 select-none text-slate-600 text-[11px] font-mono align-top">
                      {idx + 1}
                    </td>
                    <td className="text-slate-300 font-mono whitespace-pre overflow-x-auto align-top">
                      {line}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
