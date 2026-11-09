/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { X, Copy, Check, GitBranch, Github, Terminal, Download, ArrowRight, ShieldCheck } from 'lucide-react';
import { downloadRepoZip } from '../utils/zipExporter';

interface GitPushModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const GitPushModal: React.FC<GitPushModalProps> = ({ isOpen, onClose }) => {
  const [repoName, setRepoName] = useState('six-eyes');
  const [gitUser, setGitUser] = useState('YOUR-GITHUB-USERNAME');
  const [authMethod, setAuthMethod] = useState<'https' | 'ssh' | 'cli'>('https');
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState(false);

  if (!isOpen) return null;

  const remoteUrl =
    authMethod === 'https'
      ? `https://github.com/${gitUser}/${repoName}.git`
      : `git@github.com:${gitUser}/${repoName}.git`;

  const commands =
    authMethod === 'cli'
      ? `# 1. Authenticate with GitHub CLI (if not already logged in)
gh auth login

# 2. Enter repository directory
cd six-eyes

# 3. Create the remote repository on GitHub and push the main branch
gh repo create ${repoName} --public --source=. --remote=origin --push`
      : `# 1. Enter the pre-initialized six-eyes directory
cd six-eyes

# 2. (Optional) Verify git status and commit history
git status
git log -n 1 --oneline

# 3. Link your personal or organization GitHub remote
git remote add origin ${remoteUrl}

# 4. Push all branches and tags to GitHub
git push -u origin main`;

  const handleCopyCommands = () => {
    navigator.clipboard.writeText(commands);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = async () => {
    setDownloading(true);
    try {
      await downloadRepoZip();
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-150">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <Github className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Push to Connected GitHub Account</h3>
              <p className="text-xs text-slate-400">
                Commands generated from the Gemini migration breakdown (v9.1 → v10).
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5">
          {/* Repository configuration inputs */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                GitHub Username / Organization
              </label>
              <input
                type="text"
                value={gitUser}
                onChange={(e) => setGitUser(e.target.value)}
                placeholder="e.g. arash or your-org"
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Repository Name
              </label>
              <input
                type="text"
                value={repoName}
                onChange={(e) => setRepoName(e.target.value)}
                placeholder="apify-fingerprint-suite-desync"
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Protocol selector tabs */}
          <div className="flex items-center space-x-2 border-b border-slate-800 pb-2">
            {[
              { id: 'https', label: 'HTTPS (Token)' },
              { id: 'ssh', label: 'SSH Key' },
              { id: 'cli', label: 'GitHub CLI (gh)' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setAuthMethod(tab.id as any)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  authMethod === tab.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Code command block */}
          <div className="relative">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
              <pre>{commands}</pre>
            </div>
            <button
              onClick={handleCopyCommands}
              className="absolute top-3 right-3 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 shadow-md transition-colors cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Commands</span>
                </>
              )}
            </button>
          </div>

          {/* Physical repo notice */}
          <div className="p-3 rounded-xl bg-indigo-950/20 border border-indigo-900/40 text-xs text-indigo-300 flex items-start gap-2.5">
            <ShieldCheck className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-white block">
                Local Git repository pre-initialized on disk
              </span>
              <span>
                The repository is already organized and committed on <code className="text-cyan-300 font-mono">main</code> in <code className="text-cyan-300 font-mono">./six-eyes</code> with 17 files ready to push.
              </span>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Or download as .zip</span>
          </button>

          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
