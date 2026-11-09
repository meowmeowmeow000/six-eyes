/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  Layers,
  Shield,
  Workflow,
  Cpu,
  Server,
  Terminal,
  FileCheck,
  Eye,
  Globe2,
  Crosshair,
  CheckCircle,
  XCircle,
} from 'lucide-react';

interface ArchitectureViewProps {
  onOpenFile?: (path: string) => void;
}

export const ArchitectureView: React.FC<ArchitectureViewProps> = ({ onOpenFile }) => {
  const subsystems = [
    {
      title: 'eBPF Kernel Engine (The Senses)',
      badge: 'pkg/bpf/ (C + bpf2go)',
      icon: <Cpu className="w-5 h-5 text-amber-400" />,
      color: 'border-amber-500/30 bg-amber-500/5',
      description: 'Kernel-space TC egress/ingress classifier and TCP sequence state machine operating at the wire.',
      responsibilities: [
        'Interception of TCP 4-tuples via high-performance BPF hash maps',
        'Out-of-band fake RST injection with low TTL to trick middleboxes',
        'Payload fragmentation & byte-splitting at arbitrary offsets',
        'Zero-copy in-kernel packet filtering with TC_ACT_OK / TC_ACT_SHOT',
        'Auto-compilation via clang and Go binding generation with bpf2go',
      ],
      files: ['pkg/bpf/tcp_desync.bpf.c', 'pkg/bpf/headers.h', 'pkg/bpf/maps.h', 'pkg/bpf/loader.go'],
    },
    {
      title: 'Go Daemon & TCP State Machine',
      badge: 'cmd/daemon/ & pkg/ (Go 1.22)',
      icon: <Server className="w-5 h-5 text-cyan-400" />,
      color: 'border-cyan-500/30 bg-cyan-500/5',
      description: 'User-space controller, BPF bytecode loader, and high-throughput transparent SOCKS5 proxy.',
      responsibilities: [
        'BPF object loading and interface TC attachment via cilium/ebpf',
        'Stateful TCP connection tracking & out-of-order sequence synthesis',
        'Transparent SOCKS5 and HTTP CONNECT proxy multiplexing on :1080',
        'Hot-reloadable YAML configuration profiles & strategy selection',
        'Health & telemetry metrics server at :9090/healthz',
      ],
      files: ['cmd/daemon/main.go', 'pkg/desync/state_machine.go', 'pkg/proxy/socks5.go', 'pkg/config/profile.go'],
    },
    {
      title: 'Python Middlebox Cartographer',
      badge: 'scanner/ (Python 3.11 + Scapy)',
      icon: <Terminal className="w-5 h-5 text-blue-400" />,
      color: 'border-blue-500/30 bg-blue-500/5',
      description: 'Active network cartographer probing middlebox hop distance, TTL drops, and DPI filter rules.',
      responsibilities: [
        'Raw IP/TCP SYN and HTTP GET packet crafting with decreasing TTLs',
        'Middlebox hop distance discovery and stateful inspection boundary detection',
        'Detection of silent drops, HTTP 403 blocks, and injected fake RSTs',
        'Optimal TTL calculation for out-of-band fake RST attacks',
        'Automated JSON report generation for Go daemon profile tuning',
      ],
      files: ['scanner/cartographer.py', 'configs/stealth.yaml'],
    },
    {
      title: 'Build & CI/CD Pipeline',
      badge: 'Buildroot & CI Matrix',
      icon: <FileCheck className="w-5 h-5 text-emerald-400" />,
      color: 'border-emerald-500/30 bg-emerald-500/5',
      description: 'Hermetic build automation, container definitions, and GitHub Actions verification workflows.',
      responsibilities: [
        'Makefile with preflight checks, bpf2go generation, and Go build targets',
        'Multi-stage Dockerfile with clang, bpftool, and Go 1.22 runtime',
        'Docker Compose with NET_ADMIN and BPF capabilities mapped',
        'GitHub Actions CI with kernel headers, clang compilation, and tests',
      ],
      files: ['Makefile', 'go.mod', 'Dockerfile', 'docker-compose.yml', '.github/workflows/ci.yml'],
    },
  ];

  return (
    <div className="space-y-8">
      {/* Overview Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/30 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex items-center space-x-3 mb-2">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Workflow className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Six Eyes - System Architecture & Lore Matrix
            </h2>
            <p className="text-xs text-slate-400">
              Autonomous eBPF TCP Sequence Desynchronization & Middlebox DPI Evasion Framework (v10)
            </p>
          </div>
        </div>
      </div>

      {/* The Lore: Why "Six Eyes"? */}
      <div className="bg-slate-900/60 border border-indigo-500/30 rounded-2xl p-6 relative overflow-hidden shadow-xl">
        <div className="flex items-center space-x-2.5 mb-4 text-indigo-400">
          <Eye className="w-5 h-5 text-indigo-400" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">
            The Lore: Why "Six Eyes"?
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-slate-300">
          <div className="p-4 rounded-xl bg-slate-950/70 border border-indigo-500/20 space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
              <Globe2 className="w-4 h-4" />
              <span>1. The Geopolitical Level (Watching the Watchers)</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              A direct subversion of the <strong className="text-white">Five Eyes (FVEY)</strong> intelligence alliance and state-level Deep Packet Inspection (DPI) apparatuses. By standing as the "6th Eye", the tool operates outside their perceptual grid—monitoring surveillance middleboxes, mapping their exact hop distance via active TTL cartography, and desynchronizing their reassembly buffers before inspection can occur.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/70 border border-purple-500/20 space-y-2">
            <div className="flex items-center gap-2 text-purple-400 font-bold text-sm">
              <Crosshair className="w-4 h-4" />
              <span>2. The Jujutsu Kaisen / Cyberpunk Level (Atomic Manipulation)</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              In lore, Gojo Satoru's <strong className="text-white">Six Eyes</strong> grants complete, boundless perception of cursed energy flows down to the atomic level. In network warfare, that is precisely what our kernel-space <strong className="text-cyan-300 font-mono">eBPF TC classifier</strong> achieves: perceiving raw TCP sequence numbers, window boundaries, and packet flags at wire speed, bending flow geometry without user-space latency.
            </p>
          </div>
        </div>
      </div>

      {/* Monolith vs Modern v10 Architecture */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Legacy Monolith */}
        <div className="bg-slate-900/50 border border-red-500/20 rounded-2xl p-6 relative overflow-hidden">
          <div className="flex items-center space-x-2.5 mb-4 text-red-400">
            <XCircle className="w-5 h-5" />
            <h3 className="text-sm font-bold uppercase tracking-wider">
              Legacy Monolithic Prototype (Deprecated)
            </h3>
          </div>
          <div className="space-y-2.5 text-xs text-slate-400">
            <div className="p-3 rounded-lg bg-red-950/20 border border-red-900/30 text-slate-300">
              Single 2,400-line shell script with inline C strings, raw hex bytes, and no module boundaries.
            </div>
            <ul className="space-y-1.5 list-disc list-inside">
              <li>No version control separation or modular testing</li>
              <li>Impossible to compile eBPF bytecode via clean compiler toolchains</li>
              <li>Fragile string concatenations and sed/awk hacks</li>
              <li>No CI/CD automation or static kernel verifier verification</li>
              <li>High risk of silent kernel-space crashes and memory leaks</li>
            </ul>
          </div>
        </div>

        {/* Modern Modular v10 */}
        <div className="bg-slate-900/50 border border-emerald-500/30 rounded-2xl p-6 relative overflow-hidden">
          <div className="flex items-center space-x-2.5 mb-4 text-emerald-400">
            <CheckCircle className="w-5 h-5" />
            <h3 className="text-sm font-bold uppercase tracking-wider">
              Modern Six Eyes v10 Architecture (Current)
            </h3>
          </div>
          <div className="space-y-2.5 text-xs text-slate-300">
            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/30 text-emerald-300">
              Modular eBPF + Go workspace following Linux kernel conventions and Cilium tooling standards.
            </div>
            <ul className="space-y-1.5 list-disc list-inside text-slate-300">
              <li>Clean separation of eBPF C (<code className="text-cyan-300">pkg/bpf/</code>) and Go loader</li>
              <li>User-space Go daemon (<code className="text-cyan-300">cmd/daemon/main.go</code>) with state machine</li>
              <li>Python Scapy network cartographer (<code className="text-cyan-300">scanner/cartographer.py</code>)</li>
              <li>Standard Makefile with preflight checks and bpf2go targets</li>
              <li>GitHub Actions CI matrix validating Go and Python codebases</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Subsystem Architecture Grid */}
      <div className="space-y-4">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Core Subsystems & Code Organization</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {subsystems.map((sub, idx) => (
            <div
              key={idx}
              className={`rounded-2xl border p-5 space-y-4 transition-all ${sub.color}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded-xl bg-slate-950/80 border border-slate-800">
                    {sub.icon}
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-white">{sub.title}</h4>
                    <span className="font-mono text-[11px] text-slate-400">{sub.badge}</span>
                  </div>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">{sub.description}</p>

              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
                  Core Responsibilities:
                </span>
                <ul className="space-y-1">
                  {sub.responsibilities.map((resp, i) => (
                    <li key={i} className="text-xs text-slate-300 flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0" />
                      <span>{resp}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-2 border-t border-slate-800/60">
                <span className="text-[11px] font-semibold text-slate-400 block mb-1.5">
                  Source Files:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {sub.files.map((file, i) => (
                    <button
                      key={i}
                      onClick={() => onOpenFile && onOpenFile(file)}
                      className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-950 text-slate-300 border border-slate-800 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors cursor-pointer"
                    >
                      {file}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
