/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Activity,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Sliders,
  Fingerprint,
  Radio,
  Server,
  Zap,
} from 'lucide-react';
import {
  evaluateApifyFingerprintSuite,
  TcpDesyncStrategy,
  ApifyFingerprintAssessment,
} from '../utils/desyncEngine';

export const EvaluationLab: React.FC = () => {
  const [hasDesync, setHasDesync] = useState<boolean>(true);
  const [strategy, setStrategy] = useState<TcpDesyncStrategy>('FAKE_RST');
  const [browser, setBrowser] = useState<'chrome' | 'firefox' | 'safari'>('chrome');
  const [os, setOs] = useState<'windows' | 'macos' | 'linux'>('windows');
  const [runningScan, setRunningScan] = useState<boolean>(false);
  const [scanLogs, setScanLogs] = useState<string[]>([
    '[INIT] Six Eyes Autonomous DPI Evasion & Cartography Lab loaded',
    '[READY] Select profile parameters or click "Run Audit Probe"',
  ]);

  const assessment: ApifyFingerprintAssessment = evaluateApifyFingerprintSuite(
    hasDesync,
    strategy,
    browser,
    os
  );

  const handleRunScan = () => {
    setRunningScan(true);
    setScanLogs([`[*] Six Eyes probing target with ${browser} / ${os} profile...`]);

    setTimeout(() => {
      setScanLogs((prev) => [
        ...prev,
        `[*] Evaluating TLS handshake: JA4 = ${assessment.ja4Signature}`,
      ]);
    }, 400);

    setTimeout(() => {
      setScanLogs((prev) => [
        ...prev,
        hasDesync
          ? `[+] Six Eyes eBPF Desync ACTIVE: Injected ${strategy} sequence manipulation`
          : `[-] TCP Desync DISABLED: Plaintext SYN/ACK and SNI exposed to middlebox DPI`,
      ]);
    }, 800);

    setTimeout(() => {
      setScanLogs((prev) => [
        ...prev,
        `[+] Audit Complete: Bot Score = ${assessment.botScoreEstimate}/100 | Evasion = ${assessment.evasionSuccessRate}%`,
      ]);
      setRunningScan(false);
    }, 1200);
  };

  return (
    <div className="space-y-6">
      {/* Intro Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-indigo-950/40 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Fingerprint className="w-6 h-6" />
              </span>
              <div>
                <h2 className="text-xl font-bold text-white tracking-tight">
                  Six Eyes DPI Evasion & Cartography Lab
                </h2>
                <p className="text-xs text-slate-400">
                  Benchmarking middlebox DPI evasion, TLS JA4 anti-detection, and eBPF sequence desynchronization.
                </p>
              </div>
            </div>
          </div>

          <button
            onClick={handleRunScan}
            disabled={runningScan}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white shadow-lg shadow-cyan-500/25 transition-all cursor-pointer disabled:opacity-50 shrink-0"
          >
            {runningScan ? (
              <>
                <div className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin" />
                <span>Running Audit Probe...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-white" />
                <span>Run Audit Probe</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Control Panel & Live Scores */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Configuration Controls */}
        <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-5">
          <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Evaluation Parameters</h3>
          </div>

          {/* TCP Desync Toggle */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-white block">
                  eBPF TCP Desync Engine
                </span>
                <span className="text-[11px] text-slate-400">
                  Kernel-level sequence number & DPI middlebox bypass
                </span>
              </div>
              <button
                onClick={() => setHasDesync(!hasDesync)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors cursor-pointer ${
                  hasDesync ? 'bg-cyan-500' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    hasDesync ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
          </div>

          {/* Desync Strategy */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">
              Desync Strategy (v10 Kernel State Machine)
            </label>
            <select
              value={strategy}
              onChange={(e) => setStrategy(e.target.value as TcpDesyncStrategy)}
              disabled={!hasDesync}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              <option value="FAKE_RST">FAKE_RST (Injected RST with low TTL=3 / bad checksum)</option>
              <option value="HTTP_SPLIT">HTTP_SPLIT (Fragment HTTP headers across TCP segments)</option>
              <option value="TLS_RECORD_SPLIT">TLS_RECORD_SPLIT (Fragment TLS ClientHello SNI)</option>
              <option value="SEQ_OVERLAP">SEQ_OVERLAP (Duplicate sequence with decoy payload)</option>
              <option value="OUT_OF_ORDER">OUT_OF_ORDER (Deliver tail segment before head)</option>
            </select>
          </div>

          {/* Browser Profile */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">
              Target Apify Browser Profile
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { id: 'chrome', label: 'Chrome 120+' },
                { id: 'firefox', label: 'Firefox 125+' },
                { id: 'safari', label: 'Safari 17+' },
              ].map((b) => (
                <button
                  key={b.id}
                  onClick={() => setBrowser(b.id as any)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors cursor-pointer ${
                    browser === b.id
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                      : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  {b.label}
                </button>
              ))}
            </div>
          </div>

          {/* Operating System */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">Client OS</label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { id: 'windows', label: 'Windows 11' },
                { id: 'macos', label: 'macOS Sonoma' },
                { id: 'linux', label: 'Ubuntu Linux' },
              ].map((o) => (
                <button
                  key={o.id}
                  onClick={() => setOs(o.id as any)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors cursor-pointer ${
                    os === o.id
                      ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40'
                      : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  {o.label}
                </button>
              ))}
            </div>
          </div>

          {/* Security Target Suite */}
          <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-indigo-400" />
              <span>Target Benchmark:</span>
            </span>
            <span className="font-semibold text-slate-200">Apify Fingerprint Suite + Cloudflare</span>
          </div>
        </div>

        {/* Right: Real-time Evaluation Scores & Visualizer */}
        <div className="lg:col-span-7 space-y-5">
          {/* Main Bot Evasion KPI Card */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-center">
              {/* Bot Score */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block mb-1">
                  Human Bot Score
                </span>
                <div className="text-3xl font-black tracking-tight text-white flex items-center justify-center gap-1">
                  <span className={assessment.botScoreEstimate >= 80 ? 'text-emerald-400' : 'text-amber-400'}>
                    {assessment.botScoreEstimate}
                  </span>
                  <span className="text-xs text-slate-500 font-normal">/ 100</span>
                </div>
                <span className="text-[10px] text-slate-400 mt-1 block">
                  {assessment.botScoreEstimate >= 80 ? 'Classified as Human' : 'Classified as Bot'}
                </span>
              </div>

              {/* Evasion Rate */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block mb-1">
                  Evasion Success
                </span>
                <div className="text-3xl font-black tracking-tight text-cyan-400">
                  {assessment.evasionSuccessRate}%
                </div>
                <span className="text-[10px] text-slate-400 mt-1 block">
                  Middlebox & WAF bypass rate
                </span>
              </div>

              {/* Status */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col items-center justify-center">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block mb-1">
                  Middlebox State
                </span>
                {hasDesync ? (
                  <div className="flex items-center gap-1.5 text-emerald-400 text-sm font-bold">
                    <ShieldCheck className="w-5 h-5" />
                    <span>DESYNCED</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5 text-red-400 text-sm font-bold">
                    <ShieldAlert className="w-5 h-5" />
                    <span>INSPECTED</span>
                  </div>
                )}
                <span className="text-[10px] text-slate-400 mt-1 block">
                  {hasDesync ? 'DPI session table poisoned' : 'Plaintext SNI visible'}
                </span>
              </div>
            </div>

            {/* JA4 Signature Bar */}
            <div className="mt-5 p-3.5 rounded-xl bg-slate-950 border border-slate-800/90">
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Synthesized JA4 TLS Fingerprint:</span>
                </span>
                <span className="text-[11px] font-mono text-emerald-400">Valid Apify Model Match</span>
              </div>
              <div className="font-mono text-xs text-cyan-300 bg-slate-900 px-3 py-2 rounded-lg border border-slate-800 select-all overflow-x-auto">
                {assessment.ja4Signature}
              </div>
            </div>

            {/* Consistency Breakdown Progress Bars */}
            <div className="mt-5 space-y-3">
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300">TLS ClientHello Signature Consistency</span>
                  <span className="font-mono font-semibold text-slate-200">{assessment.tlsConsistency}%</span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-cyan-400 rounded-full transition-all duration-500"
                    style={{ width: `${assessment.tlsConsistency}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300">TCP Stack Signature (MSS, Window Scale, TTL)</span>
                  <span className="font-mono font-semibold text-slate-200">{assessment.tcpStackMatch}%</span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      assessment.tcpStackMatch >= 80 ? 'bg-emerald-400' : 'bg-amber-400'
                    }`}
                    style={{ width: `${assessment.tcpStackMatch}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300">HTTP/2 SETTINGS Frame Ordering Coherence</span>
                  <span className="font-mono font-semibold text-slate-200">{assessment.http2SettingsCoherence}%</span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-indigo-400 rounded-full transition-all duration-500"
                    style={{ width: `${assessment.http2SettingsCoherence}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Diagnostic Signals & Flags */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
              Auditor Diagnostic Signals
            </h4>
            <div className="space-y-2">
              {assessment.flagsDetected.map((flag, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2.5 text-xs px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-300"
                >
                  {hasDesync ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                  )}
                  <span>{flag}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Live Scanner Output Log */}
          <div className="bg-slate-950 border border-slate-800 rounded-2xl p-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2 text-slate-400 text-[11px]">
              <span className="flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                <span>Live Probe Audit Log</span>
              </span>
              <span>python3 scanner/evaluator.py</span>
            </div>
            <div className="space-y-1 text-slate-300 max-h-36 overflow-y-auto">
              {scanLogs.map((log, i) => (
                <div key={i} className="leading-relaxed">
                  {log}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
