/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  Cpu,
  Layers,
  ArrowRight,
  ArrowDown,
  ShieldCheck,
  ShieldAlert,
  Server,
  Laptop,
  Flame,
  CheckCircle2,
  AlertOctagon,
  RefreshCw,
  Sliders,
  Sparkles,
} from 'lucide-react';
import {
  processTcpSequenceDesync,
  TcpDesyncStrategy,
  TcpPacket,
} from '../utils/desyncEngine';

export const TcpDesyncVisualizer: React.FC = () => {
  const [strategy, setStrategy] = useState<TcpDesyncStrategy>('FAKE_RST');
  const [splitOffset, setSplitOffset] = useState<number>(2);
  const [fakeTtl, setFakeTtl] = useState<number>(3);
  const [testPayload, setTestPayload] = useState<string>(
    'GET /api/v1/user-data HTTP/1.1\r\nHost: target-service.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
  );

  const session = useMemo(() => {
    return processTcpSequenceDesync(
      100000,
      500000,
      strategy,
      testPayload,
      splitOffset,
      fakeTtl
    );
  }, [strategy, splitOffset, fakeTtl, testPayload]);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-purple-950/30 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Six Eyes eBPF TCP Sequence State Machine (v10)
            </h2>
            <p className="text-xs text-slate-400">
              Interactive visualization of kernel-space Traffic Control (TC) egress packet manipulation and sequence desynchronization.
            </p>
          </div>
        </div>
      </div>

      {/* Configuration Controls Bar */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          {/* Strategy selector */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 block">Desync Strategy</label>
            <select
              value={strategy}
              onChange={(e) => setStrategy(e.target.value as TcpDesyncStrategy)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="FAKE_RST">FAKE_RST (Injected RST with TTL=3)</option>
              <option value="HTTP_SPLIT">HTTP_SPLIT (Segment at byte offset)</option>
              <option value="TLS_RECORD_SPLIT">TLS_RECORD_SPLIT (Split ClientHello)</option>
              <option value="SEQ_OVERLAP">SEQ_OVERLAP (Decoy overlapping sequence)</option>
              <option value="OUT_OF_ORDER">OUT_OF_ORDER (Deliver tail before head)</option>
            </select>
          </div>

          {/* Split Offset */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-300">Split Offset</span>
              <span className="font-mono text-cyan-400">{splitOffset} bytes</span>
            </div>
            <input
              type="range"
              min="1"
              max="16"
              value={splitOffset}
              onChange={(e) => setSplitOffset(parseInt(e.target.value, 10))}
              disabled={strategy === 'FAKE_RST'}
              className="w-full accent-cyan-500 cursor-pointer disabled:opacity-30"
            />
          </div>

          {/* Fake RST TTL */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-300">Fake Packet TTL</span>
              <span className="font-mono text-purple-400">{fakeTtl} hops</span>
            </div>
            <input
              type="range"
              min="1"
              max="8"
              value={fakeTtl}
              onChange={(e) => setFakeTtl(parseInt(e.target.value, 10))}
              disabled={strategy !== 'FAKE_RST' && strategy !== 'SEQ_OVERLAP'}
              className="w-full accent-purple-500 cursor-pointer disabled:opacity-30"
            />
          </div>

          {/* Preset trigger */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setStrategy('FAKE_RST');
                setFakeTtl(3);
                setSplitOffset(2);
              }}
              className="w-full px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer flex items-center justify-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reset Defaults</span>
            </button>
          </div>
        </div>
      </div>

      {/* Network Hop Flow Diagram */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-white mb-6 flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Packet Traversal & Middlebox Desynchronization Topology</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative">
          {/* Node 1: Client & eBPF Engine */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-xl" />
            <div className="flex items-center space-x-3 mb-3">
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Laptop className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Client & Go Daemon
                </h4>
                <span className="font-mono text-[11px] text-slate-400">192.168.1.100:54321</span>
              </div>
            </div>
            <div className="space-y-1.5 text-xs text-slate-300">
              <div className="p-2 rounded bg-slate-900/80 border border-slate-800 font-mono text-[11px] text-cyan-300">
                SEC("classifier/egress")
              </div>
              <p className="text-[11px] text-slate-400">
                Hooks outbound TCP packets and injects sequence divergence before physical transmission.
              </p>
            </div>
          </div>

          {/* Node 2: DPI Middlebox / State Filter */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 rounded-full blur-xl" />
            <div className="flex items-center space-x-3 mb-3">
              <div className="p-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
                <AlertOctagon className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  DPI Middlebox (Hop {fakeTtl})
                </h4>
                <span className="font-mono text-[11px] text-slate-400">Stateful Reassembly</span>
              </div>
            </div>
            <div className="space-y-1.5 text-xs text-slate-300">
              <div className="p-2 rounded bg-slate-900/80 border border-slate-800 font-mono text-[11px] text-emerald-400 flex items-center justify-between">
                <span>STATE: DESYNCED</span>
                <CheckCircle2 className="w-3.5 h-3.5" />
              </div>
              <p className="text-[11px] text-slate-400">
                {strategy === 'FAKE_RST'
                  ? `Fake RST (TTL=${fakeTtl}) drops session tracking table here. Middlebox stops inspecting subsequent packets.`
                  : `Payload split at byte ${splitOffset} prevents signature matching across buffer boundaries.`}
              </p>
            </div>
          </div>

          {/* Node 3: Target Server & Cloudflare Edge */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-xl" />
            <div className="flex items-center space-x-3 mb-3">
              <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Server className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Target Server / Edge
                </h4>
                <span className="font-mono text-[11px] text-slate-400">104.16.249.249:443</span>
              </div>
            </div>
            <div className="space-y-1.5 text-xs text-slate-300">
              <div className="p-2 rounded bg-slate-900/80 border border-slate-800 font-mono text-[11px] text-emerald-300">
                HTTP/2 & TLS Established
              </div>
              <p className="text-[11px] text-slate-400">
                Receives full, genuine payload. Fake RST never arrives because its TTL expired at intermediate hop.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Generated Packet Stream Inspector */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 bg-slate-950/40 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">eBPF Packet Stream Inspector</h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {session.packetsGenerated.length} packets in sequence
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 text-[11px]">
                <th className="py-2.5 px-4">#</th>
                <th className="py-2.5 px-4">Direction</th>
                <th className="py-2.5 px-4">Seq Num</th>
                <th className="py-2.5 px-4">Ack Num</th>
                <th className="py-2.5 px-4">Flags</th>
                <th className="py-2.5 px-4">TTL</th>
                <th className="py-2.5 px-4">Length</th>
                <th className="py-2.5 px-4">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {session.packetsGenerated.map((pkt, idx) => {
                const isRst = pkt.flags.rst;
                const isData = pkt.payloadLength > 0;
                return (
                  <tr
                    key={pkt.id}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      pkt.isDesyncInjection ? 'bg-purple-950/20' : ''
                    }`}
                  >
                    <td className="py-3 px-4 text-slate-500 font-semibold">{idx + 1}</td>
                    <td className="py-3 px-4 text-slate-300">
                      <span className="flex items-center gap-1 text-slate-400">
                        <span>Egress</span>
                        <ArrowRight className="w-3 h-3 text-cyan-400" />
                      </span>
                    </td>
                    <td className="py-3 px-4 text-cyan-400">{pkt.seqNum}</td>
                    <td className="py-3 px-4 text-slate-400">{pkt.ackNum}</td>
                    <td className="py-3 px-4">
                      <div className="flex gap-1">
                        {pkt.flags.syn && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-500/20 text-blue-400">
                            SYN
                          </span>
                        )}
                        {pkt.flags.ack && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400">
                            ACK
                          </span>
                        )}
                        {pkt.flags.rst && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400 font-bold animate-pulse">
                            RST (FAKE)
                          </span>
                        )}
                        {pkt.flags.psh && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-400">
                            PSH
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`font-semibold ${
                          pkt.ttl <= 5 ? 'text-purple-400 font-bold' : 'text-slate-300'
                        }`}
                      >
                        {pkt.ttl}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{pkt.payloadLength} B</td>
                    <td className="py-3 px-4 text-slate-300 font-sans text-xs">
                      <div className="flex items-center gap-2">
                        {pkt.isDesyncInjection && (
                          <Flame className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                        )}
                        <span>{pkt.description}</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
