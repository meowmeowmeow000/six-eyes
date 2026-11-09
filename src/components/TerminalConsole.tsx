/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Terminal as TerminalIcon, Play, Trash2, Copy, Check, Sparkles } from 'lucide-react';

interface TerminalConsoleProps {
  initialCommand?: string;
}

export const TerminalConsole: React.FC<TerminalConsoleProps> = ({ initialCommand }) => {
  const [commandInput, setCommandInput] = useState<string>(initialCommand || 'make all');
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState<Array<{ command: string; output: string }>>([
    {
      command: 'git status',
      output: `On branch main
nothing to commit, working tree clean
Last commit: 148ace8 feat(core): initialize six-eyes v10 autonomous eBPF DPI evasion daemon`,
    },
    {
      command: 'make all',
      output: `[+] Running preflight checks...
[+] Generating eBPF bytecode via clang / bpf2go...
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c pkg/bpf/tcp_desync.bpf.c -o bin/tcp_desync.bpf.o
[+] Compiling six-eyes binary...
go build -trimpath -ldflags="-s -w" -o bin/six-eyes ./cmd/daemon/main.go
[+] Build complete: bin/six-eyes`,
    },
  ]);

  const presetCommands = [
    { label: 'make all', cmd: 'make all' },
    { label: 'python3 cartographer', cmd: 'python3 scanner/cartographer.py --target api.openai.com' },
    { label: 'make test', cmd: 'make test' },
    { label: 'git log', cmd: 'git log -n 1 --stat' },
    { label: 'bpftool map dump', cmd: 'bpftool map dump name session_map' },
    { label: 'test proxy', cmd: 'curl -x socks5h://127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace' },
  ];

  const handleRunCommand = (cmdToRun: string) => {
    const cmd = cmdToRun.trim();
    if (!cmd) return;

    let output = '';

    if (cmd === 'make all' || cmd === 'make build') {
      output = `[+] Running preflight checks...
[+] Generating eBPF bytecode via clang / bpf2go...
mkdir -p bin
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c pkg/bpf/tcp_desync.bpf.c -o bin/tcp_desync.bpf.o
[+] Compiling six-eyes binary...
go build -trimpath -ldflags="-s -w" -o bin/six-eyes ./cmd/daemon/main.go
[+] Build complete: bin/six-eyes`;
    } else if (cmd.includes('cartographer') || cmd.includes('scanner')) {
      output = `[+] Six Eyes Active Cartographer probing target: api.openai.com:443
[+] Resolving DNS... 104.18.32.7
[*] Phase 1: Traceroute TTL probing to identify middlebox hop boundary...
    Hop  1: 192.168.1.1 (Gateway) - TTL=1 (RTT 1.2ms)
    Hop  2: 10.200.0.1 (ISP Ingress) - TTL=2 (RTT 5.8ms)
    Hop  3: [!] DPI Inspection Node Detected (Stateful Inspection Middlebox) - TTL=3 (RTT 9.4ms)
    Hop  4: 104.18.32.7 (Target Edge) - TTL=4 (RTT 14.1ms)
[*] Middlebox detected at Hop 3. Calculated Fake RST TTL: 3.
[*] Phase 2: Testing desynchronization strategies...
    -> FAKE_RST (TTL=3): DPI state poisoned. Real payload bypassed. (PASS)
    -> HTTP_SPLIT (offset=2): SNI match fragmented. (PASS)
[+] Optimal evasion profile generated in configs/stealth.yaml.`;
    } else if (cmd === 'make test') {
      output = `?   	github.com/six-eyes/six-eyes/cmd/daemon	[no test files]
=== RUN   TestStateMachine
=== RUN   TestStateMachine/FakeRst
=== RUN   TestStateMachine/HttpSplit
=== RUN   TestStateMachine/SeqOverlap
--- PASS: TestStateMachine (0.02s)
PASS
ok  	github.com/six-eyes/six-eyes/pkg/desync	0.038s
PASS
ok  	github.com/six-eyes/six-eyes/pkg/config	0.011s`;
    } else if (cmd.includes('git log')) {
      output = `commit 148ace8 feat(core): initialize six-eyes v10 autonomous eBPF DPI evasion daemon (HEAD -> main)
Author: Six Eyes Operator <daemon@six-eyes.internal>
Date:   Mon Nov 9 16:56:49 2026 +0000

    feat(core): initialize six-eyes v10 autonomous eBPF DPI evasion daemon

 .github/workflows/ci.yml         |  43 +++++++++++++++
 Dockerfile                       |  34 ++++++++++++
 Makefile                         |  58 ++++++++++++++++++++
 README.md                        | 134 +++++++++++++++++++++++++++++++++++++++
 configs/stealth.yaml             |  18 ++++++
 docker-compose.yml               |  24 ++++++++
 go.mod                           |  12 ++++
 pkg/bpf/headers.h                |  44 +++++++++++++++
 pkg/bpf/loader.go                |  42 +++++++++++++
 pkg/bpf/maps.h                   |  32 +++++++++++
 pkg/bpf/tcp_desync.bpf.c         | 129 ++++++++++++++++++++++++++++++++++++++++++++
 pkg/config/profile.go            |  48 +++++++++++++++
 pkg/desync/state_machine.go      |  82 ++++++++++++++++++++++++++
 pkg/proxy/socks5.go              |  68 ++++++++++++++++++++++
 scanner/cartographer.py          | 124 +++++++++++++++++++++++++++++++++++++++
 six_eyes_architecture.md         | 112 +++++++++++++++++++++++++++++++++++
 17 files changed, 978 insertions(+)`;
    } else if (cmd.includes('bpftool')) {
      output = `[{
  "key": {
    "saddr": "192.168.1.100",
    "daddr": "104.16.249.249",
    "sport": 54321,
    "dport": 443
  },
  "value": {
    "current_seq": 1000045,
    "current_ack": 5000012,
    "strategy": 1,
    "split_offset": 2,
    "fake_rst_ttl": 3,
    "packets_seen": 42,
    "bytes_desynced": 65420,
    "last_seen_ns": 1731171800123456789
  }
}]`;
    } else if (cmd.includes('curl') || cmd.includes('proxy')) {
      output = `HTTP/2 200
date: Mon, 09 Nov 2026 16:58:12 GMT
content-type: text/plain; charset=UTF-8
server: cloudflare

fl=104f12
h=cloudflare.com
ip=192.168.1.100
ts=1731171492.381
visit_scheme=https
uag=Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
colo=IAD
sliver=none
http=http/2
loc=US
tls=TLSv1.3
sni=plaintext (Bypassed via Six Eyes eBPF desync)
warp=off
gateway=off
rbi=off
kex=X25519`;
    } else if (cmd === 'git status') {
      output = `On branch main
nothing to commit, working tree clean
Last commit: 148ace8 feat(core): initialize six-eyes v10 autonomous eBPF DPI evasion daemon`;
    } else {
      output = `six-eyes: executed '${cmd}'. Status: OK.`;
    }

    setHistory((prev) => [...prev, { command: cmd, output }]);
    setCommandInput('');
  };

  const handleClear = () => {
    setHistory([]);
  };

  const handleCopyHistory = () => {
    const text = history.map((h) => `$ ${h.command}\n${h.output}`).join('\n\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
      {/* Terminal Title Bar */}
      <div className="px-5 py-3.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center space-x-2.5">
          <div className="flex space-x-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <span className="text-xs font-mono font-medium text-slate-300 flex items-center gap-1.5 ml-2">
            <TerminalIcon className="w-3.5 h-3.5 text-cyan-400" />
            <span>six-eyes-operator@kernel-tc:~/six-eyes$</span>
          </span>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleCopyHistory}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
            title="Copy session output"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={handleClear}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
            title="Clear terminal"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Preset Command Shortcuts */}
      <div className="px-5 py-2.5 bg-slate-950/40 border-b border-slate-800/80 flex items-center gap-2 overflow-x-auto scrollbar-none">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider shrink-0 flex items-center gap-1">
          <Sparkles className="w-3 h-3 text-cyan-400" />
          <span>Quick:</span>
        </span>
        {presetCommands.map((preset, i) => (
          <button
            key={i}
            onClick={() => handleRunCommand(preset.cmd)}
            className="px-2.5 py-1 rounded-md text-[11px] font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 hover:border-slate-600 transition-colors cursor-pointer shrink-0"
          >
            {preset.label}
          </button>
        ))}
      </div>

      {/* Terminal Screen */}
      <div className="p-5 font-mono text-xs text-slate-200 bg-slate-950 min-h-[360px] max-h-[500px] overflow-y-auto space-y-4">
        {history.map((item, idx) => (
          <div key={idx} className="space-y-1">
            <div className="flex items-center space-x-2 text-cyan-400">
              <span className="text-emerald-400 font-bold">six-eyes:~$</span>
              <span className="text-white font-semibold">{item.command}</span>
            </div>
            <pre className="text-slate-300 text-xs whitespace-pre-wrap leading-relaxed pl-4 border-l border-slate-800">
              {item.output}
            </pre>
          </div>
        ))}

        {/* Input prompt line */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleRunCommand(commandInput);
          }}
          className="flex items-center space-x-2 pt-2"
        >
          <span className="text-emerald-400 font-bold">six-eyes:~$</span>
          <input
            type="text"
            value={commandInput}
            onChange={(e) => setCommandInput(e.target.value)}
            placeholder="Type command (e.g., make all, make test, git status)..."
            className="flex-1 bg-transparent border-none text-white font-mono text-xs focus:outline-none placeholder-slate-600"
          />
          <button
            type="submit"
            className="p-1 rounded bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors cursor-pointer"
          >
            <Play className="w-3 h-3" />
          </button>
        </form>
      </div>
    </div>
  );
};
