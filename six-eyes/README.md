# SIX EYES (六眼) - Autonomous DPI Evasion Daemon

[![CI Pipeline](https://github.com/six-eyes/six-eyes/actions/workflows/ci.yml/badge.svg)](https://github.com/six-eyes/six-eyes/actions)
[![License](https://img.shields.io/badge/License-Dual%20GPL%2FBSD-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/eBPF-TC%20%2F%20XDP-orange.svg)](https://ebpf.io)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)

**SIX EYES** is an autonomous, kernel-space TCP sequence desynchronization and middlebox counter-surveillance daemon built on Linux **eBPF (Traffic Control)** and **Go**.

---

## ⚡ The TCP Sequence State Machine

Stateful Deep Packet Inspection (DPI) middleboxes inspect the plaintext SNI of TLS ClientHello and HTTP Host headers by maintaining an in-memory reassembly queue.

```
Client (Six Eyes Daemon)             DPI Middlebox                Upstream Target
      |                                    |                             |
      |--- 1. TCP SYN -------------------->|---------------------------->|
      |<-- 2. TCP SYN-ACK -----------------|<----------------------------|
      |--- 3. TCP ACK (Established) ------>|---------------------------->|
      |                                    |                             |
      |=== 4. eBPF INJECT FAKE RST ======> | (DPI Session Table POISONED)|
      |    (TTL=3, bad checksum)           | (Packet dies before Target) |
      |                                                                  |
      |--- 5. Real Payload (SNI) --------------------------------------->|
      |    (Bypasses DPI Wire Sniffer)                                   |
```

### Supported Evasion Strategies:
- **`FAKE_RST`**: Injects a forged TCP RST packet with a calibrated low TTL (e.g. 3 hops). The packet reaches and poisons the DPI middlebox's session table, causing it to discard inspection, while expiring before reaching the target web server.
- **`HTTP_SPLIT` / `TLS_RECORD_SPLIT`**: Segments the initial 2 bytes of the payload across TCP packet boundaries, foiling regex pattern matching.
- **`SEQ_OVERLAP`**: Transmits duplicate sequence numbers with decoy payloads to corrupt the middlebox's reassembly buffer.
- **`OUT_OF_ORDER`**: Transmits trailing TCP segments before the initial segment.

---

## 🚀 Quick Start: Pushing to Your Connected GitHub Account

```bash
# 1. Initialize git in the six-eyes directory
git init

# 2. Stage all modular files
git add .

# 3. Create initial structured migration commit
git commit -m "feat(core): initialize six-eyes v10 autonomous eBPF DPI evasion daemon"

# 4. Set main branch
git branch -M main

# 5. Add your remote
git remote add origin https://github.com/<YOUR_USER>/six-eyes.git

# 6. Push to GitHub
git push -u origin main
```

---

## 🛠️ Build & Installation

```bash
# Run preflight checks, compile eBPF bytecode, and build Go daemon
make all

# Run unit tests
make test

# Launch middlebox cartographer probe
python3 scanner/cartographer.py --target cloudflare.com
```
