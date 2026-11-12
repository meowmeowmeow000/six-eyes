# Six Eyes

Six Eyes is a Linux-focused research framework for studying TCP desynchronization, active middlebox behavior, and DPI evasion patterns in controlled environments. It combines a Go daemon, eBPF-based packet manipulation, and a small scanner utility to model how network inspection systems react to malformed or strategically desynchronized TCP flows.

The project is designed for experimentation, architecture exploration, and defensive research rather than for indiscriminate network use. It is intended to be run only in authorized test environments where you have explicit permission to evaluate network behavior.

## What this project does

At a high level, Six Eyes focuses on:

- Observing how middleboxes inspect and reassemble TCP streams
- Mutating packet timing, sequence patterns, and payload boundaries
- Testing DPI evasion strategies in a controlled lab setup
- Emitting telemetry and structured results for analysis

The system is organized around a small set of core components:

- `cmd/daemon`: service entrypoint and runtime control
- `pkg/bpf`: eBPF C code and loader integration
- `pkg/desync`: TCP desynchronization state machine logic
- `pkg/proxy`: transparent proxy / relay behavior
- `pkg/config`: strategy and profile configuration
- `pkg/scanner`: scan utilities for target and path discovery
- `scanner/`: Python-based middlebox/cartographer helpers

## Architecture overview

The daemon is built around a Go control plane with an eBPF datapath. The idea is to let the kernel observe and manipulate packet flows while the Go service orchestrates policy, telemetry, and runtime configuration.

A typical execution flow looks like this:

1. The daemon boots and loads configuration profiles.
2. The eBPF program attaches to the relevant traffic path and monitors packet flows.
3. The desync logic computes sequence-handling strategies based on the configured profile.
4. Packet mutations are applied to influence how inspection systems reconstruct and classify traffic.
5. Telemetry and diagnostic events are captured for analysis.

## Repository layout

```text
six-eyes/
├── cmd/
│   └── daemon/
├── pkg/
│   ├── bpf/
│   ├── config/
│   ├── coordinator/
│   ├── desync/
│   ├── ipc/
│   ├── proxy/
│   ├── scanner/
│   ├── selftest/
│   └── telemetry/
├── scanner/
├── configs/
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── go.mod
├── six_eyes_architecture.md
├── README.md
└── ...
```

## Requirements

This project is intended for Linux hosts with elevated networking capabilities. In practice, you will typically need:

- Linux kernel with BPF support
- Root or CAP_NET_ADMIN privileges
- Go 1.22+
- Clang / LLVM
- Python 3
- iproute2 and related packet tooling

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/<your-user>/six-eyes.git
cd six-eyes
```

### 2. Install dependencies

```bash
make deps
```

### 3. Build the daemon

```bash
make build
```

This generates the required bytecode and produces the binary under `bin/`.

### 4. Run the daemon

```bash
sudo ./bin/six-eyes
```

The project also includes a container-based setup for development or repeatable testing:

```bash
docker compose up --build
```

## Available workflows

The project includes a few operational entrypoints:

- `make all` - run preflight checks and build the project
- `make test` - run Go test coverage for the package set
- `make clean` - remove generated artifacts
- `make git-setup` - initialize a Git repository scaffold on the `main` branch

## Safety and responsible use

Six Eyes is a research and testing project. It should only be used where you have explicit authorization to test and analyze network behavior. Avoid running it against public or shared infrastructure without consent.

This repository is intended for:

- Security research
- Defensive packet analysis
- Lab-based network experimentation
- Architecture and protocol understanding

It is not intended for unauthorized network interference.

## Further reading

For deeper design notes, see:

- `six_eyes_architecture.md` - architecture and conceptual overview
- `configs/` - configuration profiles
- `scanner/` - middlebox discovery and traffic-oriented helper tooling

## License

This project is distributed under the repository's chosen license terms. Please review the license file in the repository before redistribution or commercial use.
