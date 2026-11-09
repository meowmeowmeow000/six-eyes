# SIX EYES (六眼) - Architectural Blueprint

## The Doctrine of the 6th Eye

"Six Eyes" operates on two fundamental dimensions:

1. **The Geopolitical Level (The 6th Eye)**:
   A direct challenge to the Five Eyes (FVEY) global intelligence apparatus. Designed as a counter-surveillance weapon against state-level Deep Packet Inspection (DPI), active middleboxes, and national firewalls. We perceive and evade the watchers by poisoning their stateful connection tables.

2. **The Atomic Kernel Level (Infinitesimal Sequence Control)**:
   Like Gojo Satoru's Six Eyes granting boundless perception of energy flows, our eBPF engine perceives the sub-atomic flow of TCP sequence numbers, window scalers, and packet boundaries directly at the kernel hook (`SEC("classifier/egress")`).

---

## Directory Taxonomy

```
six-eyes/
├── cmd/
│   └── daemon/
│       └── main.go                 # Daemon entry point & IPC control
├── pkg/
│   ├── bpf/
│   │   ├── tcp_desync.bpf.c        # In-kernel C sequence mutator
│   │   ├── headers.h               # Packet flow definitions
│   │   ├── maps.h                  # BPF hash & array map definitions
│   │   └── loader.go               # bpf2go loader integration
│   ├── desync/
│   │   └── state_machine.go        # v10 Sequence state coordinator
│   ├── proxy/
│   │   └── socks5.go               # Transparent SOCKS5 multiplexer
│   └── config/
│       └── profile.go              # Strategy configuration reader
├── scanner/
│   └── cartographer.py             # Scapy middlebox TTL hop discovery
├── configs/
│   └── stealth.yaml                # Standard FAKE_RST profile
├── Makefile                        # Compilation scaffold
├── Dockerfile                      # Hermetic container definition
└── docker-compose.yml              # Multi-tier runtime
```
