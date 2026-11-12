package telemetry

import (
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
)

const Banner = `
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║   👁️  SIX EYES v10.0 // AUTONOMOUS eBPF KERNEL MULTIPLEXER & DESYNC      ║
  ╠══════════════════════════════════════════════════════════════════════════╣
  ║   [Scapy Sculptor] ──(Unix IPC)──► [Strategic Coordinator]               ║
  ║         │                                 │                              ║
  ║    Live Hop/TTL                     Hot-Swaps Maps &                     ║
  ║    Echolocation                     Escalates Frag Mode                  ║
  ║         ▼                                 ▼                              ║
  ║   [XDP eBPF Shield] ◄────────────► [Warm Pool: 3x SMUX v1] ──► [uTLS]    ║
  ║    Dynamic TTL Lockdown             3-Slice / 5-Slice SNI Split          ║
  ╚══════════════════════════════════════════════════════════════════════════╝
`

var (
	Log                 *slog.Logger
	ActiveStreams       atomic.Int64
	PoolHealthyPipes    atomic.Int64
	TotalBytesTx        atomic.Uint64
	TotalBytesRx        atomic.Uint64
	RouteRotations      atomic.Uint64
	ModeEscalations     atomic.Uint64
	XDPDroppedRSTs      atomic.Uint64
	IPCOverrides        atomic.Uint64
	DialFailures        atomic.Uint64
	CurrentExpectedTTL  atomic.Uint32
	CurrentTTLTolerance atomic.Uint32
	CurrentLockdownMode atomic.Uint32
	XDPLockdownEpoch    atomic.Uint64
)

type VitalSnapshot struct {
	ActiveStreams   int64  `json:"active_streams"`
	WarmPipes       int64  `json:"warm_pipes"`
	TxKB            uint64 `json:"tx_kb"`
	RxKB            uint64 `json:"rx_kb"`
	RouteRotations  uint64 `json:"route_rotations"`
	ModeEscalations uint64 `json:"mode_escalations"`
	XDPDroppedPkts  uint64 `json:"xdp_dropped_pkts"`
	IPCOverrides    uint64 `json:"ipc_overrides"`
	DialFailures    uint64 `json:"dial_failures"`
	ExpectedTTL     uint32 `json:"xdp_expected_ttl"`
	TTLTolerance    uint32 `json:"xdp_ttl_tolerance"`
	XDPLockdown     bool   `json:"xdp_lockdown_active"`
	ActiveRouteIP   string `json:"active_route_ip"`
	ActiveStealth   string `json:"active_stealth_mode"`
}

func InitLogger(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	Log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(Log)
}

func PrintBanner() {
	fmt.Print(Banner)
}
