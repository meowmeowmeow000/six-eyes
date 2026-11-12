package bpf

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/meowmeowmeow000/six-eyes/pkg/telemetry"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_filter.c -- -I/usr/include/bpf -O2

const (
	cfgIdxExpectedTTL  uint32 = 0
	cfgIdxTTLTolerance uint32 = 1
	cfgIdxLockdownMode uint32 = 2
)

var (
	activeConfigMap *ebpf.Map
	mapMu           sync.RWMutex
)

func UpdateXDPConfig(expectedTTL, tolerance uint8, lockdown bool) uint64 {
	if tolerance == 0 {
		tolerance = 4
	}
	var lockVal uint32
	if lockdown {
		lockVal = 1
	}
	epoch := telemetry.XDPLockdownEpoch.Add(1)
	telemetry.CurrentExpectedTTL.Store(uint32(expectedTTL))
	telemetry.CurrentTTLTolerance.Store(uint32(tolerance))
	telemetry.CurrentLockdownMode.Store(lockVal)

	mapMu.RLock()
	m := activeConfigMap
	mapMu.RUnlock()
	if m == nil {
		return epoch
	}

	expVal := uint32(expectedTTL)
	tolVal := uint32(tolerance)
	_ = m.Put(cfgIdxExpectedTTL, expVal)
	_ = m.Put(cfgIdxTTLTolerance, tolVal)
	_ = m.Put(cfgIdxLockdownMode, lockVal)

	telemetry.Log.Info("Kernel eBPF Map Hot-Swapped",
		slog.Uint64("expected_ttl", uint64(expVal)),
		slog.Uint64("ttl_tolerance", uint64(tolVal)),
		slog.Bool("lockdown_mode", lockdown))
	return epoch
}

func StartXDPRSTMonitor(ctx context.Context, ifaceName string, initialTTL, initialTol uint8, burstThreshold uint64, onSpike func()) {
	UpdateXDPConfig(initialTTL, initialTol, false)
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		telemetry.Log.Warn("XDP interface unavailable; continuing in userspace-only mode",
			slog.String("iface", ifaceName), slog.String("err", err.Error()))
		return
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		telemetry.Log.Warn("Kernel eBPF load skipped (check CAP_BPF/root); userspace engine unaffected",
			slog.String("err", err.Error()))
		return
	}
	defer func() {
		mapMu.Lock()
		activeConfigMap = nil
		mapMu.Unlock()
		objs.Close()
	}()

	mapMu.Lock()
	activeConfigMap = objs.XdpConfigMap
	mapMu.Unlock()

	UpdateXDPConfig(
		uint8(telemetry.CurrentExpectedTTL.Load()),
		uint8(telemetry.CurrentTTLTolerance.Load()),
		telemetry.CurrentLockdownMode.Load() == 1,
	)

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.FilterDpiRst,
		Interface: iface.Index,
	})
	if err != nil {
		telemetry.Log.Warn("XDP native attach failed; continuing without kernel shield",
			slog.String("iface", ifaceName), slog.String("err", err.Error()))
		return
	}
	defer xdpLink.Close()

	telemetry.Log.Info("Six Eyes XDP Dynamic Kernel Armor Engaged",
		slog.String("iface", ifaceName),
		slog.Uint64("expected_ttl", uint64(initialTTL)),
		slog.Uint64("tolerance", uint64(initialTol)))

	if burstThreshold == 0 {
		burstThreshold = 5
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastCount uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var key uint32 = 0
			var current uint64
			if err := objs.RstDropCounter.Lookup(&key, &current); err == nil {
				if current > lastCount {
					delta := current - lastCount
					lastCount = current
					telemetry.XDPDroppedRSTs.Store(current)
					telemetry.Log.Warn("XDP intercepted forged DPI TCP RST/FIN packets",
						slog.Uint64("dropped_delta", delta),
						slog.Uint64("total_dropped", current))
					if delta >= burstThreshold && onSpike != nil {
						onSpike()
					}
				}
			}
		}
	}
}
