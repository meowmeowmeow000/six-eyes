package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/meowmeowmeow000/six-eyes/pkg/bpf"
	"github.com/meowmeowmeow000/six-eyes/pkg/config"
	"github.com/meowmeowmeow000/six-eyes/pkg/coordinator"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/factory"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/pool"
	"github.com/meowmeowmeow000/six-eyes/pkg/telemetry"
)

const SockAddr = "/run/six-eyes/six_eyes_v10.sock"

type IPCCommand struct {
	Action       string                `json:"action"`
	Route        config.RouteCandidate `json:"route,omitempty"`
	ExpectedTTL  uint8                 `json:"expected_ttl,omitempty"`
	TTLTolerance uint8                 `json:"ttl_tolerance,omitempty"`
	Lockdown     bool                  `json:"lockdown,omitempty"`
	StealthMode  string                `json:"stealth_mode,omitempty"`
	FragDelayMs  int                   `json:"frag_delay_ms,omitempty"`
	JitterMs     int                   `json:"jitter_ms,omitempty"`
}

type IPCResponse struct {
	Status   string                   `json:"status"`
	Message  string                   `json:"message,omitempty"`
	Snapshot *telemetry.VitalSnapshot `json:"snapshot,omitempty"`
}

func StartControlPlane(ctx context.Context, warmPool *pool.WarmPool, strat *coordinator.Strategist) {
	if err := os.MkdirAll(filepath.Dir(SockAddr), 0700); err != nil {
		telemetry.Log.Error("IPC runtime directory unavailable", slog.String("err", err.Error()))
		return
	}
	if err := os.Chmod(filepath.Dir(SockAddr), 0700); err != nil {
		telemetry.Log.Error("Could not secure IPC runtime directory", slog.String("err", err.Error()))
		return
	}
	if _, err := os.Lstat(SockAddr); err == nil {
		telemetry.Log.Error("IPC socket path already exists; refusing to remove or replace it", slog.String("path", SockAddr))
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		telemetry.Log.Error("Could not inspect IPC socket path", slog.String("err", err.Error()))
		return
	}

	listener, err := net.Listen("unix", SockAddr)
	if err != nil {
		telemetry.Log.Error("IPC Unix socket failed to bind", slog.String("err", err.Error()))
		return
	}
	if err := os.Chmod(SockAddr, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(SockAddr)
		telemetry.Log.Error("Could not secure IPC socket", slog.String("err", err.Error()))
		return
	}
	ownedInfo, err := os.Lstat(SockAddr)
	if err != nil {
		_ = listener.Close()
		telemetry.Log.Error("Could not inspect bound IPC socket", slog.String("err", err.Error()))
		return
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
		if current, err := os.Lstat(SockAddr); err == nil && os.SameFile(ownedInfo, current) {
			_ = os.Remove(SockAddr)
		}
	}()
	telemetry.Log.Info("Six Eyes IPC Control Plane Listening", slog.String("socket", SockAddr))

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleIPCConn(conn, warmPool, strat)
	}
}

func handleIPCConn(conn net.Conn, warmPool *pool.WarmPool, strat *coordinator.Strategist) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var cmd IPCCommand
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&cmd); err != nil {
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: err.Error()})
		return
	}
	if warmPool == nil {
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "warm pool unavailable"})
		return
	}

	switch cmd.Action {
	case "inject_route":
		if cmd.Route.TargetIP == "" || net.ParseIP(cmd.Route.TargetIP) == nil {
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "route.target_ip must be a valid IP address"})
			return
		}
		switch cmd.Route.StealthMode {
		case "", factory.ModeTLSFrag, factory.ModeTLSMicroFrag, factory.ModeTLSDisorder, factory.ModeSNIFront:
		default:
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "unknown stealth_mode: " + cmd.Route.StealthMode})
			return
		}
		if cmd.Route.ExpectedTTL > 0 {
			tol := cmd.TTLTolerance
			if tol == 0 {
				tol = 3
			}
			bpf.UpdateXDPConfig(cmd.Route.ExpectedTTL, tol, cmd.Lockdown)
		}
		warmPool.InjectEmergencyRoute(cmd.Route)
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "route injected"})

	case "lockdown_xdp":
		bpf.UpdateXDPConfig(cmd.ExpectedTTL, cmd.TTLTolerance, cmd.Lockdown)
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "XDP configuration updated"})

	case "escalate_stealth":
		warmPool.EscalateStealthMode(cmd.StealthMode, cmd.FragDelayMs, cmd.JitterMs)
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "stealth mode updated"})

	case "status":
		active := warmPool.ActiveRoute()
		snap := &telemetry.VitalSnapshot{
			ActiveStreams:   telemetry.ActiveStreams.Load(),
			WarmPipes:       telemetry.PoolHealthyPipes.Load(),
			TxKB:            telemetry.TotalBytesTx.Load() / 1024,
			RxKB:            telemetry.TotalBytesRx.Load() / 1024,
			RouteRotations:  telemetry.RouteRotations.Load(),
			ModeEscalations: telemetry.ModeEscalations.Load(),
			XDPDroppedPkts:  telemetry.XDPDroppedRSTs.Load(),
			IPCOverrides:    telemetry.IPCOverrides.Load(),
			DialFailures:    telemetry.DialFailures.Load(),
			ExpectedTTL:     telemetry.CurrentExpectedTTL.Load(),
			TTLTolerance:    telemetry.CurrentTTLTolerance.Load(),
			XDPLockdown:     telemetry.CurrentLockdownMode.Load() == 1,
			ActiveRouteIP:   active.TargetIP,
			ActiveStealth:   active.StealthMode,
		}
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Snapshot: snap})
	default:
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: fmt.Sprintf("unknown IPC action: %s", cmd.Action)})
	}
}
