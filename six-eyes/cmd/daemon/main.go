package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/meowmeowmeow000/six-eyes/pkg/bpf"
	"github.com/meowmeowmeow000/six-eyes/pkg/config"
	"github.com/meowmeowmeow000/six-eyes/pkg/coordinator"
	"github.com/meowmeowmeow000/six-eyes/pkg/ipc"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/factory"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/pool"
	"github.com/meowmeowmeow000/six-eyes/pkg/scanner"
	"github.com/meowmeowmeow000/six-eyes/pkg/telemetry"
)

func queryIPCStatus() {
	conn, err := net.DialTimeout("unix", ipc.SockAddr, 2*time.Second)
	if err != nil {
		fmt.Printf("[-] Engine IPC unreachable at %s: %v\n", ipc.SockAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	_ = json.NewEncoder(conn).Encode(ipc.IPCCommand{Action: "status"})
	var resp ipc.IPCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		fmt.Printf("[-] Failed decoding IPC status: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(out))
}

func main() {
	// --- Mode Selection Flags ---
	mapMode := flag.Bool("map", false, "Run Go Cartographer to probe routes and generate Strategic combat.profile")
	runMode := flag.Bool("run", false, "Run the Autonomous Six Eyes v10 Engine")
	statusMode := flag.Bool("status", false, "Query live engine telemetry over Unix IPC socket")

	// --- Cartographer / Scanner Upgraded Flags ---
	workerHost := flag.String("worker", "my-proxy.workers.dev", "Cloudflare Worker hostname (used in --map mode)")
	customIPs := flag.String("ips", "", "Optional comma-separated Cloudflare edge IPs to probe")
	cidrBlock := flag.String("cidr", "", "Mass scan a target CIDR block (e.g. '104.16.0.0/14' or '172.64.0.0/13')")
	concurrency := flag.Int("c", 50, "Number of concurrent worker goroutines for --map pool")
	probeTimeout := flag.Duration("timeout", 4*time.Second, "Timeout per individual probe connection")
	atlasFile := flag.String("atlas", "atlas.json", "Output file for raw scanner intelligence report")
	profileFile := flag.String("profile", "combat.profile", "Output file for generated strategic combat profile")

	// --- Legacy & Engine Flags ---
	verifyWS := flag.Bool("verify-ws", true, "Verify full WebSocket 101 upgrade against worker during --map")
	baselineTTL := flag.Int("ttl", 0, "Baseline server SYN+ACK TTL measured via Scapy (0 = unknown)")
	ifaceName := flag.String("iface", "eth0", "Network interface for XDP Kernel Shield")
	listenAddr := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	verbose := flag.Bool("v", false, "Enable verbose debug telemetry")
	flag.Parse()

	telemetry.InitLogger(*verbose)

	// Mode 1: Query IPC Telemetry
	if *statusMode {
		queryIPCStatus()
		return
	}

	// Mode 2: Upgraded Go Cartographer (Senpai Scanner Engine)
	if *mapMode {
		telemetry.PrintBanner()
		telemetry.Log.Info("Launching Six Eyes Cartographer Engine v10",
			slog.String("worker", *workerHost),
			slog.Int("concurrency", *concurrency),
			slog.Duration("timeout", *probeTimeout),
			slog.Bool("verify_ws", *verifyWS),
			slog.Int("baseline_ttl", *baselineTTL))

		var targetIPs []string

		// 1. Expand CIDR block if provided
		if *cidrBlock != "" {
			expanded, err := scanner.ExpandCIDR(*cidrBlock)
			if err != nil {
				fmt.Printf("[-] Invalid CIDR block block '%s': %v\n", *cidrBlock, err)
				os.Exit(1)
			}
			targetIPs = append(targetIPs, expanded...)
		}

		// 2. Parse custom comma-separated IPs if provided
		if *customIPs != "" {
			for _, ip := range strings.Split(*customIPs, ",") {
				trimmed := strings.TrimSpace(ip)
				if trimmed != "" {
					targetIPs = append(targetIPs, trimmed)
				}
			}
		}

		// 3. Fallback default Cloudflare IPs if no targets specified
		if len(targetIPs) == 0 {
			targetIPs = []string{
				"104.18.2.161", "104.18.3.161", "104.21.16.1", "104.21.32.1",
				"172.67.128.1", "172.64.155.209", "162.159.135.42", "188.114.97.3",
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Execute worker pool scanning
		cart := scanner.NewCartographer(*concurrency, *probeTimeout)
		report := cart.Run(ctx, targetIPs, *workerHost)

		// Export raw intelligence report to JSON (decoupled)
		if err := scanner.ExportAtlasJSON(report, *atlasFile); err != nil {
			telemetry.Log.Error("Failed writing atlas intelligence report", slog.String("err", err.Error()))
		} else {
			fmt.Printf("[+] Saved raw intelligence report to %s (%d verified edges)\n", *atlasFile, report.Verified101)
		}

		// Build combat.profile consumed by the main v10 daemon
		profile, err := scanner.CompileCombatProfile(report, *profileFile)
		if err != nil {
			telemetry.Log.Warn("Cartographer completed with warnings", slog.String("warn", err.Error()))
		}
		
		fmt.Printf("[+] Strategic combat profile ready: %s (IP: %s, Mode: %s, Fingerprint: %s)\n",
			*profileFile, profile.PrimaryIP, profile.StealthMode, profile.Fingerprint)
		return
	}

	// Mode 3: Run Engine Core Daemon
	if *runMode {
		telemetry.PrintBanner()
		profile, err := config.LoadCombatProfile("combat.profile")
		if err != nil {
			fmt.Println("[-] Error: combat.profile not found. Run './bin/six-eyes --map --worker=YOUR_WORKER.workers.dev' first.")
			os.Exit(1)
		}
		telemetry.Log.Info("Six Eyes Strategic Combat Doctrine Armed",
			slog.String("version", profile.Version),
			slog.String("primary_ip", profile.Primary.TargetIP),
			slog.String("stealth_mode", profile.Primary.StealthMode),
			slog.Uint64("expected_ttl", uint64(profile.Modules.XDPShield.ExpectedTTL)),
			slog.Uint64("ttl_tolerance", uint64(profile.Modules.XDPShield.TTLTolerance)),
			slog.Int("failover_count", len(profile.Failovers)),
			slog.String("worker", profile.WorkerHost))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfFactory := factory.NewCloudflareFactory(
			profile.Modules.StealthFactory.FragmentationDelayMs,
			profile.Modules.StealthFactory.JitterMs,
		)
		cfFactory.SetInsecure(profile.Modules.StealthFactory.AllowInsecureCerts)

		strategist := coordinator.NewStrategist(profile)
		warmPool := pool.NewWarmPool(ctx, cfFactory, profile, strategist.HandleCondition)
		strategist.AttachPool(warmPool)

		go bpf.StartXDPRSTMonitor(
			ctx,
			*ifaceName,
			profile.Modules.XDPShield.ExpectedTTL,
			profile.Modules.XDPShield.TTLTolerance,
			profile.Modules.XDPShield.RSTBurstThreshold,
			func() {
				strategist.HandleCondition("tcp_rst_storm", 1, warmPool.ActiveRoute())
			},
		)

		go ipc.StartControlPlane(ctx, warmPool, strategist)

		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					active := warmPool.ActiveRoute()
					telemetry.Log.Info("Six Eyes Vital Signs",
						slog.String("route_ip", active.TargetIP),
						slog.String("stealth", active.StealthMode),
						slog.Int64("active_streams", telemetry.ActiveStreams.Load()),
						slog.Int64("warm_pipes", telemetry.PoolHealthyPipes.Load()),
						slog.Uint64("tx_kb", telemetry.TotalBytesTx.Load()/1024),
						slog.Uint64("rx_kb", telemetry.TotalBytesRx.Load()/1024),
						slog.Uint64("rotations", telemetry.RouteRotations.Load()),
						slog.Uint64("escalations", telemetry.ModeEscalations.Load()),
						slog.Uint64("ipc_overrides", telemetry.IPCOverrides.Load()),
						slog.Uint64("xdp_drops", telemetry.XDPDroppedRSTs.Load()))
				}
			}
		}()

		socksErr := make(chan error, 1)
		go func() {
			socksErr <- proxy.StartSOCKS5(ctx, *listenAddr, warmPool)
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-sigChan:
			telemetry.Log.Info("Graceful shutdown initiated...")
			cancel()
		case err := <-socksErr:
			if err == nil {
				return
			}
			telemetry.Log.Error("SOCKS5 listener failed; engine halting", slog.String("err", err.Error()))
			cancel()
			os.Exit(1)
		}
		return
	}

	// Default Usage Print
	telemetry.PrintBanner()
	fmt.Println("Usage:")
	fmt.Println("  1. Mass Scan CIDR (Go): ./bin/six-eyes --map --worker=your-worker.workers.dev --cidr=104.16.0.0/14 -c 100")
	fmt.Println("  2. Probe Custom IPs:    ./bin/six-eyes --map --worker=your-worker.workers.dev --ips=104.18.2.161,104.21.16.1")
	fmt.Println("  3. Engage Core Engine:  sudo ./bin/six-eyes --run --iface=eth0 --listen=127.0.0.1:1080")
	fmt.Println("  4. Live IPC Vitals:     sudo ./bin/six-eyes --status")
}
