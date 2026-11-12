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
	mapMode := flag.Bool("map", false, "Run bounded TLS compatibility probes on explicitly supplied IPs")
	runMode := flag.Bool("run", false, "Run the Six Eyes engine")
	statusMode := flag.Bool("status", false, "Query live engine telemetry over Unix IPC socket")
	workerHost := flag.String("worker", "", "SNI hostname for probes (required with --map)")
	customIPs := flag.String("ips", "", "Comma-separated explicitly authorized IP addresses (maximum 256 unique addresses)")
	cidrBlock := flag.String("cidr", "", "Explicitly authorized CIDR with at most 256 addresses")
	concurrency := flag.Int("c", 8, "Maximum concurrent probes (clamped to 32)")
	probeTimeout := flag.Duration("timeout", 4*time.Second, "Timeout per probe (clamped to 30 seconds)")
	atlasFile := flag.String("atlas", "atlas.json", "Output path for probe report")
	profileFile := flag.String("profile", "combat.profile", "Output path for generated profile")
	ifaceName := flag.String("iface", "eth0", "Network interface for XDP monitoring")
	listenAddr := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	verbose := flag.Bool("v", false, "Enable verbose debug telemetry")
	flag.Parse()

	telemetry.InitLogger(*verbose)
	if *statusMode {
		queryIPCStatus()
		return
	}

	if *mapMode {
		if *workerHost == "" || (*customIPs == "" && *cidrBlock == "") {
			fmt.Fprintln(os.Stderr, "[-] --map requires --worker and at least one explicitly authorized --ips or --cidr target")
			os.Exit(2)
		}
		var targetIPs []string
		if *cidrBlock != "" {
			expanded, err := scanner.ExpandCIDR(*cidrBlock)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Invalid or oversized CIDR %q: %v\n", *cidrBlock, err)
				os.Exit(2)
			}
			targetIPs = append(targetIPs, expanded...)
		}
		if *customIPs != "" {
			for _, value := range strings.Split(*customIPs, ",") {
				if ip := strings.TrimSpace(value); ip != "" {
					targetIPs = append(targetIPs, ip)
				}
			}
		}
		if len(targetIPs) > 256 {
			fmt.Fprintln(os.Stderr, "[-] Combined target list exceeds 256 addresses")
			os.Exit(2)
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		cart := scanner.NewCartographer(*concurrency, *probeTimeout)
		report := cart.Run(ctx, targetIPs, *workerHost)
		if err := scanner.ExportAtlasJSON(report, *atlasFile); err != nil {
			telemetry.Log.Error("Failed writing probe report", slog.String("err", err.Error()))
			os.Exit(1)
		}
		fmt.Printf("[+] Saved report to %s (%d verified TLS endpoints)\n", *atlasFile, report.SuccessfulTLS)
		profile, err := scanner.CompileCombatProfile(report, *profileFile)
		if err != nil {
			telemetry.Log.Error("Could not generate runtime profile", slog.String("err", err.Error()))
			os.Exit(1)
		}
		fmt.Printf("[+] Runtime profile written: %s (primary IP: %s)\n", *profileFile, profile.Primary.TargetIP)
		return
	}

	if *runMode {
		profile, err := config.LoadCombatProfile(*profileFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Could not load profile %q: %v\n", *profileFile, err)
			os.Exit(1)
		}
		telemetry.PrintBanner()
		telemetry.Log.Info("Six Eyes engine starting",
			slog.String("primary_ip", profile.Primary.TargetIP),
			slog.String("stealth_mode", profile.Primary.StealthMode),
			slog.Int("failover_count", len(profile.Failovers)),
			slog.String("worker", profile.WorkerHost))
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		cfFactory := factory.NewCloudflareFactory(profile.Modules.StealthFactory.FragmentationDelayMs, profile.Modules.StealthFactory.JitterMs)
		cfFactory.SetInsecure(profile.Modules.StealthFactory.AllowInsecureCerts)
		strategist := coordinator.NewStrategist(profile)
		warmPool := pool.NewWarmPool(ctx, cfFactory, profile, strategist.HandleCondition)
		strategist.AttachPool(warmPool)
		go bpf.StartXDPRSTMonitor(ctx, *ifaceName, profile.Modules.XDPShield.ExpectedTTL, profile.Modules.XDPShield.TTLTolerance, profile.Modules.XDPShield.RSTBurstThreshold, func() {
			strategist.HandleCondition("tcp_rst_storm", 1, warmPool.ActiveRoute())
		})
		go ipc.StartControlPlane(ctx, warmPool, strategist)
		socksErr := make(chan error, 1)
		go func() { socksErr <- proxy.StartSOCKS5(ctx, *listenAddr, warmPool) }()
		select {
		case <-ctx.Done():
			telemetry.Log.Info("Shutdown requested")
		case err := <-socksErr:
			if err != nil {
				telemetry.Log.Error("SOCKS5 listener failed", slog.String("err", err.Error()))
				os.Exit(1)
			}
		}
		return
	}

	fmt.Fprintln(os.Stderr, "Usage: six-eyes --map --worker=<your-host> (--ips=<authorized IPs> | --cidr=<authorized CIDR>) | --run | --status")
}
