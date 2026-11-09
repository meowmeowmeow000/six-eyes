// SIX EYES - Autonomous eBPF TCP Sequence Desynchronization Daemon (v10)
// Package main initializes eBPF attachments, proxy listeners, and metrics server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/six-eyes/six-eyes/pkg/config"
	"github.com/six-eyes/six-eyes/pkg/desync"
	"github.com/six-eyes/six-eyes/pkg/proxy"
)

func main() {
	configPath := flag.String("config", "configs/stealth.yaml", "Path to configuration profile")
	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 proxy address")
	adminAddr := flag.String("admin", "127.0.0.1:9090", "Admin REST interface")
	iface := flag.String("iface", "eth0", "Network interface for eBPF TC hook")
	flag.Parse()

	log.Printf("[SIX EYES] Starting Autonomous eBPF TCP Desynchronization Daemon (v10.0)...")

	cfg, err := config.LoadProfile(*configPath)
	if err != nil {
		log.Printf("[WARN] Config %s not found, loading default stealth profile: %v", *configPath, err)
		cfg = config.DefaultProfile()
	}

	sm := desync.NewStateMachine(cfg)
	if err := sm.AttachInterface(*iface); err != nil {
		log.Printf("[WARN] Kernel eBPF attachment failed (requires root / CAP_NET_ADMIN): %v", err)
		log.Printf("[INFO] Running in user-space emulation mode.")
	} else {
		log.Printf("[INFO] eBPF bytecode verified & attached to %s", *iface)
	}

	socksServer := proxy.NewSocks5Server(*listenAddr, sm)
	go func() {
		if err := socksServer.Start(); err != nil {
			log.Fatalf("[FATAL] Proxy server failed: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"app":"six-eyes","status":"active","uptime":"%s","strategy":"%s"}`, time.Since(sm.StartTime()), cfg.Strategy)
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, sm.GetStatsJSON())
	})

	adminServer := &http.Server{Addr: *adminAddr, Handler: mux}
	go func() {
		log.Printf("[INFO] Admin metrics available on http://%s/stats", *adminAddr)
		_ = adminServer.ListenAndServe()
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	log.Printf("[INFO] Received signal %v. Cleaning eBPF maps and shutting down...", sig)
	sm.DetachInterface(*iface)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = adminServer.Shutdown(ctx)
	log.Printf("[INFO] Six Eyes daemon stopped cleanly.")
}
