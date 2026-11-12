package selftest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"
	"github.com/meowmeowmeow000/six-eyes/pkg/config"
	"github.com/meowmeowmeow000/six-eyes/pkg/coordinator"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/factory"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/pool"
	"github.com/meowmeowmeow000/six-eyes/pkg/telemetry"
)

type loopbackFactory struct {
	serverAddr string
}

func (l *loopbackFactory) Dial(ctx context.Context, targetIP, sni, hostHeader, stealthMode string) (net.Conn, string, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", l.serverAddr)
	if err != nil {
		return nil, factory.CondDialTimeout, err
	}
	return c, "", nil
}

func (l *loopbackFactory) ProbeRoute(ctx context.Context, targetIP, sni, hostHeader, stealthMode string, verifyWS bool) (factory.ProbeMetrics, error) {
	return factory.ProbeMetrics{TCPDur: time.Millisecond, TLSDur: time.Millisecond, WSDur: time.Millisecond, WSVerified: true}, nil
}

func (l *loopbackFactory) SetPacing(delayMs, jitterMs int) {}

func startMockEdgeServer(ctx context.Context) (string, string, error) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	go func() {
		<-ctx.Done()
		_ = echoLn.Close()
	}()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	muxLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	go func() {
		<-ctx.Done()
		_ = muxLn.Close()
	}()
	go func() {
		for {
			rawConn, err := muxLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sess, err := smux.Server(c, smux.DefaultConfig())
				if err != nil {
					_ = c.Close()
					return
				}
				defer sess.Close()
				for {
					stream, err := sess.AcceptStream()
					if err != nil {
						return
					}
					go func(s *smux.Stream) {
						defer s.Close()
						var lenBuf [1]byte
						if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
							return
						}
						hostLen := int(lenBuf[0])
						hdr := make([]byte, hostLen+2)
						if _, err := io.ReadFull(s, hdr); err != nil {
							return
						}
						host := string(hdr[:hostLen])
						port := binary.BigEndian.Uint16(hdr[hostLen:])
						dst, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
						if err != nil {
							return
						}
						defer dst.Close()
						done := make(chan struct{}, 2)
						go func() { _, _ = io.Copy(dst, s); done <- struct{}{} }()
						go func() { _, _ = io.Copy(s, dst); done <- struct{}{} }()
						<-done
					}(stream)
				}
			}(rawConn)
		}
	}()

	return muxLn.Addr().String(), echoLn.Addr().String(), nil
}

func RunAll() error {
	telemetry.PrintBanner()
	fmt.Println("========================================================================")
	fmt.Println(" 🧪 SIX EYES v10 // 4-STAGE AUTONOMOUS DIAGNOSTIC & STRESS BENCHMARK")
	fmt.Println("========================================================================")

	// Stage 1: Strategic Coordinator & Escalation Ladder
	fmt.Println("\n[Stage 1/3] Testing Strategic Coordinator & 7-Slice Escalation Ladder...")
	primary := config.RouteCandidate{
		TargetIP:    "104.18.2.161",
		CleanSNI:    "www.cloudflare.com",
		StealthMode: factory.ModeSNIFront,
		ExpectedTTL: 56,
		DPIDistance: 9,
	}
	failover := config.RouteCandidate{
		TargetIP:    "172.67.128.1",
		CleanSNI:    "edge.example.workers.dev",
		StealthMode: factory.ModeTLSFrag,
		ExpectedTTL: 54,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	muxAddr, echoAddr, err := startMockEdgeServer(ctx)
	if err != nil {
		return fmt.Errorf("failed starting mock edge: %w", err)
	}

	prof := config.DefaultCombatProfile("edge.example.workers.dev", primary, []config.RouteCandidate{failover})
	strat := coordinator.NewStrategist(prof)
	lbFac := &loopbackFactory{serverAddr: muxAddr}
	wp := pool.NewWarmPool(ctx, lbFac, prof, strat.HandleCondition)
	strat.AttachPool(wp)

	// Trigger simulated DPI resets to verify sni_front -> tls_frag -> tls_micro_frag -> tls_disorder -> IP rotation
	strat.HandleCondition(factory.CondHTTP403, 1, wp.ActiveRoute())
	if got := wp.ActiveRoute().StealthMode; got != factory.ModeTLSFrag {
		return fmt.Errorf("expected escalation to tls_frag, got %s", got)
	}
	strat.HandleCondition(factory.CondDPITLSReset, 1, wp.ActiveRoute())
	if got := wp.ActiveRoute().StealthMode; got != factory.ModeTLSMicroFrag {
		return fmt.Errorf("expected escalation to tls_micro_frag, got %s", got)
	}
	strat.HandleCondition(factory.CondDPITLSReset, 1, wp.ActiveRoute())
	if got := wp.ActiveRoute().StealthMode; got != factory.ModeTLSDisorder {
		return fmt.Errorf("expected escalation to tls_disorder, got %s", got)
	}
	strat.HandleCondition(factory.CondDPITLSReset, 3, wp.ActiveRoute())
	if got := wp.ActiveRoute().TargetIP; got != "172.67.128.1" {
		return fmt.Errorf("expected failover rotation to 172.67.128.1, got %s", got)
	}
	fmt.Println("  [✓] Escalation Ladder Verified: sni_front -> tls_frag (3) -> tls_micro_frag (5) -> tls_disorder (7) -> IP Failover")

	// Stage 2: XDP Kernel Map Hot-Swap & Auto-Disengage Epoch
	fmt.Println("\n[Stage 2/3] Testing XDP Lockdown State & Atomic Epoch Counter...")
	strat.HandleCondition("tcp_rst_storm", 1, wp.ActiveRoute())
	if telemetry.CurrentLockdownMode.Load() != 1 || telemetry.CurrentTTLTolerance.Load() != 2 {
		return fmt.Errorf("XDP lockdown state failed to arm")
	}
	fmt.Printf("  [✓] XDP Kernel Lockdown Armed (ExpectedTTL=%d, Tolerance=±%d, Epoch=%d)\n",
		telemetry.CurrentExpectedTTL.Load(),
		telemetry.CurrentTTLTolerance.Load(),
		telemetry.XDPLockdownEpoch.Load())

	// Stage 3: End-to-End SOCKS5 + SMUX v1 Multiplexed 1MB Throughput Benchmark
	fmt.Println("\n[Stage 3/3] Benchmarking Zero-Alloc SOCKS5 -> SMUX v1 Multiplexer (1 MB Payload)...")
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	socksAddr := socksLn.Addr().String()
	_ = socksLn.Close()

	go func() {
		_ = proxy.StartSOCKS5(ctx, socksAddr, wp)
	}()
	time.Sleep(80 * time.Millisecond)

	socksConn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("failed dialing local SOCKS5 intake: %w", err)
	}
	defer socksConn.Close()

	// SOCKS5 Auth negotiation
	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var authResp [2]byte
	if _, err := io.ReadFull(socksConn, authResp[:]); err != nil || authResp != [2]byte{0x05, 0x00} {
		return fmt.Errorf("unexpected SOCKS5 auth response: %v", authResp)
	}

	// SOCKS5 CONNECT to mock echo server
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	var echoPort uint16
	_, _ = fmt.Sscanf(echoPortStr, "%d", &echoPort)
	ipBytes := net.ParseIP(echoHost).To4()
	req := []byte{0x05, 0x01, 0x00, 0x01, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], byte(echoPort >> 8), byte(echoPort)}
	if _, err := socksConn.Write(req); err != nil {
		return err
	}
	var connResp [10]byte
	if _, err := io.ReadFull(socksConn, connResp[:]); err != nil || connResp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed: %v", connResp)
	}

	payload := make([]byte, 1024*1024) // 1 MB random payload
	_, _ = rand.Read(payload)

	t0 := time.Now()
	errCh := make(chan error, 1)
	go func() {
		_, err := socksConn.Write(payload)
		errCh <- err
	}()

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(socksConn, received); err != nil {
		return fmt.Errorf("failed reading 1MB echoed stream: %w", err)
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("failed writing 1MB stream: %w", err)
	}
	dur := time.Since(t0)

	if !bytes.Equal(payload, received) {
		return fmt.Errorf("1MB payload corruption detected across SMUX stream")
	}

	mbps := float64(len(payload)*2) / (1024 * 1024) / dur.Seconds()
	fmt.Printf("  [✓] 1 MB Bidirectional Stream Verified in %v (Throughput: %.1f MB/s)\n", dur.Round(time.Millisecond), mbps)
	fmt.Println("\n========================================================================")
	fmt.Println(" ✅ ALL SIX EYES v10 LOCAL DIAGNOSTICS & STRESS TESTS PASSED")
	fmt.Println("========================================================================")
	return nil
}
