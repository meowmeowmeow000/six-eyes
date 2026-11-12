package factory

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	utls "github.com/refraction-networking/utls"
)

const (
	ModeTLSFrag      = "tls_frag"
	ModeTLSMicroFrag = "tls_micro_frag"
	ModeTLSDisorder  = "tls_disorder"
	ModeSNIFront     = "sni_front"
)

const (
	CondHTTP403     = "http_403_forbidden"
	CondDPITLSReset = "dpi_tls_reset"
	CondDialTimeout = "dial_timeout"
	CondUnreachable = "dial_unreachable"
)

type ProbeMetrics struct {
	TCPDur     time.Duration
	TLSDur     time.Duration
	WSDur      time.Duration
	WSVerified bool
}

type StealthFactory interface {
	Dial(ctx context.Context, targetIP, sni, hostHeader, stealthMode string) (net.Conn, string, error)
	ProbeRoute(ctx context.Context, targetIP, sni, hostHeader, stealthMode string, verifyWS bool) (ProbeMetrics, error)
	SetPacing(delayMs, jitterMs int)
}

type CloudflareFactory struct {
	fragDelayMs   atomic.Int64
	jitterMs      atomic.Int64
	allowInsecure atomic.Bool
}

func NewCloudflareFactory(delayMs, jitterMs int) *CloudflareFactory {
	if delayMs <= 0 {
		delayMs = 2
	}
	if jitterMs < 0 {
		jitterMs = 2
	}
	f := &CloudflareFactory{}
	f.fragDelayMs.Store(int64(delayMs))
	f.jitterMs.Store(int64(jitterMs))
	return f
}

func (f *CloudflareFactory) SetPacing(delayMs, jitterMs int) {
	if delayMs > 0 {
		f.fragDelayMs.Store(int64(delayMs))
	}
	if jitterMs >= 0 {
		f.jitterMs.Store(int64(jitterMs))
	}
}

func (f *CloudflareFactory) SetInsecure(v bool) {
	f.allowInsecure.Store(v)
}

type clientHelloFragConn struct {
	net.Conn
	fragmented   bool
	microMode    bool
	disorderMode bool
	sniBytes     []byte
	delayMs      int
	jitterMs     int
}

func (c *clientHelloFragConn) Write(b []byte) (int, error) {
	if c.fragmented || len(b) < 48 || b[0] != 0x16 {
		return c.Conn.Write(b)
	}
	c.fragmented = true
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+recLen != len(b) {
		return c.Conn.Write(b)
	}
	payload := b[5:]
	verMajor, verMinor := b[1], b[2]

	var slices [][]byte
	sniIdx := -1
	if len(c.sniBytes) > 2 {
		sniIdx = bytes.Index(payload, c.sniBytes)
	}

	if c.disorderMode && sniIdx > 37 && sniIdx+len(c.sniBytes) < len(payload) && len(c.sniBytes) >= 6 {
		// 7-Slice v10 Six Eyes Surgical Disorder Split across SNI & KeyShare
		c1 := 20
		c2 := 37
		c3 := sniIdx + 2
		c4 := sniIdx + (len(c.sniBytes) / 2)
		c5 := sniIdx + len(c.sniBytes) - 2
		c6 := sniIdx + len(c.sniBytes)
		if c3 > c2 && c4 > c3 && c5 > c4 && c6 > c5 && c6 < len(payload) {
			slices = [][]byte{
				payload[:c1],
				payload[c1:c2],
				payload[c2:c3],
				payload[c3:c4],
				payload[c4:c5],
				payload[c5:c6],
				payload[c6:],
			}
		}
	}

	if len(slices) == 0 && c.microMode && sniIdx > 37 && sniIdx+len(c.sniBytes) < len(payload) {
		c1 := 37
		c2 := sniIdx + (len(c.sniBytes) / 3)
		c3 := sniIdx + ((len(c.sniBytes) * 2) / 3)
		c4 := sniIdx + len(c.sniBytes)
		if c2 > c1 && c3 > c2 && c4 > c3 && c4 < len(payload) {
			slices = [][]byte{
				payload[:c1],
				payload[c1:c2],
				payload[c2:c3],
				payload[c3:c4],
				payload[c4:],
			}
		}
	}

	if len(slices) == 0 {
		cut1 := 37
		cut2 := len(payload) / 2
		if sniIdx > cut1 {
			cut2 = sniIdx + (len(c.sniBytes) / 2)
		}
		if cut2 <= cut1 || cut2 >= len(payload) {
			cut2 = (cut1 + len(payload)) / 2
		}
		slices = [][]byte{
			payload[:cut1],
			payload[cut1:cut2],
			payload[cut2:],
		}
	}

	for i, s := range slices {
		if len(s) == 0 {
			continue
		}
		rec := make([]byte, 5+len(s))
		rec[0] = 0x16
		rec[1] = verMajor
		rec[2] = verMinor
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(s)))
		copy(rec[5:], s)
		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
		if i < len(slices)-1 {
			sleepMs := c.delayMs
			if c.jitterMs > 0 {
				sleepMs += rand.Intn(c.jitterMs + 1)
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
	}
	return len(b), nil
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return CondDialTimeout
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "403") || strings.Contains(msg, "forbidden") {
		return CondHTTP403
	}
	if strings.Contains(msg, "reset by peer") || strings.Contains(msg, "eof") || strings.Contains(msg, "alert") {
		return CondDPITLSReset
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "host unreachable") {
		return CondUnreachable
	}
	return CondDialTimeout
}

func (f *CloudflareFactory) dialUTLSChromeHTTP11(ctx context.Context, targetAddr, sni, stealthMode string) (net.Conn, time.Duration, time.Duration, error) {
	dialer := net.Dialer{Timeout: 4 * time.Second, KeepAlive: 15 * time.Second}
	t0 := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, 0, 0, err
	}
	tcpDur := time.Since(t0)
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	var baseConn net.Conn = rawConn
	if stealthMode == ModeTLSFrag || stealthMode == ModeTLSMicroFrag || stealthMode == ModeTLSDisorder || stealthMode == "" {
		baseConn = &clientHelloFragConn{
			Conn:         rawConn,
			microMode:    stealthMode == ModeTLSMicroFrag,
			disorderMode: stealthMode == ModeTLSDisorder,
			sniBytes:     []byte(sni),
			delayMs:      int(f.fragDelayMs.Load()),
			jitterMs:     int(f.jitterMs.Load()),
		}
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		_ = rawConn.Close()
		return nil, tcpDur, 0, err
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}

	utlsCfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: f.allowInsecure.Load(),
		MinVersion:         tls.VersionTLS12,
	}

	uConn := utls.UClient(baseConn, utlsCfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		_ = rawConn.Close()
		return nil, tcpDur, 0, err
	}

	t1 := time.Now()
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, tcpDur, 0, err
	}
	tlsDur := time.Since(t1)
	return uConn, tcpDur, tlsDur, nil
}

func upgradeWebSocketOverUTLS(ctx context.Context, uConn net.Conn, hostHeader string) (*websocket.Conn, error) {
	var used bool
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if used {
				return nil, fmt.Errorf("single-use uTLS connection already consumed")
			}
			used = true
			return uConn, nil
		},
		ForceAttemptHTTP2:   false,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 1,
	}
	httpClient := &http.Client{Transport: tr}
	wsURL := fmt.Sprintf("wss://%s/tunnel", hostHeader)

	dialOpts := &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: http.Header{
			"Host":            []string{hostHeader},
			"Origin":          []string{fmt.Sprintf("https://%s", hostHeader)},
			"User-Agent":      []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
			"Accept-Language": []string{"en-US,en;q=0.9"},
			"Cache-Control":   []string{"no-cache"},
			"Pragma":          []string{"no-cache"},
		},
	}
	wsConn, _, err := websocket.Dial(ctx, wsURL, dialOpts)
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	return wsConn, nil
}

func (f *CloudflareFactory) ProbeRoute(ctx context.Context, targetIP, sni, hostHeader, stealthMode string, verifyWS bool) (ProbeMetrics, error) {
	var m ProbeMetrics
	targetAddr := net.JoinHostPort(targetIP, "443")

	uConn, tcpDur, tlsDur, err := f.dialUTLSChromeHTTP11(ctx, targetAddr, sni, stealthMode)
	if err != nil {
		return m, err
	}
	m.TCPDur = tcpDur
	m.TLSDur = tlsDur

	if !verifyWS || hostHeader == "" || hostHeader == "my-proxy.workers.dev" {
		_ = uConn.Close()
		return m, nil
	}

	tWS := time.Now()
	wsConn, err := upgradeWebSocketOverUTLS(ctx, uConn, hostHeader)
	if err != nil {
		_ = uConn.Close()
		return m, fmt.Errorf("edge rejected WS upgrade (%s, sni=%s -> host=%s): %w", stealthMode, sni, hostHeader, err)
	}
	m.WSDur = time.Since(tWS)
	m.WSVerified = true
	_ = wsConn.Close(websocket.StatusNormalClosure, "probe_ok")
	_ = uConn.Close()
	return m, nil
}

func (f *CloudflareFactory) Dial(ctx context.Context, targetIP, sni, hostHeader, stealthMode string) (net.Conn, string, error) {
	targetAddr := net.JoinHostPort(targetIP, "443")
	uConn, _, _, err := f.dialUTLSChromeHTTP11(ctx, targetAddr, sni, stealthMode)
	if err != nil {
		cond := classifyError(err)
		return nil, cond, fmt.Errorf("uTLS handshake failed (%s): %w", stealthMode, err)
	}

	wsConn, err := upgradeWebSocketOverUTLS(ctx, uConn, hostHeader)
	if err != nil {
		_ = uConn.Close()
		cond := classifyError(err)
		return nil, cond, fmt.Errorf("websocket upgrade failed (%s): %w", stealthMode, err)
	}
	wsConn.SetReadLimit(-1)
	return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), "", nil
}
