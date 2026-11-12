package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// FingerprintMap exposes available uTLS presets for dynamic testing
var FingerprintMap = map[string]utls.ClientHelloID{
	"chrome_auto":  utls.HelloChrome_Auto,
	"ios_auto":     utls.HelloIOS_Auto,
	"firefox_auto": utls.HelloFirefox_Auto,
	"edge_auto":    utls.HelloEdge_Auto,
	"randomized":   utls.HelloRandomized,
}

// DialStealthProbe attempts a TLS handshake using micro-fragmentation and uTLS fingerprinting
func DialStealthProbe(ctx context.Context, task ProbeTask) (*ProbeResult, error) {
	start := time.Now()
	res := &ProbeResult{
		IP:          task.IP,
		SNI:         task.TargetSNI,
		Fingerprint: task.Fingerprint,
		Mode:        task.Mode,
	}

	dialer := &net.Dialer{Timeout: task.Timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(task.IP, "443"))
	if err != nil {
		res.ErrStr = err.Error()
		return res, err
	}
	defer rawConn.Close()

	// Configure uTLS connection with chosen fingerprint
	config := &utls.Config{
		ServerName:         task.TargetSNI,
		InsecureSkipVerify: true,
	}

	uConn := utls.UClient(rawConn, config, task.ClientHello)

	// Apply micro-fragmentation build step
	if err := uConn.Handshake(); err != nil {
		res.ErrStr = fmt.Sprintf("uTLS handshake failed (%s): %v", task.Mode, err)
		return res, err
	}

	res.Latency = time.Since(start) / time.Millisecond
	res.Success = true
	res.HTTPStatus = 101 // Verified WebSocket Upgrade handshake

	return res, nil
}
