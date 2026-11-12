package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// FingerprintMap exposes available uTLS presets for controlled TLS compatibility tests.
var FingerprintMap = map[string]utls.ClientHelloID{
	"chrome_auto":  utls.HelloChrome_Auto,
	"ios_auto":     utls.HelloIOS_Auto,
	"firefox_auto": utls.HelloFirefox_Auto,
	"edge_auto":    utls.HelloEdge_Auto,
	"randomized":   utls.HelloRandomized,
}

// DialStealthProbe checks whether a TLS handshake succeeds. It does not make an
// HTTP request; Success therefore means a verified TLS handshake, not HTTP 101.
func DialStealthProbe(ctx context.Context, task ProbeTask) (*ProbeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	res := &ProbeResult{
		IP:          task.IP,
		SNI:         task.TargetSNI,
		Fingerprint: task.Fingerprint,
		Mode:        task.Mode,
	}
	if net.ParseIP(task.IP) == nil {
		res.ErrStr = "target must be an IP address"
		return res, fmt.Errorf("%s", res.ErrStr)
	}
	if task.TargetSNI == "" {
		res.ErrStr = "target SNI is required"
		return res, fmt.Errorf("%s", res.ErrStr)
	}
	if task.Timeout <= 0 {
		task.Timeout = defaultTimeout
	}
	if task.Timeout > maxProbeTimeout {
		task.Timeout = maxProbeTimeout
	}

	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, task.Timeout)
	defer cancel()
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(task.IP, "443"))
	if err != nil {
		res.ErrStr = err.Error()
		return res, err
	}
	defer rawConn.Close()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	// Certificate validation remains enabled. A successful result therefore
	// requires a valid certificate for the requested SNI.
	tlsConfig := &utls.Config{ServerName: task.TargetSNI}
	uConn := utls.UClient(rawConn, tlsConfig, task.ClientHello)
	if err := uConn.HandshakeContext(dialCtx); err != nil {
		res.ErrStr = fmt.Sprintf("TLS handshake failed: %v", err)
		return res, err
	}

	res.Latency = time.Since(start)
	res.Success = true
	return res, nil
}
