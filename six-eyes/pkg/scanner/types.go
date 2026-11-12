package scanner

import (
	"time"

	utls "github.com/refraction-networking/utls"
)

// StealthMode defines the configured TLS client profile.
type StealthMode string

const (
	ModeTLSFrag      StealthMode = "tls_frag"
	ModeTLSMicroFrag StealthMode = "tls_micro_frag"
	ModeTLSDisorder  StealthMode = "tls_disorder"
)

type ProbeTask struct {
	IP          string
	TargetSNI   string
	Fingerprint string
	ClientHello utls.ClientHelloID
	Mode        StealthMode
	Timeout     time.Duration
}

// Success means a certificate-verified TLS handshake completed. The scanner
// does not claim an HTTP or WebSocket upgrade unless one is actually performed.
type ProbeResult struct {
	IP          string      `json:"ip"`
	SNI         string      `json:"sni"`
	Fingerprint string      `json:"fingerprint"`
	Mode        StealthMode `json:"mode"`
	Success     bool        `json:"tls_verified"`
	Latency     time.Duration `json:"latency_ns"`
	ErrStr      string      `json:"error,omitempty"`
}

type IntelligenceReport struct {
	Timestamp    time.Time     `json:"timestamp"`
	WorkerHost   string        `json:"worker_host"`
	TotalScanned int           `json:"completed_probes"`
	SuccessfulTLS int          `json:"successful_tls_handshakes"`
	CleanEdges   []ProbeResult `json:"verified_tls_endpoints"`
}
