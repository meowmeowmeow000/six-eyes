package scanner

import (
	"time"

	utls "github.com/refraction-networking/utls"
)

// StealthMode defines the fragmentation technique
type StealthMode string

const (
	ModeTLSFrag      StealthMode = "tls_frag"
	ModeTLSMicroFrag StealthMode = "tls_micro_frag"
	ModeTLSDisorder  StealthMode = "tls_disorder"
)

// ProbeTask represents a single unit of work for a worker
type ProbeTask struct {
	IP          string
	TargetSNI   string
	Fingerprint string
	ClientHello utls.ClientHelloID
	Mode        StealthMode
	Timeout     time.Duration
}

// ProbeResult stores the outcome of a single edge scan
type ProbeResult struct {
	IP          string        `json:"ip"`
	SNI         string        `json:"sni"`
	Fingerprint string        `json:"fingerprint"`
	Mode        StealthMode   `json:"mode"`
	Success     bool          `json:"success"`
	Latency     time.Duration `json:"latency_ms"`
	HTTPStatus  int           `json:"http_status"`
	ErrStr      string        `json:"error,omitempty"`
}

// IntelligenceReport represents the decoupled raw JSON scan output
type IntelligenceReport struct {
	Timestamp    time.Time     `json:"timestamp"`
	WorkerHost   string        `json:"worker_host"`
	TotalScanned int           `json:"total_scanned"`
	Verified101  int           `json:"verified_101_count"`
	Edges        []ProbeResult `json:"clean_edges"`
}
