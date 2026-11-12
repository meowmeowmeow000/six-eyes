package config

import (
	"encoding/json"
	"os"
	"time"
)

type OperationalDoctrine struct {
	TelemetryPollingMs      int `json:"telemetry_polling_ms"`
	MaxAcceptableLatencyMs  int `json:"max_acceptable_latency_ms"`
	FallbackThresholdStreak int `json:"fallback_threshold_streak"`
}

type XDPDirective struct {
	Mode              string `json:"mode"` // "adaptive" or "lockdown"
	ExpectedTTL       uint8  `json:"expected_ttl"`
	TTLTolerance      uint8  `json:"ttl_tolerance"`
	RSTBurstThreshold uint64 `json:"rst_burst_threshold"`
}

type StealthDirective struct {
	PrimaryMode          string `json:"primary_mode"`  // "tls_frag", "tls_micro_frag", "sni_front"
	FallbackMode         string `json:"fallback_mode"` // "tls_micro_frag"
	FragmentationDelayMs int    `json:"fragmentation_delay_ms"`
	JitterMs             int    `json:"jitter_ms"`
	AllowInsecureCerts   bool   `json:"allow_insecure_certs,omitempty"`
}

type PoolDirective struct {
	TargetCapacity    int `json:"target_capacity"`
	KeepAliveInterval int `json:"keepalive_interval_sec"`
}

type ModuleDirectives struct {
	XDPShield      XDPDirective     `json:"xdp_shield"`
	StealthFactory StealthDirective `json:"stealth_factory"`
	WarmPool       PoolDirective    `json:"warm_pool"`
}

type ContingencyRule struct {
	Condition string `json:"condition"`
	Action    string `json:"action"`
}

type RouteCandidate struct {
	TargetIP       string `json:"target_ip"`
	CleanSNI       string `json:"clean_sni"`
	StealthMode    string `json:"stealth_mode"`
	ExpectedTTL    uint8  `json:"expected_ttl,omitempty"`
	DPIDistance    int    `json:"dpi_distance_hops,omitempty"`
	TCPMs          int64  `json:"tcp_ms"`
	TLSHandshakeMs int64  `json:"tls_handshake_ms"`
	WSUpgradeMs    int64  `json:"ws_upgrade_ms,omitempty"`
	WSVerified     bool   `json:"ws_verified"`
	Score          int    `json:"confidence_score"`
}

type CombatProfile struct {
	Version           string              `json:"version"`
	WorkerHost        string              `json:"worker_host"`
	ExpectedTTL       int                 `json:"expected_ttl"`
	Doctrine          OperationalDoctrine `json:"operational_doctrine"`
	Modules           ModuleDirectives    `json:"modules"`
	ContingencyMatrix []ContingencyRule   `json:"contingency_matrix"`
	Primary           RouteCandidate      `json:"primary_route"`
	Failovers         []RouteCandidate    `json:"failover_routes"`
}

type AtlasReport struct {
	Timestamp    string           `json:"timestamp"`
	TotalProbed  int              `json:"total_probed"`
	ViableRoutes int              `json:"viable_routes"`
	Throttled    bool             `json:"is_throttled"`
	RankedMatrix []RouteCandidate `json:"ranked_matrix"`
}

func DefaultCombatProfile(workerHost string, primary RouteCandidate, failovers []RouteCandidate) *CombatProfile {
	expTTL := int(primary.ExpectedTTL)
	return &CombatProfile{
		Version:     "10.0-six-eyes",
		WorkerHost:  workerHost,
		ExpectedTTL: expTTL,
		Doctrine: OperationalDoctrine{
			TelemetryPollingMs:      3000,
			MaxAcceptableLatencyMs:  800,
			FallbackThresholdStreak: 3,
		},
		Modules: ModuleDirectives{
			XDPShield: XDPDirective{
				Mode:              "adaptive",
				ExpectedTTL:       uint8(expTTL),
				TTLTolerance:      4,
				RSTBurstThreshold: 5,
			},
			StealthFactory: StealthDirective{
				PrimaryMode:          "tls_frag",
				FallbackMode:         "tls_micro_frag",
				FragmentationDelayMs: 2,
				JitterMs:             3,
			},
			WarmPool: PoolDirective{
				TargetCapacity:    3,
				KeepAliveInterval: 10,
			},
		},
		ContingencyMatrix: []ContingencyRule{
			{Condition: "http_403_forbidden", Action: "escalate_stealth_mode"},
			{Condition: "dpi_tls_reset", Action: "escalate_stealth_mode"},
			{Condition: "dial_timeout", Action: "flush_pool_and_rotate_ip"},
			{Condition: "dial_unreachable", Action: "flush_pool_and_rotate_ip"},
			{Condition: "tcp_rst_storm", Action: "engage_xdp_lockdown"},
		},
		Primary:   primary,
		Failovers: failovers,
	}
}

func LoadCombatProfile(path string) (*CombatProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p CombatProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Doctrine.FallbackThresholdStreak <= 0 {
		p.Doctrine.FallbackThresholdStreak = 3
	}
	if p.Modules.XDPShield.TTLTolerance == 0 {
		p.Modules.XDPShield.TTLTolerance = 4
	}
	if p.Modules.XDPShield.ExpectedTTL == 0 && p.ExpectedTTL > 0 {
		p.Modules.XDPShield.ExpectedTTL = uint8(p.ExpectedTTL)
	}
	if p.Modules.StealthFactory.FragmentationDelayMs <= 0 {
		p.Modules.StealthFactory.FragmentationDelayMs = 2
	}
	if len(p.ContingencyMatrix) == 0 {
		p.ContingencyMatrix = []ContingencyRule{
			{Condition: "http_403_forbidden", Action: "escalate_stealth_mode"},
			{Condition: "dpi_tls_reset", Action: "escalate_stealth_mode"},
			{Condition: "dial_timeout", Action: "flush_pool_and_rotate_ip"},
			{Condition: "dial_unreachable", Action: "flush_pool_and_rotate_ip"},
			{Condition: "tcp_rst_storm", Action: "engage_xdp_lockdown"},
		}
	}
	return &p, nil
}

func SaveProfiles(combat *CombatProfile, atlas *AtlasReport) error {
	cData, err := json.MarshalIndent(combat, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile("combat.profile", cData, 0644); err != nil {
		return err
	}
	if atlas != nil {
		if atlas.Timestamp == "" {
			atlas.Timestamp = time.Now().Format(time.RFC3339)
		}
		aData, err := json.MarshalIndent(atlas, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile("atlas.json", aData, 0644)
	}
	return nil
}
