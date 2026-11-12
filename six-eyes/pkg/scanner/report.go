package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ExportAtlasJSON writes the raw scanning intelligence to file
func ExportAtlasJSON(report *IntelligenceReport, filepath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal atlas json: %w", err)
	}
	return os.WriteFile(filepath, data, 0644)
}

// CombatProfile represents the production config consumed by main v10 daemon
type CombatProfile struct {
	PrimaryIP      string `json:"primary_ip"`
	StealthMode    string `json:"stealth_mode"`
	Fingerprint    string `json:"tls_fingerprint"`
	ExpectedTTL    int    `json:"expected_ttl"`
	TTLTolerance   int    `json:"ttl_tolerance"`
	SNI            string `json:"sni"`
}

// CompileCombatProfile converts the raw intelligence report into a production profile
func CompileCombatProfile(report *IntelligenceReport, outputPath string) (*CombatProfile, error) {
	if len(report.CleanEdges) == 0 {
		// Fallback configuration if all probes fail
		fallback := &CombatProfile{
			PrimaryIP:    "104.18.2.161",
			StealthMode:  string(ModeTLSMicroFrag),
			Fingerprint:  "chrome_auto",
			ExpectedTTL:  0,
			TTLTolerance: 4,
			SNI:          report.WorkerHost,
		}
		data, _ := json.MarshalIndent(fallback, "", "  ")
		_ = os.WriteFile(outputPath, data, 0644)
		return fallback, fmt.Errorf("zero edges verified; created fallback profile")
	}

	// Sort edges by lowest latency
	sort.Slice(report.CleanEdges, func(i, j int) bool {
		return report.CleanEdges[i].Latency < report.CleanEdges[j].Latency
	})

	bestEdge := report.CleanEdges[0]

	profile := &CombatProfile{
		PrimaryIP:    bestEdge.IP,
		StealthMode:  string(bestEdge.Mode),
		Fingerprint:  bestEdge.Fingerprint,
		ExpectedTTL:  0, // Will be set dynamically by Echolocation
		TTLTolerance: 4,
		SNI:          report.WorkerHost,
	}

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(outputPath, data, 0644)
	return profile, err
}
