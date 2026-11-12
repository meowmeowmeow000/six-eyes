package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/meowmeowmeow000/six-eyes/pkg/config"
)

// ExportAtlasJSON writes the raw probe report with owner-only permissions.
func ExportAtlasJSON(report *IntelligenceReport, filepath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal atlas json: %w", err)
	}
	return os.WriteFile(filepath, data, 0600)
}

// CompileCombatProfile converts verified TLS endpoints into the exact profile
// schema consumed by config.LoadCombatProfile. It never writes a guessed fallback.
func CompileCombatProfile(report *IntelligenceReport, outputPath string) (*config.CombatProfile, error) {
	if report == nil {
		return nil, fmt.Errorf("probe report is nil")
	}
	if len(report.CleanEdges) == 0 {
		return nil, fmt.Errorf("no certificate-verified TLS endpoints; profile was not written")
	}
	if report.WorkerHost == "" {
		return nil, fmt.Errorf("worker host is required to build a combat profile")
	}

	edges := append([]ProbeResult(nil), report.CleanEdges...)
	sort.Slice(edges, func(i, j int) bool { return edges[i].Latency < edges[j].Latency })
	best := edges[0]
	primary := config.RouteCandidate{
		TargetIP:       best.IP,
		CleanSNI:       report.WorkerHost,
		StealthMode:    string(best.Mode),
		TLSHandshakeMs: best.Latency.Milliseconds(),
		WSVerified:     false,
		Score:          100,
	}
	failovers := make([]config.RouteCandidate, 0, len(edges)-1)
	for _, edge := range edges[1:] {
		failovers = append(failovers, config.RouteCandidate{
			TargetIP:       edge.IP,
			CleanSNI:       report.WorkerHost,
			StealthMode:    string(edge.Mode),
			TLSHandshakeMs: edge.Latency.Milliseconds(),
			WSVerified:     false,
			Score:          100,
		})
	}
	profile := config.DefaultCombatProfile(report.WorkerHost, primary, failovers)
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal combat profile: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write combat profile: %w", err)
	}
	return profile, nil
}
