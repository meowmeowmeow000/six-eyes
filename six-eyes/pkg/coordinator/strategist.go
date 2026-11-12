package coordinator

import (
	"log/slog"
	"sync"
	"time"

	"github.com/meowmeowmeow000/six-eyes/pkg/bpf"
	"github.com/meowmeowmeow000/six-eyes/pkg/config"
	"github.com/meowmeowmeow000/six-eyes/pkg/desync"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/pool"
	"github.com/meowmeowmeow000/six-eyes/pkg/telemetry"
)

type Strategist struct {
	mu       sync.Mutex
	profile  *config.CombatProfile
	warmPool *pool.WarmPool
	desyncSM *desync.StateMachine
	rules    map[string]string
}

func NewStrategist(profile *config.CombatProfile) *Strategist {
	rules := make(map[string]string)
	for _, r := range profile.ContingencyMatrix {
		rules[r.Condition] = r.Action
	}
	return &Strategist{
		profile:  profile,
		desyncSM: desync.NewStateMachine(profile.Primary.DPIDistance),
		rules:    rules,
	}
}

func (s *Strategist) AttachPool(wp *pool.WarmPool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warmPool = wp
}

func (s *Strategist) HandleCondition(condition string, streak int, activeRoute config.RouteCandidate) {
	s.mu.Lock()
	wp := s.warmPool
	action, exists := s.rules[condition]
	threshold := s.profile.Doctrine.FallbackThresholdStreak
	if threshold <= 0 {
		threshold = 3
	}
	s.mu.Unlock()

	if wp == nil {
		return
	}
	if !exists {
		if streak >= threshold {
			wp.RotateRoute("unmapped_condition_" + condition)
		}
		return
	}

	switch action {
	case "escalate_stealth_mode":
		s.desyncSM.SetDPIDistance(activeRoute.DPIDistance)
		if nextProfile, ok := s.desyncSM.Escalate(activeRoute.StealthMode); ok {
			wp.EscalateStealthMode(nextProfile.Mode, nextProfile.DelayMs, nextProfile.JitterMs)
		} else if streak >= threshold {
			wp.RotateRoute("disorder_7slice_exhausted_" + condition)
		}
	case "engage_xdp_lockdown":
		expTTL := activeRoute.ExpectedTTL
		if expTTL == 0 {
			expTTL = s.profile.Modules.XDPShield.ExpectedTTL
		}
		lockdownEpoch := bpf.UpdateXDPConfig(expTTL, 2, true)
		wp.RotateRoute("tcp_rst_storm_xdp_lockdown")

		tolerance := s.profile.Modules.XDPShield.TTLTolerance
		if tolerance == 0 {
			tolerance = 4
		}
		time.AfterFunc(2*time.Minute, func() {
			if telemetry.XDPLockdownEpoch.Load() == lockdownEpoch && telemetry.CurrentLockdownMode.Load() == 1 {
				currTTL := uint8(telemetry.CurrentExpectedTTL.Load())
				bpf.UpdateXDPConfig(currTTL, tolerance, false)
				telemetry.Log.Info("XDP lockdown auto-disengaged; adaptive tolerance restored",
					slog.Uint64("expected_ttl", uint64(currTTL)),
					slog.Uint64("ttl_tolerance", uint64(tolerance)))
			}
		})
	case "flush_pool_and_rotate_ip":
		if streak >= threshold {
			wp.RotateRoute(condition)
		}
	}
	telemetry.Log.Info("Strategic Doctrine Order Executed",
		slog.String("condition", condition),
		slog.String("action", action),
		slog.Int("streak", streak))
}
