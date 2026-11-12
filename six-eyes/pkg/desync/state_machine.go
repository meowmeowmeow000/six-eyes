package desync

import "sync/atomic"

type Phase uint32

const (
	PhasePassiveTTL Phase = iota
	PhaseTLSFrag3
	PhaseTLSMicroFrag5
	PhaseTLSDisorder7
)

type PacingProfile struct {
	Mode     string
	Slices   int
	DelayMs  int
	JitterMs int
	DecoyTTL uint8
}

type StateMachine struct {
	currentPhase atomic.Uint32
	dpiHops      atomic.Int32
}

func NewStateMachine(dpiDistanceHops int) *StateMachine {
	sm := &StateMachine{}
	sm.currentPhase.Store(uint32(PhaseTLSFrag3))
	sm.dpiHops.Store(int32(dpiDistanceHops))
	return sm
}

func (s *StateMachine) CurrentPhase() Phase {
	return Phase(s.currentPhase.Load())
}

func (s *StateMachine) SetDPIDistance(hops int) {
	s.dpiHops.Store(int32(hops))
}

// SafeDecoyTTL computes a TTL that expires 1 hop before the Cloudflare edge
// but 1 hop past the ISP DPI middlebox when topological data is available.
func (s *StateMachine) SafeDecoyTTL() uint8 {
	hops := s.dpiHops.Load()
	if hops <= 1 || hops > 30 {
		return 3
	}
	return uint8(hops + 1)
}

func (s *StateMachine) Escalate(currentMode string) (PacingProfile, bool) {
	switch currentMode {
	case "sni_front":
		s.currentPhase.Store(uint32(PhaseTLSFrag3))
		return PacingProfile{Mode: "tls_frag", Slices: 3, DelayMs: 2, JitterMs: 2, DecoyTTL: s.SafeDecoyTTL()}, true
	case "tls_frag", "":
		s.currentPhase.Store(uint32(PhaseTLSMicroFrag5))
		return PacingProfile{Mode: "tls_micro_frag", Slices: 5, DelayMs: 3, JitterMs: 4, DecoyTTL: s.SafeDecoyTTL()}, true
	case "tls_micro_frag":
		s.currentPhase.Store(uint32(PhaseTLSDisorder7))
		return PacingProfile{Mode: "tls_disorder", Slices: 7, DelayMs: 4, JitterMs: 6, DecoyTTL: s.SafeDecoyTTL()}, true
	default:
		return PacingProfile{}, false
	}
}
