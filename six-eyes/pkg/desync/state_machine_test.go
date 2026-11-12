package desync

import "testing"

func TestStateMachineEscalationLadder(t *testing.T) {
	sm := NewStateMachine(9)
	if got := sm.SafeDecoyTTL(); got != 10 {
		t.Fatalf("expected SafeDecoyTTL=10 for 9 hops, got %d", got)
	}

	p1, ok := sm.Escalate("sni_front")
	if !ok || p1.Mode != "tls_frag" || p1.Slices != 3 {
		t.Fatalf("expected escalation to tls_frag (3 slices), got %+v (ok=%v)", p1, ok)
	}

	p2, ok := sm.Escalate(p1.Mode)
	if !ok || p2.Mode != "tls_micro_frag" || p2.Slices != 5 {
		t.Fatalf("expected escalation to tls_micro_frag (5 slices), got %+v (ok=%v)", p2, ok)
	}

	p3, ok := sm.Escalate(p2.Mode)
	if !ok || p3.Mode != "tls_disorder" || p3.Slices != 7 {
		t.Fatalf("expected escalation to tls_disorder (7 slices), got %+v (ok=%v)", p3, ok)
	}

	if _, ok := sm.Escalate(p3.Mode); ok {
		t.Fatalf("expected escalation to terminate after tls_disorder")
	}
}
