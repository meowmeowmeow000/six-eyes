package pool

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
	"github.com/meowmeowmeow000/six-eyes/pkg/config"
	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/factory"
	"github.com/meowmeowmeow000/six-eyes/pkg/telemetry"
)

const maxDialRetries = 3

type FailureObserver func(condition string, streak int, activeRoute config.RouteCandidate)

type WarmPool struct {
	fac            factory.StealthFactory
	sessions       []*smux.Session
	routes         []config.RouteCandidate
	routeIdx       int
	routeEpoch     uint64
	hostHeader     string
	targetCap      int
	keepAliveSec   int
	failThreshold  int
	failStreak     int
	rrIndex        atomic.Uint32
	onFailureEvent FailureObserver
	mu             sync.RWMutex
	dialSem        chan struct{}
	ctx            context.Context
}

func NewWarmPool(ctx context.Context, fac factory.StealthFactory, profile *config.CombatProfile, observer FailureObserver) *WarmPool {
	if profile == nil {
		return &WarmPool{
			fac:            fac,
			sessions:       make([]*smux.Session, 0, 1),
			routes:         nil,
			hostHeader:     "",
			targetCap:      1,
			keepAliveSec:   10,
			failThreshold:  3,
			onFailureEvent: observer,
			dialSem:        make(chan struct{}, 1),
			ctx:            ctx,
		}
	}

	routes := []config.RouteCandidate{profile.Primary}
	routes = append(routes, profile.Failovers...)

	capSize := profile.Modules.WarmPool.TargetCapacity
	if capSize <= 0 {
		capSize = 3
	}
	kaSec := profile.Modules.WarmPool.KeepAliveInterval
	if kaSec <= 0 {
		kaSec = 10
	}
	thresh := profile.Doctrine.FallbackThresholdStreak
	if thresh <= 0 {
		thresh = 3
	}

	p := &WarmPool{
		fac:            fac,
		sessions:       make([]*smux.Session, 0, capSize),
		routes:         routes,
		hostHeader:     profile.WorkerHost,
		targetCap:      capSize,
		keepAliveSec:   kaSec,
		failThreshold:  thresh,
		onFailureEvent: observer,
		dialSem:        make(chan struct{}, capSize),
		ctx:            ctx,
	}
	go p.maintainer()
	return p
}

func (p *WarmPool) activeRouteLocked() (config.RouteCandidate, bool) {
	if len(p.routes) == 0 {
		return config.RouteCandidate{}, false
	}
	idx := p.routeIdx % len(p.routes)
	return p.routes[idx], true
}

func (p *WarmPool) ActiveRoute() config.RouteCandidate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	route, ok := p.activeRouteLocked()
	if !ok {
		return config.RouteCandidate{}
	}
	return route
}

func (p *WarmPool) currentRouteAndEpoch() (config.RouteCandidate, uint64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	route, ok := p.activeRouteLocked()
	if !ok {
		return config.RouteCandidate{}, p.routeEpoch
	}
	return route, p.routeEpoch
}

func (p *WarmPool) EscalateStealthMode(newMode string, delayMs, jitterMs int) {
	p.fac.SetPacing(delayMs, jitterMs)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.routes) == 0 {
		return
	}
	idx := p.routeIdx % len(p.routes)
	oldMode := p.routes[idx].StealthMode
	if oldMode == newMode {
		return
	}
	p.routes[idx].StealthMode = newMode
	if newMode == factory.ModeTLSFrag || newMode == factory.ModeTLSMicroFrag || newMode == factory.ModeTLSDisorder {
		p.routes[idx].CleanSNI = p.hostHeader
	}
	p.routeEpoch++
	p.failStreak = 0
	oldSessions := p.sessions
	p.sessions = make([]*smux.Session, 0, p.targetCap)
	telemetry.PoolHealthyPipes.Store(0)
	ip := p.routes[idx].TargetIP

	for _, s := range oldSessions {
		_ = s.Close()
	}
	telemetry.ModeEscalations.Add(1)
	telemetry.Log.Warn("Strategic Handshake Escalation Executed",
		slog.String("ip", ip),
		slog.String("from_mode", oldMode),
		slog.String("to_mode", newMode),
		slog.Int("frag_delay_ms", delayMs))
}

func (p *WarmPool) InjectEmergencyRoute(cand config.RouteCandidate) {
	p.mu.Lock()
	if cand.StealthMode == "" {
		cand.StealthMode = factory.ModeTLSFrag
	}
	if cand.CleanSNI == "" {
		cand.CleanSNI = p.hostHeader
	}
	filtered := []config.RouteCandidate{cand}
	for _, r := range p.routes {
		if r.TargetIP != cand.TargetIP {
			filtered = append(filtered, r)
		}
	}
	p.routes = filtered
	if len(p.routes) == 0 {
		p.routes = []config.RouteCandidate{cand}
	}
	p.routeIdx = 0
	p.routeEpoch++
	p.failStreak = 0
	oldSessions := p.sessions
	p.sessions = make([]*smux.Session, 0, p.targetCap)
	telemetry.PoolHealthyPipes.Store(0)
	p.mu.Unlock()

	for _, s := range oldSessions {
		_ = s.Close()
	}
	telemetry.IPCOverrides.Add(1)
	telemetry.RouteRotations.Add(1)
	telemetry.Log.Warn("Live IPC Route Injected & Armed",
		slog.String("target_ip", cand.TargetIP),
		slog.String("stealth_mode", cand.StealthMode),
		slog.Uint64("expected_ttl", uint64(cand.ExpectedTTL)))
}

func (p *WarmPool) RotateRoute(reason string) {
	p.mu.Lock()
	if len(p.routes) <= 1 {
		p.mu.Unlock()
		return
	}
	oldRoute := p.routes[p.routeIdx%len(p.routes)]
	p.routeIdx = (p.routeIdx + 1) % len(p.routes)
	p.routeEpoch++
	newRoute := p.routes[p.routeIdx]
	p.failStreak = 0
	oldSessions := p.sessions
	p.sessions = make([]*smux.Session, 0, p.targetCap)
	telemetry.PoolHealthyPipes.Store(0)
	p.mu.Unlock()

	for _, s := range oldSessions {
		_ = s.Close()
	}
	telemetry.RouteRotations.Add(1)
	telemetry.Log.Warn("Self-Healing Route Rotation Triggered",
		slog.String("reason", reason),
		slog.String("from_ip", oldRoute.TargetIP),
		slog.String("to_ip", newRoute.TargetIP),
		slog.String("to_mode", newRoute.StealthMode),
		slog.String("to_sni", newRoute.CleanSNI))
}

func (p *WarmPool) GetStream(ctx context.Context) (net.Conn, error) {
	for attempt := 0; attempt < maxDialRetries; attempt++ {
		p.mu.RLock()
		n := len(p.sessions)
		var session *smux.Session
		if n > 0 {
			idx := int(p.rrIndex.Add(1)) % n
			session = p.sessions[idx]
		}
		p.mu.RUnlock()

		if session != nil && !session.IsClosed() {
			stream, err := session.OpenStream()
			if err == nil {
				return stream, nil
			}
			p.removeSession(session)
		}

		session, err := p.dialSession(ctx)
		if err != nil {
			continue
		}
		stream, err := session.OpenStream()
		if err == nil {
			return stream, nil
		}
		p.removeSession(session)
	}
	return nil, errors.New("warm pool exhausted all retry attempts across failover routes")
}

func (p *WarmPool) dialSession(ctx context.Context) (*smux.Session, error) {
	if p == nil {
		return nil, errors.New("warm pool is nil")
	}

	select {
	case p.dialSem <- struct{}{}:
		defer func() { <-p.dialSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	route, epochAtStart := p.currentRouteAndEpoch()
	if route.TargetIP == "" {
		return nil, errors.New("warm pool has no configured routes")
	}
	mode := route.StealthMode
	if mode == "" {
		mode = factory.ModeTLSFrag
	}
	sni := route.CleanSNI
	if (mode == factory.ModeTLSFrag || mode == factory.ModeTLSMicroFrag || mode == factory.ModeTLSDisorder) && sni != p.hostHeader {
		sni = p.hostHeader
	}

	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	rawConn, cond, err := p.fac.Dial(dialCtx, route.TargetIP, sni, p.hostHeader, mode)
	if err != nil {
		telemetry.DialFailures.Add(1)
		p.mu.Lock()
		var streak int
		var epochMatch bool
		if p.routeEpoch == epochAtStart {
			p.failStreak++
			streak = p.failStreak
			epochMatch = true
		}
		p.mu.Unlock()

		telemetry.Log.Warn("Stealth pipe dial failed",
			slog.String("ip", route.TargetIP),
			slog.String("mode", mode),
			slog.String("condition", cond),
			slog.Int("streak", streak),
			slog.String("err", err.Error()))

		if epochMatch && p.onFailureEvent != nil {
			p.onFailureEvent(cond, streak, route)
		} else if epochMatch && streak >= p.failThreshold {
			p.RotateRoute("consecutive_dial_failures")
		}
		return nil, err
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 1
	smuxCfg.KeepAliveInterval = time.Duration(p.keepAliveSec) * time.Second
	smuxCfg.KeepAliveTimeout = time.Duration(p.keepAliveSec*3) * time.Second
	smuxCfg.MaxReceiveBuffer = 4 * 1024 * 1024
	smuxCfg.MaxStreamBuffer = 1024 * 1024

	session, err := smux.Client(rawConn, smuxCfg)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	p.mu.Lock()
	if p.routeEpoch != epochAtStart {
		p.mu.Unlock()
		_ = session.Close()
		return nil, errors.New("route epoch changed during dial; discarding stale pipe")
	}

	if len(p.sessions) >= p.targetCap {
		if len(p.sessions) == 0 {
			p.mu.Unlock()
			_ = session.Close()
			return nil, errors.New("warm pool session list is empty while capacity reached")
		}
		existing := p.sessions[int(p.rrIndex.Add(1))%len(p.sessions)]
		p.mu.Unlock()
		_ = session.Close()
		return existing, nil
	}

	p.failStreak = 0
	p.sessions = append(p.sessions, session)
	poolLen := len(p.sessions)
	telemetry.PoolHealthyPipes.Store(int64(poolLen))
	p.mu.Unlock()

	telemetry.Log.Info("Warm Multiplexed Pipe Established",
		slog.String("ip", route.TargetIP),
		slog.String("mode", mode),
		slog.String("sni", sni),
		slog.Int("pool_size", poolLen))
	return session, nil
}

func (p *WarmPool) maintainer() {
	p.replenish()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.replenish()
		}
	}
}

func (p *WarmPool) replenish() {
	p.mu.Lock()
	active := make([]*smux.Session, 0, p.targetCap)
	for _, s := range p.sessions {
		if s != nil && !s.IsClosed() {
			active = append(active, s)
		}
	}
	p.sessions = active
	telemetry.PoolHealthyPipes.Store(int64(len(p.sessions)))
	deficit := p.targetCap - len(p.sessions)
	p.mu.Unlock()

	if deficit <= 0 {
		return
	}

	var wg sync.WaitGroup
	for i := 0; i < deficit; i++ {
		if p.ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.dialSession(p.ctx)
		}()
	}
	wg.Wait()
}

func (p *WarmPool) removeSession(target *smux.Session) {
	if target == nil {
		return
	}
	p.mu.Lock()
	active := make([]*smux.Session, 0, len(p.sessions))
	for _, s := range p.sessions {
		if s != nil && s != target && !s.IsClosed() {
			active = append(active, s)
		}
	}
	p.sessions = active
	telemetry.PoolHealthyPipes.Store(int64(len(p.sessions)))
	p.mu.Unlock()
	_ = target.Close()
}
