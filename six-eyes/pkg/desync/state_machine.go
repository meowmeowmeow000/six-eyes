package desync

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/six-eyes/six-eyes/pkg/config"
)

type StateMachine struct {
	cfg        *config.Profile
	startTime  time.Time
	mu         sync.RWMutex
	isAttached bool
	stats      struct {
		PacketsProcessed uint64 `json:"packets_processed"`
		FakeRstInjected  uint64 `json:"fake_rst_injected"`
		SplitsExecuted   uint64 `json:"splits_executed"`
		MiddleboxBypasses uint64 `json:"middlebox_bypasses"`
	}
}

func NewStateMachine(cfg *config.Profile) *StateMachine {
	return &StateMachine{
		cfg:       cfg,
		startTime: time.Now(),
	}
}

func (sm *StateMachine) AttachInterface(iface string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.isAttached = true
	return nil
}

func (sm *StateMachine) DetachInterface(iface string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.isAttached = false
}

func (sm *StateMachine) StartTime() time.Time {
	return sm.startTime
}

func (sm *StateMachine) RecordPacket(isDesync bool) {
	atomic.AddUint64(&sm.stats.PacketsProcessed, 1)
	if isDesync {
		if sm.cfg.Strategy == "FAKE_RST" {
			atomic.AddUint64(&sm.stats.FakeRstInjected, 1)
		} else {
			atomic.AddUint64(&sm.stats.SplitsExecuted, 1)
		}
		atomic.AddUint64(&sm.stats.MiddleboxBypasses, 1)
	}
}

func (sm *StateMachine) GetStatsJSON() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	data, _ := json.MarshalIndent(map[string]interface{}{
		"app":                "six-eyes",
		"version":            "v10.0-rc1",
		"strategy":           sm.cfg.Strategy,
		"ebpf_attached":      sm.isAttached,
		"packets_processed":  atomic.LoadUint64(&sm.stats.PacketsProcessed),
		"fake_rst_injected":  atomic.LoadUint64(&sm.stats.FakeRstInjected),
		"splits_executed":    atomic.LoadUint64(&sm.stats.SplitsExecuted),
		"middlebox_bypasses": atomic.LoadUint64(&sm.stats.MiddleboxBypasses),
		"split_offset_bytes": sm.cfg.SplitOffset,
		"fake_rst_ttl":       sm.cfg.FakeRstTTL,
	}, "", "  ")
	return string(data)
}
