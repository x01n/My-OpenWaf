package dataplane

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics tracks data-plane counters (thread-safe).
type Metrics struct {
	RequestsTotal atomic.Int64
	Status2xx     atomic.Int64
	Status4xx     atomic.Int64
	Status5xx     atomic.Int64
	WAFBlocks     atomic.Int64
	WAFObserves   atomic.Int64
	BuiltinHits   atomic.Int64

	mu        sync.Mutex
	ringIdx   int
	ring      [qpsRingSize]ringEntry
	startTime time.Time

	uniqueIPs   sync.Map // clientIP -> struct{}
	attackIPs   sync.Map // clientIP -> struct{}
	uniqueIPCnt atomic.Int64
	attackIPCnt atomic.Int64
}

const qpsRingSize = 10 // 10 × 1s buckets

type ringEntry struct {
	ts    int64
	count int64
}

func NewMetrics() *Metrics {
	return &Metrics{startTime: time.Now()}
}

func (m *Metrics) RecordRequest() {
	m.RequestsTotal.Add(1)
	now := time.Now().Unix()
	m.mu.Lock()
	idx := m.ringIdx % qpsRingSize
	if m.ring[idx].ts != now {
		m.ringIdx++
		idx = m.ringIdx % qpsRingSize
		m.ring[idx] = ringEntry{ts: now, count: 1}
	} else {
		m.ring[idx].count++
	}
	m.mu.Unlock()
}

func (m *Metrics) RecordStatus(code int) {
	switch {
	case code >= 200 && code < 300:
		m.Status2xx.Add(1)
	case code >= 400 && code < 500:
		m.Status4xx.Add(1)
	case code >= 500:
		m.Status5xx.Add(1)
	}
}

func (m *Metrics) RecordWAFBlock()   { m.WAFBlocks.Add(1) }
func (m *Metrics) RecordWAFObserve() { m.WAFObserves.Add(1) }
func (m *Metrics) RecordBuiltinHit() { m.BuiltinHits.Add(1) }

func (m *Metrics) RecordClientIP(ip string) {
	if _, loaded := m.uniqueIPs.LoadOrStore(ip, struct{}{}); !loaded {
		m.uniqueIPCnt.Add(1)
	}
}

func (m *Metrics) RecordAttackIP(ip string) {
	if _, loaded := m.attackIPs.LoadOrStore(ip, struct{}{}); !loaded {
		m.attackIPCnt.Add(1)
	}
}

// QPS returns approximate queries-per-second over the last windowSec seconds.
func (m *Metrics) QPS(windowSec int) float64 {
	if windowSec <= 0 {
		windowSec = 1
	}
	now := time.Now().Unix()
	var total int64
	m.mu.Lock()
	for i := 0; i < qpsRingSize; i++ {
		e := m.ring[i]
		if e.ts > 0 && now-e.ts < int64(windowSec) {
			total += e.count
		}
	}
	m.mu.Unlock()
	return float64(total) / float64(windowSec)
}

func (m *Metrics) UptimeSeconds() int64 {
	return int64(time.Since(m.startTime).Seconds())
}

type Summary struct {
	QPS1s       float64 `json:"qps_1s"`
	QPS5s       float64 `json:"qps_5s"`
	ReqTotal    int64   `json:"requests_total"`
	Status2xx   int64   `json:"status_2xx"`
	Status4xx   int64   `json:"errors_upstream_4xx"`
	Status5xx   int64   `json:"errors_upstream_5xx"`
	WAFBlocks   int64   `json:"waf_blocks"`
	WAFObserves int64   `json:"waf_observes"`
	BuiltinHits int64   `json:"builtin_hits"`
	UptimeSec   int64   `json:"uptime_sec"`
	UniqueIPs   int64   `json:"unique_ips"`
	AttackIPs   int64   `json:"attack_ips"`
}

func (m *Metrics) Summary() Summary {
	return Summary{
		QPS1s:       m.QPS(1),
		QPS5s:       m.QPS(5),
		ReqTotal:    m.RequestsTotal.Load(),
		Status2xx:   m.Status2xx.Load(),
		Status4xx:   m.Status4xx.Load(),
		Status5xx:   m.Status5xx.Load(),
		WAFBlocks:   m.WAFBlocks.Load(),
		WAFObserves: m.WAFObserves.Load(),
		BuiltinHits: m.BuiltinHits.Load(),
		UptimeSec:   m.UptimeSeconds(),
		UniqueIPs:   m.uniqueIPCnt.Load(),
		AttackIPs:   m.attackIPCnt.Load(),
	}
}
