package dataplane

import (
	"sync/atomic"
	"time"
)

// Metrics tracks data-plane counters (thread-safe).
// Uses atomic counters only — no sync.Map to avoid unbounded memory growth.
type Metrics struct {
	RequestsTotal atomic.Int64
	Status2xx     atomic.Int64
	Status4xx     atomic.Int64
	Status5xx     atomic.Int64
	WAFBlocks     atomic.Int64
	WAFObserves   atomic.Int64
	BuiltinHits   atomic.Int64

	ringIdx   atomic.Int64
	ring      [qpsRingSize]ringEntry
	startTime time.Time

	uniqueIPCnt atomic.Int64
	attackIPCnt atomic.Int64
}

const qpsRingSize = 10 // 10 × 1s buckets

type ringEntry struct {
	ts    atomic.Int64
	count atomic.Int64
}

func NewMetrics() *Metrics {
	return &Metrics{startTime: time.Now()}
}

func (m *Metrics) RecordRequest() {
	m.RequestsTotal.Add(1)
	now := time.Now().Unix()
	// Simple ring buffer: find current second's slot or advance.
	idx := int(m.ringIdx.Load()) % qpsRingSize
	if m.ring[idx].ts.Load() == now {
		m.ring[idx].count.Add(1)
	} else {
		// Advance to next slot (benign race: worst case we overcount slightly).
		newIdx := (idx + 1) % qpsRingSize
		m.ringIdx.Store(int64(newIdx))
		m.ring[newIdx].ts.Store(now)
		m.ring[newIdx].count.Store(1)
	}
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

// RecordClientIP increments the unique IP counter.
// Uses a simple atomic counter instead of storing individual IPs.
func (m *Metrics) RecordClientIP(_ string) {
	m.uniqueIPCnt.Add(1)
}

// RecordAttackIP increments the attack IP counter.
// Uses a simple atomic counter instead of storing individual IPs.
func (m *Metrics) RecordAttackIP(_ string) {
	m.attackIPCnt.Add(1)
}

// QPS returns approximate queries-per-second over the last windowSec seconds.
func (m *Metrics) QPS(windowSec int) float64 {
	if windowSec <= 0 {
		windowSec = 1
	}
	now := time.Now().Unix()
	var total int64
	for i := 0; i < qpsRingSize; i++ {
		ts := m.ring[i].ts.Load()
		if ts > 0 && now-ts < int64(windowSec) {
			total += m.ring[i].count.Load()
		}
	}
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
