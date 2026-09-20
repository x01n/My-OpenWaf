package dataplane

import (
	"sync"
	"testing"
)

func TestMetricsCountsDistinctClientAndAttackIPs(t *testing.T) {
	m := NewMetrics()
	m.RecordClientIP("127.0.0.1")
	m.RecordClientIP("127.0.0.1")
	m.RecordClientIP("203.0.113.10")
	m.RecordClientIP("")
	m.RecordAttackIP("127.0.0.1")
	m.RecordAttackIP("127.0.0.1")
	m.RecordAttackIP("198.51.100.20")
	m.RecordAttackIP("")

	s := m.Summary()
	if s.UniqueIPs != 2 {
		t.Fatalf("UniqueIPs = %d, want 2", s.UniqueIPs)
	}
	if s.AttackIPs != 2 {
		t.Fatalf("AttackIPs = %d, want 2", s.AttackIPs)
	}
}

func TestMetricsDistinctIPCountersAreConcurrentSafe(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordClientIP("127.0.0.1")
			m.RecordAttackIP("127.0.0.1")
		}()
	}
	wg.Wait()

	if got := m.Summary().UniqueIPs; got != 1 {
		t.Fatalf("UniqueIPs = %d, want 1", got)
	}
	if got := m.Summary().AttackIPs; got != 1 {
		t.Fatalf("AttackIPs = %d, want 1", got)
	}
}
