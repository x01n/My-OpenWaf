package upstream

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPoolPickSkipsUnhealthyAndBalances(t *testing.T) {
	pool := NewPool()
	urls := []string{"http://a", "http://b", "http://c"}
	pool.Mark("http://b", assertErr{})
	pool.Mark("http://b", assertErr{})

	seq := []uint32{0, 1, 2}
	idx := 0
	picked := make([]string, 0, len(seq))
	for range seq {
		got, ok := pool.Pick(urls, func(n uint32) uint32 {
			v := seq[idx] % n
			idx++
			return v
		})
		if !ok {
			t.Fatal("expected upstream")
		}
		picked = append(picked, got)
	}

	want := []string{"http://a", "http://c", "http://c"}
	for i := range want {
		if picked[i] != want[i] {
			t.Fatalf("picked[%d]=%q want %q; all=%v", i, picked[i], want[i], picked)
		}
	}
}

func TestPoolFallsBackWhenAllUnhealthy(t *testing.T) {
	pool := NewPool()
	urls := []string{"http://a", "http://b"}
	for _, raw := range urls {
		pool.Mark(raw, assertErr{})
		pool.Mark(raw, assertErr{})
	}
	got, ok := pool.Pick(urls, func(uint32) uint32 { return 1 })
	if !ok || got != "http://b" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestPoolMarkRecoversUpstream(t *testing.T) {
	pool := NewPool()
	pool.Mark("http://a", assertErr{})
	pool.Mark("http://a", assertErr{})
	if pool.IsAvailable("http://a") {
		t.Fatal("expected upstream unavailable after repeated failures")
	}
	pool.Mark("http://a", nil)
	if !pool.IsAvailable("http://a") {
		t.Fatal("expected upstream available after success")
	}
}

func TestPoolProbeUpdatesStates(t *testing.T) {
	pool := NewPool()
	pool.Probe(context.Background(), []string{"http://a", "http://b"}, func(_ context.Context, raw string) error {
		if raw == "http://b" {
			return errors.New("down")
		}
		return nil
	})
	pool.Probe(context.Background(), []string{"http://b"}, func(context.Context, string) error { return errors.New("down") })
	if !pool.IsAvailable("http://a") {
		t.Fatal("expected http://a healthy")
	}
	if pool.IsAvailable("http://b") {
		t.Fatal("expected http://b unhealthy after repeated probe failures")
	}
}

func TestPoolStartStopsWithContext(t *testing.T) {
	pool := NewPool()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan struct{}, 4)
	pool.Start(ctx, func() []string { return []string{"http://a"} }, time.Millisecond, func(context.Context, string) error {
		calls <- struct{}{}
		return nil
	})
	<-calls
	cancel()
}

type assertErr struct{}

func (assertErr) Error() string { return "err" }
