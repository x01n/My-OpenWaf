package dataplane

import (
	"testing"

	"My-OpenWaf/internal/upstream"
)

func TestPickUpstreamSkipsUnhealthy(t *testing.T) {
	pool := upstream.NewPool()
	pool.Mark("http://b", errForTest{})
	pool.Mark("http://b", errForTest{})

	got, ok := pickUpstream([]string{"http://a", "http://b", "http://c"}, pool, func(uint32) uint32 { return 1 })
	if !ok || got != "http://c" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestPickUpstreamNoPoolUsesRoundRobinIndex(t *testing.T) {
	got, ok := pickUpstream([]string{"http://a", "http://b"}, nil, func(uint32) uint32 { return 1 })
	if !ok || got != "http://b" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestPickUpstreamPrefersHigherProtocolTier(t *testing.T) {
	pool := upstream.NewPool()
	got, ok := pickUpstream([]string{"http://plain-a", "h2c://clear-a", "https://secure-a", "h3://quic-a"}, pool, func(uint32) uint32 { return 0 })
	if !ok || got != "h3://quic-a" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

type errForTest struct{}

func (errForTest) Error() string { return "err" }
