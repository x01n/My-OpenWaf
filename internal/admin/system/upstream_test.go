package system

import (
	"testing"
	"time"

	"My-OpenWaf/internal/upstream"
)

func TestBuildUpstreamStatusIncludesLatency(t *testing.T) {
	pool := upstream.NewPool()
	pool.MarkResult("http://b", assertErr{}, 250*time.Millisecond)
	pool.MarkResult("http://b", nil, 50*time.Millisecond)
	pool.MarkResult("http://a", nil, 10*time.Millisecond)

	items := BuildUpstreamStatus(pool)
	if len(items) != 2 {
		t.Fatalf("item count = %d, want 2", len(items))
	}
	if items[0].URL != "http://a" || items[1].URL != "http://b" {
		t.Fatalf("items not sorted by url: %#v", items)
	}
	got := items[1]
	if got.LastLatencyMs != 50 {
		t.Fatalf("last latency = %d, want 50", got.LastLatencyMs)
	}
	if got.AverageLatencyMs != 150 {
		t.Fatalf("average latency = %d, want 150", got.AverageLatencyMs)
	}
	if got.CheckedAt == "" {
		t.Fatal("expected checked_at")
	}
}

func TestBuildUpstreamStatusIncludesProtocolFailureAndSuccessMetadata(t *testing.T) {
	pool := upstream.NewPool()
	pool.MarkProbeResult("h3://b.example.test/live", upstream.ProbeResult{Err: assertErr{}, FailureKind: "http3_request_failed"}, 250*time.Millisecond)
	pool.MarkProbeResult("h2c://a.example.test/health", upstream.ProbeResult{HTTPProtocol: "HTTP/2.0"}, 50*time.Millisecond)

	items := BuildUpstreamStatus(pool)
	if len(items) != 2 {
		t.Fatalf("item count = %d, want 2", len(items))
	}
	if items[0].URL != "h2c://a.example.test" || items[0].ConfiguredProtocol != "h2c" {
		t.Fatalf("first item = %#v, want h2c normalized URL and protocol", items[0])
	}
	if items[0].LastSuccessAt == "" {
		t.Fatalf("first item = %#v, want last_success_at", items[0])
	}
	if items[0].LastHTTPProtocol != "HTTP/2.0" {
		t.Fatalf("first item = %#v, want last_http_protocol", items[0])
	}
	if items[0].LastError != "" {
		t.Fatalf("first item last_error = %q, want empty after success", items[0].LastError)
	}
	if items[1].URL != "h3://b.example.test" || items[1].ConfiguredProtocol != "h3" {
		t.Fatalf("second item = %#v, want h3 normalized URL and protocol", items[1])
	}
	if items[1].LastError != "err" {
		t.Fatalf("second item last_error = %q, want err", items[1].LastError)
	}
	if items[1].LastFailureKind != "http3_request_failed" {
		t.Fatalf("second item last_failure_kind = %q, want http3_request_failed", items[1].LastFailureKind)
	}
	if items[1].LastSuccessAt != "" {
		t.Fatalf("second item last_success_at = %q, want empty without success", items[1].LastSuccessAt)
	}
	if items[1].LastHTTPProtocol != "" {
		t.Fatalf("second item last_http_protocol = %q, want empty without success", items[1].LastHTTPProtocol)
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "err" }
