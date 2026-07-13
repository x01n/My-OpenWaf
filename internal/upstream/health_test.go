package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"My-OpenWaf/internal/acme"
)

var benchmarkProbeResultFuncSink ProbeResultFunc

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

func TestPickByProtocolPreference(t *testing.T) {
	pool := NewPool()
	urls := []string{
		"http://plain-a",
		"https://secure-a",
		"h2c://clear-a",
		"h3://quic-a",
		"https://secure-b",
	}
	got, ok := PickByProtocolPreference(urls, pool, func(uint32) uint32 { return 0 })
	if !ok || got != "h3://quic-a" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestPickByProtocolPreferenceAcceptsUppercaseSchemes(t *testing.T) {
	pool := NewPool()
	urls := []string{
		"HTTP://plain-a",
		"HTTPS://secure-a",
		"H2C://clear-a",
		"H3://quic-a",
	}
	got, ok := PickByProtocolPreference(urls, pool, func(uint32) uint32 { return 0 })
	if !ok || got != "H3://quic-a" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestPickByProtocolPreferenceSkipsUnavailableHigherTier(t *testing.T) {
	pool := NewPool()
	pool.Mark("h3://quic-a", assertErr{})
	pool.Mark("h3://quic-a", assertErr{})
	urls := []string{
		"h3://quic-a",
		"h2c://clear-a",
		"https://secure-a",
		"http://plain-a",
	}
	got, ok := PickByProtocolPreference(urls, pool, func(uint32) uint32 { return 0 })
	if !ok || got != "h2c://clear-a" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestPickByProtocolPreferenceUsesFastestKnownPeerInSameProtocolGroup(t *testing.T) {
	pool := NewPool()
	pool.MarkResult("h3://quic-a", nil, 300*time.Millisecond)
	pool.MarkResult("h3://quic-b", nil, 50*time.Millisecond)
	pool.MarkResult("h2c://clear-a", nil, 5*time.Millisecond)

	urls := []string{
		"h3://quic-a",
		"h3://quic-b",
		"h2c://clear-a",
	}
	got, ok := PickByProtocolPreference(urls, pool, func(uint32) uint32 { return 0 })
	if !ok || got != "h3://quic-b" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestPickPreservesRoundRobinWhenLatencySamplesAreIncomplete(t *testing.T) {
	pool := NewPool()
	pool.MarkResult("http://a", nil, 300*time.Millisecond)

	urls := []string{"http://a", "http://b"}
	got, ok := pool.Pick(urls, func(uint32) uint32 { return 1 })
	if !ok || got != "http://b" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestGroupURLsByProtocolPreference(t *testing.T) {
	urls := []string{
		"http://plain-a",
		"h3://quic-a",
		"https://secure-a",
		"h2c://clear-a",
		"ftp://other-a",
	}
	groups := GroupURLsByProtocolPreference(urls)
	if len(groups) != 4 {
		t.Fatalf("group count = %d, want 4", len(groups))
	}
	if got := groups[0]; len(got) != 1 || got[0] != "h3://quic-a" {
		t.Fatalf("group[0] = %#v", got)
	}
	if got := groups[1]; len(got) != 1 || got[0] != "h2c://clear-a" {
		t.Fatalf("group[1] = %#v", got)
	}
	if got := groups[2]; len(got) != 1 || got[0] != "https://secure-a" {
		t.Fatalf("group[2] = %#v", got)
	}
	if got := groups[3]; len(got) != 2 || got[0] != "http://plain-a" || got[1] != "ftp://other-a" {
		t.Fatalf("group[3] = %#v", got)
	}
}

func TestGroupURLsByProtocolPreferenceAcceptsUppercaseSchemes(t *testing.T) {
	urls := []string{
		"HTTP://plain-a",
		"H3://quic-a",
		"HTTPS://secure-a",
		"H2C://clear-a",
		"FTP://other-a",
	}
	groups := GroupURLsByProtocolPreference(urls)
	if len(groups) != 4 {
		t.Fatalf("group count = %d, want 4", len(groups))
	}
	if got := groups[0]; len(got) != 1 || got[0] != "H3://quic-a" {
		t.Fatalf("group[0] = %#v", got)
	}
	if got := groups[1]; len(got) != 1 || got[0] != "H2C://clear-a" {
		t.Fatalf("group[1] = %#v", got)
	}
	if got := groups[2]; len(got) != 1 || got[0] != "HTTPS://secure-a" {
		t.Fatalf("group[2] = %#v", got)
	}
	if got := groups[3]; len(got) != 2 || got[0] != "HTTP://plain-a" || got[1] != "FTP://other-a" {
		t.Fatalf("group[3] = %#v", got)
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

func TestPickByProtocolPreferenceFallsBackWhenAllUnhealthy(t *testing.T) {
	pool := NewPool()
	urls := []string{"http://plain", "https://secure"}
	for _, raw := range urls {
		pool.Mark(raw, assertErr{})
		pool.Mark(raw, assertErr{})
	}
	got, ok := PickByProtocolPreference(urls, pool, func(uint32) uint32 { return 0 })
	if !ok || got != "https://secure" {
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

func TestPoolMarkResultTracksLatency(t *testing.T) {
	pool := NewPool()
	pool.MarkResult("http://a", nil, 120*time.Millisecond)
	pool.MarkResult("http://a", assertErr{}, 60*time.Millisecond)
	pool.MarkResult("http://a", nil, 30*time.Millisecond)

	states := pool.Snapshot()
	state, ok := states["http://a"]
	if !ok {
		t.Fatal("expected upstream state")
	}
	if state.LastLatencyMs != 30 {
		t.Fatalf("last latency = %d, want 30", state.LastLatencyMs)
	}
	if state.AverageLatencyMs != 70 {
		t.Fatalf("average latency = %d, want 70", state.AverageLatencyMs)
	}
	if state.LatencySamples != 3 {
		t.Fatalf("latency samples = %d, want 3", state.LatencySamples)
	}
}

func TestPoolMarkResultTracksLastErrorAndSuccessTime(t *testing.T) {
	pool := NewPool()
	pool.MarkResult("h3://origin.test/live", errors.New("dial udp 127.0.0.1:443: connect: connection refused"), 15*time.Millisecond)
	pool.MarkResult("h3://origin.test/other", errors.New("head failed\n"+strings.Repeat("x", 600)), 20*time.Millisecond)

	states := pool.Snapshot()
	state := states["h3://origin.test"]
	if state.LastError == "" {
		t.Fatal("expected last error after failed probe")
	}
	if len(state.LastError) > 515 {
		t.Fatalf("last error length = %d, want truncated error", len(state.LastError))
	}
	if !strings.HasSuffix(state.LastError, "...") {
		t.Fatalf("last error = %q, want truncation suffix", state.LastError)
	}
	if strings.Contains(state.LastError, "\n") {
		t.Fatalf("last error = %q, want single-line error", state.LastError)
	}
	if !state.LastSuccessAt.IsZero() {
		t.Fatalf("last success at = %s, want zero before success", state.LastSuccessAt)
	}

	pool.MarkResult("h3://origin.test/health", nil, 10*time.Millisecond)
	state = pool.Snapshot()["h3://origin.test"]
	if state.LastError != "" {
		t.Fatalf("last error = %q, want cleared after success", state.LastError)
	}
	if state.LastSuccessAt.IsZero() {
		t.Fatal("expected last success timestamp after success")
	}
}

func TestPoolMarkProbeResultTracksFailureKindAndClearsOnSuccess(t *testing.T) {
	pool := NewPool()
	pool.MarkProbeResult("https://origin.test/health", ProbeResult{
		Err:         errors.New("protocol failed"),
		FailureKind: probeFailureProtocol,
	}, 10*time.Millisecond)

	state := pool.Snapshot()["https://origin.test"]
	if state.LastFailureKind != probeFailureProtocol {
		t.Fatalf("last failure kind = %q, want %q", state.LastFailureKind, probeFailureProtocol)
	}
	if state.LastError != "protocol failed" {
		t.Fatalf("last error = %q, want protocol failed", state.LastError)
	}

	pool.MarkProbeResult("https://origin.test/health", ProbeResult{HTTPProtocol: "HTTP/2.0"}, 10*time.Millisecond)
	state = pool.Snapshot()["https://origin.test"]
	if state.LastFailureKind != "" {
		t.Fatalf("last failure kind after success = %q, want empty", state.LastFailureKind)
	}
	if state.LastError != "" {
		t.Fatalf("last error after success = %q, want empty", state.LastError)
	}
}

func TestConfiguredProtocol(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "h3://origin.test/live", want: "h3"},
		{raw: "h2c://origin.test/live", want: "h2c"},
		{raw: "https://origin.test/live", want: "https"},
		{raw: "http://origin.test/live", want: "http"},
		{raw: "ftp://origin.test/live", want: "ftp"},
		{raw: "not a url", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := ConfiguredProtocol(tt.raw); got != tt.want {
				t.Fatalf("ConfiguredProtocol(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "http path query fragment", raw: "http://origin.test/live?x=1#frag", want: "http://origin.test"},
		{name: "https uppercase", raw: "HTTPS://origin.test/base", want: "https://origin.test"},
		{name: "h2c uppercase with port", raw: "H2C://origin.test:8080/base?x=1", want: "h2c://origin.test:8080"},
		{name: "h3 path only", raw: "h3://origin.test/live", want: "h3://origin.test"},
		{name: "invalid raw fallback", raw: "http://bad host/path", want: "http://bad host/path"},
		{name: "non-url fallback", raw: "not a url", want: "not a url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.raw); got != tt.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func BenchmarkPickByProtocolPreference(b *testing.B) {
	urls := []string{
		"HTTP://plain-a",
		"HTTPS://secure-a/path?x=1",
		"h2c://clear-a/base?y=2",
		"H3://quic-a/live#frag",
		"http://plain-b",
		"https://secure-b",
		"h2c://clear-b",
		"h3://quic-b",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := PickByProtocolPreference(urls, nil, func(uint32) uint32 { return 0 }); !ok {
			b.Fatal("expected upstream")
		}
	}
}

func BenchmarkPickByProtocolPreferenceWithPool(b *testing.B) {
	urls := []string{
		"HTTP://plain-a",
		"HTTPS://secure-a/path?x=1",
		"h2c://clear-a/base?y=2",
		"H3://quic-a/live#frag",
		"http://plain-b",
		"https://secure-b",
		"h2c://clear-b",
		"h3://quic-b",
	}
	pool := NewPool()
	pool.MarkResult("HTTP://plain-a", nil, 90*time.Millisecond)
	pool.MarkResult("HTTPS://secure-a/path?x=1", nil, 20*time.Millisecond)
	pool.MarkResult("h2c://clear-a/base?y=2", nil, 10*time.Millisecond)
	pool.MarkResult("H3://quic-a/live#frag", nil, 5*time.Millisecond)
	pool.MarkResult("http://plain-b", nil, 80*time.Millisecond)
	pool.MarkResult("https://secure-b", nil, 25*time.Millisecond)
	pool.MarkResult("h2c://clear-b", nil, 15*time.Millisecond)
	pool.MarkResult("h3://quic-b", nil, 6*time.Millisecond)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := PickByProtocolPreference(urls, pool, func(uint32) uint32 { return 0 }); !ok {
			b.Fatal("expected upstream")
		}
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

func TestPoolProbeTrimsDeduplicatesAndStoresNormalizedState(t *testing.T) {
	pool := NewPool()
	var probed []string
	pool.Probe(context.Background(), []string{
		" http://origin.test/base?x=1 ",
		"http://origin.test/other",
		" ",
	}, func(_ context.Context, raw string) error {
		probed = append(probed, raw)
		return nil
	})
	if len(probed) != 1 || probed[0] != "http://origin.test/base?x=1" {
		t.Fatalf("probed URLs = %#v, want one trimmed origin probe", probed)
	}
	states := pool.Snapshot()
	if _, ok := states["http://origin.test"]; !ok {
		t.Fatalf("states = %#v, want normalized origin key", states)
	}
	if _, ok := states[" http://origin.test/base?x=1 "]; ok {
		t.Fatalf("states = %#v, must not store untrimmed URL key", states)
	}
	if _, ok := states["http://origin.test/base?x=1"]; ok {
		t.Fatalf("states = %#v, must not store path/query URL key", states)
	}
}

func TestPoolProbeWithResultTracksLastHTTPProtocolAndPreservesOnFailure(t *testing.T) {
	pool := NewPool()
	pool.ProbeWithResult(context.Background(), []string{"https://origin.test/a"}, func(context.Context, string) ProbeResult {
		return ProbeResult{HTTPProtocol: "HTTP/2.0"}
	})

	state := pool.Snapshot()["https://origin.test"]
	if state.LastHTTPProtocol != "HTTP/2.0" {
		t.Fatalf("last HTTP protocol = %q, want HTTP/2.0", state.LastHTTPProtocol)
	}
	if state.LastSuccessAt.IsZero() {
		t.Fatal("expected last success timestamp")
	}

	pool.ProbeWithResult(context.Background(), []string{"https://origin.test/b"}, func(context.Context, string) ProbeResult {
		return ProbeResult{Err: errors.New("probe failed")}
	})

	state = pool.Snapshot()["https://origin.test"]
	if state.LastHTTPProtocol != "HTTP/2.0" {
		t.Fatalf("last HTTP protocol after failure = %q, want preserved HTTP/2.0", state.LastHTTPProtocol)
	}
	if state.LastError != "probe failed" {
		t.Fatalf("last error = %q, want probe failed", state.LastError)
	}
}

func TestPoolAvailabilityUsesNormalizedStateAcrossPaths(t *testing.T) {
	pool := NewPool()
	pool.Mark("h3://quic.test/probe", assertErr{})
	pool.Mark("h3://quic.test/other", assertErr{})
	if pool.IsAvailable("h3://quic.test/live") {
		t.Fatal("expected normalized h3 origin to be unavailable across paths")
	}
	got, ok := PickByProtocolPreference([]string{
		"h3://quic.test/live",
		"h2c://clear.test/live",
	}, pool, func(uint32) uint32 { return 0 })
	if !ok || got != "h2c://clear.test/live" {
		t.Fatalf("got %q ok=%v, want h2c fallback after h3 origin failures", got, ok)
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

func TestPoolStartWithResultRecordsHTTPProtocol(t *testing.T) {
	pool := NewPool()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.StartWithResult(ctx, func() []string {
		return []string{"https://origin.test/path"}
	}, time.Hour, func(context.Context, string) ProbeResult {
		return ProbeResult{HTTPProtocol: "HTTP/2.0"}
	})

	state := pool.Snapshot()["https://origin.test"]
	if state.LastHTTPProtocol != "HTTP/2.0" {
		t.Fatalf("last HTTP protocol = %q, want HTTP/2.0", state.LastHTTPProtocol)
	}
}

func BenchmarkHTTPProbeWithResultConstruction(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmarkProbeResultFuncSink = HTTPProbeWithResult(time.Second)
	}
}

func TestHTTPProbeSupportsExplicitH2CUpstream(t *testing.T) {
	for name, scheme := range map[string]string{
		"lowercase": "h2c://",
		"uppercase": "H2C://",
	} {
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Proto != "HTTP/2.0" {
					t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = io.WriteString(w, "ok")
			}))
			upstream.Config.Protocols = new(http.Protocols)
			upstream.Config.Protocols.SetHTTP1(true)
			upstream.Config.Protocols.SetUnencryptedHTTP2(true)
			upstream.Start()
			defer upstream.Close()

			raw := scheme + upstream.Listener.Addr().String()
			result := HTTPProbeWithResult(time.Second)(context.Background(), raw)
			if result.Err != nil {
				t.Fatalf("HTTPProbeWithResult returned error: %v", result.Err)
			}
			if result.HTTPProtocol != "HTTP/2.0" {
				t.Fatalf("HTTP probe protocol = %q, want HTTP/2.0", result.HTTPProtocol)
			}
		})
	}
}

func TestHTTPProbeFallsBackToGETForExplicitH2CUpstream(t *testing.T) {
	for name, scheme := range map[string]string{
		"lowercase": "h2c://",
		"uppercase": "H2C://",
	} {
		t.Run(name, func(t *testing.T) {
			seenMethods := make(chan string, 2)
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Proto != "HTTP/2.0" {
					t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
				}
				if r.URL.Path != "/probe-base" {
					t.Fatalf("upstream request path = %q, want %q", r.URL.Path, "/probe-base")
				}
				seenMethods <- r.Method
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				if r.Method != http.MethodGet {
					t.Fatalf("fallback method = %q, want %q", r.Method, http.MethodGet)
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = io.WriteString(w, "ok")
			}))
			upstream.Config.Protocols = new(http.Protocols)
			upstream.Config.Protocols.SetHTTP1(true)
			upstream.Config.Protocols.SetUnencryptedHTTP2(true)
			upstream.Start()
			defer upstream.Close()

			raw := scheme + upstream.Listener.Addr().String() + "/probe-base"
			result := HTTPProbeWithResult(time.Second)(context.Background(), raw)
			if result.Err != nil {
				t.Fatalf("HTTPProbeWithResult returned error: %v", result.Err)
			}
			if result.HTTPProtocol != "HTTP/2.0" {
				t.Fatalf("HTTP probe fallback protocol = %q, want HTTP/2.0", result.HTTPProtocol)
			}

			for i, want := range []string{http.MethodHead, http.MethodGet} {
				select {
				case got := <-seenMethods:
					if got != want {
						t.Fatalf("probe method[%d] = %q, want %q", i, got, want)
					}
				case <-time.After(time.Second):
					t.Fatalf("timed out waiting for probe method %q", want)
				}
			}
		})
	}
}

func TestHTTPProbeDefaultClientSupportsTLS10HTTPSUpstream(t *testing.T) {
	client := newHTTPProbeClient(time.Second)
	if client.Timeout != time.Second {
		t.Fatalf("HTTP probe client timeout = %s, want %s", client.Timeout, time.Second)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP probe transport = %T, want *http.Transport", client.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("HTTP probe should preserve ProxyFromEnvironment behavior")
	}
	if tr.DialContext == nil {
		t.Fatal("HTTP probe DialContext is nil")
	}
	if tr.IdleConnTimeout != defaultHTTPProbeIdleConnTimeout {
		t.Fatalf("HTTP probe idle timeout = %s, want %s", tr.IdleConnTimeout, defaultHTTPProbeIdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != defaultHTTPProbeTLSHandshakeTimeout {
		t.Fatalf("HTTP probe TLS handshake timeout = %s, want %s", tr.TLSHandshakeTimeout, defaultHTTPProbeTLSHandshakeTimeout)
	}
	if tr.ExpectContinueTimeout != defaultHTTPProbeExpectContinue {
		t.Fatalf("HTTP probe expect-continue timeout = %s, want %s", tr.ExpectContinueTimeout, defaultHTTPProbeExpectContinue)
	}
	if tr.MaxIdleConns != 128 || tr.MaxIdleConnsPerHost != 32 {
		t.Fatalf("HTTP probe idle pool = %d/%d, want 128/32", tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("HTTP probe ForceAttemptHTTP2 should be enabled")
	}
	if !tr.DisableCompression {
		t.Fatal("HTTP probe DisableCompression should be enabled")
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("expected HTTP probe TLS config")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Fatalf("HTTP probe TLS MinVersion = %#x, want %#x", tr.TLSClientConfig.MinVersion, tls.VersionTLS10)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("HTTP probe should keep certificate verification enabled")
	}
}

func TestHTTPProbeH2CClientUsesBoundedTransport(t *testing.T) {
	client := newHTTPProbeH2CClient(time.Second)
	if client.Timeout != time.Second {
		t.Fatalf("h2c probe client timeout = %s, want %s", client.Timeout, time.Second)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("h2c probe transport = %T, want *http.Transport", client.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("h2c probe DialContext is nil")
	}
	if tr.IdleConnTimeout != defaultHTTPProbeIdleConnTimeout {
		t.Fatalf("h2c probe idle timeout = %s, want %s", tr.IdleConnTimeout, defaultHTTPProbeIdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != defaultHTTPProbeTLSHandshakeTimeout {
		t.Fatalf("h2c probe TLS handshake timeout = %s, want %s", tr.TLSHandshakeTimeout, defaultHTTPProbeTLSHandshakeTimeout)
	}
	if tr.ExpectContinueTimeout != defaultHTTPProbeExpectContinue {
		t.Fatalf("h2c probe expect-continue timeout = %s, want %s", tr.ExpectContinueTimeout, defaultHTTPProbeExpectContinue)
	}
	if tr.MaxIdleConns != 128 || tr.MaxIdleConnsPerHost != 32 {
		t.Fatalf("h2c probe idle pool = %d/%d, want 128/32", tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("h2c probe ForceAttemptHTTP2 should be enabled")
	}
	if !tr.DisableCompression {
		t.Fatal("h2c probe DisableCompression should be enabled")
	}
	if tr.Protocols == nil {
		t.Fatal("h2c probe Protocols is nil")
	}
}

func TestHTTPProbeHTTP3ClientUsesBoundedQUICTransport(t *testing.T) {
	client := newHTTPProbeHTTP3Client(time.Second)
	if client.Timeout != time.Second {
		t.Fatalf("HTTP/3 probe client timeout = %s, want %s", client.Timeout, time.Second)
	}
	tr, ok := client.Transport.(*http3.Transport)
	if !ok {
		t.Fatalf("HTTP/3 probe transport = %T, want *http3.Transport", client.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("HTTP/3 probe TLS config is nil")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 probe TLS min version = %#x, want %#x", tr.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("HTTP/3 probe should skip verification for explicit h3 health probe endpoints")
	}
	if len(tr.TLSClientConfig.NextProtos) != 1 || tr.TLSClientConfig.NextProtos[0] != http3.NextProtoH3 {
		t.Fatalf("HTTP/3 probe NextProtos = %#v, want [%s]", tr.TLSClientConfig.NextProtos, http3.NextProtoH3)
	}
	if tr.QUICConfig == nil {
		t.Fatal("HTTP/3 probe QUIC config is nil")
	}
	if tr.QUICConfig.HandshakeIdleTimeout != defaultHTTPProbeQUICHandshakeIdle {
		t.Fatalf("HTTP/3 probe handshake idle timeout = %s, want %s", tr.QUICConfig.HandshakeIdleTimeout, defaultHTTPProbeQUICHandshakeIdle)
	}
	if tr.QUICConfig.MaxIdleTimeout != defaultHTTPProbeQUICMaxIdle {
		t.Fatalf("HTTP/3 probe max idle timeout = %s, want %s", tr.QUICConfig.MaxIdleTimeout, defaultHTTPProbeQUICMaxIdle)
	}
	if !tr.DisableCompression {
		t.Fatal("HTTP/3 probe DisableCompression should be enabled")
	}
}

func TestHTTPProbeSupportsExplicitH3Upstream(t *testing.T) {
	for name, scheme := range map[string]string{
		"lowercase": "h3://",
		"uppercase": "H3://",
	} {
		t.Run(name, func(t *testing.T) {
			upstream, raw := startTestHTTP3ProbeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Proto != "HTTP/3.0" {
					t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = io.WriteString(w, "ok")
			}))
			defer closeTestHTTP3ProbeServer(t, upstream)

			result := HTTPProbeWithResult(time.Second)(context.Background(), scheme+strings.TrimPrefix(raw, "h3://"))
			if result.Err != nil {
				t.Fatalf("HTTPProbeWithResult returned error: %v", result.Err)
			}
			if result.HTTPProtocol != "HTTP/3.0" {
				t.Fatalf("HTTP probe protocol = %q, want HTTP/3.0", result.HTTPProtocol)
			}
		})
	}
}

func TestDoProbeRequestRejectsExplicitProtocolMismatch(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Proto:      "HTTP/1.1",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})}

	resp, err := doProbeRequest(client, context.Background(), http.MethodHead, "http://example.test", "HTTP/2.0")
	if resp != nil {
		t.Fatalf("response = %#v, want nil on protocol mismatch", resp)
	}
	if err == nil {
		t.Fatal("expected protocol mismatch error")
	}
	if !strings.Contains(err.Error(), "unexpected upstream protocol") {
		t.Fatalf("error = %q, want protocol mismatch", err.Error())
	}
	if kind := probeFailureKind("", err); kind != probeFailureProtocol {
		t.Fatalf("failure kind = %q, want %q", kind, probeFailureProtocol)
	}
}

func TestHTTPProbeWithResultClassifiesInvalidRequest(t *testing.T) {
	result := HTTPProbeWithResult(time.Second)(context.Background(), "http://[::1")
	if result.Err == nil {
		t.Fatal("expected invalid request error")
	}
	if result.FailureKind != probeFailureInvalidRequest {
		t.Fatalf("failure kind = %q, want %q", result.FailureKind, probeFailureInvalidRequest)
	}
}

func TestHTTPProbeFallsBackToGETForExplicitH3Upstream(t *testing.T) {
	for name, scheme := range map[string]string{
		"lowercase": "h3://",
		"uppercase": "H3://",
	} {
		t.Run(name, func(t *testing.T) {
			seenMethods := make(chan string, 2)
			upstream, raw := startTestHTTP3ProbeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Proto != "HTTP/3.0" {
					t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
				}
				if r.URL.Path != "/probe-base" {
					t.Fatalf("upstream request path = %q, want %q", r.URL.Path, "/probe-base")
				}
				seenMethods <- r.Method
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				if r.Method != http.MethodGet {
					t.Fatalf("fallback method = %q, want %q", r.Method, http.MethodGet)
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = io.WriteString(w, "ok")
			}))
			defer closeTestHTTP3ProbeServer(t, upstream)

			raw = scheme + strings.TrimPrefix(raw, "h3://") + "/probe-base"
			result := HTTPProbeWithResult(time.Second)(context.Background(), raw)
			if result.Err != nil {
				t.Fatalf("HTTPProbeWithResult returned error: %v", result.Err)
			}
			if result.HTTPProtocol != "HTTP/3.0" {
				t.Fatalf("HTTP probe fallback protocol = %q, want HTTP/3.0", result.HTTPProtocol)
			}

			for i, want := range []string{http.MethodHead, http.MethodGet} {
				select {
				case got := <-seenMethods:
					if got != want {
						t.Fatalf("probe method[%d] = %q, want %q", i, got, want)
					}
				case <-time.After(time.Second):
					t.Fatalf("timed out waiting for probe method %q", want)
				}
			}
		})
	}
}

func startTestHTTP3ProbeServer(t *testing.T, handler http.Handler) (*http3.Server, string) {
	t.Helper()

	cert, err := acme.GenerateSelfSigned("127.0.0.1:0")
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	server := &http3.Server{
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h3"},
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(pc)
	}()
	t.Cleanup(func() {
		closeTestHTTP3ProbeServer(t, server)
		select {
		case serveErr := <-errCh:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Fatalf("http3 serve returned error: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("http3 server did not stop in time")
		}
	})

	return server, "h3://" + pc.LocalAddr().String()
}

func closeTestHTTP3ProbeServer(t *testing.T, server *http3.Server) {
	t.Helper()
	if server == nil {
		return
	}
	if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("close http3 server: %v", err)
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "err" }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
