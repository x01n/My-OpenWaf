package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

var benchmarkProxyBoolSink bool

func TestVaryDisallowsCaching(t *testing.T) {
	if varyDisallowsCaching("") {
		t.Fatal("empty Vary should not block")
	}
	if varyDisallowsCaching("Accept-Encoding") {
		t.Fatal("Accept-Encoding only should not block")
	}
	if varyDisallowsCaching("accept-encoding, Accept-Encoding") {
		t.Fatal("duplicate accept-encoding should not block")
	}
	if !varyDisallowsCaching("Accept-Encoding, User-Agent") {
		t.Fatal("multi-axis Vary should block")
	}
	if !varyDisallowsCaching("User-Agent") {
		t.Fatal("non-encoding Vary should block")
	}
}

func TestUpstreamErrorLoggingHelpers(t *testing.T) {
	for _, n := range []uint64{1, 16, 1024, 2048} {
		if !shouldLogUpstreamErrorCount(n) {
			t.Fatalf("expected count %d to be logged", n)
		}
	}
	for _, n := range []uint64{17, 1023, 1025} {
		if shouldLogUpstreamErrorCount(n) {
			t.Fatalf("expected count %d to be sampled out", n)
		}
	}

	err := &url.Error{Op: "Get", URL: "http://127.0.0.1:8800/secret?token=value", Err: errors.New("dial tcp 127.0.0.1:8800: connectex")}
	reason := upstreamErrorReason(err)
	if strings.Contains(reason, "token=value") || strings.Contains(reason, "/secret") {
		t.Fatalf("upstream error reason leaked request URL: %q", reason)
	}
}

func TestIsHTTPSUpstreamBase(t *testing.T) {
	cases := map[string]bool{
		"":                          false,
		"http://127.0.0.1:8800":     false,
		"https://example.test":      true,
		"HTTPS://example.test":      true,
		"HtTpS://example.test/path": true,
		"ftp://example.test":        false,
	}
	for input, want := range cases {
		if got := isHTTPSUpstreamBase(input); got != want {
			t.Fatalf("isHTTPSUpstreamBase(%q) = %v, want %v", input, got, want)
		}
	}
}

func BenchmarkIsHTTPSUpstreamBase(b *testing.B) {
	base := "HTTPS://127.0.0.1:8800/api/v1/example/path?alpha=1&beta=2"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isHTTPSUpstreamBase(base)
	}
}

func BenchmarkIsHTTPSUpstreamBaseToLower(b *testing.B) {
	base := "HTTPS://127.0.0.1:8800/api/v1/example/path?alpha=1&beta=2"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = strings.HasPrefix(strings.ToLower(base), "https://")
	}
}

func TestShouldCacheHTTPResponse_VaryAcceptEncoding(t *testing.T) {
	h := http.Header{}
	h.Set("Vary", "Accept-Encoding")
	resp := &HTTPResponse{StatusCode: 200, Body: []byte("ok"), Header: h}
	if !ShouldCacheHTTPResponse("GET", resp, false) {
		t.Fatal("expected cacheable with Vary: Accept-Encoding")
	}
	h.Set("Vary", "User-Agent")
	if ShouldCacheHTTPResponse("GET", resp, false) {
		t.Fatal("should not cache with Vary: User-Agent")
	}
}

func TestShouldCacheHTTPResponse_BypassUpstreamPrivate(t *testing.T) {
	h := http.Header{}
	h.Set("Cache-Control", "private, no-cache, no-store, max-age=0, must-revalidate")
	resp := &HTTPResponse{StatusCode: 200, Body: []byte("x"), Header: h}
	if ShouldCacheHTTPResponse("GET", resp, false) {
		t.Fatal("should block without bypass")
	}
	if !ShouldCacheHTTPResponse("GET", resp, true) {
		t.Fatal("expected cacheable with bypass")
	}
	h.Set("Set-Cookie", "a=b")
	if ShouldCacheHTTPResponse("GET", resp, true) {
		t.Fatal("set-cookie must still block")
	}
}

func TestSiteCacheTTLDetails_QueryAware(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "exact", Value: "/x?q=1", TTL: 10},
		},
	}
	if ttl, explicit := SiteCacheTTLDetails(rt, "/x?q=1"); ttl != 10 || !explicit {
		t.Fatalf("exact+query: ttl=%d explicit=%v", ttl, explicit)
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/x"); ttl != 0 {
		t.Fatalf("exact should not match path without query, got %d", ttl)
	}
	rt2 := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/a", TTL: 5},
		},
	}
	if ttl, explicit := SiteCacheTTLDetails(rt2, "/a/b?r=1"); ttl != 5 || !explicit {
		t.Fatalf("prefix+query: ttl=%d explicit=%v", ttl, explicit)
	}
}

func TestSiteCacheTTLDetails_DefaultNotExplicit(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled:    true,
		CacheDefaultTTL: 60,
	}
	if ttl, explicit := SiteCacheTTLDetails(rt, "/anything"); ttl != 0 || explicit {
		t.Fatalf("default TTL must not apply without a matching rule, got ttl=%d explicit=%v", ttl, explicit)
	}
}

func TestSiteCacheTTLDetails_RuleTTLZeroUsesDefault(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled:    true,
		CacheDefaultTTL: 120,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/static", TTL: 0},
		},
	}
	if ttl, ex := SiteCacheTTLDetails(rt, "/static/a.js"); ttl != 120 || !ex {
		t.Fatalf("rule ttl 0 should inherit cache_default_ttl, got ttl=%d explicit=%v", ttl, ex)
	}
}

func TestSanitizeHeadersForEdgeCache(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Encoding", "br")
	h.Set("Content-Type", "application/javascript")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Content-Length", "999")
	h.Set("Cache-Control", "public")
	out := SanitizeHeadersForEdgeCache(h)
	if out.Get("Content-Encoding") != "br" {
		t.Fatalf("want br, got %q", out.Get("Content-Encoding"))
	}
	if out.Get("Transfer-Encoding") != "" {
		t.Fatal("expected Transfer-Encoding removed")
	}
	if out.Get("Content-Length") != "" {
		t.Fatal("expected Content-Length removed")
	}
}

func TestBuildUpstreamRequestStripsHopByHopHeadersCaseInsensitive(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("CoNnEcTiOn", "close")
	ctx.Request.Header.Set("Proxy-Connection", "keep-alive")
	ctx.Request.Header.Set("Transfer-Encoding", "chunked")
	ctx.Request.Header.Set("X-Test", "kept")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("Connection"); got != "" {
		t.Fatalf("expected Connection stripped, got %q", got)
	}
	if got := req.Header.Get("Proxy-Connection"); got != "" {
		t.Fatalf("expected Proxy-Connection stripped, got %q", got)
	}
	if got := req.Header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("expected Transfer-Encoding stripped, got %q", got)
	}
	if got := req.Header.Get("X-Test"); got != "kept" {
		t.Fatalf("expected X-Test kept, got %q", got)
	}
}

func TestBuildUpstreamRequestPreservesRepeatedCanonicalHeaders(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Add("x-repeat", "one")
	ctx.Request.Header.Add("X-Repeat", "two")
	ctx.Request.Header.Set("x-test", "kept")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("X-Test"); got != "kept" {
		t.Fatalf("expected X-Test kept, got %q", got)
	}
	values := req.Header.Values("X-Repeat")
	if len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("expected repeated X-Repeat values preserved, got %#v", values)
	}
}

func TestBuildUpstreamRequestCanonicalHeaderStorage(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Accept", "application/json")
	ctx.Request.Header.Set("x-test", "kept")
	ctx.Request.Header.Add("x-repeat", "one")
	ctx.Request.Header.Add("X-Repeat", "two")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header["User-Agent"]; len(got) != 1 || got[0] != "bench-agent" {
		t.Fatalf("expected canonical User-Agent storage, got %#v", got)
	}
	if got := req.Header["Accept"]; len(got) != 1 || got[0] != "application/json" {
		t.Fatalf("expected canonical Accept storage, got %#v", got)
	}
	if got := req.Header.Get("X-Test"); got != "kept" {
		t.Fatalf("expected X-Test kept, got %q", got)
	}
	values := req.Header.Values("X-Repeat")
	if len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("expected repeated X-Repeat values preserved, got %#v", values)
	}
}

func TestBuildUpstreamRequestCopiesHeaderValues(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("X-Test", "kept")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	ctx.Request.Header.Set("X-Test", "mutated")

	if got := req.Header.Get("X-Test"); got != "kept" {
		t.Fatalf("X-Test after source mutation = %q, want kept", got)
	}
}

func TestAddUpstreamHeader(t *testing.T) {
	header := http.Header{}
	addUpstreamHeader(header, []byte("Accept"), []byte("application/json"))
	addUpstreamHeader(header, []byte("User-Agent"), []byte("bench-agent"))
	addUpstreamHeader(header, []byte("Content-Type"), []byte("application/json"))
	addUpstreamHeader(header, []byte("x-test"), []byte("kept"))
	addUpstreamHeader(header, []byte("x-repeat"), []byte("one"))
	addUpstreamHeader(header, []byte("X-Repeat"), []byte("two"))

	if got := header["Accept"]; len(got) != 1 || got[0] != "application/json" {
		t.Fatalf("Accept = %#v", got)
	}
	if got := header["User-Agent"]; len(got) != 1 || got[0] != "bench-agent" {
		t.Fatalf("User-Agent = %#v", got)
	}
	if got := header["Content-Type"]; len(got) != 1 || got[0] != "application/json" {
		t.Fatalf("Content-Type = %#v", got)
	}
	if got := header.Get("X-Test"); got != "kept" {
		t.Fatalf("X-Test = %q", got)
	}
	values := header.Values("X-Repeat")
	if len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("X-Repeat = %#v", values)
	}
}

func TestAddUpstreamHeaderBrowserCanonicalFastPaths(t *testing.T) {
	header := http.Header{}
	keys := []string{
		"Accept-Encoding",
		"Accept-Language",
		"Referer",
		"Origin",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Dest",
		"Cache-Control",
		"Pragma",
		"Upgrade-Insecure-Requests",
		"X-Client-Data",
		"X-Requested-With",
		"If-Modified-Since",
		"X-Tingyun-Id",
		"Cookie",
		"Content-Length",
	}
	for _, key := range keys {
		addUpstreamHeader(header, []byte(key), []byte("kept"))
	}

	for _, key := range keys {
		values := header[key]
		if len(values) != 1 || values[0] != "kept" {
			t.Fatalf("%s = %#v", key, values)
		}
	}
}

func TestBuildUpstreamRequestPOSTBodySemantics(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"ok":true}`))

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if req.ContentLength != int64(len(`{"ok":true}`)) {
		t.Fatalf("ContentLength = %d", req.ContentLength)
	}
	if req.Body == nil || req.Body == http.NoBody {
		t.Fatalf("expected readable Body, got %#v", req.Body)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("Body = %q", string(body))
	}
	if req.GetBody == nil {
		t.Fatalf("GetBody is nil")
	}
	second, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody returned error: %v", err)
	}
	defer second.Close()
	replayed, err := io.ReadAll(second)
	if err != nil {
		t.Fatalf("read replay body: %v", err)
	}
	if string(replayed) != `{"ok":true}` {
		t.Fatalf("GetBody replay = %q", string(replayed))
	}
}

func TestBuildUpstreamRequestEmptyPOSTBodySemantics(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if req.Body != nil {
		t.Fatalf("Body = %#v", req.Body)
	}
	if req.GetBody != nil {
		t.Fatalf("GetBody is not nil")
	}
	if req.ContentLength != 0 {
		t.Fatalf("ContentLength = %d", req.ContentLength)
	}
}

func TestBuildUpstreamRequestPOSTBodySendsToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != int64(len(`{"ok":true}`)) {
			t.Fatalf("upstream ContentLength = %d", r.ContentLength)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("upstream read body: %v", err)
		}
		if string(body) != `{"ok":true}` {
			t.Fatalf("upstream body = %q", string(body))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"ok":true}`))

	req, err := buildUpstreamRequest(context.Background(), ctx, upstream.URL, nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http client Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("StatusCode = %d", resp.StatusCode)
	}
}

func TestBuildUpstreamRequestURLAndHostSemantics(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource/sub?x=1&y=two")

	req, err := buildUpstreamRequest(context.Background(), ctx, "https://origin.example:9443/base", net.ParseIP("203.0.113.10"), "client.example", true)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if req.Method != http.MethodGet {
		t.Fatalf("Method = %q", req.Method)
	}
	if req.URL.Scheme != "https" {
		t.Fatalf("URL.Scheme = %q", req.URL.Scheme)
	}
	if req.URL.Host != "origin.example:9443" {
		t.Fatalf("URL.Host = %q", req.URL.Host)
	}
	if req.URL.Path != "/base/resource/sub" {
		t.Fatalf("URL.Path = %q", req.URL.Path)
	}
	if req.URL.RawQuery != "x=1&y=two" {
		t.Fatalf("URL.RawQuery = %q", req.URL.RawQuery)
	}
	if req.Host != "client.example" {
		t.Fatalf("Host = %q", req.Host)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "client.example" {
		t.Fatalf("X-Forwarded-Host = %q", got)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.10" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto = %q", got)
	}
}

func TestBuildUpstreamRequestRejectsInvalidUpstreamBase(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")

	if _, err := buildUpstreamRequest(context.Background(), ctx, "http://[::1", nil, "example.test", false); err == nil {
		t.Fatalf("expected invalid upstream base error")
	}
}

func TestBuildUpstreamRequestMatchesNewRequestCoreSemantics(t *testing.T) {
	t.Run("nil context rejected", func(t *testing.T) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/resource")
		if _, err := buildUpstreamRequest(nil, ctx, "http://127.0.0.1:8800", nil, "example.test", false); err == nil {
			t.Fatalf("expected nil context error")
		}
	})

	t.Run("empty method defaults to get", func(t *testing.T) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("")
		ctx.Request.SetRequestURI("/resource")
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			t.Fatalf("buildUpstreamRequest returned error: %v", err)
		}
		if req.Method != http.MethodGet {
			t.Fatalf("Method = %q", req.Method)
		}
	})

	t.Run("invalid method rejected", func(t *testing.T) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("BAD METHOD")
		ctx.Request.SetRequestURI("/resource")
		if _, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false); err == nil {
			t.Fatalf("expected invalid method error")
		}
	})

	t.Run("empty port normalized", func(t *testing.T) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/resource")
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://origin.example:", nil, "example.test", false)
		if err != nil {
			t.Fatalf("buildUpstreamRequest returned error: %v", err)
		}
		if req.URL.Host != "origin.example" {
			t.Fatalf("URL.Host = %q", req.URL.Host)
		}
		if req.Host != "origin.example" {
			t.Fatalf("Host = %q", req.Host)
		}
	})
}

func TestUpstreamRequestURL(t *testing.T) {
	tests := []struct {
		name string
		base string
		uri  string
		want string
	}{
		{name: "query", base: "http://127.0.0.1:8800", uri: "/resource?x=1", want: "http://127.0.0.1:8800/resource?x=1"},
		{name: "base trailing slash", base: "http://127.0.0.1:8800/", uri: "/resource?x=1", want: "http://127.0.0.1:8800/resource?x=1"},
		{name: "no query", base: "http://127.0.0.1:8800", uri: "/resource", want: "http://127.0.0.1:8800/resource"},
		{name: "empty path", base: "http://127.0.0.1:8800", uri: "", want: "http://127.0.0.1:8800/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI(tt.uri)
			if got := upstreamRequestURL(ctx, tt.base); got != tt.want {
				t.Fatalf("upstreamRequestURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequestMethod(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "GET", want: "GET"},
		{input: "POST", want: "POST"},
		{input: "HEAD", want: "HEAD"},
		{input: "PUT", want: "PUT"},
		{input: "PATCH", want: "PATCH"},
		{input: "TRACE", want: "TRACE"},
		{input: "DELETE", want: "DELETE"},
		{input: "OPTIONS", want: "OPTIONS"},
		{input: "CONNECT", want: "CONNECT"},
		{input: "post", want: "post"},
		{input: "Head", want: "Head"},
		{input: "custom", want: "custom"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod(tt.input)
			if got := requestMethod(ctx); got != tt.want {
				t.Fatalf("requestMethod() = %q, want %q", got, tt.want)
			}
		})
	}
}

func BenchmarkRequestMethodGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if requestMethod(ctx) == "" {
			b.Fatal("empty method")
		}
	}
}

func BenchmarkRequestMethodStringGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if string(ctx.Method()) == "" {
			b.Fatal("empty method")
		}
	}
}

func TestForwardedProtoFromHeader(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"   ":         "",
		"http":        "http",
		" HtTp ":      "http",
		"HTTPS":       "https",
		" h3 ":        "h3",
		"CustomProto": "customproto",
	}
	for input, want := range cases {
		if got := forwardedProtoFromHeader([]byte(input)); got != want {
			t.Fatalf("forwardedProtoFromHeader(%q) = %q, want %q", input, got, want)
		}
	}
}

func BenchmarkIsHopByHopBytesMixedCase(b *testing.B) {
	name := []byte("TrAnSfEr-EnCoDiNg")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isHopByHopBytes(name)
	}
}

func BenchmarkIsHopByHopStringMixedCase(b *testing.B) {
	name := "TrAnSfEr-EnCoDiNg"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isHopByHop(name)
	}
}

func BenchmarkInboundProtoDefaultHTTP(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if inboundProto(ctx) == "" {
			b.Fatal("empty proto")
		}
	}
}

func BenchmarkInboundProtoForwardedMixedCase(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("X-Forwarded-Proto", " HtTpS ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if inboundProto(ctx) != "https" {
			b.Fatal("unexpected proto")
		}
	}
}

func BenchmarkBuildUpstreamRequestSmallGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Accept", "application/json")
	ctx.Request.Header.Set("X-Test", "kept")
	ctx.Request.Header.Set("Connection", "close")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.URL.Path == "" {
			b.Fatal("empty path")
		}
	}
}

func BenchmarkBuildUpstreamRequestSmallPOST(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Accept", "application/json")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("X-Test", "kept")
	ctx.Request.SetBody([]byte(`{"ok":true}`))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.Body == nil {
			b.Fatal("empty body reader")
		}
	}
}

func BenchmarkBuildUpstreamRequestBrowserHeadersGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Host", "127.0.0.1:80")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	ctx.Request.Header.Set("Sec-Ch-Ua", `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`)
	ctx.Request.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	ctx.Request.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	ctx.Request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	ctx.Request.Header.Set("Sec-Fetch-Site", "same-origin")
	ctx.Request.Header.Set("Sec-Fetch-Mode", "navigate")
	ctx.Request.Header.Set("Sec-Fetch-Dest", "document")
	ctx.Request.Header.Set("Referer", "http://127.0.0.1:80/")
	ctx.Request.Header.Set("Accept-Encoding", "gzip, deflate, br")
	ctx.Request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	ctx.Request.Header.Set("Connection", "close")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.Header.Get("Sec-Fetch-Dest") == "" {
			b.Fatal("missing browser header")
		}
	}
}

func BenchmarkRequestPathOriginal(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if requestPath(ctx) == "" {
			b.Fatal("empty path")
		}
	}
}

func BenchmarkUpstreamRequestURLWithQuery(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if upstreamRequestURL(ctx, "http://127.0.0.1:8800") == "" {
			b.Fatal("empty url")
		}
	}
}

func BenchmarkUpstreamRequestURLNoQuery(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if upstreamRequestURL(ctx, "http://127.0.0.1:8800") == "" {
			b.Fatal("empty url")
		}
	}
}

func TestSiteCacheTTLDetails_SuffixMidTokenRejected(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: "ig", TTL: 10},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/v1/api/config"); ttl != 0 {
		t.Fatalf("suffix ig must not match inside config, got ttl=%d", ttl)
	}
}

func TestSiteCacheTTLDetails_SuffixJSWithQuery(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".js", TTL: 10},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/a/b.js?v=1"); ttl != 10 {
		t.Fatalf("want .js match with query ignored for suffix, got %d", ttl)
	}
}

func TestSiteCacheTTLDetails_SuffixPageTxt(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: "__PAGE__.txt", TTL: 10},
		},
	}
	k := "/blog/archive/__next.blog.archive.__PAGE__.txt"
	if ttl, _ := SiteCacheTTLDetails(rt, k); ttl != 10 {
		t.Fatalf("want __PAGE__.txt match, got %d for %q", ttl, k)
	}
}

func TestSiteCacheTTLDetails_CaseInsensitivePrefix(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/api", TTL: 10, CaseInsensitive: true},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/API/v1/config"); ttl != 10 {
		t.Fatalf("want case-insensitive prefix match, got %d", ttl)
	}
}

func TestSiteCacheTTLDetails_IgnoreQueryForSuffix(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".js", TTL: 10, IgnoreQuery: true},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/a/b.js?v=1&x=2"); ttl != 10 {
		t.Fatalf("want suffix match ignoring query comparison, got %d", ttl)
	}
}

func TestSiteCacheTTLDetails_Contains(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "contains", Value: "/cdn/", TTL: 10},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/x/cdn/foo"); ttl != 10 {
		t.Fatalf("contains path: want ttl 10, got %d", ttl)
	}
}

func TestSiteCacheTTLDetails_Regex(t *testing.T) {
	re := regexp.MustCompile(`\.(js|mjs)$`)
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "regex", Value: `\.(js|mjs)$`, TTL: 10, Regex: re},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/a.X"); ttl != 0 {
		t.Fatalf("regex should not match, got %d", ttl)
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/a/b.mjs"); ttl != 10 {
		t.Fatalf("regex mjs: want ttl 10, got %d", ttl)
	}
	rt2 := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "regex", Value: `\.(js|mjs)$`, TTL: 10, Regex: re, IgnoreQuery: true},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt2, "/a/b.mjs?x=1"); ttl != 10 {
		t.Fatalf("regex+ignore query: want ttl 10, got %d", ttl)
	}
}

func TestSiteCacheEligible_AllowedWithClientNoCache(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/favicon.ico")
	req.SetHost("127.0.0.1")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}
	key, ttl, _ := SiteCacheEligible(rt, ctx)
	if key == "" || ttl != 60 {
		t.Fatalf("expected cache eligible with client no-cache, got key=%q ttl=%d", key, ttl)
	}
}

func TestSiteCacheEligible_Methods(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}
	tests := []struct {
		method string
		want   bool
	}{
		{method: "GET", want: true},
		{method: "get", want: true},
		{method: "HEAD", want: true},
		{method: "head", want: true},
		{method: "POST", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			var req protocol.Request
			req.SetMethod(tt.method)
			req.SetRequestURI("/favicon.ico")
			req.SetHost("127.0.0.1")
			ctx := app.NewContext(0)
			req.CopyTo(&ctx.Request)

			key, ttl, _ := SiteCacheEligible(rt, ctx)
			got := key != "" && ttl == 60
			if got != tt.want {
				t.Fatalf("SiteCacheEligible() cacheable = %v, want %v, key=%q ttl=%d", got, tt.want, key, ttl)
			}
		})
	}
}

func BenchmarkIsCacheableRequestMethodGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	method := ctx.Method()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isCacheableRequestMethod(method)
	}
}

func BenchmarkIsCacheableRequestMethodPOST(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	method := ctx.Method()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isCacheableRequestMethod(method)
	}
}

func BenchmarkIsCacheableRequestMethodStringGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	method := ctx.Method()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := string(method)
		benchmarkProxyBoolSink = strings.EqualFold(m, "GET") || strings.EqualFold(m, "HEAD")
	}
}

func BenchmarkIsCacheableRequestMethodStringPOST(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	method := ctx.Method()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := string(method)
		benchmarkProxyBoolSink = strings.EqualFold(m, "GET") || strings.EqualFold(m, "HEAD")
	}
}

func BenchmarkSiteCacheEligibleGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/favicon.ico")
	ctx.Request.SetHost("127.0.0.1")
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key, ttl, _ := SiteCacheEligible(rt, ctx)
		if key == "" || ttl != 60 {
			b.Fatal("not cache eligible")
		}
	}
}

func BenchmarkSiteCacheEligiblePOST(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/favicon.ico")
	ctx.Request.SetHost("127.0.0.1")
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key, ttl, _ := SiteCacheEligible(rt, ctx)
		if key != "" || ttl != 0 {
			b.Fatal("post should not be cache eligible")
		}
	}
}
