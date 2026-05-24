package proxy

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

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
