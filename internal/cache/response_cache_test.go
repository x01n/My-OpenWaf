package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestResponseCacheBasic(t *testing.T) {
	rc := NewResponseCache(10, 60)
	defer rc.Close()

	key := CacheKey("GET", "example.com", "/page", "")
	body := []byte("<html>hello</html>")

	// Miss
	if entry := rc.Get(key); entry != nil {
		t.Fatal("expected cache miss")
	}

	// Set and hit
	rc.Set(key, 200, "text/html", body, 60, nil)
	entry := rc.Get(key)
	if entry == nil {
		t.Fatal("expected cache hit")
	}
	if entry.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", entry.StatusCode)
	}
	if string(entry.Body) != "<html>hello</html>" {
		t.Errorf("unexpected body")
	}

	// Stats
	entries, size := rc.Stats()
	if entries != 1 {
		t.Errorf("expected 1 entry, got %d", entries)
	}
	if size <= int64(len(body)) || size > 10*1024*1024 {
		t.Errorf("estimated cache size %d does not include bounded entry metadata", size)
	}
}

func TestResponseCacheConstructorUsesDocumentedDefaults(t *testing.T) {
	rc := NewResponseCache(0, 0)
	defer rc.Close()

	key := CacheKey("GET", "defaults.example.test", "/", "")
	rc.Set(key, http.StatusOK, "text/plain", []byte("default"), 0)
	entry := rc.Get(key)
	if entry == nil {
		t.Fatal("zero constructor values must use a usable cache")
	}
	if entry.TTL != defaultResponseCacheTTLSec {
		t.Fatalf("default TTL=%d, want %d", entry.TTL, defaultResponseCacheTTLSec)
	}
	if entries, _ := rc.Stats(); entries != 1 {
		t.Fatalf("default cache entries=%d, want 1", entries)
	}
}

func TestResponseCacheClear(t *testing.T) {
	rc := NewResponseCache(10, 60)
	defer rc.Close()

	key := CacheKey("GET", "example.com", "/", "")
	rc.Set(key, 200, "text/plain", []byte("body"), 60, nil)
	rc.Clear()

	if entry := rc.Lookup(key); entry != nil {
		t.Fatal("expected Lookup miss after Clear")
	}
	if entries, size := rc.Stats(); entries != 0 || size != 0 {
		t.Fatalf("stats after Clear = entries %d size %d", entries, size)
	}
}

func TestResponseCacheClearConcurrentSet(t *testing.T) {
	rc := NewResponseCache(10, 60)
	defer rc.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			rc.Set(CacheKey("GET", "example.com", "/", strconv.Itoa(i)), 200, "text/plain", []byte("body"), 60, nil)
		}
	}()
	for i := 0; i < 20; i++ {
		rc.Clear()
	}
	<-done
}

func TestResponseCacheClearRejectsOldGeneration(t *testing.T) {
	rc := NewResponseCache(10, 60)
	defer rc.Close()

	key := CacheKey("GET", "example.com", "/epoch", "")
	oldGeneration := rc.Generation()
	rc.Set(key, 200, "text/plain", []byte("old"), 60, nil)
	rc.Clear()

	if ok := rc.SetIfGeneration(oldGeneration, key, 200, "text/plain", []byte("stale"), 60, nil); ok {
		t.Fatal("expected stale generation write to be rejected")
	}
	if entry := rc.Lookup(key); entry != nil {
		t.Fatalf("stale entry repopulated cache: %q", entry.Body)
	}

	if ok := rc.SetIfGeneration(rc.Generation(), key, 200, "text/plain", []byte("current"), 60, nil); !ok {
		t.Fatal("expected current generation write to succeed")
	}
	if entry := rc.Get(key); entry == nil || string(entry.Body) != "current" {
		t.Fatalf("current generation entry = %#v", entry)
	}
}

func TestResponseCacheExpiry(t *testing.T) {
	rc := NewResponseCache(10, 1)
	defer rc.Close()

	key := CacheKey("GET", "example.com", "/", "")
	rc.Set(key, 200, "text/html", []byte("x"), 0, nil) // TTL=0 → uses defaultTTL=1s

	entry := rc.Get(key)
	if entry == nil {
		t.Fatal("expected cache hit immediately after set")
	}
}

func TestResponseCacheDisabled(t *testing.T) {
	rc := NewResponseCache(10, 60)
	defer rc.Close()

	rc.SetEnabled(false)

	key := CacheKey("GET", "example.com", "/", "")
	rc.Set(key, 200, "text/html", []byte("x"), 60, nil)

	if entry := rc.Get(key); entry != nil {
		t.Fatal("expected no cache hit when disabled")
	}
}

func TestResponseCacheDisableClearsStoredEntries(t *testing.T) {
	rc := NewResponseCache(1, 60)
	defer rc.Close()
	key := CacheKey("GET", "example.com", "/private", "")
	rc.Set(key, 200, "text/plain", []byte("body"), 60)
	rc.SetEnabled(false)
	if entry := rc.Lookup(key); entry != nil {
		t.Fatal("disabling cache must clear existing entries")
	}
	rc.SetEnabled(true)
	if entry := rc.Lookup(key); entry != nil {
		t.Fatal("re-enabling cache must not restore cleared entries")
	}
}

func TestResponseCacheCloseIsIdempotent(t *testing.T) {
	rc := NewResponseCache(10, 60)
	rc.Close()
	rc.Close()
}

func TestResponseCacheNilReceiverIsSafe(t *testing.T) {
	var rc *ResponseCache

	if rc.Lookup("missing") != nil {
		t.Fatal("nil cache Lookup must miss")
	}
	if rc.LookupIfGeneration(0, "missing") != nil {
		t.Fatal("nil cache LookupIfGeneration must miss")
	}
	if rc.LookupFreshIfGeneration(0, "missing") != nil {
		t.Fatal("nil cache LookupFreshIfGeneration must miss")
	}
	if rc.LookupStaleIfGeneration(0, "missing", 60) != nil {
		t.Fatal("nil cache LookupStaleIfGeneration must miss")
	}
	rc.Close()
}

func TestResponseCacheLookupExpired(t *testing.T) {
	rc := NewResponseCache(10, 1)
	defer rc.Close()

	key := CacheKey("GET", "example.com", "/stale", "")
	rc.Set(key, 200, "text/html", []byte("old"), 1, nil)

	if rc.Lookup(key) == nil {
		t.Fatal("expected lookup hit right after set")
	}

	time.Sleep(2500 * time.Millisecond)

	entry := rc.Lookup(key)
	if entry == nil {
		t.Fatal("expected Lookup to see expired entry until Get or cleaner removes it")
	}
	if !entry.IsExpired() {
		t.Fatal("expected expired entry")
	}
	if string(entry.Body) != "old" {
		t.Fatalf("body %q", entry.Body)
	}

	if rc.Get(key) != nil {
		t.Fatal("expected Get to miss after TTL")
	}
}

func TestCacheKeyDeterministic(t *testing.T) {
	k1 := CacheKey("GET", "a.com", "/x", "q=1")
	k2 := CacheKey("GET", "a.com", "/x", "q=1")
	k3 := CacheKey("POST", "a.com", "/x", "q=1")

	if k1 != k2 {
		t.Error("same inputs should produce same key")
	}
	if k1 == k3 {
		t.Error("different methods should produce different keys")
	}
}

func TestCacheKeyMatchesPreviousHashInput(t *testing.T) {
	tests := []struct {
		name   string
		method string
		host   string
		path   string
		query  string
	}{
		{name: "empty query", method: "GET", host: ":80|1|127.0.0.1", path: "/favicon.ico"},
		{name: "with query", method: "GET", host: ":443|7|cache.example.com", path: "/assets/app.js", query: "v=1&lang=zh"},
		{name: "head normalized upstream", method: "GET", host: ":80|9|example.com", path: "/index.html", query: "utm=1"},
		{name: "long path", method: "GET", host: ":80|1|example.com", path: "/" + strings.Repeat("a", 600), query: "x=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CacheKey(tt.method, tt.host, tt.path, tt.query)
			want := cacheKeyStringForTest(tt.method, tt.host, tt.path, tt.query)
			if got != want {
				t.Fatalf("CacheKey() = %q, want %q", got, want)
			}
			gotBytes := CacheKeyBytes(tt.method, []byte(tt.host), tt.path, []byte(tt.query))
			if gotBytes != want {
				t.Fatalf("CacheKeyBytes() = %q, want %q", gotBytes, want)
			}
			partsHost := tt.host
			if strings.Count(partsHost, "|") == 2 {
				parts := strings.Split(partsHost, "|")
				siteID, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					t.Fatalf("parse site id: %v", err)
				}
				gotParts := CacheKeyWithHostParts(tt.method, parts[0], siteID, []byte(parts[2]), tt.path, []byte(tt.query))
				if gotParts != want {
					t.Fatalf("CacheKeyWithHostParts() = %q, want %q", gotParts, want)
				}
				gotPartsBytesPath := CacheKeyWithHostPartsBytesPath(tt.method, parts[0], siteID, []byte(parts[2]), []byte(tt.path), []byte(tt.query))
				if gotPartsBytesPath != want {
					t.Fatalf("CacheKeyWithHostPartsBytesPath() = %q, want %q", gotPartsBytesPath, want)
				}
			}
		})
	}
}

func cacheKeyStringForTest(method, host, path, query string) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(host))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(query))
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	var encoded [sha256.Size * 2]byte
	hex.Encode(encoded[:], sum[:])
	return string(encoded[:])
}

func BenchmarkCacheKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if CacheKey("GET", ":80|1|127.0.0.1", "/favicon.ico", "") == "" {
			b.Fatal("empty key")
		}
	}
}

func BenchmarkCacheKeyStringForTest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if cacheKeyStringForTest("GET", ":80|1|127.0.0.1", "/favicon.ico", "") == "" {
			b.Fatal("empty key")
		}
	}
}

func BenchmarkCacheKeyBytes(b *testing.B) {
	host := []byte(":80|1|127.0.0.1")
	query := []byte("x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if CacheKeyBytes("GET", host, "/favicon.ico", query) == "" {
			b.Fatal("empty key")
		}
	}
}

func BenchmarkCacheKeyWithHostParts(b *testing.B) {
	host := []byte("127.0.0.1")
	query := []byte("x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if CacheKeyWithHostParts("GET", ":80", 1, host, "/favicon.ico", query) == "" {
			b.Fatal("empty key")
		}
	}
}

func BenchmarkCacheKeyWithHostPartsBytesPath(b *testing.B) {
	host := []byte("127.0.0.1")
	path := []byte("/favicon.ico")
	query := []byte("x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if CacheKeyWithHostPartsBytesPath("GET", ":80", 1, host, path, query) == "" {
			b.Fatal("empty key")
		}
	}
}

func TestResponseCacheRoundtripHeaders(t *testing.T) {
	rc := NewResponseCache(10, 60)
	defer rc.Close()
	key := CacheKey("GET", "ex", "/a.js", "")
	h := http.Header{}
	h.Set("Content-Encoding", "br")
	h.Set("Cache-Control", "public, max-age=60")
	rc.Set(key, 200, "application/javascript", []byte{1, 2, 3}, 60, h)
	ent := rc.Get(key)
	if ent == nil {
		t.Fatal("miss")
	}
	if ent.Header == nil || ent.Header.Get("Content-Encoding") != "br" {
		t.Fatalf("header: %#v", ent.Header)
	}
	if ent.Header.Get("Content-Length") != "" {
		t.Fatal("unexpected content-length in test header")
	}
}

func TestResponseCacheEvictsToMaxSize(t *testing.T) {
	rc := NewResponseCache(1, 60)
	defer rc.Close()
	body := make([]byte, 80*1024)
	for i := 0; i < 40; i++ {
		rc.Set(CacheKey("GET", "example.com", "/asset", string(rune(i))), 200, "text/plain", body, 60, nil)
	}
	_, size := rc.Stats()
	if size > 1024*1024 {
		t.Fatalf("cache exceeded max size: %d", size)
	}
}

func TestResponseCacheMaxEntryBodySizeMatchesSetLimit(t *testing.T) {
	rc := NewResponseCache(1, 60)
	defer rc.Close()

	limit := rc.MaxEntryBodySize()
	if limit != 1024*1024/10 {
		t.Fatalf("MaxEntryBodySize = %d, want %d", limit, 1024*1024/10)
	}

	rc.Set("within", 200, "text/plain", make([]byte, limit-512), 60, nil)
	if rc.Get("within") == nil {
		t.Fatal("expected body at max entry size to be cached")
	}

	rc.Set("too-large", 200, "text/plain", make([]byte, limit+1), 60, nil)
	if rc.Get("too-large") != nil {
		t.Fatal("expected body above max entry size to be rejected")
	}
}

func TestResponseCacheSetForSiteClonesBodyAndPurgesTarget(t *testing.T) {
	rc := NewResponseCache(1, 60)
	defer rc.Close()
	body := []byte("immutable")
	generation := rc.Generation()
	if !rc.SetForSiteIfGeneration(generation, 7, "/asset.js?v=1", "site-key", 200, "text/plain", body, 60, nil) {
		t.Fatal("site-scoped cache write was rejected")
	}
	body[0] = 'X'
	entry := rc.Get("site-key")
	if entry == nil || string(entry.Body) != "immutable" {
		t.Fatalf("cached body aliases caller memory: %#v", entry)
	}
	rc.PurgeSiteTarget(7, "/asset.js?v=2")
	if rc.Get("site-key") != nil {
		t.Fatal("site target purge did not remove query variants")
	}
}

func TestResponseCachePurgeSiteTargetKeepsUnrelatedEntries(t *testing.T) {
	rc := NewResponseCache(1, 60)
	defer rc.Close()

	set := func(key string, siteID uint, target string) {
		t.Helper()
		if !rc.SetForSiteIfGeneration(rc.Generation(), siteID, target, key, 200, "text/plain", []byte(key), 60, nil) {
			t.Fatalf("cache write %q was rejected", key)
		}
	}
	set("site7-asset-query1", 7, "/asset.js?v=1")
	set("site7-asset-query2", 7, "/asset.js?v=2")
	set("site7-other", 7, "/other.js")
	set("site8-asset", 8, "/asset.js?v=1")

	if got := len(rc.targetIndex); got != 3 {
		t.Fatalf("target index groups = %d, want 3", got)
	}
	rc.PurgeSiteTarget(7, "/asset.js?v=3")

	for _, key := range []string{"site7-asset-query1", "site7-asset-query2"} {
		if rc.Get(key) != nil {
			t.Fatalf("purged cache entry %q remained", key)
		}
	}
	for _, key := range []string{"site7-other", "site8-asset"} {
		if rc.Get(key) == nil {
			t.Fatalf("unrelated cache entry %q was purged", key)
		}
	}
	if got := len(rc.targetIndex); got != 2 {
		t.Fatalf("target index groups after purge = %d, want 2", got)
	}

	// Replacing a key must move it between target groups so a later purge cannot
	// remove an entry using stale reverse-index state.
	set("site7-asset-query1", 7, "/other.js")
	rc.PurgeSiteTarget(7, "/asset.js")
	if rc.Get("site7-asset-query1") == nil {
		t.Fatal("replacement entry was removed through stale target index")
	}
}

func TestResponseCacheCleanerRemovesReverseTargetIndex(t *testing.T) {
	rc := NewResponseCache(1, 1)
	defer rc.Close()

	if !rc.SetForSiteIfGeneration(rc.Generation(), 7, "/expired.js?v=1", "expired", 200, "text/plain", []byte("body"), 1, nil) {
		t.Fatal("cache write was rejected")
	}
	if len(rc.targetIndex) != 1 {
		t.Fatalf("target index groups before expiry = %d, want 1", len(rc.targetIndex))
	}
	time.Sleep(2100 * time.Millisecond)
	rc.cleanExpiredEntries()

	if entry := rc.Lookup("expired"); entry != nil {
		t.Fatal("expired entry remained after cleaner")
	}
	if entries, size := rc.Stats(); entries != 0 || size != 0 {
		t.Fatalf("stats after cleaner = entries %d size %d", entries, size)
	}
	if len(rc.targetIndex) != 0 {
		t.Fatalf("target index groups after cleaner = %d, want 0", len(rc.targetIndex))
	}
}

func TestResponseCacheBoundsOneByteEntries(t *testing.T) {
	rc := NewResponseCache(1, 60)
	defer rc.Close()
	for i := int64(0); i < rc.maxEntries+100; i++ {
		rc.Set(strconv.FormatInt(i, 10), 200, "text/plain", []byte{'x'}, 60, nil)
	}
	entries, size := rc.Stats()
	if int64(entries) > rc.maxEntries {
		t.Fatalf("entries = %d, max = %d", entries, rc.maxEntries)
	}
	if size > rc.maxSize {
		t.Fatalf("estimated size = %d, max = %d", size, rc.maxSize)
	}
}

func TestResponseCacheLargeTTLIsNotEvictedByOverflow(t *testing.T) {
	rc := NewResponseCache(1, 60)
	defer rc.Close()

	key := "large-ttl"
	rc.Set(key, http.StatusOK, "text/plain", []byte("body"), int64(^uint64(0)>>1), nil)
	body := make([]byte, 120*1024)
	for i := 0; i < 7; i++ {
		rc.Set("regular-"+strconv.Itoa(i), http.StatusOK, "text/plain", body, 60, nil)
	}
	// Keep the large-TTL entry newest, then force a size eviction. A wrapped
	// CachedAt+TTL check would treat it as expired before the LRU pass.
	rc.Set(key, http.StatusOK, "text/plain", []byte("body"), int64(^uint64(0)>>1), nil)
	rc.Set("regular-final-1", http.StatusOK, "text/plain", body, 60, nil)
	rc.Set("regular-final-2", http.StatusOK, "text/plain", body, 60, nil)
	if rc.Get(key) == nil {
		t.Fatal("entry with a large positive TTL was evicted as expired")
	}
}
