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
	if size != int64(len(body)) {
		t.Errorf("expected size %d, got %d", len(body), size)
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

func TestResponseCacheCloseIsIdempotent(t *testing.T) {
	rc := NewResponseCache(10, 60)
	rc.Close()
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

	rc.Set("within", 200, "text/plain", make([]byte, limit), 60, nil)
	if rc.Get("within") == nil {
		t.Fatal("expected body at max entry size to be cached")
	}

	rc.Set("too-large", 200, "text/plain", make([]byte, limit+1), 60, nil)
	if rc.Get("too-large") != nil {
		t.Fatal("expected body above max entry size to be rejected")
	}
}
