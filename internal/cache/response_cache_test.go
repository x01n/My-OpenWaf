package cache

import (
	"net/http"
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

func BenchmarkCacheKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if CacheKey("GET", ":80|1|127.0.0.1", "/favicon.ico", "") == "" {
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
