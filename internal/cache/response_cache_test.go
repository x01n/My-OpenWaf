package cache

import "testing"

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
	rc.Set(key, 200, "text/html", body, 60)
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
	rc.Set(key, 200, "text/html", []byte("x"), 0) // TTL=0 → uses defaultTTL=1s

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
	rc.Set(key, 200, "text/html", []byte("x"), 60)

	if entry := rc.Get(key); entry != nil {
		t.Fatal("expected no cache hit when disabled")
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
