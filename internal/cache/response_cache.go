package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ResponseEntry is a cached upstream response.
type ResponseEntry struct {
	StatusCode  int
	ContentType string
	Body        []byte
	// Header holds hop-by-hop-sanitized upstream headers (e.g. Content-Encoding: br) so
	// cached hits match live fetches. Nil means legacy entries with Content-Type only.
	Header   http.Header
	CachedAt int64
	TTL      int64 // seconds
}

// IsExpired returns true if the entry has passed its TTL.
func (e *ResponseEntry) IsExpired() bool {
	return time.Now().Unix() > e.CachedAt+e.TTL
}

// ResponseCache is an in-memory LRU-like response cache for safe (GET) requests.
// Uses sharded mutexes to reduce lock contention on the hot path.
type ResponseCache struct {
	shards     [64]shard
	maxSize    int64
	curSize    atomic.Int64
	enabled    atomic.Bool
	defaultTTL int64
	stopCh     chan struct{}
}

type shard struct {
	mu    sync.RWMutex
	items map[string]*ResponseEntry
}

// NewResponseCache creates a cache with the given max size in bytes and default TTL.
func NewResponseCache(maxSizeMB int, defaultTTLSec int) *ResponseCache {
	rc := &ResponseCache{
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		defaultTTL: int64(defaultTTLSec),
		stopCh:     make(chan struct{}),
	}
	for i := range rc.shards {
		rc.shards[i].items = make(map[string]*ResponseEntry)
	}
	rc.enabled.Store(true)
	go rc.cleaner()
	return rc
}

// CacheKey generates a deterministic key from method + host + path + query.
func CacheKey(method, host, path, query string) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(host))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(query))
	return hex.EncodeToString(h.Sum(nil))
}

func (rc *ResponseCache) shardFor(key string) *shard {
	// Simple hash-based shard selection.
	var h uint64
	for _, b := range key {
		h = h*31 + uint64(b)
	}
	return &rc.shards[h%64]
}

// Lookup returns a cached entry when present, including entries past TTL.
// It does not delete expired entries; use for stale fallback after upstream errors.
func (rc *ResponseCache) Lookup(key string) *ResponseEntry {
	if !rc.enabled.Load() {
		return nil
	}
	s := rc.shardFor(key)
	s.mu.RLock()
	entry, ok := s.items[key]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return entry
}

// Get retrieves a cached response. Returns nil if miss or expired.
func (rc *ResponseCache) Get(key string) *ResponseEntry {
	if !rc.enabled.Load() {
		return nil
	}
	s := rc.shardFor(key)
	s.mu.RLock()
	entry, ok := s.items[key]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	if entry.IsExpired() {
		s.mu.Lock()
		if current, ok := s.items[key]; ok && current == entry {
			delete(s.items, key)
			rc.curSize.Add(-int64(len(entry.Body)))
		}
		s.mu.Unlock()
		return nil
	}
	return entry
}

// Set stores a response in the cache. header is optional hop-by-hop-sanitized upstream
// headers (clone is stored); nil stores only Content-Type/body semantics.
func (rc *ResponseCache) Set(key string, statusCode int, contentType string, body []byte, ttl int64, header http.Header) {
	if !rc.enabled.Load() {
		return
	}
	if ttl <= 0 {
		ttl = rc.defaultTTL
	}
	bodySize := int64(len(body))
	if bodySize > rc.maxSize/10 {
		return
	}

	var hdr http.Header
	if header != nil && len(header) > 0 {
		hdr = header.Clone()
	}

	entry := &ResponseEntry{
		StatusCode:  statusCode,
		ContentType: contentType,
		Body:        body,
		Header:      hdr,
		CachedAt:    time.Now().Unix(),
		TTL:         ttl,
	}

	s := rc.shardFor(key)
	s.mu.Lock()
	if old, ok := s.items[key]; ok {
		rc.curSize.Add(-int64(len(old.Body)))
	}
	s.items[key] = entry
	s.mu.Unlock()
	rc.curSize.Add(bodySize)
	rc.evictToMaxSize()
}

func (rc *ResponseCache) evictToMaxSize() {
	if rc.maxSize <= 0 || rc.curSize.Load() <= rc.maxSize {
		return
	}
	now := time.Now().Unix()
	for rc.curSize.Load() > rc.maxSize {
		evicted := false
		for i := range rc.shards {
			if rc.curSize.Load() <= rc.maxSize {
				return
			}
			s := &rc.shards[i]
			s.mu.Lock()
			for k, v := range s.items {
				delete(s.items, k)
				rc.curSize.Add(-int64(len(v.Body)))
				evicted = true
				if now > v.CachedAt+v.TTL || rc.curSize.Load() <= rc.maxSize {
					break
				}
			}
			s.mu.Unlock()
		}
		if !evicted {
			return
		}
	}
}

// SetEnabled toggles the cache on/off.
func (rc *ResponseCache) SetEnabled(v bool) { rc.enabled.Store(v) }

func (rc *ResponseCache) Clear() {
	for i := range rc.shards {
		rc.shards[i].mu.Lock()
		rc.shards[i].items = make(map[string]*ResponseEntry)
		rc.shards[i].mu.Unlock()
	}
	rc.curSize.Store(0)
}

// Stats returns current cache statistics.
func (rc *ResponseCache) Stats() (entries int, sizeBytes int64) {
	for i := range rc.shards {
		rc.shards[i].mu.RLock()
		entries += len(rc.shards[i].items)
		rc.shards[i].mu.RUnlock()
	}
	return entries, rc.curSize.Load()
}

// Close stops the background cleaner.
func (rc *ResponseCache) Close() {
	close(rc.stopCh)
}

func (rc *ResponseCache) cleaner() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-rc.stopCh:
			return
		case <-ticker.C:
			for i := range rc.shards {
				rc.shards[i].mu.Lock()
				for k, v := range rc.shards[i].items {
					if v.IsExpired() {
						rc.curSize.Add(-int64(len(v.Body)))
						delete(rc.shards[i].items, k)
					}
				}
				rc.shards[i].mu.Unlock()
			}
		}
	}
}
