package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"strconv"
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
	Header     http.Header
	CachedAt   int64
	TTL        int64 // seconds
	lastAccess int64 // unix nano, updated atomically on cache hit
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
	closeOnce  sync.Once
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

// MaxEntryBodySize returns the largest body size accepted by Set.
func (rc *ResponseCache) MaxEntryBodySize() int64 {
	if rc == nil || rc.maxSize <= 0 {
		return 0
	}
	return rc.maxSize / 10
}

// CacheKey generates a deterministic key from method + host + path + query.
func CacheKey(method, host, path, query string) string {
	var stack [512]byte
	need := len(method) + len(host) + len(path) + len(query) + 3
	buf := stack[:0]
	if need > len(stack) {
		buf = make([]byte, 0, need)
	}
	buf = append(buf, method...)
	buf = append(buf, 0)
	buf = append(buf, host...)
	buf = append(buf, 0)
	buf = append(buf, path...)
	buf = append(buf, 0)
	buf = append(buf, query...)
	sum := sha256.Sum256(buf)
	var encoded [sha256.Size * 2]byte
	hex.Encode(encoded[:], sum[:])
	return string(encoded[:])
}

// CacheKeyBytes generates a deterministic key from method + host + path + query without forcing byte inputs through strings.
func CacheKeyBytes(method string, host []byte, path string, query []byte) string {
	var stack [512]byte
	need := len(method) + len(host) + len(path) + len(query) + 3
	buf := stack[:0]
	if need > len(stack) {
		buf = make([]byte, 0, need)
	}
	buf = append(buf, method...)
	buf = append(buf, 0)
	buf = append(buf, host...)
	buf = append(buf, 0)
	buf = append(buf, path...)
	buf = append(buf, 0)
	buf = append(buf, query...)
	sum := sha256.Sum256(buf)
	var encoded [sha256.Size * 2]byte
	hex.Encode(encoded[:], sum[:])
	return string(encoded[:])
}

// CacheKeyWithHostParts generates a cache key while building the host component inside the hash input.
func CacheKeyWithHostParts(method, bind string, siteID uint64, normalizedHost []byte, path string, query []byte) string {
	var stack [512]byte
	need := len(method) + len(bind) + 1 + 20 + 1 + len(normalizedHost) + len(path) + len(query) + 3
	buf := stack[:0]
	if need > len(stack) {
		buf = make([]byte, 0, need)
	}
	buf = append(buf, method...)
	buf = append(buf, 0)
	buf = append(buf, bind...)
	buf = append(buf, '|')
	buf = strconv.AppendUint(buf, siteID, 10)
	buf = append(buf, '|')
	buf = append(buf, normalizedHost...)
	buf = append(buf, 0)
	buf = append(buf, path...)
	buf = append(buf, 0)
	buf = append(buf, query...)
	sum := sha256.Sum256(buf)
	var encoded [sha256.Size * 2]byte
	hex.Encode(encoded[:], sum[:])
	return string(encoded[:])
}

// CacheKeyWithHostPartsBytesPath generates a cache key without forcing Hertz path bytes through a string.
func CacheKeyWithHostPartsBytesPath(method, bind string, siteID uint64, normalizedHost []byte, path []byte, query []byte) string {
	var stack [512]byte
	need := len(method) + len(bind) + 1 + 20 + 1 + len(normalizedHost) + len(path) + len(query) + 3
	buf := stack[:0]
	if need > len(stack) {
		buf = make([]byte, 0, need)
	}
	buf = append(buf, method...)
	buf = append(buf, 0)
	buf = append(buf, bind...)
	buf = append(buf, '|')
	buf = strconv.AppendUint(buf, siteID, 10)
	buf = append(buf, '|')
	buf = append(buf, normalizedHost...)
	buf = append(buf, 0)
	buf = append(buf, path...)
	buf = append(buf, 0)
	buf = append(buf, query...)
	sum := sha256.Sum256(buf)
	var encoded [sha256.Size * 2]byte
	hex.Encode(encoded[:], sum[:])
	return string(encoded[:])
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
	atomic.StoreInt64(&entry.lastAccess, time.Now().UnixNano())
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
	atomic.StoreInt64(&entry.lastAccess, time.Now().UnixNano())
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
	if bodySize > rc.MaxEntryBodySize() {
		return
	}

	var hdr http.Header
	if len(header) > 0 {
		hdr = header.Clone()
	}

	entry := &ResponseEntry{
		StatusCode:  statusCode,
		ContentType: contentType,
		Body:        body,
		Header:      hdr,
		CachedAt:    time.Now().Unix(),
		TTL:         ttl,
		lastAccess:  time.Now().UnixNano(),
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
	// 第一轮：优先驱逐过期条目
	for i := range rc.shards {
		if rc.curSize.Load() <= rc.maxSize {
			return
		}
		s := &rc.shards[i]
		s.mu.Lock()
		for k, v := range s.items {
			if now > v.CachedAt+v.TTL {
				delete(s.items, k)
				rc.curSize.Add(-int64(len(v.Body)))
			}
		}
		s.mu.Unlock()
	}
	// 第二轮：按 lastAccess 最老优先逐条驱逐，直到满足容量
	for rc.curSize.Load() > rc.maxSize {
		var oldestKey string
		var oldestShard *shard
		var oldestAccess int64 = math.MaxInt64
		var oldestSize int64
		for i := range rc.shards {
			s := &rc.shards[i]
			s.mu.RLock()
			for k, v := range s.items {
				la := atomic.LoadInt64(&v.lastAccess)
				if la < oldestAccess {
					oldestAccess = la
					oldestKey = k
					oldestShard = s
					oldestSize = int64(len(v.Body))
				}
			}
			s.mu.RUnlock()
		}
		if oldestShard == nil {
			return
		}
		oldestShard.mu.Lock()
		if _, ok := oldestShard.items[oldestKey]; ok {
			delete(oldestShard.items, oldestKey)
			rc.curSize.Add(-oldestSize)
		}
		oldestShard.mu.Unlock()
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
	rc.closeOnce.Do(func() {
		close(rc.stopCh)
	})
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
