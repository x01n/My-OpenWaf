package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
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
	SiteID     uint
	TargetURI  string
	sizeBytes  int64
	lastAccess int64 // unix nano, updated atomically on cache hit
}

// IsExpired returns true if the entry has passed its TTL.
func (e *ResponseEntry) IsExpired() bool {
	return e == nil || time.Now().Unix()-e.CachedAt > e.TTL
}

// IsStaleWithin reports whether an expired entry is still inside the configured
// stale-if-error window.
func (e *ResponseEntry) IsStaleWithin(maxStaleSeconds int64) bool {
	if e == nil || maxStaleSeconds <= 0 {
		return false
	}
	age := time.Now().Unix() - e.CachedAt
	return age > e.TTL && age-e.TTL <= maxStaleSeconds
}

// ResponseCache is an in-memory LRU-like response cache for safe (GET) requests.
// Uses sharded mutexes to reduce lock contention on the hot path.
type ResponseCache struct {
	shards       [64]shard
	maxSize      int64
	maxEntries   int64
	curSize      atomic.Int64
	entryCount   atomic.Int64
	enabled      atomic.Bool
	defaultTTL   int64
	stopCh       chan struct{}
	closeOnce    sync.Once
	clearMu      sync.RWMutex
	generation   atomic.Uint64
	accountingMu sync.Mutex
	fillMu       sync.Mutex
	fills        map[string]chan struct{}
	// targetIndex maps a site/path pair to the cache keys that represent it.
	// Unsafe requests can then invalidate only affected entries instead of
	// scanning every shard.
	targetIndex map[string]map[string]struct{}

	// hits/misses 记录读取命中与未命中次数，供 /metrics 暴露命中率。
	hits   atomic.Int64
	misses atomic.Int64
}

type shard struct {
	mu    sync.RWMutex
	items map[string]*ResponseEntry
}

const (
	defaultResponseCacheMB     = 64
	defaultResponseCacheTTLSec = 60
)

// NewResponseCache creates a cache with the given max size in bytes and default TTL.
func NewResponseCache(maxSizeMB int, defaultTTLSec int) *ResponseCache {
	// Config.LoadConfigFromEnv already supplies these defaults, but constructors
	// are also used by tests and embedded callers. Treat zero/negative values as
	// the documented defaults instead of silently creating a zero-capacity cache
	// whose entries expire immediately.
	if maxSizeMB <= 0 {
		maxSizeMB = defaultResponseCacheMB
	}
	if defaultTTLSec <= 0 {
		defaultTTLSec = defaultResponseCacheTTLSec
	}
	maxSize := int64(maxSizeMB) * 1024 * 1024
	maxEntries := maxSize / 1024
	if maxSize > 0 && maxEntries < 1 {
		maxEntries = 1
	}
	rc := &ResponseCache{
		maxSize:     maxSize,
		maxEntries:  maxEntries,
		defaultTTL:  int64(defaultTTLSec),
		stopCh:      make(chan struct{}),
		fills:       make(map[string]chan struct{}),
		targetIndex: make(map[string]map[string]struct{}),
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
	if rc == nil || !rc.enabled.Load() {
		return nil
	}
	rc.clearMu.RLock()
	defer rc.clearMu.RUnlock()
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

// LookupIfGeneration returns a cached entry only when the supplied generation
// is still current. It is used by stale fallback paths that may finish after
// another request clears the cache.
func (rc *ResponseCache) LookupIfGeneration(generation uint64, key string) *ResponseEntry {
	if rc == nil || !rc.enabled.Load() {
		return nil
	}
	rc.clearMu.RLock()
	defer rc.clearMu.RUnlock()
	if rc.generation.Load() != generation {
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

// LookupFreshIfGeneration returns a non-expired entry without deleting an
// expired backup. It is used by followers that have waited for a fill: calling
// Get in that situation could remove the stale-if-error entry that the leader
// still needs for a safe fallback.
func (rc *ResponseCache) LookupFreshIfGeneration(generation uint64, key string) *ResponseEntry {
	entry := rc.LookupIfGeneration(generation, key)
	if entry == nil || entry.IsExpired() {
		if rc != nil {
			rc.misses.Add(1)
		}
		return nil
	}
	if rc != nil {
		rc.hits.Add(1)
	}
	return entry
}

// LookupStaleIfGeneration returns an expired entry only while it is inside the
// caller's explicit stale-if-error window and the cache generation is unchanged.
func (rc *ResponseCache) LookupStaleIfGeneration(generation uint64, key string, maxStaleSeconds int64) *ResponseEntry {
	entry := rc.LookupIfGeneration(generation, key)
	if !entry.IsStaleWithin(maxStaleSeconds) {
		return nil
	}
	return entry
}

func (rc *ResponseCache) Get(key string) *ResponseEntry {
	if rc == nil || !rc.enabled.Load() {
		return nil
	}
	rc.clearMu.RLock()
	defer rc.clearMu.RUnlock()
	s := rc.shardFor(key)
	s.mu.RLock()
	entry, ok := s.items[key]
	s.mu.RUnlock()
	if !ok {
		rc.misses.Add(1)
		return nil
	}
	now := time.Now()
	if now.Unix()-entry.CachedAt > entry.TTL {
		rc.accountingMu.Lock()
		s.mu.Lock()
		if current, ok := s.items[key]; ok && current == entry {
			delete(s.items, key)
			rc.curSize.Add(-entry.sizeBytes)
			rc.entryCount.Add(-1)
			rc.removeTargetIndexLocked(key, entry)
		}
		s.mu.Unlock()
		rc.accountingMu.Unlock()
		rc.misses.Add(1)
		return nil
	}
	atomic.StoreInt64(&entry.lastAccess, now.UnixNano())
	rc.hits.Add(1)
	return entry
}

// HitStats 返回累计的命中与未命中次数，供 /metrics 暴露命中率。
// nil 接收者返回 0，保证空缓存场景不 panic。
func (rc *ResponseCache) HitStats() (hits, misses int64) {
	if rc == nil {
		return 0, 0
	}
	return rc.hits.Load(), rc.misses.Load()
}

// Generation returns the current cache generation. Callers that may complete
// an in-flight fetch after Clear should pass this value to SetIfGeneration.
func (rc *ResponseCache) Generation() uint64 {
	if rc == nil {
		return 0
	}
	return rc.generation.Load()
}

// Set stores a response in the cache. header is optional hop-by-hop-sanitized upstream
// headers (clone is stored); nil stores only Content-Type/body semantics.
func (rc *ResponseCache) Set(key string, statusCode int, contentType string, body []byte, ttl int64, headers ...http.Header) {
	if rc == nil {
		return
	}
	var header http.Header
	if len(headers) > 0 {
		header = headers[0]
	}
	rc.clearMu.RLock()
	generation := rc.generation.Load()
	rc.setIfGenerationLocked(generation, 0, "", key, statusCode, contentType, body, ttl, header)
	rc.clearMu.RUnlock()
}

// SetIfGeneration stores a response only when generation still matches the
// current cache generation. It prevents an in-flight fetch started before
// Clear from repopulating the cache after the clear has completed.
func (rc *ResponseCache) SetIfGeneration(generation uint64, key string, statusCode int, contentType string, body []byte, ttl int64, headers ...http.Header) bool {
	if rc == nil {
		return false
	}
	var header http.Header
	if len(headers) > 0 {
		header = headers[0]
	}
	rc.clearMu.RLock()
	defer rc.clearMu.RUnlock()
	return rc.setIfGenerationLocked(generation, 0, "", key, statusCode, contentType, body, ttl, header)
}

// SetForSiteIfGeneration stores an immutable response with site and target URI
// metadata so unsafe methods can invalidate only the affected site resource.
func (rc *ResponseCache) SetForSiteIfGeneration(generation uint64, siteID uint, targetURI, key string, statusCode int, contentType string, body []byte, ttl int64, headers ...http.Header) bool {
	if rc == nil {
		return false
	}
	var header http.Header
	if len(headers) > 0 {
		header = headers[0]
	}
	rc.clearMu.RLock()
	defer rc.clearMu.RUnlock()
	return rc.setIfGenerationLocked(generation, siteID, targetURI, key, statusCode, contentType, body, ttl, header)
}

func (rc *ResponseCache) setIfGenerationLocked(generation uint64, siteID uint, targetURI, key string, statusCode int, contentType string, body []byte, ttl int64, header http.Header) bool {
	if !rc.enabled.Load() {
		return false
	}
	if ttl <= 0 {
		ttl = rc.defaultTTL
	}
	if len(body) == 0 || int64(len(body)) > rc.MaxEntryBodySize() || rc.maxEntries <= 0 {
		return false
	}

	bodyCopy := append([]byte(nil), body...)
	var hdr http.Header
	if len(header) > 0 {
		hdr = header.Clone()
	}
	entrySize := estimateResponseEntrySize(key, targetURI, contentType, bodyCopy, hdr)
	if entrySize <= 0 || entrySize > rc.maxSize/10 {
		return false
	}

	entry := &ResponseEntry{
		StatusCode:  statusCode,
		ContentType: contentType,
		Body:        bodyCopy,
		Header:      hdr,
		CachedAt:    time.Now().Unix(),
		TTL:         ttl,
		SiteID:      siteID,
		TargetURI:   targetURI,
		sizeBytes:   entrySize,
		lastAccess:  time.Now().UnixNano(),
	}

	if rc.generation.Load() != generation {
		return false
	}
	rc.accountingMu.Lock()
	defer rc.accountingMu.Unlock()
	if rc.generation.Load() != generation {
		return false
	}
	s := rc.shardFor(key)
	s.mu.Lock()
	if old, ok := s.items[key]; ok {
		rc.curSize.Add(-old.sizeBytes)
		rc.removeTargetIndexLocked(key, old)
	} else {
		rc.entryCount.Add(1)
	}
	s.items[key] = entry
	rc.addTargetIndexLocked(key, entry)
	s.mu.Unlock()
	rc.curSize.Add(entrySize)
	rc.evictToMaxSizeLocked()
	return true
}

func estimateResponseEntrySize(key, targetURI, contentType string, body []byte, header http.Header) int64 {
	// The fixed allowance covers the entry object, map slot, string/slice headers,
	// pointers, and allocator metadata. Variable data is counted exactly.
	const fixedOverhead = int64(256)
	size := fixedOverhead + int64(len(key)+len(targetURI)+len(contentType)+len(body))
	for name, values := range header {
		size += int64(len(name))
		for _, value := range values {
			size += int64(len(value))
		}
	}
	return size
}

// evictCandidate 保存驱逐候选的元数据，避免在排序阶段持有锁。
type evictCandidate struct {
	key        string
	shardIdx   int
	sizeBytes  int64
	lastAccess int64
}

// evictCandidatePool 复用 eviction 候选 slice 的底层数组，减少 eviction 触发时的堆分配。
var evictCandidatePool = sync.Pool{
	New: func() any { s := make([]evictCandidate, 0, 256); return &s },
}

func (rc *ResponseCache) evictToMaxSizeLocked() {
	if rc.maxSize <= 0 || rc.curSize.Load() <= rc.maxSize && rc.entryCount.Load() <= rc.maxEntries {
		return
	}
	// 第一轮：优先驱逐过期条目
	for i := range rc.shards {
		if rc.curSize.Load() <= rc.maxSize && rc.entryCount.Load() <= rc.maxEntries {
			return
		}
		s := &rc.shards[i]
		s.mu.Lock()
		for k, v := range s.items {
			// Use the subtraction-based expiry check to avoid overflowing when a
			// caller supplies a very large TTL.
			if v.IsExpired() {
				delete(s.items, k)
				rc.curSize.Add(-v.sizeBytes)
				rc.entryCount.Add(-1)
				rc.removeTargetIndexLocked(k, v)
			}
		}
		s.mu.Unlock()
	}
	if rc.curSize.Load() <= rc.maxSize && rc.entryCount.Load() <= rc.maxEntries {
		return
	}
	// 第二轮：一次性收集所有候选，按 lastAccess 升序排序后批量删除，
	// 避免逐条扫描全部 shard 的 O(n²) 退化。
	// 从 pool 取出复用 slice，减少反复触发 eviction 时的堆分配。
	cp := evictCandidatePool.Get().(*[]evictCandidate)
	candidates := (*cp)[:0]
	for i := range rc.shards {
		s := &rc.shards[i]
		s.mu.RLock()
		for k, v := range s.items {
			candidates = append(candidates, evictCandidate{
				key:        k,
				shardIdx:   i,
				sizeBytes:  v.sizeBytes,
				lastAccess: atomic.LoadInt64(&v.lastAccess),
			})
		}
		s.mu.RUnlock()
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].lastAccess < candidates[j].lastAccess
	})
	for _, c := range candidates {
		if rc.curSize.Load() <= rc.maxSize && rc.entryCount.Load() <= rc.maxEntries {
			break
		}
		s := &rc.shards[c.shardIdx]
		s.mu.Lock()
		if cur, ok := s.items[c.key]; ok {
			// 校验 bodySize：并发写入可能替换了条目
			delete(s.items, c.key)
			rc.curSize.Add(-cur.sizeBytes)
			rc.entryCount.Add(-1)
			rc.removeTargetIndexLocked(c.key, cur)
		}
		s.mu.Unlock()
	}
	*cp = candidates[:0]
	evictCandidatePool.Put(cp)
}

// BeginFill elects one leader for a cache key. Followers wait for that fill,
// recheck the cache, and may fetch independently when the leader's response was
// not cacheable. The returned release function must be called by the leader.
func (rc *ResponseCache) BeginFill(ctx context.Context, key string) (leader bool, release func(), err error) {
	if rc == nil {
		return true, func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rc.fillMu.Lock()
	if done, ok := rc.fills[key]; ok {
		rc.fillMu.Unlock()
		select {
		case <-done:
			return false, func() {}, nil
		case <-ctx.Done():
			return false, nil, ctx.Err()
		}
	}
	done := make(chan struct{})
	rc.fills[key] = done
	rc.fillMu.Unlock()
	var once sync.Once
	return true, func() {
		once.Do(func() {
			rc.fillMu.Lock()
			if current, ok := rc.fills[key]; ok && current == done {
				delete(rc.fills, key)
				close(done)
			}
			rc.fillMu.Unlock()
		})
	}, nil
}

// PurgeSiteTarget removes cached GET responses for the same site and path. All
// query variants are removed because an unsafe request can mutate shared state
// represented by any query form of that resource.
func (rc *ResponseCache) PurgeSiteTarget(siteID uint, targetURI string) {
	if rc == nil || siteID == 0 {
		return
	}
	targetPath := cacheTargetPath(targetURI)
	rc.clearMu.Lock()
	defer rc.clearMu.Unlock()
	// Reject cache fills that started before this invalidation.
	rc.generation.Add(1)
	rc.accountingMu.Lock()
	defer rc.accountingMu.Unlock()
	indexKey := cacheTargetIndexKey(siteID, targetPath)
	keys := rc.targetIndex[indexKey]
	if len(keys) == 0 {
		return
	}
	for key := range keys {
		s := rc.shardFor(key)
		s.mu.Lock()
		entry, ok := s.items[key]
		if ok && entry.SiteID == siteID && cacheTargetPath(entry.TargetURI) == targetPath {
			delete(s.items, key)
			rc.curSize.Add(-entry.sizeBytes)
			rc.entryCount.Add(-1)
			rc.removeTargetIndexLocked(key, entry)
		}
		s.mu.Unlock()
	}
}

func cacheTargetIndexKey(siteID uint, targetPath string) string {
	return strconv.FormatUint(uint64(siteID), 10) + "\x00" + targetPath
}

func (rc *ResponseCache) addTargetIndexLocked(key string, entry *ResponseEntry) {
	if entry == nil || entry.SiteID == 0 {
		return
	}
	indexKey := cacheTargetIndexKey(entry.SiteID, cacheTargetPath(entry.TargetURI))
	keys := rc.targetIndex[indexKey]
	if keys == nil {
		keys = make(map[string]struct{})
		rc.targetIndex[indexKey] = keys
	}
	keys[key] = struct{}{}
}

func (rc *ResponseCache) removeTargetIndexLocked(key string, entry *ResponseEntry) {
	if entry == nil || entry.SiteID == 0 {
		return
	}
	indexKey := cacheTargetIndexKey(entry.SiteID, cacheTargetPath(entry.TargetURI))
	keys := rc.targetIndex[indexKey]
	if keys == nil {
		return
	}
	delete(keys, key)
	if len(keys) == 0 {
		delete(rc.targetIndex, indexKey)
	}
}

func cacheTargetPath(targetURI string) string {
	if index := strings.IndexByte(targetURI, '?'); index >= 0 {
		return targetURI[:index]
	}
	return targetURI
}

// SetEnabled toggles the cache on/off.
func (rc *ResponseCache) SetEnabled(v bool) {
	if rc == nil {
		return
	}
	wasEnabled := rc.enabled.Swap(v)
	if wasEnabled && !v {
		// 禁用缓存时立即丢弃已有响应，重新启用后不会复用停用期间
		// 形成的旧内容或跨配置代的条目。
		rc.Clear()
	}
}

func (rc *ResponseCache) Clear() {
	if rc == nil {
		return
	}
	rc.clearMu.Lock()
	defer rc.clearMu.Unlock()
	rc.generation.Add(1)
	rc.accountingMu.Lock()
	defer rc.accountingMu.Unlock()
	for i := range rc.shards {
		rc.shards[i].mu.Lock()
		rc.shards[i].items = make(map[string]*ResponseEntry)
		rc.shards[i].mu.Unlock()
	}
	rc.targetIndex = make(map[string]map[string]struct{})
	rc.curSize.Store(0)
	rc.entryCount.Store(0)
}

// Stats returns current cache statistics.
func (rc *ResponseCache) Stats() (entries int, sizeBytes int64) {
	if rc == nil {
		return 0, 0
	}
	rc.clearMu.RLock()
	defer rc.clearMu.RUnlock()
	rc.accountingMu.Lock()
	defer rc.accountingMu.Unlock()
	return int(rc.entryCount.Load()), rc.curSize.Load()
}

// Close stops the background cleaner.
func (rc *ResponseCache) Close() {
	if rc == nil {
		return
	}
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
			rc.cleanExpiredEntries()
		}
	}
}

// cleanExpiredEntries removes expired entries and keeps the reverse target
// index in sync. It is split from cleaner so expiry cleanup can be tested
// deterministically without waiting for the background ticker.
func (rc *ResponseCache) cleanExpiredEntries() {
	if rc == nil {
		return
	}
	rc.clearMu.RLock()
	rc.accountingMu.Lock()
	for i := range rc.shards {
		rc.shards[i].mu.Lock()
		for k, v := range rc.shards[i].items {
			if v.IsExpired() {
				rc.curSize.Add(-v.sizeBytes)
				rc.entryCount.Add(-1)
				delete(rc.shards[i].items, k)
				rc.removeTargetIndexLocked(k, v)
			}
		}
		if len(rc.shards[i].items) == 0 {
			rc.shards[i].items = make(map[string]*ResponseEntry)
		}
		rc.shards[i].mu.Unlock()
	}
	rc.accountingMu.Unlock()
	rc.clearMu.RUnlock()
}
