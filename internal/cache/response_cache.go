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

// ResponseEntry 表示一条已缓存的上游响应。
type ResponseEntry struct {
	StatusCode  int
	ContentType string
	Body        []byte
	/**
	 * Header 保存经过逐跳清理的上游响应头（例如 Content-Encoding: br），
	 * 使缓存命中与实时抓取保持一致。
	 *
	 * nil 表示仅含 Content-Type 的历史条目。
	 */
	Header     http.Header
	CachedAt   int64
	TTL        int64 // 秒
	SiteID     uint
	TargetURI  string
	sizeBytes  int64
	lastAccess int64 // Unix 纳秒时间戳，缓存命中时以原子方式更新
}

// IsExpired 报告条目是否已超过自身 TTL。
func (e *ResponseEntry) IsExpired() bool {
	return e == nil || time.Now().Unix()-e.CachedAt > e.TTL
}

/**
 * IsStaleWithin 报告一个已过期条目是否仍位于调用方给定的 stale-if-error 窗口内。
 */
func (e *ResponseEntry) IsStaleWithin(maxStaleSeconds int64) bool {
	if e == nil || maxStaleSeconds <= 0 {
		return false
	}
	age := time.Now().Unix() - e.CachedAt
	return age > e.TTL && age-e.TTL <= maxStaleSeconds
}

/**
 * ResponseCache 是面向安全方法（GET）请求的内存 LRU 式响应缓存。
 *
 * 采用分片互斥锁，降低热路径上的锁竞争。
 */
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
	// targetIndex 把「站点 + 路径」映射到代表它的缓存键。
	// 这样不安全方法只需失效受影响的条目，而不必扫描所有分片。
	targetIndex map[string]map[string]struct{}

	// hits/misses 记录读取命中与未命中次数，供 /metrics 暴露命中率。
	hits   atomic.Int64
	misses atomic.Int64
}

// shard 是 ResponseCache 的一个分片。
type shard struct {
	mu    sync.RWMutex
	items map[string]*ResponseEntry
}

const (
	defaultResponseCacheMB     = 64
	defaultResponseCacheTTLSec = 60
)

// NewResponseCache 创建缓存，参数为最大容量（字节）与默认 TTL。
func NewResponseCache(maxSizeMB int, defaultTTLSec int) *ResponseCache {
	// Config.LoadConfigFromEnv 已提供这些默认值，但构造函数同样被测试和
	// 嵌入式调用方使用。这里把零值/负值按文档默认值处理，而不是静默地
	// 建出一个容量为零、条目立即过期的缓存。
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

// MaxEntryBodySize 返回 Set 可接受的最大响应体字节数。
func (rc *ResponseCache) MaxEntryBodySize() int64 {
	if rc == nil || rc.maxSize <= 0 {
		return 0
	}
	return rc.maxSize / 10
}

// CacheKey 由 method + host + path + query 生成确定性缓存键。
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

// CacheKeyBytes 由 method + host + path + query 生成确定性缓存键，且不强制把字节输入转成 string。
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

// CacheKeyWithHostParts 生成缓存键，并在哈希输入内部拼装 host 部分。
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

// CacheKeyWithHostPartsBytesPath 生成缓存键，且不把 Hertz 的路径字节转成 string。
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
	// 简单的哈希分片选择。
	var h uint64
	for _, b := range key {
		h = h*31 + uint64(b)
	}
	return &rc.shards[h%64]
}

/**
 * Lookup 在条目存在时返回它，包含已超过 TTL 的条目。
 *
 * 它不会删除过期条目，用于上游报错后的陈旧数据兜底。
 */
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

/**
 * LookupIfGeneration 仅在传入的代际号仍为当前代际时返回缓存条目。
 *
 * 供陈旧兜底路径使用：这类路径完成时，另一个请求可能已经清空了缓存。
 */
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

/**
 * LookupFreshIfGeneration 返回未过期的条目，且不删除已过期的备份条目。
 *
 * 供已等待过一次回填的跟随者使用：此情此景下调用 Get 会删掉领导者
 * 仍需要用作安全兜底的 stale-if-error 条目。
 */
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

/**
 * LookupStaleIfGeneration 仅在过期条目仍处于调用方给定的 stale-if-error
 * 窗口内、且缓存代际未变时返回它。
 */
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

/**
 * Generation 返回当前缓存代际号。
 *
 * 可能在 Clear 之后才完成的在途抓取，应把该值传给 SetIfGeneration。
 */
func (rc *ResponseCache) Generation() uint64 {
	if rc == nil {
		return 0
	}
	return rc.generation.Load()
}

/**
 * Set 把一条响应写入缓存。
 *
 * header 为可选的、经过逐跳清理的上游响应头（会存入其克隆）；传 nil
 * 表示只保留 Content-Type 与响应体语义。
 */
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

/**
 * SetIfGeneration 仅在代际号仍与当前缓存代际一致时写入响应。
 *
 * 它防止 Clear 之前启动的在途抓取，在清空完成后又把缓存填回去。
 */
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

/**
 * SetForSiteIfGeneration 写入一条不可变响应，并带上站点与目标 URI 元数据，
 * 使不安全方法只需失效受影响的站点资源。
 */
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
	// 固定开销用于覆盖条目对象本身、map 槽位、string/slice 头部、
	// 指针以及分配器元数据；可变数据则按实际字节精确计入。
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
			// 采用减法形式的过期判定，避免调用方传入极大 TTL 时溢出。
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

/**
 * BeginFill 为某个缓存键选举唯一的领导者。
 *
 * 跟随者等待该次回填，之后重新检查缓存；若领导者的响应不可缓存，
 * 跟随者可以自行发起抓取。返回的 release 函数必须由领导者调用。
 */
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

/**
 * PurgeSiteTarget 清除同一站点、同一路径下已缓存的 GET 响应。
 *
 * 所有查询参数变体都会被删除，因为一个不安全请求可能改变该资源
 * 任意查询形式所代表的共享状态。
 */
func (rc *ResponseCache) PurgeSiteTarget(siteID uint, targetURI string) {
	if rc == nil || siteID == 0 {
		return
	}
	targetPath := cacheTargetPath(targetURI)
	rc.clearMu.Lock()
	defer rc.clearMu.Unlock()
	// 拒绝在本次失效之前启动的缓存回填。
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

// SetEnabled 打开或关闭缓存。
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

// Stats 返回当前缓存统计：条目数与占用字节数。
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

// Close 停止后台清理协程。
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

/**
 * cleanExpiredEntries 删除过期条目，并保持反向目标索引同步。
 *
 * 它与 cleaner 分开，是为了让过期清理可以在不等待后台 ticker 的情况下
 * 被确定性地测试。
 */
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
