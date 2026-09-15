package repository

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// fingerprintResultCacheTTL 限制绕过 AccessLogRepo 写入时的短暂陈旧窗口；
	// 通过仓储自身写入会立即递增代际并失效。
	fingerprintResultCacheTTL                  = 5 * time.Second
	fingerprintResultCacheMaxEntries           = 64
	fingerprintResultCacheMaxKeyBytes          = 64 << 10
	fingerprintResultCacheMaxGenerationRetries = 1
)

var fingerprintCacheNamespaceSequence atomic.Uint64

type fingerprintResult struct {
	Items []FingerprintSummary
	Total int64
}

type fingerprintResultCacheKey struct {
	Offset int
	Limit  int
	Filter FingerprintFilter
}

func (k fingerprintResultCacheKey) cacheable() bool {
	return len(k.flightKey()) <= fingerprintResultCacheMaxKeyBytes
}

func (k fingerprintResultCacheKey) flightKey() string {
	return fingerprintResultCacheCanonical(k.Offset, k.Limit, k.Filter)
}

type fingerprintResultCacheEntry struct {
	Result     fingerprintResult
	ExpiresAt  time.Time
	Sequence   uint64
	Generation uint64
}

// fingerprintResultCache 是进程内指纹聚合结果回源缓存。它设置硬条目上限、
// 短 TTL 与 singleflight，避免管理员页面刷新造成无界内存增长或数据库尖峰。
type fingerprintResultCache struct {
	mu         sync.Mutex
	entries    map[fingerprintResultCacheKey]fingerprintResultCacheEntry
	sequence   uint64
	generation atomic.Uint64
	flight     singleflight.Group
}

func newFingerprintResultCache() *fingerprintResultCache {
	return &fingerprintResultCache{entries: make(map[fingerprintResultCacheKey]fingerprintResultCacheEntry)}
}

func (c *fingerprintResultCache) get(key fingerprintResultCacheKey) (fingerprintResult, bool) {
	if c == nil {
		return fingerprintResult{}, false
	}
	now := time.Now()
	generation := c.generation.Load()
	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok && (entry.Generation != generation || !now.Before(entry.ExpiresAt)) {
		delete(c.entries, key)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return fingerprintResult{}, false
	}
	if c.generation.Load() != generation {
		return fingerprintResult{}, false
	}
	return cloneFingerprintResult(entry.Result), true
}

func (c *fingerprintResultCache) generationValue() uint64 {
	if c == nil {
		return 0
	}
	return c.generation.Load()
}

func (c *fingerprintResultCache) setIfGeneration(key fingerprintResultCacheKey, result fingerprintResult, generation uint64) {
	if c == nil {
		return
	}
	if c.generation.Load() != generation {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation.Load() != generation {
		return
	}
	for existingKey, entry := range c.entries {
		if entry.Generation != generation || !now.Before(entry.ExpiresAt) {
			delete(c.entries, existingKey)
		}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= fingerprintResultCacheMaxEntries {
		var oldestKey fingerprintResultCacheKey
		var oldestSequence uint64
		first := true
		for existingKey, entry := range c.entries {
			if first || entry.Sequence < oldestSequence {
				oldestKey = existingKey
				oldestSequence = entry.Sequence
				first = false
			}
		}
		if !first {
			delete(c.entries, oldestKey)
		}
	}
	c.sequence++
	c.entries[key] = fingerprintResultCacheEntry{
		Result:     cloneFingerprintResult(result),
		ExpiresAt:  now.Add(fingerprintResultCacheTTL),
		Sequence:   c.sequence,
		Generation: generation,
	}
}

func (c *fingerprintResultCache) invalidate() {
	if c == nil {
		return
	}
	c.generation.Add(1)
}

func (c *fingerprintResultCache) getOrLoad(key fingerprintResultCacheKey, loader func() (fingerprintResult, error)) (fingerprintResult, error) {
	if c == nil {
		return loader()
	}
	for attempt := 0; attempt <= fingerprintResultCacheMaxGenerationRetries; attempt++ {
		generation := c.generationValue()
		if cached, ok := c.get(key); ok {
			if c.generationValue() == generation {
				return cached, nil
			}
			continue
		}
		flightKey := key.flightKey() + "|g:" + strconv.FormatUint(generation, 10)
		value, err, _ := c.flight.Do(flightKey, func() (any, error) {
			if cached, ok := c.get(key); ok {
				return cached, nil
			}
			loadGeneration := c.generationValue()
			loaded, loadErr := loader()
			if loadErr != nil {
				return nil, loadErr
			}
			c.setIfGeneration(key, loaded, loadGeneration)
			return loaded, nil
		})
		if err != nil {
			return fingerprintResult{}, err
		}
		if c.generationValue() != generation {
			if attempt == fingerprintResultCacheMaxGenerationRetries {
				// 持续高频写入时不无限等待代际稳定：直接回源一次，不写入当前进程缓存。
				loaded, loadErr := loader()
				if loadErr != nil {
					return fingerprintResult{}, loadErr
				}
				return cloneFingerprintResult(loaded), nil
			}
			continue
		}
		result, ok := value.(fingerprintResult)
		if !ok {
			return fingerprintResult{}, errFingerprintCacheValue
		}
		return cloneFingerprintResult(result), nil
	}
	return fingerprintResult{}, errFingerprintCacheValue
}

var errFingerprintCacheValue = errors.New("invalid fingerprint cache value")

func cloneFingerprintResult(result fingerprintResult) fingerprintResult {
	result.Items = cloneFingerprintSummaries(result.Items)
	return result
}

func cloneFingerprintSummaries(items []FingerprintSummary) []FingerprintSummary {
	if items == nil {
		return nil
	}
	cloned := make([]FingerprintSummary, len(items))
	copy(cloned, items)
	return cloned
}

func fingerprintResultCacheCanonical(offset, limit int, f FingerprintFilter) string {
	var b strings.Builder
	b.Grow(256)
	b.WriteString("fp:v1|o:")
	b.WriteString(strconv.Itoa(offset))
	b.WriteString("|l:")
	b.WriteString(strconv.Itoa(limit))
	appendPart := func(tag, value string) {
		b.WriteByte('|')
		b.WriteString(tag)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
	}
	appendPart("j3h", f.TLSJA3Hash)
	appendPart("j4", f.TLSJA4)
	appendPart("tv", f.TLSVersion)
	appendPart("alpn", f.TLSALPN)
	appendPart("sni", f.TLSSNI)
	appendPart("cs", f.TLSCipherSuites)
	appendPart("ext", f.TLSExtensions)
	appendPart("cur", f.TLSCurves)
	appendPart("pf", f.TLSPointFormats)
	return b.String()
}

func newFingerprintCacheNamespace() string {
	var random [16]byte
	if _, err := cryptorand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	sequence := fingerprintCacheNamespaceSequence.Add(1)
	return strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatUint(sequence, 10)
}

func fingerprintHotCacheKey(namespace string, generation uint64, key fingerprintResultCacheKey) string {
	canonical := fingerprintResultCacheCanonical(key.Offset, key.Limit, key.Filter)
	keyMaterial := namespace + "|" + canonical
	digest := sha256.Sum256([]byte(keyMaterial))
	return "fp_list:v1:n" + namespace + ":g" + strconv.FormatUint(generation, 10) + ":" + hex.EncodeToString(digest[:])
}
