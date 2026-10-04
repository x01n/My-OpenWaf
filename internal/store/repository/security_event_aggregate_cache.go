package repository

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"My-OpenWaf/internal/store"

	"golang.org/x/sync/singleflight"
)

const (
	// 45 秒可跨过前端下一次 30 秒轮询，同时把陈旧度控制在有界范围内。
	securityEventAggregateCacheTTL                  = 45 * time.Second
	securityEventAggregateCacheMaxEntries           = 128
	securityEventAggregateCacheMaxGenerationRetries = 1
)

type securityEventAggregateKind uint8

const (
	securityEventAggregateStats securityEventAggregateKind = iota + 1
	securityEventAggregateTimeline
)

type securityEventAggregateKey struct {
	kind   securityEventAggregateKind
	scoped bool
	siteID uint
	hours  int
}

func (k securityEventAggregateKey) flightKey() string {
	return strconv.Itoa(int(k.kind)) + ":" +
		strconv.FormatBool(k.scoped) + ":" +
		strconv.FormatUint(uint64(k.siteID), 10) + ":" +
		strconv.Itoa(k.hours)
}

type securityEventAggregateCacheEntry struct {
	value     any
	expiresAt time.Time
	sequence  uint64
}

type securityEventAggregateCache struct {
	mu         sync.Mutex
	entries    map[securityEventAggregateKey]securityEventAggregateCacheEntry
	sequence   uint64
	generation atomic.Uint64
	flight     singleflight.Group
}

func newSecurityEventAggregateCache() *securityEventAggregateCache {
	return &securityEventAggregateCache{
		entries: make(map[securityEventAggregateKey]securityEventAggregateCacheEntry),
	}
}

func (c *securityEventAggregateCache) get(key securityEventAggregateKey) (any, bool) {
	now := time.Now()
	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok && !now.Before(entry.expiresAt) {
		delete(c.entries, key)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	return entry.value, true
}

func (c *securityEventAggregateCache) set(key securityEventAggregateKey, value any) {
	c.setIfGeneration(key, value, c.generation.Load())
}

func (c *securityEventAggregateCache) setIfGeneration(key securityEventAggregateKey, value any, generation uint64) {
	now := time.Now()
	if c.generation.Load() != generation {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation.Load() != generation {
		return
	}

	for existingKey, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, existingKey)
		}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= securityEventAggregateCacheMaxEntries {
		var oldestKey securityEventAggregateKey
		var oldestSequence uint64
		first := true
		for existingKey, entry := range c.entries {
			if first || entry.sequence < oldestSequence {
				oldestKey = existingKey
				oldestSequence = entry.sequence
				first = false
			}
		}
		if !first {
			delete(c.entries, oldestKey)
		}
	}
	c.sequence++
	c.entries[key] = securityEventAggregateCacheEntry{
		value:     value,
		expiresAt: now.Add(securityEventAggregateCacheTTL),
		sequence:  c.sequence,
	}
}

// invalidate 清除已完成的聚合值并推进代际。
// 在本次失效之前就已开始的加载器，无法在写入提交之后发布它的旧结果。
func (c *securityEventAggregateCache) invalidate() {
	if c == nil {
		return
	}
	c.generation.Add(1)
	c.mu.Lock()
	c.entries = make(map[securityEventAggregateKey]securityEventAggregateCacheEntry)
	c.mu.Unlock()
}

func (c *securityEventAggregateCache) getOrLoad(
	key securityEventAggregateKey,
	loader func() (any, error),
) (any, error) {
	if c == nil {
		return loader()
	}
	for attempt := 0; attempt <= securityEventAggregateCacheMaxGenerationRetries; attempt++ {
		generation := c.generation.Load()
		if value, ok := c.get(key); ok && c.generation.Load() == generation {
			return value, nil
		}
		flightKey := key.flightKey() + ":g" + strconv.FormatUint(generation, 10)
		value, err, _ := c.flight.Do(flightKey, func() (any, error) {
			if cached, ok := c.get(key); ok && c.generation.Load() == generation {
				return cached, nil
			}
			loadGeneration := c.generation.Load()
			loaded, loadErr := loader()
			if loadErr != nil {
				return nil, loadErr
			}
			c.setIfGeneration(key, loaded, loadGeneration)
			return loaded, nil
		})
		if err != nil {
			return nil, err
		}
		if c.generation.Load() == generation {
			return value, nil
		}
	}
	// 持续写入可能让代际始终无法稳定。此时直接回源加载一次且不填充缓存，
	// 而不是无限自旋。
	return loader()
}

// SecurityEventStatsSnapshot 是全局与站点级安全事件统计 handler 共用的完整响应载荷。
type SecurityEventStatsSnapshot struct {
	Total        int64          `json:"total"`
	Hours        int            `json:"hours"`
	Categories   []CategoryStat `json:"categories"`
	TopIPs       []IPStat       `json:"top_ips"`
	TopPaths     []PathStat     `json:"top_paths"`
	TopRules     []RuleStat     `json:"top_rules"`
	TopCountries []CountryStat  `json:"top_countries"`
	Intercepts   int64          `json:"intercepts"`
	Observes     int64          `json:"observes"`
	Requests     int64          `json:"requests"`
	Challenges   int64          `json:"challenges"`
}

// StatsSnapshot 返回所请求滚动窗口的全局聚合。
func (r *SecurityEventRepo) StatsSnapshot(hours int) (SecurityEventStatsSnapshot, error) {
	return r.statsSnapshot(false, 0, hours)
}

// StatsSnapshotBySite 返回所请求滚动窗口的站点级聚合。
func (r *SecurityEventRepo) StatsSnapshotBySite(siteID uint, hours int) (SecurityEventStatsSnapshot, error) {
	return r.statsSnapshot(true, siteID, hours)
}

func (r *SecurityEventRepo) statsSnapshot(scoped bool, siteID uint, hours int) (SecurityEventStatsSnapshot, error) {
	key := securityEventAggregateKey{
		kind:   securityEventAggregateStats,
		scoped: scoped,
		siteID: siteID,
		hours:  hours,
	}
	value, err := r.aggregateCache.getOrLoad(key, func() (any, error) {
		return r.loadStatsSnapshot(scoped, siteID, hours)
	})
	if err != nil {
		return SecurityEventStatsSnapshot{}, err
	}
	return cloneSecurityEventStatsSnapshot(value.(SecurityEventStatsSnapshot)), nil
}

func (r *SecurityEventRepo) loadStatsSnapshot(scoped bool, siteID uint, hours int) (SecurityEventStatsSnapshot, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	snapshot := SecurityEventStatsSnapshot{Hours: hours}
	var err error
	if scoped {
		if snapshot.Categories, err = r.CategoryStatsBySite(siteID, since); err != nil {
			return SecurityEventStatsSnapshot{}, err
		}
		if snapshot.TopIPs, err = r.TopIPsBySite(siteID, since, 10); err != nil {
			return SecurityEventStatsSnapshot{}, err
		}
		if snapshot.TopPaths, err = r.TopPathsBySite(siteID, since, 10); err != nil {
			return SecurityEventStatsSnapshot{}, err
		}
		if snapshot.TopRules, err = r.TopRulesBySite(siteID, since, 10); err != nil {
			return SecurityEventStatsSnapshot{}, err
		}
		if snapshot.TopCountries, err = r.TopCountriesBySite(siteID, since, 10); err != nil {
			return SecurityEventStatsSnapshot{}, err
		}
		counts, err := r.loadStatsCounts(true, siteID, since)
		if err != nil {
			return SecurityEventStatsSnapshot{}, err
		}
		applySecurityEventStatsCounts(&snapshot, counts)
		return snapshot, nil
	}

	if snapshot.Categories, err = r.CategoryStats(since); err != nil {
		return SecurityEventStatsSnapshot{}, err
	}
	if snapshot.TopIPs, err = r.TopIPs(since, 10); err != nil {
		return SecurityEventStatsSnapshot{}, err
	}
	if snapshot.TopPaths, err = r.TopPaths(since, 10); err != nil {
		return SecurityEventStatsSnapshot{}, err
	}
	if snapshot.TopRules, err = r.TopRules(since, 10); err != nil {
		return SecurityEventStatsSnapshot{}, err
	}
	if snapshot.TopCountries, err = r.TopCountries(since, 10); err != nil {
		return SecurityEventStatsSnapshot{}, err
	}
	counts, err := r.loadStatsCounts(false, 0, since)
	if err != nil {
		return SecurityEventStatsSnapshot{}, err
	}
	applySecurityEventStatsCounts(&snapshot, counts)
	return snapshot, nil
}

type securityEventStatsCounts struct {
	Total      int64
	Intercepts int64
	Observes   int64
	Requests   int64
	Challenges int64
}

func (r *SecurityEventRepo) loadStatsCounts(scoped bool, siteID uint, since time.Time) (securityEventStatsCounts, error) {
	var counts securityEventStatsCounts
	query := r.db.Model(&store.SecurityEvent{})
	if scoped {
		query = query.Where("site_id = ?", siteID)
	}
	err := query.
		Select(
			`COUNT(*) AS total,
			 COALESCE(SUM(CASE WHEN action IN ? THEN 1 ELSE 0 END), 0) AS intercepts,
			 COALESCE(SUM(CASE WHEN action = ? THEN 1 ELSE 0 END), 0) AS observes,
			 COUNT(DISTINCT request_id) AS requests,
			 COALESCE(SUM(CASE WHEN action IN ? THEN 1 ELSE 0 END), 0) AS challenges`,
			terminalSecurityEventActions,
			"observe",
			challengeSecurityEventActions,
		).
		Where("created_at >= ?", since).
		Scan(&counts).Error
	return counts, err
}

func applySecurityEventStatsCounts(snapshot *SecurityEventStatsSnapshot, counts securityEventStatsCounts) {
	snapshot.Total = counts.Total
	snapshot.Intercepts = counts.Intercepts
	snapshot.Observes = counts.Observes
	snapshot.Requests = counts.Requests
	snapshot.Challenges = counts.Challenges
}

// TimelineSnapshot 返回某个滚动窗口的全局终止事件时间线。
func (r *SecurityEventRepo) TimelineSnapshot(hours int) ([]TimelineBucket, error) {
	return r.timelineSnapshot(false, 0, hours)
}

// TimelineSnapshotBySite 返回某个滚动窗口的站点级终止事件时间线。
func (r *SecurityEventRepo) TimelineSnapshotBySite(siteID uint, hours int) ([]TimelineBucket, error) {
	return r.timelineSnapshot(true, siteID, hours)
}

func (r *SecurityEventRepo) timelineSnapshot(scoped bool, siteID uint, hours int) ([]TimelineBucket, error) {
	key := securityEventAggregateKey{
		kind:   securityEventAggregateTimeline,
		scoped: scoped,
		siteID: siteID,
		hours:  hours,
	}
	value, err := r.aggregateCache.getOrLoad(key, func() (any, error) {
		until := time.Now()
		since := until.Add(-time.Duration(hours) * time.Hour)
		if scoped {
			return r.TimelineBySite(siteID, since, until)
		}
		return r.Timeline(since, until)
	})
	if err != nil {
		return nil, err
	}
	return cloneSlice(value.([]TimelineBucket)), nil
}

func cloneSecurityEventStatsSnapshot(snapshot SecurityEventStatsSnapshot) SecurityEventStatsSnapshot {
	snapshot.Categories = cloneSlice(snapshot.Categories)
	snapshot.TopIPs = cloneSlice(snapshot.TopIPs)
	snapshot.TopPaths = cloneSlice(snapshot.TopPaths)
	snapshot.TopRules = cloneSlice(snapshot.TopRules)
	snapshot.TopCountries = cloneSlice(snapshot.TopCountries)
	return snapshot
}

func cloneSlice[T any](items []T) []T {
	if items == nil {
		return nil
	}
	return append(make([]T, 0, len(items)), items...)
}
