package dataplane

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

const (
	// aggregatorMaxKeys 是内存中并发聚合的唯一资源键上限。键由
	// (site_id, method, host, path, query_string) 组成，基数可被外部请求放大；
	// 设硬上限后内存恒定封顶，达顶的溢出条直接同步 Upsert（不丢数据、不 OOM）。
	aggregatorMaxKeys = 2048
	// aggregatorFlushInterval 是周期性批量落库的间隔。窗口内对同一资源的多次命中
	// 合并为一条 HitCount=N 的 Upsert，把每命中一次写一次 DB 降为每窗口写一次。
	aggregatorFlushInterval = 2 * time.Second

	// aggregatorRedisCountKey / aggregatorRedisMetaKey 是 Redis 卸载模式下承载
	// 跨节点计数与最新元数据的两个 hash 的键名（不含全局 redisPrefix）。
	aggregatorRedisCountKey = "recorded_res:counts"
	aggregatorRedisMetaKey  = "recorded_res:meta"
	// aggregatorSinkInterval 是 sink 节点从 Redis 取回聚合并回写 DB 的周期，
	// 取比 flush 更长的窗口进一步合并跨节点计数、降低 DB 写频率。
	aggregatorSinkInterval = 5 * time.Second
	// aggregatorSinkLockKey / aggregatorSinkLockTTL 用于选出唯一 sink 节点：
	// 同一时刻只有持锁者执行 Drain+回写，避免多节点重复 Upsert 造成双重累加。
	aggregatorSinkLockKey = "recorded_res:sink_lock"
	aggregatorSinkLockTTL = 30 * time.Second
	// aggregatorRedisHashTTL 是 Redis 两个 hash 的存活时间，防止所有节点下线后
	// 未回写的计数无限残留。
	aggregatorRedisHashTTL = 10 * time.Minute
)

// recordedResourceAggregator 在内存中按资源唯一键聚合 AppRoute 命中，周期性批量
// 落库，替代“每命中请求 spawn goroutine + 同步 Upsert”的高频写放大。
//
// 内存上界由 aggregatorMaxKeys 保证：达到上限后新键的写入降级为同步单条 Upsert，
// 避免 map 无界增长导致 OOM。落库依赖 RecordedResourceRepo.Upsert 的
// hit_count 累加语义，因此窗口内累计的 HitCount 会被正确合入既有行。
type recordedResourceAggregator struct {
	repo *repository.RecordedResourceRepo
	log  *slog.Logger

	// redis 非 nil 且 Available() 时启用跨节点卸载：flush 累加进 Redis hash，
	// 由持锁的 sink 节点周期回写 DB；否则退化为纯内存聚合 + 本地 DB 直写。
	redis *cache.RedisKV
	// sinkToken 是本节点争抢 sink 锁的持有令牌，进程内唯一即可。
	sinkToken string

	mu      sync.Mutex
	pending map[string]*store.RecordedResource

	flushInterval time.Duration
	maxKeys       int

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewRecordedResourceAggregator 构造聚合器并启动后台 flush 循环。repo 为 nil 时
// 返回 nil，调用方据此回退为“不记录”。
func NewRecordedResourceAggregator(repo *repository.RecordedResourceRepo, log *slog.Logger) *recordedResourceAggregator {
	if repo == nil {
		return nil
	}
	a := &recordedResourceAggregator{
		repo:          repo,
		log:           log,
		sinkToken:     newSinkToken(),
		pending:       make(map[string]*store.RecordedResource),
		flushInterval: aggregatorFlushInterval,
		maxKeys:       aggregatorMaxKeys,
		stopCh:        make(chan struct{}),
	}
	a.wg.Add(2)
	go a.loop()
	go a.sinkLoop()
	return a
}

// SetRedis 注入可选的 RedisKV。传入非 nil 后，flush 在 Redis 可用时走跨节点
// hash 累加，由 sink 循环回写 DB；Redis 不可用时自动回退纯内存 + 本地 DB。
func (a *recordedResourceAggregator) SetRedis(kv *cache.RedisKV) {
	if a == nil {
		return
	}
	a.redis = kv
}

// newSinkToken 生成本进程用于争抢 sink 锁的令牌。基于纳秒时钟即可满足进程间区分。
func newSinkToken() string {
	return "sink-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// aggregatorKey 拼出资源唯一键，字段间用不可见分隔符防止歧义拼接。
func aggregatorKey(rec *store.RecordedResource) string {
	var b strings.Builder
	b.Grow(len(rec.Method) + len(rec.Host) + len(rec.Path) + len(rec.QueryString) + 24)
	b.WriteString(strconv.FormatUint(uint64(rec.SiteID), 10))
	b.WriteByte('\x00')
	b.WriteString(rec.Method)
	b.WriteByte('\x00')
	b.WriteString(rec.Host)
	b.WriteByte('\x00')
	b.WriteString(rec.Path)
	b.WriteByte('\x00')
	b.WriteString(rec.QueryString)
	return b.String()
}

// Record 聚合一次命中。已存在的键累加 hit_count 并刷新最新元数据；新键在未达上限
// 时纳入内存，达上限时降级为同步单条 Upsert 以保证内存封顶。
func (a *recordedResourceAggregator) Record(siteID uint, ids []uint, m *appresource.Material) {
	if a == nil {
		return
	}
	rec := appresource.BuildRecordedResource(siteID, ids, m)
	if rec == nil {
		return
	}
	rec.HitCount = 1
	key := aggregatorKey(rec)

	a.mu.Lock()
	if existing, ok := a.pending[key]; ok {
		existing.HitCount++
		mergeRecordedMetadata(existing, rec)
		a.mu.Unlock()
		return
	}
	if len(a.pending) >= a.maxKeys {
		a.mu.Unlock()
		// 溢出条不进内存，直接同步落库，保证内存上界的同时不丢数据。
		if err := a.repo.Upsert(rec); err != nil && a.log != nil {
			a.log.Warn("recorded resource overflow upsert failed", "err", err)
		}
		return
	}
	a.pending[key] = rec
	a.mu.Unlock()
}

// mergeRecordedMetadata 用最新一次命中的元数据覆盖累积条目，使落库行反映最近状态。
// hit_count 已在调用处累加，此处只刷新可变元数据字段。
func mergeRecordedMetadata(dst, src *store.RecordedResource) {
	dst.ClientIP = src.ClientIP
	dst.StatusCode = src.StatusCode
	dst.ContentType = src.ContentType
	dst.TLSVersion = src.TLSVersion
	dst.TLSSNI = src.TLSSNI
	dst.TLSALPN = src.TLSALPN
	dst.JA3Hash = src.JA3Hash
	dst.JA4 = src.JA4
	dst.UserAgent = src.UserAgent
	if src.MatchedRuleIDs != "" {
		dst.MatchedRuleIDs = src.MatchedRuleIDs
	}
	if src.PrimaryRuleID > 0 {
		dst.PrimaryRuleID = src.PrimaryRuleID
	}
	dst.RequestHeadersJSON = src.RequestHeadersJSON
	dst.ResponseHeadersJSON = src.ResponseHeadersJSON
	dst.RequestBodySnippet = src.RequestBodySnippet
	dst.ResponseBodySnippet = src.ResponseBodySnippet
}

func (a *recordedResourceAggregator) loop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.flush()
		case <-a.stopCh:
			a.flush()
			return
		}
	}
}

// flush 原子换出待写映射；Redis 可用时累加进跨节点 hash（由 sink 回写 DB），
// 否则逐条本地 Upsert。换出后释放锁，IO 不阻塞 Record 热路径。
func (a *recordedResourceAggregator) flush() {
	a.mu.Lock()
	if len(a.pending) == 0 {
		a.mu.Unlock()
		return
	}
	batch := a.pending
	a.pending = make(map[string]*store.RecordedResource)
	a.mu.Unlock()

	if a.redis.Available() {
		if a.flushToRedis(batch) {
			return
		}
		// Redis 写失败时回退本地 DB，避免丢这批计数。
	}
	for _, rec := range batch {
		if err := a.repo.Upsert(rec); err != nil && a.log != nil {
			a.log.Warn("recorded resource flush upsert failed", "err", err)
		}
	}
}

// flushToRedis 把本批聚合送入 Redis：计数走 HINCRBY 跨节点累加，元数据以资源
// 唯一键为 field 存 JSON。成功返回 true。field 名直接复用内存聚合键。
func (a *recordedResourceAggregator) flushToRedis(batch map[string]*store.RecordedResource) bool {
	counts := make(map[string]int64, len(batch))
	metas := make(map[string][]byte, len(batch))
	for key, rec := range batch {
		counts[key] = rec.HitCount
		data, err := json.Marshal(rec)
		if err != nil {
			if a.log != nil {
				a.log.Warn("recorded resource marshal failed", "err", err)
			}
			continue
		}
		metas[key] = data
	}
	if len(counts) == 0 {
		return true
	}
	if err := a.redis.HAggregateFlush(aggregatorRedisCountKey, aggregatorRedisMetaKey, counts, metas, aggregatorRedisHashTTL); err != nil {
		if a.log != nil {
			a.log.Warn("recorded resource redis flush failed", "err", err)
		}
		return false
	}
	return true
}

// sinkLoop 是跨节点回写循环：周期争抢分布式锁，仅持锁者从 Redis 原子取出并清空
// 聚合 hash，再逐条 Upsert 回 DB。Redis 不可用时该循环空转（无锁可得）。
func (a *recordedResourceAggregator) sinkLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(aggregatorSinkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.sinkOnce()
		case <-a.stopCh:
			// 停机前尝试最后回写一次，减少残留在 Redis 的未落库计数。
			a.sinkOnce()
			return
		}
	}
}

// sinkOnce 争锁成功后把 Redis 聚合回写 DB。锁保证集群内同一时刻仅一个节点回写，
// Drain 的原子取出即清空保证同一批数据不被重复 Upsert。
func (a *recordedResourceAggregator) sinkOnce() {
	if !a.redis.Available() {
		return
	}
	if !a.redis.AcquireLock(aggregatorSinkLockKey, a.sinkToken, aggregatorSinkLockTTL) {
		return
	}
	defer a.redis.ReleaseLock(aggregatorSinkLockKey, a.sinkToken)

	counts, metas, err := a.redis.DrainAggregated(aggregatorRedisCountKey, aggregatorRedisMetaKey)
	if err != nil {
		if a.log != nil {
			a.log.Warn("recorded resource redis drain failed", "err", err)
		}
		return
	}
	for key, n := range counts {
		if n <= 0 {
			continue
		}
		raw, ok := metas[key]
		if !ok {
			continue
		}
		var rec store.RecordedResource
		if err := json.Unmarshal(raw, &rec); err != nil {
			if a.log != nil {
				a.log.Warn("recorded resource unmarshal failed", "err", err)
			}
			continue
		}
		// Redis 中累计的 n 即窗口内跨节点总命中，覆盖 JSON 里最后一次写入的 HitCount。
		rec.HitCount = n
		if err := a.repo.Upsert(&rec); err != nil && a.log != nil {
			a.log.Warn("recorded resource sink upsert failed", "err", err)
		}
	}
}

// Close 停止后台循环并落库剩余聚合条目。可安全地对 nil 接收者调用。
func (a *recordedResourceAggregator) Close() {
	if a == nil {
		return
	}
	close(a.stopCh)
	a.wg.Wait()
}
