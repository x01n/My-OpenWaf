package repository

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type AccessLogRepo struct {
	db                   *gorm.DB
	countCache           CountCache
	hotCache             HotCacheBackend
	writeQueue           WriteQueueBackend
	fingerprintCache     *fingerprintResultCache
	fingerprintNamespace string
}

// CountCache is an optional cache for expensive COUNT queries.
type CountCache interface {
	Get(key string) (any, bool)
	Set(key string, value any)
}

// CountCacheInvalidator is implemented by caches that can discard all count
// entries after an append/delete. The optional interface keeps lightweight test
// doubles compatible while allowing the production QueryCache to preserve
// write-after-read count consistency.
type CountCacheInvalidator interface {
	InvalidateAll()
}

func NewAccessLogRepo(db *gorm.DB) *AccessLogRepo {
	return &AccessLogRepo{
		db:                   db,
		fingerprintCache:     newFingerprintResultCache(),
		fingerprintNamespace: newFingerprintCacheNamespace(),
	}
}

// SetCountCache configures an optional count cache for list queries.
func (r *AccessLogRepo) SetCountCache(c CountCache) {
	r.countCache = c
}

func (r *AccessLogRepo) invalidateCountCache() {
	if r == nil || r.countCache == nil {
		return
	}
	invalidateCountCachePrefixes(r.countCache, accessLogCountCachePrefix, accessLogListCachePrefix)
}

// SetHotCache configures Redis-backed hot cache for large query results.
func (r *AccessLogRepo) SetHotCache(hc HotCacheBackend) {
	r.hotCache = hc
}

// SetWriteQueue configures async write queue for batch writes.
func (r *AccessLogRepo) SetWriteQueue(wq WriteQueueBackend) {
	r.writeQueue = wq
}

// invalidateFingerprintCache 清除进程内指纹聚合结果，并递增共享缓存的代际。
// Redis 旧键仅保留短 TTL，避免在每次高频日志写入时执行昂贵的 SCAN 删除。
func (r *AccessLogRepo) invalidateFingerprintCache() {
	if r == nil || r.fingerprintCache == nil {
		return
	}
	r.fingerprintCache.invalidate()
}

type AccessLogFilter struct {
	ID              uint
	SiteID          uint
	Query           string
	RequestID       string
	ClientIP        string
	Host            string
	Path            string
	QueryString     string
	Method          string
	WAFAction       string
	CacheState      string
	StatusGroup     string
	TLSVersion      string
	TLSSNI          string
	TLSALPN         string
	TLSJA3Hash      string
	TLSJA4          string
	TLSCipherSuites string
	TLSExtensions   string
	TLSCurves       string
	TLSPointFormats string
	Since           *time.Time
	Until           *time.Time
}

type SiteAccessLogStats struct {
	Requests      int64 `json:"requests"`
	Intercepts    int64 `json:"intercepts"`
	Observes      int64 `json:"observes"`
	CacheHits     int64 `json:"cache_hits"`
	CacheMisses   int64 `json:"cache_misses"`
	CacheBypasses int64 `json:"cache_bypasses"`
	CacheStales   int64 `json:"cache_stales"`
}

// VisitorKindStats 表达窗口内人工/机器/未判定拦截访问数（按唯一 request_id 计）。
//
// 与 BotScoreLog 统计区别见 visitorKindStatsInternal 注释。
//
// 注意：HumanVisits + BotVisits + UnclassifiedIntercept 不必然等于 TotalVisits。
// 差额是「其他非安全类」动作（basic_auth / maintenance / dynamic_key*），
// 三类均采用正向枚举，未知 waf_action 不会被静默归入任何一类。
type VisitorKindStats struct {
	HumanVisits           int64 `json:"human_visits"`
	BotVisits             int64 `json:"bot_visits"`
	UnclassifiedIntercept int64 `json:"unclassified_intercept"`
	TotalVisits           int64 `json:"total_visits"`
}

// visitorKindTerminalActions 是 AccessLog.waf_action 中「安全判定驱动的终止动作」字面值。
//
// 取自 internal/core/action/action.go:9-25 常量集与 internal/dataplane/handler.go
// 直接字面值写入点。"block" 为 legacy 别名（归一化后写 "intercept"），一并列出以覆盖历史数据。
// "redirect" 归入此类：handler.go:903 记录时携带 result.Action.RedirectTo，
// 属 WAF 判定驱动的安全重定向，非业务跳转。
var visitorKindTerminalActions = []string{
	"intercept",
	"block",
	"drop",
	"rate_limit",
	"challenge",
	"captcha_challenge",
	"shield_challenge",
	"chain_challenge",
	"redirect",
}

// visitorKindHumanActions 是 AccessLog.waf_action 中「请求已放行至上游」的字面值。
//
// "challenge_passed"（handler.go:956）归入此类：质询通过意味着真实浏览器解出了质询。
// "observe" / "tag" / "log_only" 为非终止动作，请求已放行。
// "" 覆盖未设置 waf_action 的历史行与零值写入，避免正向枚举把它们排除出全部分类。
var visitorKindHumanActions = []string{
	"none",
	"allow",
	"observe",
	"tag",
	"log_only",
	"challenge_passed",
	"",
}

type FingerprintSummary struct {
	TLSJA3Hash      string    `json:"tls_ja3_hash"`
	TLSJA4          string    `json:"tls_ja4"`
	TLSVersion      string    `json:"tls_version"`
	TLSALPN         string    `json:"tls_alpn"`
	TLSSNI          string    `json:"tls_sni"`
	TLSCipherSuites string    `json:"tls_cipher_suites"`
	TLSExtensions   string    `json:"tls_extensions"`
	TLSCurves       string    `json:"tls_curves"`
	TLSPointFormats string    `json:"tls_point_formats"`
	Count           int64     `json:"count"`
	HighRiskCount   int64     `json:"high_risk_count"`
	AvgBotScore     float64   `json:"avg_bot_score"`
	LastSeen        time.Time `json:"last_seen"`
	LastUserAgent   string    `json:"last_user_agent"`
	LastClientIP    string    `json:"last_client_ip"`
	LastHeaderOrder string    `json:"last_header_order"`
}

type FingerprintFilter struct {
	TLSJA3Hash      string
	TLSJA4          string
	TLSVersion      string
	TLSALPN         string
	TLSSNI          string
	TLSCipherSuites string
	TLSExtensions   string
	TLSCurves       string
	TLSPointFormats string
}

var fingerprintGroupColumnNames = []string{
	"tls_ja3_hash",
	"tls_ja4",
	"tls_version",
	"tls_alpn",
	"tls_sni",
	"tls_cipher_suites",
	"tls_extensions",
	"tls_curves",
	"tls_point_formats",
}

type fingerprintRow struct {
	FingerprintKey  string `gorm:"column:fingerprint_key"`
	TLSJA3Hash      string `json:"tls_ja3_hash"`
	TLSJA4          string `json:"tls_ja4"`
	TLSVersion      string `json:"tls_version"`
	TLSALPN         string `json:"tls_alpn"`
	TLSSNI          string `json:"tls_sni"`
	TLSCipherSuites string `json:"tls_cipher_suites"`
	TLSExtensions   string `json:"tls_extensions"`
	TLSCurves       string `json:"tls_curves"`
	TLSPointFormats string `json:"tls_point_formats"`
	Count           int64  `json:"count"`
}

// fingerprintLatestRow 是指纹列表补充最新访问元数据时的窄读模型。
//
// 该查询只需要下面 14 个字段，却曾经把结果扫描到完整的 store.AccessLog；
// 后者包含请求/响应头体等大字段。即使 SELECT 没有读取这些列，GORM 仍会为
// 完整模型执行字段映射和结构体初始化。独立模型保持列名与 SQL 完全一致，
// 只减少 ORM 层的反射与分配，不改变数据库查询语义。
type fingerprintLatestRow struct {
	ID              uint      `gorm:"column:id"`
	CreatedAt       time.Time `gorm:"column:created_at"`
	UserAgent       string    `gorm:"column:user_agent"`
	ClientIP        string    `gorm:"column:client_ip"`
	HeaderOrder     string    `gorm:"column:header_order"`
	FingerprintKey  string    `gorm:"column:fingerprint_key"`
	TLSJA3Hash      string    `gorm:"column:tls_ja3_hash"`
	TLSJA4          string    `gorm:"column:tls_ja4"`
	TLSVersion      string    `gorm:"column:tls_version"`
	TLSALPN         string    `gorm:"column:tls_alpn"`
	TLSSNI          string    `gorm:"column:tls_sni"`
	TLSCipherSuites string    `gorm:"column:tls_cipher_suites"`
	TLSExtensions   string    `gorm:"column:tls_extensions"`
	TLSCurves       string    `gorm:"column:tls_curves"`
	TLSPointFormats string    `gorm:"column:tls_point_formats"`
}

// accessLogListCacheValue contains only the already-projected list columns.
// Detail payloads are never loaded into this cache.
type accessLogListCacheValue struct {
	Items []store.AccessLog
	Total int64
}

const accessLogListCacheMaxLimit = 50

type fingerprintKey struct {
	FingerprintKey string
}

func fingerprintKeyFromRow(row fingerprintRow) fingerprintKey {
	return fingerprintKey{
		FingerprintKey: row.FingerprintKey,
	}
}

func fingerprintKeyFromLatestRow(row fingerprintLatestRow) fingerprintKey {
	return fingerprintKey{
		FingerprintKey: row.FingerprintKey,
	}
}

func fingerprintColumns(alias string) string {
	var b strings.Builder
	for i, column := range fingerprintGroupColumnNames {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(alias)
		b.WriteString(column)
	}
	return b.String()
}

// fingerprintRowsPredicate selects the page of already-grouped fingerprints in
// a fixed number of follow-up queries. Alias is an internal SQL literal such as
// "al."; all data values remain bound parameters.
func fingerprintRowsPredicate(rows []fingerprintRow, alias string) (string, []any) {
	var b strings.Builder
	args := make([]any, 0, len(rows))
	for i, row := range rows {
		if i > 0 {
			b.WriteString(" OR ")
		}
		b.WriteByte('(')
		b.WriteString(alias)
		b.WriteString("fingerprint_key = ?")
		args = append(args, row.FingerprintKey)
		b.WriteByte(')')
	}
	return b.String(), args
}

func latestFingerprintRowPredicate() string {
	return "NOT EXISTS (SELECT 1 FROM access_logs AS newer WHERE newer.fingerprint_key = al.fingerprint_key AND (newer.created_at > al.created_at OR (newer.created_at = al.created_at AND newer.id > al.id)))"
}

type fingerprintBotAggregate struct {
	FingerprintKey string
	HighRiskCount  int64
	AvgBotScore    float64
}

func fingerprintKeyFromBotAggregate(row fingerprintBotAggregate) fingerprintKey {
	return fingerprintKey{
		FingerprintKey: row.FingerprintKey,
	}
}

// accessLogListColumns excludes the large request/response audit payloads from
// list and realtime polling queries. Get and FindByRequestID intentionally keep
// selecting the complete row for detail and request-trace views.
var accessLogListColumns = []string{
	"id", "created_at", "site_id", "request_id", "client_ip", "host", "path", "query_string", "method",
	"status_code", "waf_action", "cache_state", "upstream", "user_agent", "request_body_truncated", "request_size",
	"http_protocol", "upstream_http_protocol", "tls_version", "tls_sni", "tls_alpn", "tls_ja3", "tls_ja3_hash", "tls_ja4",
	"tls_cipher_suites", "tls_extensions", "tls_curves", "tls_point_formats", "header_order",
	"visitor_fusion_class", "visitor_fusion_score", "visitor_fusion_client_family", "visitor_fusion_ua_claim",
	"visitor_fusion_consistency", "visitor_fusion_evidence_sufficient", "visitor_fusion_reasons",
	"upstream_latency_ms", "response_size",
}

func (r *AccessLogRepo) List(offset, limit int, f AccessLogFilter) ([]store.AccessLog, int64, error) {
	f = normalizeAccessLogFilter(f)
	cacheKey := accessLogCountCacheKey(f)
	listCacheKey := accessLogListCacheKey(f, offset, limit)

	// Try Redis hot cache for large query results.
	if r.hotCache != nil && r.hotCache.Available() {
		hcKey := "al_list:" + cacheKey + ":o" + strconv.Itoa(offset) + ":l" + strconv.Itoa(limit)
		if rawItems, cachedTotal, ok := r.hotCache.GetListRaw(hcKey); ok {
			var items []store.AccessLog
			if json.Unmarshal(rawItems, &items) == nil {
				normalizeAccessLogProtocols(items)
				return items, cachedTotal, nil
			}
		}
	}

	// Reuse the bounded in-process query cache when Redis is unavailable or cold.
	// Only the lightweight list projection is stored, and small pages are capped
	// to keep user-controlled filter cardinality from consuming excessive memory.
	if r.countCache != nil && limit > 0 && limit <= accessLogListCacheMaxLimit {
		if value, ok := r.countCache.Get(listCacheKey); ok {
			if cached, ok := value.(accessLogListCacheValue); ok {
				items := cloneAccessLogs(cached.Items)
				normalizeAccessLogProtocols(items)
				return items, cached.Total, nil
			}
		}
	}

	q := r.db.Model(&store.AccessLog{})
	q = applyAccessLogFilters(q, f)

	var total int64
	cached := false
	if r.countCache != nil {
		if value, ok := r.countCache.Get(cacheKey); ok {
			if cachedTotal, ok := value.(int64); ok {
				total = cachedTotal
				cached = true
			}
		}
	}
	if !cached {
		if err := q.Count(&total).Error; err != nil {
			return nil, 0, err
		}
		if r.countCache != nil {
			r.countCache.Set(cacheKey, total)
		}
	}
	if !cached && total == 0 {
		items := []store.AccessLog{}
		if r.countCache != nil && limit > 0 && limit <= accessLogListCacheMaxLimit {
			r.countCache.Set(listCacheKey, accessLogListCacheValue{
				Items: items,
				Total: total,
			})
		}
		if r.hotCache != nil && r.hotCache.Available() {
			hcKey := "al_list:" + cacheKey + ":o" + strconv.Itoa(offset) + ":l" + strconv.Itoa(limit)
			r.hotCache.SetList(hcKey, items, total, 5*time.Second)
		}
		return items, total, nil
	}

	var items []store.AccessLog
	if err := q.Select(accessLogListColumns).Offset(offset).Limit(limit).Order("created_at DESC, id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	normalizeAccessLogProtocols(items)
	if r.countCache != nil && limit > 0 && limit <= accessLogListCacheMaxLimit {
		r.countCache.Set(listCacheKey, accessLogListCacheValue{
			Items: cloneAccessLogs(items),
			Total: total,
		})
	}

	// Cache large results in Redis for subsequent requests.
	if r.hotCache != nil && r.hotCache.Available() {
		hcKey := "al_list:" + cacheKey + ":o" + strconv.Itoa(offset) + ":l" + strconv.Itoa(limit)
		r.hotCache.SetList(hcKey, items, total, 5*time.Second)
	}

	return items, total, nil
}

func (r *AccessLogRepo) StatsBySite(siteID uint, since time.Time) (SiteAccessLogStats, error) {
	var stats SiteAccessLogStats
	terminalActions := []string{"intercept", "block", "drop", "challenge", "captcha_challenge", "shield_challenge", "chain_challenge", "rate_limit"}
	err := r.db.Model(&store.AccessLog{}).
		Select("COUNT(*) AS requests, SUM(CASE WHEN waf_action IN ? THEN 1 ELSE 0 END) AS intercepts, SUM(CASE WHEN waf_action = ? THEN 1 ELSE 0 END) AS observes, SUM(CASE WHEN cache_state = ? THEN 1 ELSE 0 END) AS cache_hits, SUM(CASE WHEN cache_state = ? THEN 1 ELSE 0 END) AS cache_misses, SUM(CASE WHEN cache_state = ? THEN 1 ELSE 0 END) AS cache_bypasses, SUM(CASE WHEN cache_state = ? THEN 1 ELSE 0 END) AS cache_stales", terminalActions, "observe", "hit", "miss", "bypass", "stale").
		Where("site_id = ? AND created_at >= ?", siteID, since).
		Scan(&stats).Error
	return stats, err
}

// VisitorKindStats 聚合某窗口内 human/bot/未判定拦截 访问条数（口径二）。
//
// bot = 窗口内 BotScoreLog 写入的唯一 request_id 数。BotScoreLog 仅在 bot 分类既非
// "human" 也非 "good" 时写入（见 internal/core/rules/phases.go:463-464），因此它只覆盖
// 「被判为 malicious 或 suspicious」的请求。注意与 dashboard.bot_total_24h 含义不同——
// 后者是 BotScoreLog 条数（未去重）。
//
// UnclassifiedIntercept = 无 BotScoreLog 关联、且 waf_action 属安全终止动作的访问。
// BotDetection 位于 pipeline 第 7 位，OWASP/CVE/ACL/IPRep 的终止动作会短路，这些请求
// 永不进入 BotDetection、永不写 BotScoreLog；若直接反推会被计入 human，使攻击流量抬高
// 「人工」占比。单列此类正是口径二相对口径一的关键修正。
//
// human = 无 BotScoreLog 关联、且 waf_action 属放行动作的访问。
//
// 三类均按唯一 request_id 计数，空 request_id 不计入。TotalVisits 为窗口内唯一 request_id
// 总数；三类之和与 TotalVisits 的差额是「其他非安全类」动作，见 VisitorKindStats 注释。
// siteID=0 表示全局。优先级：有 BotScoreLog 关联者一律计入 bot，不再看 waf_action。
// BotScoreLog 与 AccessLog 共享 LogDB（见 internal/store/repository/repository.go:74-76）。
func (r *AccessLogRepo) VisitorKindStats(siteID uint, since time.Time) (VisitorKindStats, error) {
	return r.visitorKindStatsInternal(siteID, since)
}

// VisitorKindStatsGlobal 聚合全局（跨站点）的 human/bot 访问数。
func (r *AccessLogRepo) VisitorKindStatsGlobal(since time.Time) (VisitorKindStats, error) {
	return r.visitorKindStatsInternal(0, since)
}

func (r *AccessLogRepo) visitorKindStatsInternal(siteID uint, since time.Time) (VisitorKindStats, error) {
	var stats VisitorKindStats

	// 分母：窗口内唯一 request_id 总数。用于暴露三类之和与总数的差额。
	totalQ := r.db.Model(&store.AccessLog{}).
		Where("created_at >= ? AND request_id <> ?", since, "")
	if siteID > 0 {
		totalQ = totalQ.Where("site_id = ?", siteID)
	}
	if err := totalQ.Distinct("request_id").Count(&stats.TotalVisits).Error; err != nil {
		return stats, err
	}

	hasBotScoreTable := r.db.Migrator().HasTable(&store.BotScoreLog{})
	if !hasBotScoreTable {
		// 无 BotScoreLog 表：bot 恒为 0，但 human 与「未判定拦截」的区分只依赖
		// waf_action，与 bot 表无关，故此处仍按正向枚举拆分，不再一律计入 human。
		humanQ := r.db.Model(&store.AccessLog{}).
			Where("created_at >= ? AND request_id <> ?", since, "").
			Where("waf_action IN ?", visitorKindHumanActions)
		if siteID > 0 {
			humanQ = humanQ.Where("site_id = ?", siteID)
		}
		if err := humanQ.Distinct("request_id").Count(&stats.HumanVisits).Error; err != nil {
			return stats, err
		}

		interceptQ := r.db.Model(&store.AccessLog{}).
			Where("created_at >= ? AND request_id <> ?", since, "").
			Where("waf_action IN ?", visitorKindTerminalActions)
		if siteID > 0 {
			interceptQ = interceptQ.Where("site_id = ?", siteID)
		}
		err := interceptQ.Distinct("request_id").Count(&stats.UnclassifiedIntercept).Error
		return stats, err
	}

	// bot = 窗口内 BotScoreLog 唯一 request_id 数（仅记录非 human/good 的请求）。
	botQ := r.db.Model(&store.BotScoreLog{}).
		Where("created_at >= ? AND request_id <> ?", since, "")
	if siteID > 0 {
		botQ = botQ.Where("site_id = ?", siteID)
	}
	if err := botQ.Distinct("request_id").Count(&stats.BotVisits).Error; err != nil {
		return stats, err
	}

	// 无 bot 关联的判定条件。NOT EXISTS 直推，避免两阶段相减在并发写入下产生负值。
	const noBotAssoc = "NOT EXISTS (SELECT 1 FROM bot_score_logs bs WHERE bs.request_id = access_logs.request_id AND bs.created_at >= ? AND bs.request_id <> ?)"

	// human = 无 bot 关联 且 waf_action 属放行动作。
	humanQ := r.db.Model(&store.AccessLog{}).
		Where("access_logs.created_at >= ? AND access_logs.request_id <> ?", since, "").
		Where("access_logs.waf_action IN ?", visitorKindHumanActions).
		Where(noBotAssoc, since, "")
	if siteID > 0 {
		humanQ = humanQ.Where("access_logs.site_id = ?", siteID)
	}
	if err := humanQ.Distinct("access_logs.request_id").Count(&stats.HumanVisits).Error; err != nil {
		return stats, err
	}

	// 未判定拦截 = 无 bot 关联 且 waf_action 属安全终止动作。
	interceptQ := r.db.Model(&store.AccessLog{}).
		Where("access_logs.created_at >= ? AND access_logs.request_id <> ?", since, "").
		Where("access_logs.waf_action IN ?", visitorKindTerminalActions).
		Where(noBotAssoc, since, "")
	if siteID > 0 {
		interceptQ = interceptQ.Where("access_logs.site_id = ?", siteID)
	}
	if err := interceptQ.Distinct("access_logs.request_id").Count(&stats.UnclassifiedIntercept).Error; err != nil {
		return stats, err
	}
	return stats, nil
}

func (r *AccessLogRepo) ListFingerprints(offset, limit int, f FingerprintFilter) ([]FingerprintSummary, int64, error) {
	f = normalizeFingerprintFilter(f)
	key := fingerprintResultCacheKey{Offset: offset, Limit: limit, Filter: f}
	if r.fingerprintCache == nil || !key.cacheable() {
		result, err := r.loadFingerprints(offset, limit, f)
		return result.Items, result.Total, err
	}
	generation := r.fingerprintCache.generationValue()
	result, err := r.fingerprintCache.getOrLoad(key, func() (fingerprintResult, error) {
		if r.hotCache != nil && r.hotCache.Available() {
			hotKey := fingerprintHotCacheKey(r.fingerprintNamespace, generation, key)
			if rawItems, cachedTotal, ok := r.hotCache.GetListRaw(hotKey); ok {
				var items []FingerprintSummary
				if json.Unmarshal(rawItems, &items) == nil {
					return fingerprintResult{Items: items, Total: cachedTotal}, nil
				}
			}
		}
		loaded, loadErr := r.loadFingerprints(offset, limit, f)
		if loadErr != nil {
			return fingerprintResult{}, loadErr
		}
		if r.hotCache != nil && r.hotCache.Available() {
			r.hotCache.SetList(fingerprintHotCacheKey(r.fingerprintNamespace, generation, key), loaded.Items, loaded.Total, fingerprintResultCacheTTL)
		}
		return loaded, nil
	})
	return result.Items, result.Total, err
}

func (r *AccessLogRepo) loadFingerprints(offset, limit int, f FingerprintFilter) (fingerprintResult, error) {
	base := func() *gorm.DB {
		q := r.db.Model(&store.AccessLog{}).Where("fingerprint_key <> ?", "")
		return applyFingerprintFilters(q, f)
	}
	// The digest index is the grouping identity. The original nine fields are
	// projected with MAX so the response shape remains unchanged without putting
	// the wide TEXT columns in GROUP BY or the temporary B-tree.
	groupColumns := "fingerprint_key"
	groupSelect := groupColumns +
		", MAX(tls_ja3_hash) AS tls_ja3_hash" +
		", MAX(tls_ja4) AS tls_ja4" +
		", MAX(tls_version) AS tls_version" +
		", MAX(tls_alpn) AS tls_alpn" +
		", MAX(tls_sni) AS tls_sni" +
		", MAX(tls_cipher_suites) AS tls_cipher_suites" +
		", MAX(tls_extensions) AS tls_extensions" +
		", MAX(tls_curves) AS tls_curves" +
		", MAX(tls_point_formats) AS tls_point_formats"

	var total int64
	countQ := r.db.Table(
		"(?) as fp",
		base().Select(groupColumns).Group(groupColumns),
	)
	if err := countQ.Count(&total).Error; err != nil {
		return fingerprintResult{}, err
	}

	var rows []fingerprintRow
	err := base().Select(groupSelect + ", COUNT(*) AS count").
		Group(groupColumns).
		Order("MAX(created_at) DESC, " + groupColumns).
		Offset(offset).Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return fingerprintResult{}, err
	}
	if len(rows) == 0 {
		return fingerprintResult{Items: []FingerprintSummary{}, Total: total}, nil
	}

	latestPredicate, latestArgs := fingerprintRowsPredicate(rows, "al.")
	var latestRows []fingerprintLatestRow
	if err := r.db.Table("access_logs AS al").
		Select("al.id, al.created_at, al.user_agent, al.client_ip, al.header_order, al.fingerprint_key, "+fingerprintColumns("al.")).
		Where(latestPredicate, latestArgs...).
		Where(latestFingerprintRowPredicate()).
		Order("al.created_at DESC, al.id DESC").
		Find(&latestRows).Error; err != nil {
		return fingerprintResult{}, err
	}
	latestByFingerprint := make(map[fingerprintKey]fingerprintLatestRow, len(rows))
	for _, latest := range latestRows {
		key := fingerprintKeyFromLatestRow(latest)
		if _, exists := latestByFingerprint[key]; !exists {
			latestByFingerprint[key] = latest
		}
	}

	botByFingerprint := make(map[fingerprintKey]fingerprintBotAggregate, len(rows))
	if r.db.Migrator().HasTable(&store.BotScoreLog{}) {
		selectedPredicate, selectedArgs := fingerprintRowsPredicate(rows, "")
		requestIDs := r.db.Model(&store.AccessLog{}).
			Select("fingerprint_key, request_id").
			Where(selectedPredicate, selectedArgs...).
			Where("request_id <> ?", "").
			Group("fingerprint_key, request_id")

		var botRows []fingerprintBotAggregate
		if err := r.db.Table("(?) AS fp_requests", requestIDs).
			Select("fp_requests.fingerprint_key, SUM(CASE WHEN bs.is_high_risk = ? THEN 1 ELSE 0 END) AS high_risk_count, COALESCE(AVG(bs.total_score), 0) AS avg_bot_score", true).
			Joins("JOIN bot_score_logs AS bs ON bs.request_id = fp_requests.request_id").
			Group("fp_requests.fingerprint_key").
			Scan(&botRows).Error; err != nil {
			return fingerprintResult{}, err
		}
		for _, aggregate := range botRows {
			botByFingerprint[fingerprintKeyFromBotAggregate(aggregate)] = aggregate
		}
	}

	items := make([]FingerprintSummary, 0, len(rows))
	for _, row := range rows {
		key := fingerprintKeyFromRow(row)
		last, ok := latestByFingerprint[key]
		if !ok {
			return fingerprintResult{}, fmt.Errorf("latest access log not found for fingerprint key %q", row.FingerprintKey)
		}
		botAggregate := botByFingerprint[key]
		items = append(items, FingerprintSummary{
			TLSJA3Hash:      row.TLSJA3Hash,
			TLSJA4:          row.TLSJA4,
			TLSVersion:      row.TLSVersion,
			TLSALPN:         row.TLSALPN,
			TLSSNI:          row.TLSSNI,
			TLSCipherSuites: row.TLSCipherSuites,
			TLSExtensions:   row.TLSExtensions,
			TLSCurves:       row.TLSCurves,
			TLSPointFormats: row.TLSPointFormats,
			Count:           row.Count,
			HighRiskCount:   botAggregate.HighRiskCount,
			AvgBotScore:     botAggregate.AvgBotScore,
			LastSeen:        last.CreatedAt,
			LastUserAgent:   last.UserAgent,
			LastClientIP:    last.ClientIP,
			LastHeaderOrder: last.HeaderOrder,
		})
	}
	return fingerprintResult{Items: items, Total: total}, nil
}

func applyFingerprintFilters(q *gorm.DB, f FingerprintFilter) *gorm.DB {
	f = normalizeFingerprintFilter(f)
	if f.TLSJA3Hash != "" {
		q = q.Where("tls_ja3_hash = ?", f.TLSJA3Hash)
	}
	if f.TLSJA4 != "" {
		q = q.Where("tls_ja4 = ?", f.TLSJA4)
	}
	if f.TLSVersion != "" {
		q = q.Where("tls_version = ?", f.TLSVersion)
	}
	if f.TLSALPN != "" {
		q = q.Where("tls_alpn LIKE ?", "%"+f.TLSALPN+"%")
	}
	if f.TLSSNI != "" {
		q = q.Where("tls_sni LIKE ?", "%"+f.TLSSNI+"%")
	}
	if f.TLSCipherSuites != "" {
		q = q.Where("tls_cipher_suites LIKE ?", "%"+f.TLSCipherSuites+"%")
	}
	if f.TLSExtensions != "" {
		q = q.Where("tls_extensions LIKE ?", "%"+f.TLSExtensions+"%")
	}
	if f.TLSCurves != "" {
		q = q.Where("tls_curves LIKE ?", "%"+f.TLSCurves+"%")
	}
	if f.TLSPointFormats != "" {
		q = q.Where("tls_point_formats LIKE ?", "%"+f.TLSPointFormats+"%")
	}
	return q
}

func accessLogCountCacheKey(f AccessLogFilter) string {
	f = normalizeAccessLogFilter(f)
	var b strings.Builder
	var ibuf [20]byte
	b.Grow(64)
	b.WriteString(accessLogCountCachePrefix)
	appendPart := func(tag, value string) {
		b.WriteByte('|')
		b.WriteString(tag)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
	}
	appendUint := func(tag string, value uint64) {
		appendPart(tag, string(strconv.AppendUint(ibuf[:0], value, 10)))
	}
	if f.ID > 0 {
		appendUint("id", uint64(f.ID))
	}
	if f.SiteID > 0 {
		appendUint("s", uint64(f.SiteID))
	}
	if f.Query != "" {
		appendPart("q", f.Query)
	}
	if f.RequestID != "" {
		appendPart("rid", f.RequestID)
	}
	if f.ClientIP != "" {
		appendPart("ip", f.ClientIP)
	}
	if f.Host != "" {
		appendPart("h", f.Host)
	}
	if f.Path != "" {
		appendPart("p", f.Path)
	}
	if f.QueryString != "" {
		appendPart("qs", f.QueryString)
	}
	if f.Method != "" {
		appendPart("m", f.Method)
	}
	if f.WAFAction != "" {
		appendPart("wa", f.WAFAction)
	}
	if f.CacheState != "" {
		appendPart("cs", f.CacheState)
	}
	if f.StatusGroup != "" {
		appendPart("sg", f.StatusGroup)
	}
	if f.TLSVersion != "" {
		appendPart("tv", f.TLSVersion)
	}
	if f.TLSSNI != "" {
		appendPart("sni", f.TLSSNI)
	}
	if f.TLSALPN != "" {
		appendPart("alpn", f.TLSALPN)
	}
	if f.TLSJA3Hash != "" {
		appendPart("j3h", f.TLSJA3Hash)
	}
	if f.TLSJA4 != "" {
		appendPart("j4", f.TLSJA4)
	}
	if f.TLSCipherSuites != "" {
		appendPart("tcs", f.TLSCipherSuites)
	}
	if f.TLSExtensions != "" {
		appendPart("tex", f.TLSExtensions)
	}
	if f.TLSCurves != "" {
		appendPart("tcu", f.TLSCurves)
	}
	if f.TLSPointFormats != "" {
		appendPart("tpf", f.TLSPointFormats)
	}
	if f.Since != nil {
		appendPart("si", f.Since.UTC().Format(time.RFC3339Nano))
	}
	if f.Until != nil {
		appendPart("un", f.Until.UTC().Format(time.RFC3339Nano))
	}
	return b.String()
}

func accessLogListCacheKey(f AccessLogFilter, offset, limit int) string {
	filterKey := accessLogCountCacheKey(f)
	return accessLogListCachePrefix + "|f:" + strconv.Itoa(len(filterKey)) + ":" + filterKey +
		"|o:" + strconv.Itoa(offset) + "|l:" + strconv.Itoa(limit)
}

func cloneAccessLogs(items []store.AccessLog) []store.AccessLog {
	if len(items) == 0 {
		return []store.AccessLog{}
	}
	cloned := make([]store.AccessLog, len(items))
	copy(cloned, items)
	return cloned
}

func (r *AccessLogRepo) Create(item *store.AccessLog) error {
	if r.writeQueue != nil {
		// 先失效，避免异步写入尚未落库期间继续返回旧聚合；成功后再失效一次，
		// 覆盖写入与回源查询并发的窗口。
		r.invalidateFingerprintCache()
		r.writeQueue.Submit(func(tx *gorm.DB) error {
			err := tx.Create(item).Error
			if err == nil {
				r.invalidateFingerprintCache()
				r.invalidateCountCache()
			}
			return err
		})
		return nil
	}
	err := r.db.Create(item).Error
	if err == nil {
		r.invalidateFingerprintCache()
		r.invalidateCountCache()
	}
	return err
}

func (r *AccessLogRepo) BatchCreate(items []store.AccessLog) error {
	if len(items) == 0 {
		return nil
	}
	if r.writeQueue != nil {
		batch := make([]store.AccessLog, len(items))
		copy(batch, items)
		r.invalidateFingerprintCache()
		r.writeQueue.Submit(func(tx *gorm.DB) error {
			err := tx.CreateInBatches(batch, 100).Error
			if err == nil {
				r.invalidateFingerprintCache()
				r.invalidateCountCache()
			}
			return err
		})
		return nil
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		return tx.CreateInBatches(items, 100).Error
	})
	if err == nil {
		r.invalidateFingerprintCache()
		r.invalidateCountCache()
	}
	return err
}

func (r *AccessLogRepo) DeleteOlderThan(before time.Time) (int64, error) {
	var totalDeleted int64
	const batchSize = 5000
	r.invalidateFingerprintCache()
	r.invalidateCountCache()

	for {
		tx := r.db.Where("id IN (?)",
			r.db.Model(&store.AccessLog{}).Select("id").Where("created_at < ?", before).Limit(batchSize),
		).Delete(&store.AccessLog{})
		if tx.Error != nil {
			return totalDeleted, tx.Error
		}
		totalDeleted += tx.RowsAffected
		if tx.RowsAffected > 0 {
			r.invalidateFingerprintCache()
			r.invalidateCountCache()
		}
		if tx.RowsAffected < batchSize {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return totalDeleted, nil
}

func (r *AccessLogRepo) Get(id uint) (*store.AccessLog, error) {
	var item store.AccessLog
	if err := r.db.First(&item, id).Error; err != nil {
		return &item, err
	}
	normalizeAccessLogProtocol(&item)
	return &item, nil
}

func (r *AccessLogRepo) FindByRequestID(requestID string) ([]store.AccessLog, error) {
	var items []store.AccessLog
	err := r.db.Where("request_id = ?", requestID).Order("id ASC").Find(&items).Error
	normalizeAccessLogProtocols(items)
	return items, err
}

func normalizeAccessLogProtocols(items []store.AccessLog) {
	for i := range items {
		normalizeAccessLogProtocol(&items[i])
	}
}

func normalizeAccessLogProtocol(item *store.AccessLog) {
	if item == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(item.HTTPProtocol)) {
	case "http/2.0":
		item.HTTPProtocol = "h2"
		return
	case "http/3.0":
		item.HTTPProtocol = "h3"
		return
	case "https", "http":
		if item.TLSALPN != "" {
			item.HTTPProtocol = item.TLSALPN
			return
		}
		if item.HTTPProtocol == "https" {
			item.HTTPProtocol = "http/1.1"
			return
		}
	}
}

func applyAccessLogFilters(q *gorm.DB, f AccessLogFilter) *gorm.DB {
	f = normalizeAccessLogFilter(f)
	if f.ID > 0 {
		q = q.Where("id = ?", f.ID)
	}
	if f.SiteID > 0 {
		q = q.Where("site_id = ?", f.SiteID)
	}
	if f.Query != "" {
		like := "%" + f.Query + "%"
		q = q.Where(
			"(request_id LIKE ? OR client_ip LIKE ? OR host LIKE ? OR path LIKE ? OR query_string LIKE ? OR tls_sni LIKE ? OR tls_ja3_hash LIKE ? OR tls_ja4 LIKE ? OR tls_cipher_suites LIKE ? OR tls_extensions LIKE ? OR tls_curves LIKE ? OR tls_point_formats LIKE ?)",
			like, like, like, like, like, like, like, like, like, like, like, like,
		)
	}
	if f.RequestID != "" {
		q = q.Where("request_id = ?", f.RequestID)
	}
	if f.ClientIP != "" {
		q = q.Where("client_ip = ?", f.ClientIP)
	}
	if f.Host != "" {
		q = q.Where("host LIKE ?", "%"+f.Host+"%")
	}
	if f.Path != "" {
		q = q.Where("path LIKE ?", "%"+f.Path+"%")
	}
	if f.QueryString != "" {
		q = q.Where("query_string LIKE ?", "%"+f.QueryString+"%")
	}
	if f.Method != "" {
		q = q.Where("method = ?", f.Method)
	}
	if f.WAFAction != "" {
		q = q.Where("waf_action = ?", f.WAFAction)
	}
	if f.CacheState != "" {
		q = q.Where("cache_state = ?", f.CacheState)
	}
	switch f.StatusGroup {
	case "2xx":
		q = q.Where("status_code >= ? AND status_code < ?", 200, 300)
	case "3xx":
		q = q.Where("status_code >= ? AND status_code < ?", 300, 400)
	case "4xx":
		q = q.Where("status_code >= ? AND status_code < ?", 400, 500)
	case "5xx":
		q = q.Where("status_code >= ? AND status_code < ?", 500, 600)
	}
	if f.TLSVersion != "" {
		q = q.Where("tls_version = ?", f.TLSVersion)
	}
	if f.TLSSNI != "" {
		q = q.Where("tls_sni LIKE ?", "%"+f.TLSSNI+"%")
	}
	if f.TLSALPN != "" {
		q = q.Where("tls_alpn = ?", f.TLSALPN)
	}
	if f.TLSJA3Hash != "" {
		q = q.Where("tls_ja3_hash = ?", f.TLSJA3Hash)
	}
	if f.TLSJA4 != "" {
		q = q.Where("tls_ja4 = ?", f.TLSJA4)
	}
	if f.TLSCipherSuites != "" {
		q = q.Where("tls_cipher_suites LIKE ?", "%"+f.TLSCipherSuites+"%")
	}
	if f.TLSExtensions != "" {
		q = q.Where("tls_extensions LIKE ?", "%"+f.TLSExtensions+"%")
	}
	if f.TLSCurves != "" {
		q = q.Where("tls_curves LIKE ?", "%"+f.TLSCurves+"%")
	}
	if f.TLSPointFormats != "" {
		q = q.Where("tls_point_formats LIKE ?", "%"+f.TLSPointFormats+"%")
	}
	if f.Since != nil {
		q = q.Where("created_at >= ?", *f.Since)
	}
	if f.Until != nil {
		q = q.Where("created_at <= ?", *f.Until)
	}
	return q
}
