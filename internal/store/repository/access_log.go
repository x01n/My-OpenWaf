package repository

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type AccessLogRepo struct {
	db         *gorm.DB
	countCache CountCache
	hotCache   HotCacheBackend
	writeQueue WriteQueueBackend
}

// CountCache is an optional cache for expensive COUNT queries.
type CountCache interface {
	Get(key string) (any, bool)
	Set(key string, value any)
}

func NewAccessLogRepo(db *gorm.DB) *AccessLogRepo {
	return &AccessLogRepo{db: db}
}

// SetCountCache configures an optional count cache for list queries.
func (r *AccessLogRepo) SetCountCache(c CountCache) {
	r.countCache = c
}

// SetHotCache configures Redis-backed hot cache for large query results.
func (r *AccessLogRepo) SetHotCache(hc HotCacheBackend) {
	r.hotCache = hc
}

// SetWriteQueue configures async write queue for batch writes.
func (r *AccessLogRepo) SetWriteQueue(wq WriteQueueBackend) {
	r.writeQueue = wq
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

func (r *AccessLogRepo) List(offset, limit int, f AccessLogFilter) ([]store.AccessLog, int64, error) {
	f = normalizeAccessLogFilter(f)
	cacheKey := accessLogCountCacheKey(f)

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

	q := r.db.Model(&store.AccessLog{})
	q = applyAccessLogFilters(q, f)

	var total int64
	cached := false
	if r.countCache != nil {
		if value, ok := r.countCache.Get(cacheKey); ok {
			total = value.(int64)
			cached = true
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

	var items []store.AccessLog
	if err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	normalizeAccessLogProtocols(items)

	// Cache large results in Redis for subsequent requests.
	if r.hotCache != nil && r.hotCache.Available() && len(items) > 0 {
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
	base := r.db.Model(&store.AccessLog{}).Where("tls_ja3_hash <> ? OR tls_ja4 <> ?", "", "")
	base = applyFingerprintFilters(base, f)
	var total int64
	countQ := r.db.Table(
		"(?) as fp",
		base.Select("tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni, tls_cipher_suites, tls_extensions, tls_curves, tls_point_formats").
			Group("tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni, tls_cipher_suites, tls_extensions, tls_curves, tls_point_formats"),
	)
	if err := countQ.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	type fingerprintRow struct {
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
	var rows []fingerprintRow
	err := base.Select("tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni, tls_cipher_suites, tls_extensions, tls_curves, tls_point_formats, COUNT(*) as count").
		Group("tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni, tls_cipher_suites, tls_extensions, tls_curves, tls_point_formats").
		Order("MAX(created_at) DESC").
		Offset(offset).Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return nil, 0, err
	}

	hasBotScoreTable := r.db.Migrator().HasTable(&store.BotScoreLog{})

	items := make([]FingerprintSummary, 0, len(rows))
	for _, row := range rows {
		var last store.AccessLog
		if err := r.db.Model(&store.AccessLog{}).
			Where(
				"tls_ja3_hash = ? AND tls_ja4 = ? AND tls_version = ? AND tls_alpn = ? AND tls_sni = ? AND tls_cipher_suites = ? AND tls_extensions = ? AND tls_curves = ? AND tls_point_formats = ?",
				row.TLSJA3Hash,
				row.TLSJA4,
				row.TLSVersion,
				row.TLSALPN,
				row.TLSSNI,
				row.TLSCipherSuites,
				row.TLSExtensions,
				row.TLSCurves,
				row.TLSPointFormats,
			).
			Order("created_at DESC").
			Limit(1).
			Take(&last).Error; err != nil {
			return nil, 0, err
		}
		var highRiskCount int64
		var avgBotScore float64
		if hasBotScoreTable {
			requestIDs := func() *gorm.DB {
				return r.db.Model(&store.AccessLog{}).
					Distinct().
					Select("request_id").
					Where(
						"tls_ja3_hash = ? AND tls_ja4 = ? AND tls_version = ? AND tls_alpn = ? AND tls_sni = ? AND tls_cipher_suites = ? AND tls_extensions = ? AND tls_curves = ? AND tls_point_formats = ?",
						row.TLSJA3Hash,
						row.TLSJA4,
						row.TLSVersion,
						row.TLSALPN,
						row.TLSSNI,
						row.TLSCipherSuites,
						row.TLSExtensions,
						row.TLSCurves,
						row.TLSPointFormats,
					).
					Where("request_id <> ?", "")
			}
			if err := r.db.Model(&store.BotScoreLog{}).
				Where("request_id IN (?)", requestIDs()).
				Where("is_high_risk = ?", true).
				Count(&highRiskCount).Error; err != nil {
				return nil, 0, err
			}
			if err := r.db.Model(&store.BotScoreLog{}).
				Where("request_id IN (?)", requestIDs()).
				Select("COALESCE(AVG(total_score), 0)").
				Scan(&avgBotScore).Error; err != nil {
				return nil, 0, err
			}
		}
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
			HighRiskCount:   highRiskCount,
			AvgBotScore:     avgBotScore,
			LastSeen:        last.CreatedAt,
			LastUserAgent:   last.UserAgent,
			LastClientIP:    last.ClientIP,
			LastHeaderOrder: last.HeaderOrder,
		})
	}
	return items, total, nil
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
	b.WriteString("al_count:v2")
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

func (r *AccessLogRepo) Create(item *store.AccessLog) error {
	if r.writeQueue != nil {
		r.writeQueue.Submit(func(tx *gorm.DB) error {
			return tx.Create(item).Error
		})
		return nil
	}
	return r.db.Create(item).Error
}

func (r *AccessLogRepo) BatchCreate(items []store.AccessLog) error {
	if len(items) == 0 {
		return nil
	}
	if r.writeQueue != nil {
		batch := make([]store.AccessLog, len(items))
		copy(batch, items)
		r.writeQueue.Submit(func(tx *gorm.DB) error {
			return tx.CreateInBatches(batch, 100).Error
		})
		return nil
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		return tx.CreateInBatches(items, 100).Error
	})
}

func (r *AccessLogRepo) DeleteOlderThan(before time.Time) (int64, error) {
	var totalDeleted int64
	const batchSize = 5000

	for {
		tx := r.db.Where("id IN (?)",
			r.db.Model(&store.AccessLog{}).Select("id").Where("created_at < ?", before).Limit(batchSize),
		).Delete(&store.AccessLog{})
		if tx.Error != nil {
			return totalDeleted, tx.Error
		}
		totalDeleted += tx.RowsAffected
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
