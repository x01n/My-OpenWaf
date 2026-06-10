package repository

import (
	"encoding/json"
	"fmt"
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
	ID          uint
	SiteID      uint
	RequestID   string
	ClientIP    string
	Host        string
	Path        string
	Method      string
	WAFAction   string
	CacheState  string
	StatusGroup string
	TLSVersion  string
	TLSSNI      string
	TLSALPN     string
	TLSJA3Hash  string
	TLSJA4      string
	Since       *time.Time
	Until       *time.Time
}

type SiteAccessLogStats struct {
	Requests   int64 `json:"requests"`
	Intercepts int64 `json:"intercepts"`
	Observes   int64 `json:"observes"`
}

type FingerprintSummary struct {
	TLSJA3Hash      string    `json:"tls_ja3_hash"`
	TLSJA4          string    `json:"tls_ja4"`
	TLSVersion      string    `json:"tls_version"`
	TLSALPN         string    `json:"tls_alpn"`
	TLSSNI          string    `json:"tls_sni"`
	Count           int64     `json:"count"`
	HighRiskCount   int64     `json:"high_risk_count"`
	AvgBotScore     float64   `json:"avg_bot_score"`
	LastSeen        time.Time `json:"last_seen"`
	LastUserAgent   string    `json:"last_user_agent"`
	LastClientIP    string    `json:"last_client_ip"`
	LastHeaderOrder string    `json:"last_header_order"`
}

func (r *AccessLogRepo) List(offset, limit int, f AccessLogFilter) ([]store.AccessLog, int64, error) {
	// Try Redis hot cache for large query results.
	if r.hotCache != nil && r.hotCache.Available() {
		cacheKey := "al_list:" + accessLogCountCacheKey(f) + fmt.Sprintf(":o%d:l%d", offset, limit)
		if rawItems, cachedTotal, ok := r.hotCache.GetListRaw(cacheKey); ok {
			var items []store.AccessLog
			if json.Unmarshal(rawItems, &items) == nil {
				return items, cachedTotal, nil
			}
		}
	}

	q := r.db.Model(&store.AccessLog{})
	q = applyAccessLogFilters(q, f)

	var total int64
	cacheKey := accessLogCountCacheKey(f)
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

	// Cache large results in Redis for subsequent requests.
	if r.hotCache != nil && r.hotCache.Available() && len(items) > 0 {
		hcKey := "al_list:" + cacheKey + fmt.Sprintf(":o%d:l%d", offset, limit)
		r.hotCache.SetList(hcKey, items, total, 5*time.Second)
	}

	return items, total, nil
}

func (r *AccessLogRepo) StatsBySite(siteID uint, since time.Time) (SiteAccessLogStats, error) {
	var stats SiteAccessLogStats
	terminalActions := []string{"intercept", "block", "drop", "challenge", "captcha_challenge", "shield_challenge", "chain_challenge", "rate_limit"}
	err := r.db.Model(&store.AccessLog{}).
		Select("COUNT(*) AS requests, SUM(CASE WHEN waf_action IN ? THEN 1 ELSE 0 END) AS intercepts, SUM(CASE WHEN waf_action = ? THEN 1 ELSE 0 END) AS observes", terminalActions, "observe").
		Where("site_id = ? AND created_at >= ?", siteID, since).
		Scan(&stats).Error
	return stats, err
}

func (r *AccessLogRepo) ListFingerprints(offset, limit int) ([]FingerprintSummary, int64, error) {
	base := r.db.Model(&store.AccessLog{}).Where("tls_ja3_hash <> ? OR tls_ja4 <> ?", "", "")
	var total int64
	countQ := r.db.Table("(?) as fp", base.Select("tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni").Group("tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni"))
	if err := countQ.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	type fingerprintRow struct {
		TLSJA3Hash string `json:"tls_ja3_hash"`
		TLSJA4     string `json:"tls_ja4"`
		TLSVersion string `json:"tls_version"`
		TLSALPN    string `json:"tls_alpn"`
		TLSSNI     string `json:"tls_sni"`
		Count      int64  `json:"count"`
	}
	var rows []fingerprintRow
	err := base.Select("tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni, COUNT(*) as count").
		Group("tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni").
		Order("MAX(created_at) DESC").
		Offset(offset).Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return nil, 0, err
	}

	items := make([]FingerprintSummary, 0, len(rows))
	for _, row := range rows {
		var last store.AccessLog
		if err := r.db.Model(&store.AccessLog{}).
			Where("tls_ja3_hash = ? AND tls_ja4 = ? AND tls_version = ? AND tls_alpn = ? AND tls_sni = ?", row.TLSJA3Hash, row.TLSJA4, row.TLSVersion, row.TLSALPN, row.TLSSNI).
			Order("created_at DESC").
			Limit(1).
			Take(&last).Error; err != nil {
			return nil, 0, err
		}
		var highRiskCount int64
		var avgBotScore float64
		if r.db.Migrator().HasTable(&store.BotScoreLog{}) {
			botQuery := r.db.Model(&store.BotScoreLog{}).
				Where("tls_ja3_hash = ? AND tls_ja4 = ? AND tls_version = ? AND tls_alpn = ? AND tls_sni = ?", row.TLSJA3Hash, row.TLSJA4, row.TLSVersion, row.TLSALPN, row.TLSSNI)
			botQuery.Where("is_high_risk = ?", true).Count(&highRiskCount)
			botQuery.Select("COALESCE(AVG(total_score), 0)").Scan(&avgBotScore)
		}
		items = append(items, FingerprintSummary{
			TLSJA3Hash:      row.TLSJA3Hash,
			TLSJA4:          row.TLSJA4,
			TLSVersion:      row.TLSVersion,
			TLSALPN:         row.TLSALPN,
			TLSSNI:          row.TLSSNI,
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

func accessLogCountCacheKey(f AccessLogFilter) string {
	key := "al_count"
	if f.ID > 0 {
		key += ":id" + fmt.Sprint(f.ID)
	}
	if f.SiteID > 0 {
		key += ":s" + fmt.Sprint(f.SiteID)
	}
	if f.RequestID != "" {
		key += ":rid" + f.RequestID
	}
	if f.ClientIP != "" {
		key += ":ip" + f.ClientIP
	}
	if f.Host != "" {
		key += ":h" + f.Host
	}
	if f.Path != "" {
		key += ":p" + f.Path
	}
	if f.Method != "" {
		key += ":m" + f.Method
	}
	if f.WAFAction != "" {
		key += ":wa" + f.WAFAction
	}
	if f.CacheState != "" {
		key += ":cs" + f.CacheState
	}
	if f.StatusGroup != "" {
		key += ":sg" + f.StatusGroup
	}
	if f.TLSVersion != "" {
		key += ":tv" + f.TLSVersion
	}
	if f.TLSSNI != "" {
		key += ":sni" + f.TLSSNI
	}
	if f.TLSALPN != "" {
		key += ":alpn" + f.TLSALPN
	}
	if f.TLSJA3Hash != "" {
		key += ":j3h" + f.TLSJA3Hash
	}
	if f.TLSJA4 != "" {
		key += ":j4" + f.TLSJA4
	}
	if f.Since != nil {
		key += ":si" + f.Since.Format("0601021504")
	}
	if f.Until != nil {
		key += ":un" + f.Until.Format("0601021504")
	}
	return key
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
	return &item, r.db.First(&item, id).Error
}

func (r *AccessLogRepo) FindByRequestID(requestID string) ([]store.AccessLog, error) {
	var items []store.AccessLog
	err := r.db.Where("request_id = ?", requestID).Order("id ASC").Find(&items).Error
	return items, err
}

func applyAccessLogFilters(q *gorm.DB, f AccessLogFilter) *gorm.DB {
	if f.ID > 0 {
		q = q.Where("id = ?", f.ID)
	}
	if f.SiteID > 0 {
		q = q.Where("site_id = ?", f.SiteID)
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
	if f.Since != nil {
		q = q.Where("created_at >= ?", *f.Since)
	}
	if f.Until != nil {
		q = q.Where("created_at <= ?", *f.Until)
	}
	return q
}
