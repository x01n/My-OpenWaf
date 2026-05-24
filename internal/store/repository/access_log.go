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
	SiteID      uint
	ClientIP    string
	Host        string
	Path        string
	Method      string
	WAFAction   string
	CacheState  string
	StatusGroup string
	Since       *time.Time
	Until       *time.Time
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
	if r.countCache != nil {
		if cached, ok := r.countCache.Get(cacheKey); ok {
			total = cached.(int64)
		}
	}
	if total == 0 {
		if err := q.Count(&total).Error; err != nil {
			return nil, 0, err
		}
		if r.countCache != nil && total > 0 {
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

func accessLogCountCacheKey(f AccessLogFilter) string {
	key := "al_count"
	if f.SiteID > 0 {
		key += ":s" + fmt.Sprint(f.SiteID)
	}
	if f.ClientIP != "" {
		key += ":ip" + f.ClientIP
	}
	if f.WAFAction != "" {
		key += ":wa" + f.WAFAction
	}
	if f.StatusGroup != "" {
		key += ":sg" + f.StatusGroup
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

func (r *AccessLogRepo) FindByRequestID(requestID string) ([]store.AccessLog, error) {
	var items []store.AccessLog
	err := r.db.Where("request_id = ?", requestID).Order("id ASC").Find(&items).Error
	return items, err
}

func applyAccessLogFilters(q *gorm.DB, f AccessLogFilter) *gorm.DB {
	if f.SiteID > 0 {
		q = q.Where("site_id = ?", f.SiteID)
	}
	if f.ClientIP != "" {
		q = q.Where("client_ip = ?", f.ClientIP)
	}
	if f.Host != "" {
		q = q.Where("host = ?", f.Host)
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
	if f.Since != nil {
		q = q.Where("created_at >= ?", *f.Since)
	}
	if f.Until != nil {
		q = q.Where("created_at <= ?", *f.Until)
	}
	return q
}
