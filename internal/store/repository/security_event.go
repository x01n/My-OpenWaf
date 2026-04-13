package repository

import (
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type SecurityEventRepo struct{ db *gorm.DB }

func NewSecurityEventRepo(db *gorm.DB) *SecurityEventRepo {
	return &SecurityEventRepo{db: db}
}

// SecurityEventFilter holds query filters for listing events.
type SecurityEventFilter struct {
	Action   string
	Phase    string
	Category string
	ClientIP string
	Host     string
	Path     string
	RuleID   uint
	Since    *time.Time
	Until    *time.Time
}

func (r *SecurityEventRepo) List(offset, limit int, f SecurityEventFilter) ([]store.SecurityEvent, int64, error) {
	q := r.db.Model(&store.SecurityEvent{})
	q = applyEventFilters(q, f)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var items []store.SecurityEvent
	if err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *SecurityEventRepo) Get(id uint) (*store.SecurityEvent, error) {
	var item store.SecurityEvent
	return &item, r.db.First(&item, id).Error
}

func (r *SecurityEventRepo) Create(item *store.SecurityEvent) error {
	return r.db.Create(item).Error
}

func (r *SecurityEventRepo) BatchCreate(items []store.SecurityEvent) error {
	if len(items) == 0 {
		return nil
	}
	return r.db.CreateInBatches(items, 100).Error
}

// DeleteOlderThan removes events older than the given time. Returns deleted count.
func (r *SecurityEventRepo) DeleteOlderThan(before time.Time) (int64, error) {
	tx := r.db.Where("created_at < ?", before).Delete(&store.SecurityEvent{})
	return tx.RowsAffected, tx.Error
}

// ─── Aggregation queries for dashboard ────────────────────────────

type CategoryStat struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

func (r *SecurityEventRepo) CategoryStats(since time.Time) ([]CategoryStat, error) {
	var stats []CategoryStat
	err := r.db.Model(&store.SecurityEvent{}).
		Select("category, COUNT(*) as count").
		Where("created_at >= ? AND category != ''", since).
		Group("category").
		Order("count DESC").
		Scan(&stats).Error
	return stats, err
}

type IPStat struct {
	ClientIP string `json:"client_ip"`
	Count    int64  `json:"count"`
}

func (r *SecurityEventRepo) TopIPs(since time.Time, limit int) ([]IPStat, error) {
	var stats []IPStat
	err := r.db.Model(&store.SecurityEvent{}).
		Select("client_ip, COUNT(*) as count").
		Where("created_at >= ?", since).
		Group("client_ip").
		Order("count DESC").
		Limit(limit).
		Scan(&stats).Error
	return stats, err
}

type PathStat struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

func (r *SecurityEventRepo) TopPaths(since time.Time, limit int) ([]PathStat, error) {
	var stats []PathStat
	err := r.db.Model(&store.SecurityEvent{}).
		Select("path, COUNT(*) as count").
		Where("created_at >= ?", since).
		Group("path").
		Order("count DESC").
		Limit(limit).
		Scan(&stats).Error
	return stats, err
}

type RuleStat struct {
	RuleIDStr string `json:"rule_id_str"`
	Count     int64  `json:"count"`
}

func (r *SecurityEventRepo) TopRules(since time.Time, limit int) ([]RuleStat, error) {
	var stats []RuleStat
	err := r.db.Model(&store.SecurityEvent{}).
		Select("rule_id_str, COUNT(*) as count").
		Where("created_at >= ? AND rule_id_str != ''", since).
		Group("rule_id_str").
		Order("count DESC").
		Limit(limit).
		Scan(&stats).Error
	return stats, err
}

type TimelineBucket struct {
	Bucket string `json:"bucket"`
	Count  int64  `json:"count"`
}

// Timeline returns event counts grouped by hour for the given time range.
func (r *SecurityEventRepo) Timeline(since, until time.Time) ([]TimelineBucket, error) {
	var buckets []TimelineBucket
	// Use strftime for SQLite compatibility; works with MySQL DATE_FORMAT too.
	err := r.db.Model(&store.SecurityEvent{}).
		Select("strftime('%Y-%m-%d %H:00', created_at) as bucket, COUNT(*) as count").
		Where("created_at >= ? AND created_at <= ?", since, until).
		Group("bucket").
		Order("bucket ASC").
		Scan(&buckets).Error
	return buckets, err
}

func (r *SecurityEventRepo) Count(f SecurityEventFilter) (int64, error) {
	q := r.db.Model(&store.SecurityEvent{})
	q = applyEventFilters(q, f)
	var total int64
	return total, q.Count(&total).Error
}

func applyEventFilters(q *gorm.DB, f SecurityEventFilter) *gorm.DB {
	if f.Action != "" {
		q = q.Where("action = ?", f.Action)
	}
	if f.Phase != "" {
		q = q.Where("phase = ?", f.Phase)
	}
	if f.Category != "" {
		q = q.Where("category = ?", f.Category)
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
	if f.RuleID > 0 {
		q = q.Where("rule_id = ?", f.RuleID)
	}
	if f.Since != nil {
		q = q.Where("created_at >= ?", *f.Since)
	}
	if f.Until != nil {
		q = q.Where("created_at <= ?", *f.Until)
	}
	return q
}
