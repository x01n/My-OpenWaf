package repository

import (
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type DropEventRepo struct{ db *gorm.DB }

func NewDropEventRepo(db *gorm.DB) *DropEventRepo {
	return &DropEventRepo{db: db}
}

// DropEventFilter holds query filters for listing drop events.
type DropEventFilter struct {
	ClientIP  string
	Source    string
	StartTime *time.Time
	EndTime   *time.Time
}

func (r *DropEventRepo) Create(item *store.DropEvent) error {
	return r.db.Create(item).Error
}

func (r *DropEventRepo) List(offset, limit int, f DropEventFilter) ([]store.DropEvent, int64, error) {
	q := r.db.Model(&store.DropEvent{})
	if f.ClientIP != "" {
		q = q.Where("client_ip = ?", f.ClientIP)
	}
	if f.Source != "" {
		q = q.Where("source = ?", f.Source)
	}
	if f.StartTime != nil {
		q = q.Where("created_at >= ?", *f.StartTime)
	}
	if f.EndTime != nil {
		q = q.Where("created_at <= ?", *f.EndTime)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var items []store.DropEvent
	if err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// DropStatsSummary holds aggregated drop statistics.
type DropStatsSummary struct {
	Total24h       int64 `json:"total_24h"`
	ByBot          int64 `json:"by_bot"`
	ByCVE          int64 `json:"by_cve"`
	ByRule         int64 `json:"by_rule"`
	ByIPReputation int64 `json:"by_ip_reputation"`
}

// DeleteOlderThan removes drop events older than the given time. Returns deleted count.
func (r *DropEventRepo) DeleteOlderThan(before time.Time) (int64, error) {
	tx := r.db.Where("created_at < ?", before).Delete(&store.DropEvent{})
	return tx.RowsAffected, tx.Error
}

func (r *DropEventRepo) Stats24h() (*DropStatsSummary, error) {
	since := time.Now().Add(-24 * time.Hour)
	var stats DropStatsSummary

	r.db.Model(&store.DropEvent{}).Where("created_at >= ?", since).Count(&stats.Total24h)
	r.db.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'bot'", since).Count(&stats.ByBot)
	r.db.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'cve'", since).Count(&stats.ByCVE)
	r.db.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'rule'", since).Count(&stats.ByRule)
	r.db.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'ip_reputation'", since).Count(&stats.ByIPReputation)

	return &stats, nil
}
