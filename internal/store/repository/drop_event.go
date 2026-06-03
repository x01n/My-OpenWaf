package repository

import (
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type DropEventRepo struct {
	db         *gorm.DB
	writeQueue WriteQueueBackend
}

func NewDropEventRepo(db *gorm.DB) *DropEventRepo {
	return &DropEventRepo{db: db}
}

// SetWriteQueue configures async write queue for batch writes.
func (r *DropEventRepo) SetWriteQueue(wq WriteQueueBackend) {
	r.writeQueue = wq
}

// DropEventFilter holds query filters for listing drop events.
type DropEventFilter struct {
	SiteID    uint
	ClientIP  string
	Source    string
	StartTime *time.Time
	EndTime   *time.Time
}

func (r *DropEventRepo) Create(item *store.DropEvent) error {
	if r.writeQueue != nil {
		r.writeQueue.Submit(func(tx *gorm.DB) error {
			return tx.Create(item).Error
		})
		return nil
	}
	return r.db.Create(item).Error
}

// BatchCreate inserts multiple drop events in a single transaction.
func (r *DropEventRepo) BatchCreate(items []store.DropEvent) error {
	if len(items) == 0 {
		return nil
	}
	if r.writeQueue != nil {
		batch := make([]store.DropEvent, len(items))
		copy(batch, items)
		r.writeQueue.Submit(func(tx *gorm.DB) error {
			return tx.CreateInBatches(batch, 100).Error
		})
		return nil
	}
	return r.db.CreateInBatches(items, 100).Error
}

func (r *DropEventRepo) List(offset, limit int, f DropEventFilter) ([]store.DropEvent, int64, error) {
	q := r.db.Model(&store.DropEvent{})
	if f.SiteID > 0 {
		q = q.Where("site_id = ?", f.SiteID)
	}
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
	Total24h       int64 `gorm:"column:total_24h" json:"total_24h"`
	ByBot          int64 `gorm:"column:by_bot" json:"by_bot"`
	ByCVE          int64 `gorm:"column:by_cve" json:"by_cve"`
	ByRule         int64 `gorm:"column:by_rule" json:"by_rule"`
	ByIPReputation int64 `gorm:"column:by_ip_reputation" json:"by_ip_reputation"`
}

// DeleteOlderThan removes drop events older than the given time. Returns deleted count.
// Uses batched deletion to reduce lock contention on large tables.
func (r *DropEventRepo) DeleteOlderThan(before time.Time) (int64, error) {
	var totalDeleted int64
	const batchSize = 5000

	for {
		tx := r.db.Where("id IN (?)",
			r.db.Model(&store.DropEvent{}).Select("id").Where("created_at < ?", before).Limit(batchSize),
		).Delete(&store.DropEvent{})
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

func (r *DropEventRepo) Stats24h() (*DropStatsSummary, error) {
	return r.Stats24hBySite(0)
}

func (r *DropEventRepo) Stats24hBySite(siteID uint) (*DropStatsSummary, error) {
	since := time.Now().Add(-24 * time.Hour)
	var stats DropStatsSummary
	q := r.db.Model(&store.DropEvent{}).
		Select("COUNT(*) AS total24h, SUM(CASE WHEN source = ? THEN 1 ELSE 0 END) AS by_bot, SUM(CASE WHEN source = ? THEN 1 ELSE 0 END) AS by_cve, SUM(CASE WHEN source = ? THEN 1 ELSE 0 END) AS by_rule, SUM(CASE WHEN source = ? THEN 1 ELSE 0 END) AS by_ip_reputation", "bot", "cve", "rule", "ip_reputation").
		Where("created_at >= ?", since)
	if siteID > 0 {
		q = q.Where("site_id = ?", siteID)
	}
	if err := q.Scan(&stats).Error; err != nil {
		return nil, err
	}

	return &stats, nil
}
