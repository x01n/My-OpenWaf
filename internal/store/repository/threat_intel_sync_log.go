package repository

import (
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

/**
 * ThreatIntelSyncLogRepo 威胁情报同步日志仓库。
 */
type ThreatIntelSyncLogRepo struct {
	db *gorm.DB
}

// NewThreatIntelSyncLogRepo 创建仓库实例。
func NewThreatIntelSyncLogRepo(db *gorm.DB) *ThreatIntelSyncLogRepo {
	return &ThreatIntelSyncLogRepo{db: db}
}

// Create 追加一条同步日志。
func (r *ThreatIntelSyncLogRepo) Create(rec *store.ThreatIntelSyncLog) error {
	return r.db.Create(rec).Error
}

// List 分页列出同步日志（按 created_at DESC）。
// feedID > 0 时只返回该 feed 的日志；successOnly 为 "success" 或 "failed" 可过滤成功/失败。
func (r *ThreatIntelSyncLogRepo) List(offset, limit int, feedID uint, status string) ([]store.ThreatIntelSyncLog, int64, error) {
	q := r.db.Model(&store.ThreatIntelSyncLog{})
	if feedID > 0 {
		q = q.Where("feed_id = ?", feedID)
	}
	switch status {
	case "success":
		q = q.Where("success = ?", true)
	case "failed":
		q = q.Where("success = ?", false)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var items []store.ThreatIntelSyncLog
	if err := q.Order("created_at DESC").Offset(offset).Limit(limit).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// DeleteOlderThan 删除超过指定时间的日志（用于保留策略）。
// 返回删除的行数。
func (r *ThreatIntelSyncLogRepo) DeleteOlderThan(before time.Time) (int64, error) {
	tx := r.db.Where("created_at < ?", before).Delete(&store.ThreatIntelSyncLog{})
	return tx.RowsAffected, tx.Error
}
