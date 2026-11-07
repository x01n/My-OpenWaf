package threat

import (
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store/threatintel"
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
func (r *ThreatIntelSyncLogRepo) Create(rec *threatintel.ThreatIntelSyncLog) error {
	return r.db.Create(rec).Error
}

// List 分页列出同步日志（按 created_at DESC）。
// feedID > 0 时只返回该 feed 的日志；successOnly 为 "success" 或 "failed" 可过滤成功/失败。
func (r *ThreatIntelSyncLogRepo) List(offset, limit int, feedID uint, status string) ([]threatintel.ThreatIntelSyncLog, int64, error) {
	q := r.db.Model(&threatintel.ThreatIntelSyncLog{})
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
	var items []threatintel.ThreatIntelSyncLog
	if err := q.Order("created_at DESC").Offset(offset).Limit(limit).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// DeleteOlderThan 删除指定时间之前的同步日志，返回删除的条数。
func (r *ThreatIntelSyncLogRepo) DeleteOlderThan(before time.Time) (int64, error) {
	var totalDeleted int64
	const batchSize = 5000

	for {
		// derived table 包一层以兼容 MySQL 8.0：`IN (SELECT ... LIMIT n)` 会被
		// MySQL 拒绝（ERROR 1235），同表子查询另有 ERROR 1093；别名不可省
		// （ERROR 1248）。含 LIMIT 的派生表不会被合并回外层，三方言行为一致。
		// 详见 SecurityEventRepo.DeleteOlderThan 的说明。
		tx := r.db.Where("id IN (SELECT id FROM (?) AS archive_batch)",
			r.db.Model(&threatintel.ThreatIntelSyncLog{}).Select("id").Where("created_at < ?", before).Limit(batchSize),
		).Delete(&threatintel.ThreatIntelSyncLog{})
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
