package repository

import (
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"My-OpenWaf/internal/store"
)

/**
 * FalsePositiveRepo 误报反馈仓库。
 */
type FalsePositiveRepo struct {
	db *gorm.DB
}

// NewFalsePositiveRepo 创建仓库实例。
func NewFalsePositiveRepo(db *gorm.DB) *FalsePositiveRepo {
	return &FalsePositiveRepo{db: db}
}

// Create 创建反馈记录。
func (r *FalsePositiveRepo) Create(rec *store.FalsePositiveReport) error {
	return r.db.Create(rec).Error
}

// CreateOrGetBySourceEvent creates one feedback record for a source security event.
// A repeated submission returns the existing record instead of duplicating the feedback.
func (r *FalsePositiveRepo) CreateOrGetBySourceEvent(rec *store.FalsePositiveReport) (*store.FalsePositiveReport, bool, error) {
	if rec == nil || rec.SourceEventKey == nil || *rec.SourceEventKey == "" {
		return nil, false, errors.New("source event key required")
	}

	result := r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "source_event_key"}},
		DoNothing: true,
	}).Create(rec)
	if result.Error != nil {
		return nil, false, result.Error
	}

	var saved store.FalsePositiveReport
	if err := r.db.Where("source_event_key = ?", *rec.SourceEventKey).First(&saved).Error; err != nil {
		return nil, false, err
	}
	return &saved, result.RowsAffected > 0, nil
}

// List 分页列出反馈；status 为空则不过滤。
func (r *FalsePositiveRepo) List(offset, limit int, status string) ([]store.FalsePositiveReport, int64, error) {
	q := r.db.Model(&store.FalsePositiveReport{})
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var items []store.FalsePositiveReport
	if err := q.Order("created_at DESC").Offset(offset).Limit(limit).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// Get 按主键读取一条记录。
func (r *FalsePositiveRepo) Get(id uint) (*store.FalsePositiveReport, error) {
	var rec store.FalsePositiveReport
	if err := r.db.First(&rec, id).Error; err != nil {
		return nil, err
	}
	return &rec, nil
}

// UpdateStatus 更新审查状态（pending/confirmed/rejected）。
// 记录不存在时返回 gorm.ErrRecordNotFound，供上层区分"无此记录"与其他错误。
func (r *FalsePositiveRepo) UpdateStatus(id uint, status string) error {
	result := r.db.Model(&store.FalsePositiveReport{}).Where("id = ?", id).Update("status", status)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		return nil
	}
	// 新状态与原状态相同时，部分驱动（如未开启 CLIENT_FOUND_ROWS 的 MySQL）会返回
	// 0 行受影响，故不能仅凭受影响行数判定记录不存在，需再做一次存在性确认。
	var count int64
	if err := r.db.Model(&store.FalsePositiveReport{}).Where("id = ?", id).Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// Delete deletes a feedback record and clears its idempotency key first.
// The cleared key permits a newly submitted feedback record for the same source event.
// 记录不存在时返回 gorm.ErrRecordNotFound，此时整个事务回滚，置空操作不留痕迹。
func (r *FalsePositiveRepo) Delete(id uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&store.FalsePositiveReport{}).Where("id = ?", id).Update("source_event_key", nil).Error; err != nil {
			return err
		}
		// 以软删除的受影响行数判定记录是否存在：软删除写入 deleted_at 必然改变列值，
		// 各驱动都会如实返回 1；而置空 source_event_key 在其本就为 NULL 时可能返回 0。
		result := tx.Delete(&store.FalsePositiveReport{}, id)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}
