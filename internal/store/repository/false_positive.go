package repository

import (
	"gorm.io/gorm"

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
func (r *FalsePositiveRepo) UpdateStatus(id uint, status string) error {
	return r.db.Model(&store.FalsePositiveReport{}).Where("id = ?", id).Update("status", status).Error
}

// Delete 删除反馈记录。
func (r *FalsePositiveRepo) Delete(id uint) error {
	return r.db.Delete(&store.FalsePositiveReport{}, id).Error
}
