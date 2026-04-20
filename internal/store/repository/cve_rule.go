package repository

import (
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf"

	"gorm.io/gorm"
)

type CVERuleRepo struct{ db *gorm.DB }

func NewCVERuleRepo(db *gorm.DB) *CVERuleRepo {
	return &CVERuleRepo{db: db}
}

// CVERuleFilter holds query filters for listing CVE rules.
type CVERuleFilter struct {
	Category string
	Severity string
	Enabled  *bool
	Source   string
}

func (r *CVERuleRepo) List(offset, limit int, f CVERuleFilter) ([]waf.CVERuleModel, int64, error) {
	q := r.db.Model(&waf.CVERuleModel{})
	if f.Category != "" {
		q = q.Where("category = ?", f.Category)
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.Enabled != nil {
		q = q.Where("enabled = ?", *f.Enabled)
	}
	if f.Source != "" {
		q = q.Where("source = ?", f.Source)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var items []waf.CVERuleModel
	if err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *CVERuleRepo) Get(id uint) (*waf.CVERuleModel, error) {
	var item waf.CVERuleModel
	return &item, r.db.First(&item, id).Error
}

func (r *CVERuleRepo) Create(item *waf.CVERuleModel) error {
	return r.db.Create(item).Error
}

func (r *CVERuleRepo) Update(item *waf.CVERuleModel) error {
	return r.db.Save(item).Error
}

func (r *CVERuleRepo) Delete(id uint) error {
	return r.db.Delete(&waf.CVERuleModel{}, id).Error
}

func (r *CVERuleRepo) Toggle(id uint, enabled bool) error {
	return r.db.Model(&waf.CVERuleModel{}).Where("id = ?", id).Update("enabled", enabled).Error
}

// PendingApprovalCount returns the number of rules that are not yet approved.
func (r *CVERuleRepo) PendingApprovalCount() (int64, error) {
	var count int64
	err := r.db.Model(&waf.CVERuleModel{}).Where("approved = ?", false).Count(&count).Error
	return count, err
}

// ─── CVE Sync Log ───────────────────────────────────────────────────

type CVESyncLogRepo struct{ db *gorm.DB }

func NewCVESyncLogRepo(db *gorm.DB) *CVESyncLogRepo {
	return &CVESyncLogRepo{db: db}
}

func (r *CVESyncLogRepo) Create(item *store.CVESyncLog) error {
	return r.db.Create(item).Error
}

func (r *CVESyncLogRepo) Latest(limit int) ([]store.CVESyncLog, error) {
	var items []store.CVESyncLog
	err := r.db.Order("id DESC").Limit(limit).Find(&items).Error
	return items, err
}
