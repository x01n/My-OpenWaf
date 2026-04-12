package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type PolicyRepo struct{ db *gorm.DB }

func NewPolicyRepo(db *gorm.DB) *PolicyRepo { return &PolicyRepo{db: db} }

func (r *PolicyRepo) List(offset, limit int) ([]store.Policy, int64, error) {
	var items []store.Policy
	var total int64
	if err := r.db.Model(&store.Policy{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := r.db.Offset(offset).Limit(limit).Order("id ASC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *PolicyRepo) Get(id uint) (*store.Policy, error) {
	var item store.Policy
	return &item, r.db.First(&item, id).Error
}

func (r *PolicyRepo) Create(item *store.Policy) error { return r.db.Create(item).Error }

func (r *PolicyRepo) Update(item *store.Policy) error { return r.db.Save(item).Error }

func (r *PolicyRepo) Delete(id uint) error { return r.db.Delete(&store.Policy{}, id).Error }
