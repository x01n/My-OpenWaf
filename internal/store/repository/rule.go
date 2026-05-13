package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type RuleRepo struct{ db *gorm.DB }

func NewRuleRepo(db *gorm.DB) *RuleRepo { return &RuleRepo{db: db} }

func (r *RuleRepo) BatchCreate(items []store.Rule) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for i := range items {
			if err := tx.Create(&items[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *RuleRepo) List(offset, limit int) ([]store.Rule, int64, error) {
	var items []store.Rule
	var total int64
	if err := r.db.Model(&store.Rule{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := r.db.Offset(offset).Limit(limit).Order("priority ASC, id ASC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *RuleRepo) ListByPolicy(policyID uint) ([]store.Rule, error) {
	var items []store.Rule
	return items, r.db.Where("policy_id = ?", policyID).Order("priority ASC, id ASC").Find(&items).Error
}

func (r *RuleRepo) Get(id uint) (*store.Rule, error) {
	var item store.Rule
	return &item, r.db.First(&item, id).Error
}

func (r *RuleRepo) Create(item *store.Rule) error { return r.db.Create(item).Error }

func (r *RuleRepo) Update(item *store.Rule) error { return r.db.Save(item).Error }

func (r *RuleRepo) Delete(id uint) error { return r.db.Delete(&store.Rule{}, id).Error }
