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

func (r *PolicyRepo) GetDefault() (*store.Policy, error) {
	var item store.Policy
	return &item, r.db.Where("default_slot = ?", 1).First(&item).Error
}

func (r *PolicyRepo) Exists(id uint) (bool, error) {
	if id == 0 {
		return false, nil
	}
	var count int64
	err := r.db.Model(&store.Policy{}).Where("id = ?", id).Count(&count).Error
	return count == 1, err
}

func (r *PolicyRepo) SetDefault(id uint) (*store.Policy, error) {
	var item store.Policy
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&item, id).Error; err != nil {
			return err
		}
		if item.DefaultSlot != nil && *item.DefaultSlot == 1 {
			item.IsDefault = true
			return nil
		}
		if err := tx.Unscoped().Model(&store.Policy{}).
			Where("default_slot = ?", 1).
			Update("default_slot", nil).Error; err != nil {
			return err
		}
		one := uint(1)
		if err := tx.Model(&store.Policy{}).Where("id = ?", id).Update("default_slot", &one).Error; err != nil {
			return err
		}
		item.DefaultSlot = &one
		item.IsDefault = true
		return nil
	})
	return &item, err
}

func (r *PolicyRepo) ReferenceCounts(id uint) (siteRefs, ruleRefs int64, err error) {
	if err = r.db.Model(&store.Site{}).Where("policy_id = ?", id).Count(&siteRefs).Error; err != nil {
		return
	}
	if !r.db.Migrator().HasTable(&store.Rule{}) {
		return siteRefs, 0, nil
	}
	err = r.db.Model(&store.Rule{}).Where("policy_id = ?", id).Count(&ruleRefs).Error
	return
}

func (r *PolicyRepo) IsDefault(id uint) (bool, error) {
	item, err := r.Get(id)
	if err != nil {
		return false, err
	}
	return item.DefaultSlot != nil && *item.DefaultSlot == 1, nil
}
