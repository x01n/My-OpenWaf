package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type ForwardingProfileRepo struct{ db *gorm.DB }

func NewForwardingProfileRepo(db *gorm.DB) *ForwardingProfileRepo {
	return &ForwardingProfileRepo{db: db}
}

func (r *ForwardingProfileRepo) List(offset, limit int) ([]store.ForwardingProfile, int64, error) {
	var items []store.ForwardingProfile
	var total int64
	if err := r.db.Model(&store.ForwardingProfile{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := r.db.Offset(offset).Limit(limit).Order("id ASC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *ForwardingProfileRepo) Get(id uint) (*store.ForwardingProfile, error) {
	var item store.ForwardingProfile
	return &item, r.db.First(&item, id).Error
}

func (r *ForwardingProfileRepo) Create(item *store.ForwardingProfile) error {
	return r.db.Create(item).Error
}

func (r *ForwardingProfileRepo) Update(item *store.ForwardingProfile) error {
	return r.db.Save(item).Error
}

func (r *ForwardingProfileRepo) Delete(id uint) error {
	return r.db.Delete(&store.ForwardingProfile{}, id).Error
}
