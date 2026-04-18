package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type SiteRepo struct{ db *gorm.DB }

func NewSiteRepo(db *gorm.DB) *SiteRepo { return &SiteRepo{db: db} }

func (r *SiteRepo) List(offset, limit int) ([]store.Site, int64, error) {
	var items []store.Site
	var total int64
	if err := r.db.Model(&store.Site{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := r.db.Offset(offset).Limit(limit).Order("id ASC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *SiteRepo) FindEnabled() ([]store.Site, error) {
	var items []store.Site
	return items, r.db.Where("enabled = ?", true).Order("id ASC").Find(&items).Error
}

func (r *SiteRepo) FindByBind(bind string) ([]store.Site, error) {
	var items []store.Site
	return items, r.db.Where("bind = ? AND enabled = ?", bind, true).Order("id ASC").Find(&items).Error
}

func (r *SiteRepo) Get(id uint) (*store.Site, error) {
	var item store.Site
	return &item, r.db.First(&item, id).Error
}

func (r *SiteRepo) Create(item *store.Site) error { return r.db.Create(item).Error }

func (r *SiteRepo) Update(item *store.Site) error { return r.db.Save(item).Error }

func (r *SiteRepo) Delete(id uint) error { return r.db.Delete(&store.Site{}, id).Error }
