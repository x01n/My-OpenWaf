package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type IPListRepo struct{ db *gorm.DB }

func NewIPListRepo(db *gorm.DB) *IPListRepo { return &IPListRepo{db: db} }

func (r *IPListRepo) List(offset, limit int, kind string, siteID *uint) ([]store.IPListEntry, int64, error) {
	q := r.db.Model(&store.IPListEntry{})
	if kind != "" {
		q = q.Where("kind = ?", kind)
	}
	if siteID != nil {
		q = q.Where("site_id = ?", *siteID)
	} else {
		q = q.Where("site_id IS NULL")
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var items []store.IPListEntry
	if err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *IPListRepo) AllEnabled() ([]store.IPListEntry, error) {
	var items []store.IPListEntry
	return items, r.db.Where("enabled = ?", true).Find(&items).Error
}

// AllEnabledForSite 返回指定站点及全局的已启用 IP 列表条目。
func (r *IPListRepo) AllEnabledForSite(siteID uint) ([]store.IPListEntry, error) {
	var items []store.IPListEntry
	return items, r.db.Where("enabled = ? AND (site_id IS NULL OR site_id = ?)", true, siteID).Find(&items).Error
}

// AllEnabledGlobal 返回仅全局（site_id IS NULL）的已启用 IP 列表条目。
func (r *IPListRepo) AllEnabledGlobal() ([]store.IPListEntry, error) {
	var items []store.IPListEntry
	return items, r.db.Where("enabled = ? AND site_id IS NULL", true).Find(&items).Error
}

func (r *IPListRepo) Get(id uint) (*store.IPListEntry, error) {
	var item store.IPListEntry
	return &item, r.db.First(&item, id).Error
}

func (r *IPListRepo) Create(item *store.IPListEntry) error { return r.db.Create(item).Error }
func (r *IPListRepo) Update(item *store.IPListEntry) error { return r.db.Save(item).Error }
func (r *IPListRepo) Delete(id uint) error                 { return r.db.Delete(&store.IPListEntry{}, id).Error }
