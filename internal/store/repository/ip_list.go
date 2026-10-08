package repository

import (
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/iplist"

	"gorm.io/gorm"
)

type IPListRepo struct{ db *gorm.DB }

func NewIPListRepo(db *gorm.DB) *IPListRepo { return &IPListRepo{db: db} }

func (r *IPListRepo) List(offset, limit int, kind string, siteID *uint) ([]iplist.IPListEntry, int64, error) {
	q := r.db.Model(&iplist.IPListEntry{})
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
	var items []iplist.IPListEntry
	if err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *IPListRepo) AllEnabled() ([]iplist.IPListEntry, error) {
	var items []iplist.IPListEntry
	return items, r.db.Where("enabled = ?", true).Find(&items).Error
}

// AllEnabledForSite 返回指定站点及全局的已启用 IP 列表条目。
func (r *IPListRepo) AllEnabledForSite(siteID uint) ([]iplist.IPListEntry, error) {
	var items []iplist.IPListEntry
	return items, r.db.Where("enabled = ? AND (site_id IS NULL OR site_id = ?)", true, siteID).Find(&items).Error
}

// AllEnabledGlobal 返回仅全局（site_id IS NULL）的已启用 IP 列表条目。
func (r *IPListRepo) AllEnabledGlobal() ([]iplist.IPListEntry, error) {
	var items []iplist.IPListEntry
	return items, r.db.Where("enabled = ? AND site_id IS NULL", true).Find(&items).Error
}

func (r *IPListRepo) Get(id uint) (*iplist.IPListEntry, error) {
	var item iplist.IPListEntry
	return &item, r.db.First(&item, id).Error
}

// Create 新建名单条目。Enabled 带 gorm default:true，见 CreateWithZeroDefaults。
func (r *IPListRepo) Create(item *iplist.IPListEntry) error {
	return store.CreateWithZeroDefaults(r.db, item)
}
func (r *IPListRepo) Update(item *iplist.IPListEntry) error { return r.db.Save(item).Error }
func (r *IPListRepo) Delete(id uint) error                  { return r.db.Delete(&iplist.IPListEntry{}, id).Error }
