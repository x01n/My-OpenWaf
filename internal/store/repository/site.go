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

func (r *SiteRepo) CountByCertID(certID uint) (int64, error) {
	var count int64
	err := r.db.Model(&store.Site{}).Where("cert_id = ?", certID).Count(&count).Error
	return count, err
}

func (r *SiteRepo) ApplyCertificate(siteIDs []uint, certID uint) (int64, error) {
	if len(siteIDs) == 0 {
		return 0, nil
	}
	tx := r.db.Model(&store.Site{}).
		Where("id IN ?", siteIDs).
		Updates(map[string]any{"tls_enabled": true, "cert_id": certID})
	return tx.RowsAffected, tx.Error
}

func (r *SiteRepo) CountByPolicyID(policyID uint) (int64, error) {
	var count int64
	err := r.db.Model(&store.Site{}).Where("policy_id = ?", policyID).Count(&count).Error
	return count, err
}

func (r *SiteRepo) DeleteWithListeners(id uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("site_id = ?", id).Delete(&store.SiteListener{}).Error; err != nil {
			return err
		}
		return tx.Delete(&store.Site{}, id).Error
	})
}
