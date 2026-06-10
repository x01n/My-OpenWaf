package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type SiteListenerRepo struct{ db *gorm.DB }

func NewSiteListenerRepo(db *gorm.DB) *SiteListenerRepo { return &SiteListenerRepo{db: db} }

// All returns every listener (including disabled) ordered by site/bind.
func (r *SiteListenerRepo) All() ([]store.SiteListener, error) {
	var items []store.SiteListener
	return items, r.db.Order("site_id ASC, bind ASC").Find(&items).Error
}

// AllEnabled returns only listeners marked enabled.
func (r *SiteListenerRepo) AllEnabled() ([]store.SiteListener, error) {
	var items []store.SiteListener
	return items, r.db.Where("enabled = ?", true).Order("site_id ASC, bind ASC").Find(&items).Error
}

// ListBySite returns listeners for a specific site ordered by bind.
func (r *SiteListenerRepo) ListBySite(siteID uint) ([]store.SiteListener, error) {
	var items []store.SiteListener
	return items, r.db.Where("site_id = ?", siteID).Order("bind ASC").Find(&items).Error
}

func (r *SiteListenerRepo) Get(id uint) (*store.SiteListener, error) {
	var item store.SiteListener
	return &item, r.db.First(&item, id).Error
}

func (r *SiteListenerRepo) Create(item *store.SiteListener) error {
	return r.db.Create(item).Error
}

func (r *SiteListenerRepo) Update(item *store.SiteListener) error {
	return r.db.Save(item).Error
}

func (r *SiteListenerRepo) Delete(id uint) error {
	return r.db.Delete(&store.SiteListener{}, id).Error
}

func (r *SiteListenerRepo) DeleteBySite(siteID uint) error {
	return r.db.Where("site_id = ?", siteID).Delete(&store.SiteListener{}).Error
}

func (r *SiteListenerRepo) CountByCertID(certID uint) (int64, error) {
	var count int64
	err := r.db.Model(&store.SiteListener{}).Where("cert_id = ?", certID).Count(&count).Error
	return count, err
}

func (r *SiteListenerRepo) ApplyCertificateToTLSListeners(siteIDs []uint, certID uint) (int64, error) {
	if len(siteIDs) == 0 {
		return 0, nil
	}
	tx := r.db.Model(&store.SiteListener{}).
		Where("site_id IN ? AND tls_enabled = ?", siteIDs, true).
		Updates(map[string]any{"cert_id": certID})
	return tx.RowsAffected, tx.Error
}

func (r *SiteListenerRepo) CreateWithLegacyPromotion(item *store.SiteListener, legacy *store.SiteListener) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if legacy != nil {
			if err := tx.Create(legacy).Error; err != nil {
				return err
			}
		}
		return tx.Create(item).Error
	})
}
