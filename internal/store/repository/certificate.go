package repository

import (
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type CertificateRepo struct{ db *gorm.DB }

func NewCertificateRepo(db *gorm.DB) *CertificateRepo { return &CertificateRepo{db: db} }

func (r *CertificateRepo) List(offset, limit int) ([]store.Certificate, int64, error) {
	var items []store.Certificate
	var total int64
	if err := r.db.Model(&store.Certificate{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	q := r.db.Order("id ASC")
	if limit > 0 {
		q = q.Offset(offset).Limit(limit)
	}
	if err := q.Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *CertificateRepo) Get(id uint) (*store.Certificate, error) {
	var item store.Certificate
	return &item, r.db.First(&item, id).Error
}

func (r *CertificateRepo) GetByID(idStr string) (*store.Certificate, error) {
	var item store.Certificate
	return &item, r.db.First(&item, idStr).Error
}

func (r *CertificateRepo) Create(item *store.Certificate) error { return r.db.Create(item).Error }

func (r *CertificateRepo) Update(item *store.Certificate) error { return r.db.Save(item).Error }

func (r *CertificateRepo) Delete(id uint) error {
	return r.db.Delete(&store.Certificate{}, id).Error
}

func (r *CertificateRepo) ListBySource(source string) ([]store.Certificate, error) {
	var items []store.Certificate
	err := r.db.Where("source = ?", source).Order("id ASC").Find(&items).Error
	return items, err
}

func (r *CertificateRepo) ListAutoRenew() ([]store.Certificate, error) {
	var items []store.Certificate
	err := r.db.Where("auto_renew = ? AND source = ?", true, store.CertSourceACME).Find(&items).Error
	return items, err
}

func (r *CertificateRepo) UpdateCert(id uint, certPEM, keyPEM string, expiresAt, renewedAt *time.Time) error {
	updates := map[string]interface{}{
		"cert_pem":      certPEM,
		"key_pem":       keyPEM,
		"expires_at":    expiresAt,
		"last_renew_at": renewedAt,
		"renew_error":   "",
	}
	return r.db.Model(&store.Certificate{}).Where("id = ?", id).Updates(updates).Error
}

func (r *CertificateRepo) UpdateRenewStatus(id uint, errMsg string, attemptedAt *time.Time) error {
	updates := map[string]interface{}{
		"renew_error":   errMsg,
		"last_renew_at": attemptedAt,
	}
	return r.db.Model(&store.Certificate{}).Where("id = ?", id).Updates(updates).Error
}

func (r *CertificateRepo) GetByDomain(domain string) (*store.Certificate, error) {
	var item store.Certificate
	err := r.db.Where("domain = ? AND source = ?", domain, store.CertSourceACME).First(&item).Error
	if err != nil {
		return nil, err
	}
	return &item, nil
}
