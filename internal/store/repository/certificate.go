package repository

import (
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
	if err := r.db.Offset(offset).Limit(limit).Order("id ASC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *CertificateRepo) Get(id uint) (*store.Certificate, error) {
	var item store.Certificate
	return &item, r.db.First(&item, id).Error
}

func (r *CertificateRepo) Create(item *store.Certificate) error { return r.db.Create(item).Error }

func (r *CertificateRepo) Update(item *store.Certificate) error { return r.db.Save(item).Error }

func (r *CertificateRepo) Delete(id uint) error {
	return r.db.Delete(&store.Certificate{}, id).Error
}
