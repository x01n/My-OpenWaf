package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type ListenerRepo struct{ db *gorm.DB }

func NewListenerRepo(db *gorm.DB) *ListenerRepo { return &ListenerRepo{db: db} }

func (r *ListenerRepo) List(offset, limit int) ([]store.Listener, int64, error) {
	var items []store.Listener
	var total int64
	if err := r.db.Model(&store.Listener{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := r.db.Offset(offset).Limit(limit).Order("id ASC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *ListenerRepo) ListByRole(role store.ListenerRole) ([]store.Listener, error) {
	var items []store.Listener
	return items, r.db.Where("role = ? AND enabled = ?", role, true).Order("id ASC").Find(&items).Error
}

func (r *ListenerRepo) Get(id uint) (*store.Listener, error) {
	var item store.Listener
	return &item, r.db.First(&item, id).Error
}

func (r *ListenerRepo) Create(item *store.Listener) error { return r.db.Create(item).Error }

func (r *ListenerRepo) Update(item *store.Listener) error { return r.db.Save(item).Error }

func (r *ListenerRepo) Delete(id uint) error { return r.db.Delete(&store.Listener{}, id).Error }
