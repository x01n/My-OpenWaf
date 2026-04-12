package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type SystemSettingsRepo struct{ db *gorm.DB }

func NewSystemSettingsRepo(db *gorm.DB) *SystemSettingsRepo {
	return &SystemSettingsRepo{db: db}
}

func (r *SystemSettingsRepo) Get(key string) (string, error) {
	var s store.SystemSettings
	if err := r.db.Where("`key` = ?", key).First(&s).Error; err != nil {
		return "", err
	}
	return s.Value, nil
}

func (r *SystemSettingsRepo) Set(key, value string) error {
	var s store.SystemSettings
	result := r.db.Where("`key` = ?", key).First(&s)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return r.db.Create(&store.SystemSettings{Key: key, Value: value}).Error
		}
		return result.Error
	}
	s.Value = value
	return r.db.Save(&s).Error
}

func (r *SystemSettingsRepo) All() ([]store.SystemSettings, error) {
	var items []store.SystemSettings
	return items, r.db.Order("`key` ASC").Find(&items).Error
}

func (r *SystemSettingsRepo) Delete(key string) error {
	return r.db.Where("`key` = ?", key).Delete(&store.SystemSettings{}).Error
}
