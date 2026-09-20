package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type SystemSettingsRepo struct{ db *gorm.DB }

func NewSystemSettingsRepo(db *gorm.DB) *SystemSettingsRepo {
	return &SystemSettingsRepo{db: db}
}

/**
 * 在同一个数据库事务中执行系统配置读写。
 *
 * @param fn 接收绑定当前事务的仓储实例
 * @returns 事务执行错误
 */
func (r *SystemSettingsRepo) Transaction(fn func(txRepo *SystemSettingsRepo) error) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		return fn(NewSystemSettingsRepo(tx))
	})
}

func systemSettingKeyEquals(key string) clause.Eq {
	return clause.Eq{Column: clause.Column{Name: "key"}, Value: key}
}

func systemSettingKeyOrder() clause.OrderBy {
	return clause.OrderBy{
		Columns: []clause.OrderByColumn{{Column: clause.Column{Name: "key"}}},
	}
}

func (r *SystemSettingsRepo) Get(key string) (string, error) {
	var s store.SystemSettings
	if err := r.db.Where(systemSettingKeyEquals(key)).First(&s).Error; err != nil {
		return "", err
	}
	return s.Value, nil
}

func (r *SystemSettingsRepo) Set(key, value string) error {
	return r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&store.SystemSettings{Key: key, Value: value}).Error
}

func (r *SystemSettingsRepo) All() ([]store.SystemSettings, error) {
	var items []store.SystemSettings
	return items, r.db.Clauses(systemSettingKeyOrder()).Find(&items).Error
}

func (r *SystemSettingsRepo) Delete(key string) error {
	return r.db.Where(systemSettingKeyEquals(key)).Delete(&store.SystemSettings{}).Error
}

func (r *SystemSettingsRepo) DB() *gorm.DB { return r.db }
