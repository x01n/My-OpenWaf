package migrations

import (
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const siteTLSMinVersionInheritanceMigrationKey = "migration_v6_site_tls_min_version_inheritance"

// V6MigrateSiteTLSMinVersionInheritance 把历史上的站点 TLS 1.2 最低版本默认值
// 转换为当前的空字符串继承标记。该标记可避免后续显式的 TLS12 覆盖
// 在之后的重启中被清除。
func V6MigrateSiteTLSMinVersionInheritance(db *gorm.DB) error {
	if !db.Migrator().HasTable(&siteTLSMinVersionInheritanceTable{}) {
		return nil
	}
	if !db.Migrator().HasTable(&migrationSystemSetting{}) {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		var marker migrationSystemSetting
		markerQuery := tx.Where(clause.Eq{
			Column: clause.Column{Name: "key"},
			Value:  siteTLSMinVersionInheritanceMigrationKey,
		}).Limit(1).Find(&marker)
		if markerQuery.Error != nil {
			return fmt.Errorf("failed to load site TLS min version migration marker: %w", markerQuery.Error)
		}
		if markerQuery.RowsAffected > 0 {
			return nil
		}

		if err := tx.Model(&siteTLSMinVersionInheritanceTable{}).
			Where("min_tls_version = ?", "TLS12").
			Update("min_tls_version", "").Error; err != nil {
			return fmt.Errorf("failed to migrate sites.min_tls_version default: %w", err)
		}

		if err := tx.Create(&migrationSystemSetting{
			Key:   siteTLSMinVersionInheritanceMigrationKey,
			Value: "true",
		}).Error; err != nil {
			return fmt.Errorf("failed to store site TLS min version migration marker: %w", err)
		}
		return nil
	})
}

type siteTLSMinVersionInheritanceTable struct {
	MinTLSVersion string `gorm:"column:min_tls_version"`
}

func (siteTLSMinVersionInheritanceTable) TableName() string {
	return "sites"
}

type migrationSystemSetting struct {
	Key   string `gorm:"column:key;primaryKey"`
	Value string `gorm:"column:value"`
}

func (migrationSystemSetting) TableName() string {
	return "system_settings"
}
