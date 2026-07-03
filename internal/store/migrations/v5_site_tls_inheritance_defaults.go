package migrations

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// V5MigrateSiteTLSInheritanceDefaults removes schema defaults where the
// current SQL dialect supports dropping them, so site-level TLS inheritance
// can continue to be represented as an empty string.
func V5MigrateSiteTLSInheritanceDefaults(db *gorm.DB) error {
	if !db.Migrator().HasTable(&siteTLSInheritanceTable{}) {
		return nil
	}

	switch strings.ToLower(db.Dialector.Name()) {
	case "sqlite":
		return nil
	case "mysql":
		return db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("ALTER TABLE sites ALTER COLUMN min_tls_version DROP DEFAULT").Error; err != nil {
				if !isIgnorableDropDefaultError(err) {
					return fmt.Errorf("failed to drop sites.min_tls_version default: %w", err)
				}
			}
			if err := tx.Exec("ALTER TABLE sites ALTER COLUMN max_tls_version DROP DEFAULT").Error; err != nil {
				if !isIgnorableDropDefaultError(err) {
					return fmt.Errorf("failed to drop sites.max_tls_version default: %w", err)
				}
			}
			if err := tx.Exec("ALTER TABLE sites ALTER COLUMN alpn DROP DEFAULT").Error; err != nil {
				if !isIgnorableDropDefaultError(err) {
					return fmt.Errorf("failed to drop sites.alpn default: %w", err)
				}
			}
			return nil
		})
	case "postgres", "postgresql":
		return db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("ALTER TABLE sites ALTER COLUMN min_tls_version DROP DEFAULT").Error; err != nil {
				return fmt.Errorf("failed to drop sites.min_tls_version default: %w", err)
			}
			if err := tx.Exec("ALTER TABLE sites ALTER COLUMN max_tls_version DROP DEFAULT").Error; err != nil {
				return fmt.Errorf("failed to drop sites.max_tls_version default: %w", err)
			}
			if err := tx.Exec("ALTER TABLE sites ALTER COLUMN alpn DROP DEFAULT").Error; err != nil {
				return fmt.Errorf("failed to drop sites.alpn default: %w", err)
			}
			return nil
		})
	default:
		return nil
	}
}

type siteTLSInheritanceTable struct {
	MinTLSVersion string `gorm:"column:min_tls_version"`
	MaxTLSVersion string `gorm:"column:max_tls_version"`
	ALPN          string `gorm:"column:alpn"`
}

func (siteTLSInheritanceTable) TableName() string {
	return "sites"
}

func isIgnorableDropDefaultError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "can't drop") ||
		strings.Contains(msg, "cannot drop") ||
		strings.Contains(msg, "check that column/key exists") ||
		strings.Contains(msg, "doesn't have a default value")
}
