package repository

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/store"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func newDryRunPostgresDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "host=127.0.0.1 user=openwaf dbname=openwaf sslmode=disable",
		PreferSimpleProtocol: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open dry-run postgres db: %v", err)
	}
	return db
}

func TestSystemSettingsRepoUsesDialectQuotedKeyColumn(t *testing.T) {
	db := newDryRunPostgresDB(t)
	repo := NewSystemSettingsRepo(db)

	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "where",
			sql: repo.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				return tx.Where(systemSettingKeyEquals(store.SettingKeyRedisConfig)).Find(&store.SystemSettings{})
			}),
		},
		{
			name: "delete",
			sql: repo.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				return tx.Where(systemSettingKeyEquals(store.SettingKeyRedisConfig)).Delete(&store.SystemSettings{})
			}),
		},
		{
			name: "order",
			sql: repo.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				return tx.Clauses(systemSettingKeyOrder()).Find(&[]store.SystemSettings{})
			}),
		},
	}

	for _, tt := range tests {
		if strings.TrimSpace(tt.sql) == "" {
			t.Fatalf("%s SQL should not be empty", tt.name)
		}
		if strings.Contains(tt.sql, "`key`") {
			t.Fatalf("%s SQL should not contain MySQL-style key quoting: %s", tt.name, tt.sql)
		}
		if !strings.Contains(tt.sql, `"key"`) {
			t.Fatalf("%s SQL should contain dialect-quoted key column: %s", tt.name, tt.sql)
		}
	}
}
