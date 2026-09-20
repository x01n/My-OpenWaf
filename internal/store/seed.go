package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SeedDefaults ensures default API key and admin account exist.
// Returns the first-run API token and admin password (empty if not first run).
func SeedDefaults(db *gorm.DB, adminBind string, log *slog.Logger) (firstRunToken string, firstRunPassword string, err error) {
	// Admin listener is no longer needed - admin server is always started separately

	firstRunToken, err = seedFirstAPIKey(db)
	if err != nil {
		return "", "", err
	}

	// Seed admin account with random password on first run.
	var aCount int64
	if err := db.Model(&AdminAccount{}).Where("username = ?", "admin").Count(&aCount).Error; err != nil {
		return "", "", fmt.Errorf("seed: count admin accounts: %w", err)
	}
	if aCount == 0 {
		password := generateToken(16)
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return "", "", fmt.Errorf("seed: hash admin password: %w", err)
		}
		a := AdminAccount{
			Username:     "admin",
			PasswordHash: string(hash),
			Role:         RoleAdmin,
		}
		result := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&a)
		if result.Error != nil {
			return "", "", fmt.Errorf("seed: create admin account: %w", result.Error)
		}
		if result.RowsAffected > 0 {
			firstRunPassword = password
			log.Info("admin account created", slog.String("username", "admin"))
		}
	}

	return firstRunToken, firstRunPassword, nil
}

// seedFirstAPIKey 使用唯一系统设置 marker 保护首次 key 创建，避免并发进程
// 同时看到空表而各自生成一枚初始令牌。没有 system_settings 表的旧调用方
// 保留原有 count 路径，正式启动在 AutoMigrate 后总是使用 marker 事务。
func seedFirstAPIKey(db *gorm.DB) (string, error) {
	if db == nil {
		return "", fmt.Errorf("seed: database is nil")
	}
	if !db.Migrator().HasTable(&SystemSettings{}) {
		var count int64
		if err := db.Unscoped().Model(&AdminAPIKey{}).Count(&count).Error; err != nil {
			return "", fmt.Errorf("seed: count api keys: %w", err)
		}
		if count > 0 {
			return "", nil
		}
		return createFirstAPIKey(db)
	}

	var token string
	err := db.Transaction(func(tx *gorm.DB) error {
		marker := SystemSettings{Key: SettingKeyAPIKeySeedMarker, Value: "true"}
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&marker)
		if result.Error != nil {
			return fmt.Errorf("seed: reserve api key marker: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return nil
		}
		var count int64
		if err := tx.Unscoped().Model(&AdminAPIKey{}).Count(&count).Error; err != nil {
			return fmt.Errorf("seed: count api keys: %w", err)
		}
		if count > 0 {
			return nil
		}
		created, err := createFirstAPIKey(tx)
		if err != nil {
			return err
		}
		token = created
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func createFirstAPIKey(db *gorm.DB) (string, error) {
	token := generateToken(32)
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("seed: hash token: %w", err)
	}
	key := AdminAPIKey{
		Name:      "default",
		Prefix:    token[:8],
		TokenHash: string(hash),
	}
	if err := db.Create(&key).Error; err != nil {
		return "", fmt.Errorf("seed: create api key: %w", err)
	}
	return token, nil
}

func generateToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("store: failed to generate secure random token: " + err.Error())
	}
	return hex.EncodeToString(b)
}
