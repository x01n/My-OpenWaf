package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SeedDefaults ensures default admin listener, API key, and admin account exist.
// Returns the first-run API token and admin password (empty if not first run).
func SeedDefaults(db *gorm.DB, adminBind string, log *slog.Logger) (firstRunToken string, firstRunPassword string, err error) {
	var lCount int64
	if err := db.Model(&Listener{}).Where("role = ?", ListenerRoleAdmin).Count(&lCount).Error; err != nil {
		return "", "", fmt.Errorf("seed: count listeners: %w", err)
	}
	if lCount == 0 {
		l := Listener{
			Role:    ListenerRoleAdmin,
			Bind:    adminBind,
			Network: "tcp",
			Enabled: true,
		}
		if err := db.Create(&l).Error; err != nil {
			return "", "", fmt.Errorf("seed: create admin listener: %w", err)
		}
		log.Info("created default admin listener", slog.String("bind", adminBind))
	}

	var kCount int64
	if err := db.Model(&AdminAPIKey{}).Count(&kCount).Error; err != nil {
		return "", "", fmt.Errorf("seed: count api keys: %w", err)
	}
	if kCount == 0 {
		token := generateToken(32)
		hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
		if err != nil {
			return "", "", fmt.Errorf("seed: hash token: %w", err)
		}
		k := AdminAPIKey{
			Name:      "default",
			TokenHash: string(hash),
		}
		if err := db.Create(&k).Error; err != nil {
			return "", "", fmt.Errorf("seed: create api key: %w", err)
		}
		firstRunToken = token
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
		}
		if err := db.Create(&a).Error; err != nil {
			return "", "", fmt.Errorf("seed: create admin account: %w", err)
		}
		firstRunPassword = password
		log.Info("admin account created", slog.String("username", "admin"))
	}

	return firstRunToken, firstRunPassword, nil
}

func generateToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
