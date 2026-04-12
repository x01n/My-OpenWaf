package repository

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type AdminAPIKeyRepo struct{ db *gorm.DB }

func NewAdminAPIKeyRepo(db *gorm.DB) *AdminAPIKeyRepo { return &AdminAPIKeyRepo{db: db} }

func (r *AdminAPIKeyRepo) List() ([]store.AdminAPIKey, error) {
	var items []store.AdminAPIKey
	return items, r.db.Order("id ASC").Find(&items).Error
}

func (r *AdminAPIKeyRepo) Get(id uint) (*store.AdminAPIKey, error) {
	var item store.AdminAPIKey
	return &item, r.db.First(&item, id).Error
}

// Create generates a new token, stores the bcrypt hash, returns the plaintext (shown once).
func (r *AdminAPIKeyRepo) Create(name string) (token string, item *store.AdminAPIKey, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("rand: %w", err)
	}
	token = hex.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, fmt.Errorf("bcrypt: %w", err)
	}
	k := &store.AdminAPIKey{Name: name, TokenHash: string(hash)}
	if err := r.db.Create(k).Error; err != nil {
		return "", nil, err
	}
	return token, k, nil
}

// Verify checks a bearer token against all stored hashes.
func (r *AdminAPIKeyRepo) Verify(token string) (*store.AdminAPIKey, bool) {
	var keys []store.AdminAPIKey
	if err := r.db.Find(&keys).Error; err != nil {
		return nil, false
	}
	for i := range keys {
		if bcrypt.CompareHashAndPassword([]byte(keys[i].TokenHash), []byte(token)) == nil {
			now := time.Now()
			keys[i].LastUsedAt = &now
			_ = r.db.Save(&keys[i]).Error
			return &keys[i], true
		}
	}
	return nil, false
}

func (r *AdminAPIKeyRepo) Delete(id uint) error {
	return r.db.Delete(&store.AdminAPIKey{}, id).Error
}
