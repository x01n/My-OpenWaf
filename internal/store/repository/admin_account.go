package repository

import (
	"My-OpenWaf/internal/store"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AdminAccountRepo struct{ db *gorm.DB }

func NewAdminAccountRepo(db *gorm.DB) *AdminAccountRepo { return &AdminAccountRepo{db: db} }

func (r *AdminAccountRepo) GetByUsername(username string) (*store.AdminAccount, error) {
	var a store.AdminAccount
	return &a, r.db.Where("username = ?", username).First(&a).Error
}

func (r *AdminAccountRepo) VerifyPassword(username, password string) (*store.AdminAccount, bool) {
	a, err := r.GetByUsername(username)
	if err != nil {
		return nil, false
	}
	if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(password)) != nil {
		return nil, false
	}
	return a, true
}

func (r *AdminAccountRepo) UpdatePassword(username, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return r.db.Model(&store.AdminAccount{}).Where("username = ?", username).
		Update("password_hash", string(hash)).Error
}
