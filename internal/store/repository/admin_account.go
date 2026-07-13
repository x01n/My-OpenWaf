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

func (r *AdminAccountRepo) GetByID(id uint) (*store.AdminAccount, error) {
	var a store.AdminAccount
	return &a, r.db.First(&a, id).Error
}

func (r *AdminAccountRepo) List() ([]store.AdminAccount, error) {
	var accounts []store.AdminAccount
	err := r.db.Order("id ASC").Find(&accounts).Error
	return accounts, err
}

func (r *AdminAccountRepo) Create(username, password, role string) (*store.AdminAccount, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	a := store.AdminAccount{
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
	}
	return &a, r.db.Create(&a).Error
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

func (r *AdminAccountRepo) UpdatePasswordByID(id uint, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return r.db.Model(&store.AdminAccount{}).Where("id = ?", id).
		Update("password_hash", string(hash)).Error
}

func (r *AdminAccountRepo) UpdateRole(id uint, role string) error {
	return r.db.Model(&store.AdminAccount{}).Where("id = ?", id).
		Update("role", role).Error
}

func (r *AdminAccountRepo) Delete(id uint) error {
	return r.db.Delete(&store.AdminAccount{}, id).Error
}

func (r *AdminAccountRepo) CountByRole(role string) (int64, error) {
	var count int64
	err := r.db.Model(&store.AdminAccount{}).Where("role = ?", role).Count(&count).Error
	return count, err
}
