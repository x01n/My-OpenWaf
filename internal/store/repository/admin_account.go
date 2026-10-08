package repository

import (
	"My-OpenWaf/internal/store/auth"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AdminAccountRepo struct{ db *gorm.DB }

func NewAdminAccountRepo(db *gorm.DB) *AdminAccountRepo { return &AdminAccountRepo{db: db} }

func (r *AdminAccountRepo) GetByUsername(username string) (*auth.AdminAccount, error) {
	var a auth.AdminAccount
	return &a, r.db.Where("username = ?", username).First(&a).Error
}

func (r *AdminAccountRepo) GetByID(id uint) (*auth.AdminAccount, error) {
	var a auth.AdminAccount
	return &a, r.db.First(&a, id).Error
}

func (r *AdminAccountRepo) List() ([]auth.AdminAccount, error) {
	var accounts []auth.AdminAccount
	err := r.db.Order("id ASC").Find(&accounts).Error
	return accounts, err
}

func (r *AdminAccountRepo) Create(username, password, role string) (*auth.AdminAccount, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	a := auth.AdminAccount{
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
	}
	return &a, r.db.Create(&a).Error
}

func (r *AdminAccountRepo) VerifyPassword(username, password string) (*auth.AdminAccount, bool) {
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
	return r.db.Model(&auth.AdminAccount{}).Where("username = ?", username).
		Update("password_hash", string(hash)).Error
}

func (r *AdminAccountRepo) UpdatePasswordByID(id uint, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return r.db.Model(&auth.AdminAccount{}).Where("id = ?", id).
		Update("password_hash", string(hash)).Error
}

func (r *AdminAccountRepo) UpdateRole(id uint, role string) error {
	return r.db.Model(&auth.AdminAccount{}).Where("id = ?", id).
		Update("role", role).Error
}

func (r *AdminAccountRepo) Delete(id uint) error {
	return r.db.Delete(&auth.AdminAccount{}, id).Error
}

func (r *AdminAccountRepo) CountByRole(role string) (int64, error) {
	var count int64
	err := r.db.Model(&auth.AdminAccount{}).Where("role = ?", role).Count(&count).Error
	return count, err
}
