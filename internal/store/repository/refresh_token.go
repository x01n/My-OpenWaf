package repository

import (
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type RefreshTokenRepo struct{ db *gorm.DB }

func NewRefreshTokenRepo(db *gorm.DB) *RefreshTokenRepo { return &RefreshTokenRepo{db: db} }

func (r *RefreshTokenRepo) Create(jti, tokenHash string, expiresAt time.Time) (*store.RefreshToken, error) {
	rt := &store.RefreshToken{
		JTI:       jti,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}
	return rt, r.db.Create(rt).Error
}

func (r *RefreshTokenRepo) FindByJTI(jti string) (*store.RefreshToken, error) {
	var rt store.RefreshToken
	return &rt, r.db.Where("jti = ? AND revoked = ? AND expires_at > ?", jti, false, time.Now()).First(&rt).Error
}

func (r *RefreshTokenRepo) Revoke(jti, replacedBy string) error {
	return r.db.Model(&store.RefreshToken{}).Where("jti = ?", jti).
		Updates(map[string]any{"revoked": true, "replaced_by": replacedBy}).Error
}

func (r *RefreshTokenRepo) RevokeAll() error {
	return r.db.Model(&store.RefreshToken{}).Where("revoked = ?", false).
		Update("revoked", true).Error
}

func (r *RefreshTokenRepo) CleanExpired() error {
	return r.db.Where("expires_at < ? OR revoked = ?", time.Now(), true).
		Delete(&store.RefreshToken{}).Error
}
