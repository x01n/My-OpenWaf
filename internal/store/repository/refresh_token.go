package repository

import (
	"errors"
	"fmt"
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RefreshTokenRepo struct{ db *gorm.DB }

var ErrRefreshTokenUnavailable = errors.New("refresh token is expired or revoked")

func NewRefreshTokenRepo(db *gorm.DB) *RefreshTokenRepo { return &RefreshTokenRepo{db: db} }

func (r *RefreshTokenRepo) Create(jti, tokenHash, username, role string, expiresAt time.Time) (*store.RefreshToken, error) {
	rt := &store.RefreshToken{
		JTI:       jti,
		TokenHash: tokenHash,
		Username:  username,
		Role:      role,
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

// RevokeFamily 撤销指定刷新令牌及其轮换产生的全部后继令牌。
// 沿服务端 replaced_by 链遍历，确保登出只影响当前浏览器会话，不撤销其他设备令牌。
func (r *RefreshTokenRepo) RevokeFamily(jti string) error {
	if r == nil || r.db == nil || jti == "" {
		return nil
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		current := jti
		seen := make(map[string]struct{})
		for current != "" {
			if _, exists := seen[current]; exists {
				return nil
			}
			seen[current] = struct{}{}

			var token store.RefreshToken
			if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
				Where("jti = ?", current).First(&token).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil
				}
				return err
			}
			if err := tx.Model(&store.RefreshToken{}).
				Where("jti = ?", current).
				Update("revoked", true).Error; err != nil {
				return err
			}

			// 重新读取 replacement，确保并发 refresh 已提交的后继令牌
			// 也被纳入本次注销；行锁在支持的数据库上避免旧快照。
			var latest store.RefreshToken
			if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
				Select("replaced_by").
				Where("jti = ?", current).First(&latest).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil
				}
				return err
			}
			current = latest.ReplacedBy
		}
		return nil
	})
}

// Rotate atomically consumes an active refresh token and creates its replacement.
func (r *RefreshTokenRepo) Rotate(oldJTI, newJTI, tokenHash, username, role string, expiresAt time.Time) (*store.RefreshToken, error) {
	next := &store.RefreshToken{
		JTI:       newJTI,
		TokenHash: tokenHash,
		Username:  username,
		Role:      role,
		ExpiresAt: expiresAt,
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&store.RefreshToken{}).
			Where("jti = ? AND revoked = ? AND expires_at > ?", oldJTI, false, time.Now()).
			Updates(map[string]any{"revoked": true, "replaced_by": newJTI})
		if result.Error != nil {
			return fmt.Errorf("revoke old refresh token: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return ErrRefreshTokenUnavailable
		}
		if err := tx.Create(next).Error; err != nil {
			return fmt.Errorf("create replacement refresh token: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return next, nil
}

// RevokeByUsername revokes every active refresh token owned by one account.
func (r *RefreshTokenRepo) RevokeByUsername(username string) error {
	query := r.db.Model(&store.RefreshToken{})
	if username == "admin" {
		query = query.Where("(username = ? OR username = '')", username)
	} else {
		query = query.Where("username = ?", username)
	}
	return query.Where("revoked = ?", false).
		Update("revoked", true).Error
}

func (r *RefreshTokenRepo) RevokeAll() error {
	return r.db.Model(&store.RefreshToken{}).Where("revoked = ?", false).
		Update("revoked", true).Error
}

func (r *RefreshTokenRepo) CleanExpired(limits ...int) error {
	limit := 64
	if len(limits) > 0 {
		limit = limits[0]
	}
	if r == nil || r.db == nil || limit <= 0 {
		return nil
	}
	var ids []uint
	if err := r.db.Model(&store.RefreshToken{}).
		Where("revoked = ? OR expires_at <= ?", true, time.Now()).
		Order("id ASC").
		Limit(limit).
		Pluck("id", &ids).Error; err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	return r.db.Where("id IN ?", ids).Delete(&store.RefreshToken{}).Error
}
