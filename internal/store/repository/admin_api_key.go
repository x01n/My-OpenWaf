package repository

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"My-OpenWaf/internal/store/auth"

	"gorm.io/gorm"
)

type AdminAPIKeyRepo struct{ db *gorm.DB }

func NewAdminAPIKeyRepo(db *gorm.DB) *AdminAPIKeyRepo { return &AdminAPIKeyRepo{db: db} }

func (r *AdminAPIKeyRepo) List() ([]auth.AdminAPIKey, error) {
	var items []auth.AdminAPIKey
	return items, r.db.Order("id ASC").Find(&items).Error
}

/**
 * ListByUser 按归属账号列出令牌，供「我的令牌」类视图使用。
 *
 * @param userID AdminAccount 主键。
 * @return 该账号名下的令牌，按 id 升序。
 */
func (r *AdminAPIKeyRepo) ListByUser(userID uint) ([]auth.AdminAPIKey, error) {
	var items []auth.AdminAPIKey
	return items, r.db.Where("user_id = ?", userID).Order("id ASC").Find(&items).Error
}

func (r *AdminAPIKeyRepo) Get(id uint) (*auth.AdminAPIKey, error) {
	var item auth.AdminAPIKey
	return &item, r.db.First(&item, id).Error
}

/**
 * Create 为指定账号生成新令牌，存储其 bcrypt 哈希，并返回明文（只展示这一次）。
 *
 * @param userID 令牌归属的 AdminAccount 主键。
 * @param name 令牌的展示名。
 * @return token 明文令牌，仅在本次响应中返回一次。
 * @return item 已落库的令牌记录。
 * @return err 生成或落库失败。
 */
func (r *AdminAPIKeyRepo) Create(userID uint, name string) (token string, item *auth.AdminAPIKey, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("rand: %w", err)
	}
	token = hex.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, fmt.Errorf("bcrypt: %w", err)
	}
	prefix := token[:8]
	k := &auth.AdminAPIKey{UserID: userID, Name: name, Prefix: prefix, TokenHash: string(hash)}
	if err := r.db.Create(k).Error; err != nil {
		return "", nil, err
	}
	return token, k, nil
}

// Verify 用已存储的哈希校验 bearer 令牌。
// 快路径：按前缀（前 8 个字符）匹配。回退路径：为没有前缀的 legacy 密钥做全表扫描。
func (r *AdminAPIKeyRepo) Verify(token string) (*auth.AdminAPIKey, bool) {
	if len(token) >= 8 {
		prefix := token[:8]
		var keys []auth.AdminAPIKey
		if err := r.db.Where("prefix = ?", prefix).Find(&keys).Error; err == nil && len(keys) > 0 {
			for i := range keys {
				if bcrypt.CompareHashAndPassword([]byte(keys[i].TokenHash), []byte(token)) == nil {
					now := time.Now()
					keys[i].LastUsedAt = &now
					_ = r.db.Save(&keys[i]).Error
					return &keys[i], true
				}
			}
		}
	}
	// 回退路径：没有前缀的 legacy 密钥。
	var legacy []auth.AdminAPIKey
	if err := r.db.Where("prefix = '' OR prefix IS NULL").Find(&legacy).Error; err != nil {
		return nil, false
	}
	for i := range legacy {
		if bcrypt.CompareHashAndPassword([]byte(legacy[i].TokenHash), []byte(token)) == nil {
			now := time.Now()
			legacy[i].LastUsedAt = &now
			if len(token) >= 8 {
				legacy[i].Prefix = token[:8]
			}
			_ = r.db.Save(&legacy[i]).Error
			return &legacy[i], true
		}
	}
	return nil, false
}

func (r *AdminAPIKeyRepo) Delete(id uint) error {
	return r.db.Delete(&auth.AdminAPIKey{}, id).Error
}
