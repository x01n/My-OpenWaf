package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/**
 * SeedDefaults 确保默认管理员账号存在。
 *
 * 不预置任何 API 令牌：令牌一律由已登录的管理员在自己的账号下主动创建，
 * 因此首次运行只返回管理员口令（非首次运行为空串）。
 *
 * @param db 主数据库句柄。
 * @param adminBind 管理端监听地址（保留参数，当前实现未使用）。
 * @param log 结构化日志器。
 * @return firstRunPassword 首次运行时生成的管理员口令；非首次为空串。
 * @return err 数据库操作错误。
 */
func SeedDefaults(db *gorm.DB, adminBind string, log *slog.Logger) (firstRunPassword string, err error) {
	_ = adminBind

	// 首次运行时为管理员账号生成随机口令。
	var aCount int64
	if err := db.Model(&AdminAccount{}).Where("username = ?", "admin").Count(&aCount).Error; err != nil {
		return "", fmt.Errorf("seed: count admin accounts: %w", err)
	}
	if aCount == 0 {
		password := generateToken(16)
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return "", fmt.Errorf("seed: hash admin password: %w", err)
		}
		a := AdminAccount{
			Username:     "admin",
			PasswordHash: string(hash),
			Role:         RoleAdmin,
		}
		result := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&a)
		if result.Error != nil {
			return "", fmt.Errorf("seed: create admin account: %w", result.Error)
		}
		if result.RowsAffected > 0 {
			firstRunPassword = password
			log.Info("admin account created", slog.String("username", "admin"))
		}
	}

	return firstRunPassword, nil
}

func generateToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("store: failed to generate secure random token: " + err.Error())
	}
	return hex.EncodeToString(b)
}
