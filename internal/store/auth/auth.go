package auth

import (
	"time"

	"gorm.io/gorm"
)

/**
 * AdminAPIKey 是无需 JWT 即可调用管理 API 的静态 API 令牌。
 *
 * 每个令牌都归属于一个 AdminAccount：令牌的权限取自所属账号的角色，
 * 账号一经删除其令牌随之失效。系统启动时不预置任何令牌。
 */
type AdminAPIKey struct {
	ID         uint           `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
	UserID     uint           `gorm:"index;not null;default:0" json:"user_id"`
	Name       string         `gorm:"size:128" json:"name"`
	Prefix     string         `gorm:"size:16;index" json:"-"`
	TokenHash  string         `gorm:"size:255;not null" json:"-"`
	LastUsedAt *time.Time     `json:"last_used_at,omitempty"`
}

// AdminAccount 表示一个用户名/口令形式的管理员账号。
type AdminAccount struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"size:64;uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	Role         string    `gorm:"size:32;not null;default:'admin'" json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RefreshToken 表示一个 httpOnly refresh-token 会话。
type RefreshToken struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	JTI        string    `gorm:"size:128;uniqueIndex;not null" json:"jti"`
	TokenHash  string    `gorm:"size:255;not null" json:"-"`
	Username   string    `gorm:"size:64;not null;default:''" json:"username"`
	Role       string    `gorm:"size:32;not null;default:'admin'" json:"role"`
	ExpiresAt  time.Time `gorm:"not null" json:"expires_at"`
	Revoked    bool      `gorm:"default:false" json:"revoked"`
	ReplacedBy string    `gorm:"size:128" json:"replaced_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// TokenBlacklist 保存已拉黑的 JTI（吊销 / 强制下线 / 轮换）。
type TokenBlacklist struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	JTI       string    `gorm:"uniqueIndex;size:64" json:"jti"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	Reason    string    `gorm:"size:128" json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// LoginAttempt 记录单次管理员登录尝试。
type LoginAttempt struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	Username  string    `gorm:"index;size:64" json:"username"`
	IP        string    `gorm:"index;size:45" json:"ip"`
	Success   bool      `json:"success"`
	UserAgent string    `gorm:"size:256" json:"user_agent"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// ActiveSession 按 JTI 记录一个活跃的管理员会话。
type ActiveSession struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	Username string `gorm:"index;size:64" json:"username"`
	JTI      string `gorm:"uniqueIndex;size:64" json:"jti"`
	// RefreshJTI 仅用于服务端精确撤销对应的轮换令牌，不向管理端响应暴露。
	RefreshJTI   string    `gorm:"index;size:128" json:"-"`
	IP           string    `gorm:"size:45" json:"ip"`
	UserAgent    string    `gorm:"size:256" json:"user_agent"`
	DeviceInfo   string    `gorm:"size:128" json:"device_info"`
	LoginAt      time.Time `json:"login_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `gorm:"index" json:"expires_at"`
}

// RBAC 角色。
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleReadonly = "readonly"
)
