package store

import (
	"time"

	"gorm.io/gorm"
)

// AdminAPIKey is a static API token used to call the admin API without JWT.
type AdminAPIKey struct {
	ID         uint           `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
	Name       string         `gorm:"size:128" json:"name"`
	Prefix     string         `gorm:"size:16;index" json:"-"`
	TokenHash  string         `gorm:"size:255;not null" json:"-"`
	LastUsedAt *time.Time     `json:"last_used_at,omitempty"`
}

// AdminAccount represents a username/password admin user.
type AdminAccount struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"size:64;uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	Role         string    `gorm:"size:32;not null;default:'admin'" json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RefreshToken represents an httpOnly refresh-token session.
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

// TokenBlacklist holds blacklisted JTIs (revoked / forced logout / rotated).
type TokenBlacklist struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	JTI       string    `gorm:"uniqueIndex;size:64" json:"jti"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	Reason    string    `gorm:"size:128" json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// LoginAttempt records a single admin login attempt.
type LoginAttempt struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	Username  string    `gorm:"index;size:64" json:"username"`
	IP        string    `gorm:"index;size:45" json:"ip"`
	Success   bool      `json:"success"`
	UserAgent string    `gorm:"size:256" json:"user_agent"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// ActiveSession records an active admin session by JTI.
type ActiveSession struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	Username     string    `gorm:"index;size:64" json:"username"`
	JTI          string    `gorm:"uniqueIndex;size:64" json:"jti"`
	IP           string    `gorm:"size:45" json:"ip"`
	UserAgent    string    `gorm:"size:256" json:"user_agent"`
	DeviceInfo   string    `gorm:"size:128" json:"device_info"`
	LoginAt      time.Time `json:"login_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `gorm:"index" json:"expires_at"`
}

// RBAC roles.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleReadonly = "readonly"
)
