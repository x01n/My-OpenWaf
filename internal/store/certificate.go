package store

import (
	"time"

	"gorm.io/gorm"
)

// Certificate stores a TLS certificate + private key pair used by site listeners.
type Certificate struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name    string `gorm:"size:128;not null" json:"name"`
	CertPEM string `gorm:"type:text;not null" json:"cert_pem"`
	KeyPEM  string `gorm:"type:text;not null" json:"key_pem"`
}
