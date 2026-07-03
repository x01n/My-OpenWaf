package store

import (
	"time"

	"gorm.io/gorm"
)

// CertSourceManual 手动上传证书。
const CertSourceManual = "manual"

// CertSourceACME 通过 ACME 自动申请的证书。
const CertSourceACME = "acme"

// CertSourceSelfSigned 自签证书。
const CertSourceSelfSigned = "self_signed"

// Certificate stores a TLS certificate + private key pair used by site listeners.
type Certificate struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name    string `gorm:"size:128;not null" json:"name"`
	CertPEM string `gorm:"type:text;not null" json:"cert_pem"`
	KeyPEM  string `gorm:"type:text;not null" json:"key_pem"`
	// OCSPStaplePEM stores an optional OCSP response in PEM or raw DER form.
	OCSPStaplePEM string `gorm:"type:text" json:"ocsp_staple_pem,omitempty"`

	// ACME 相关字段
	Source      string     `gorm:"size:32;default:manual" json:"source"`
	Domain      string     `gorm:"size:255" json:"domain,omitempty"`
	ACMEEmail   string     `gorm:"size:255" json:"acme_email,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	AutoRenew   bool       `gorm:"default:false" json:"auto_renew"`
	LastRenewAt *time.Time `json:"last_renew_at,omitempty"`
	RenewError  string     `gorm:"size:512" json:"renew_error,omitempty"`
}
