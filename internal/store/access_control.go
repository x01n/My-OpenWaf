package store

import "time"

// 访问控制的认证提供方类型常量。
const (
	AccessProviderPassword = "password"
	AccessProviderOAuth2   = "oauth2"
	AccessProviderOIDC     = "oidc"
)

// 访问控制路径规则的动作常量。
const (
	AccessActionRequireAuth = "require_auth"
	AccessActionAllow       = "allow"
	AccessActionDeny        = "deny"
)

// SiteAccessConfig 站点访问控制配置，每个站点最多一条。
type SiteAccessConfig struct {
	ID      uint `gorm:"primarykey" json:"id"`
	SiteID  uint `gorm:"uniqueIndex;not null" json:"site_id"` // 关联 Site.ID
	Enabled bool `gorm:"default:false" json:"enabled"`
	// SharedPasswordHash 共享密码的 bcrypt 哈希，不可逆存储。
	SharedPasswordHash string `gorm:"size:255" json:"-"`
	// SessionTTL 会话有效期（秒），默认 24 小时。
	SessionTTL int       `gorm:"default:86400" json:"session_ttl"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AccessProvider 认证提供方，一个站点可配置多个。
type AccessProvider struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	SiteID   uint   `gorm:"index;not null" json:"site_id"`
	Type     string `gorm:"size:20;not null" json:"type"`  // password, oauth2, oidc
	Name     string `gorm:"size:100;not null" json:"name"` // 显示名称
	Priority int    `gorm:"default:0" json:"priority"`     // 排序，数字越小越靠前
	Enabled  bool   `gorm:"default:true" json:"enabled"`
	// Config 为 OAuth2/OIDC 配置的 JSON 序列化（OAuthProviderConfig）。
	Config    string    `gorm:"type:text" json:"config,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AccessUser 本地用户名密码，按站点隔离。
type AccessUser struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	SiteID   uint   `gorm:"not null;uniqueIndex:ux_access_user_site_name" json:"site_id"`
	Username string `gorm:"size:100;not null;uniqueIndex:ux_access_user_site_name" json:"username"`
	// PasswordHash bcrypt 哈希，不可逆存储。
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	Enabled      bool      `gorm:"default:true" json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AccessPathRule 路径访问控制规则。
type AccessPathRule struct {
	ID     uint   `gorm:"primarykey" json:"id"`
	SiteID uint   `gorm:"index;not null" json:"site_id"`
	Path   string `gorm:"size:500;not null" json:"path"` // 路径模式
	// Action 取值 require_auth, allow, deny。
	Action    string    `gorm:"size:20;not null;default:'require_auth'" json:"action"`
	Priority  int       `gorm:"default:0" json:"priority"` // 优先级，数字越小越先匹配
	Enabled   bool      `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AccessSession 访问控制会话。
type AccessSession struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	SiteID    uint      `gorm:"index;not null" json:"site_id"`
	Token     string    `gorm:"uniqueIndex;size:64;not null" json:"-"` // 会话 token
	Identity  string    `gorm:"size:255" json:"identity"`              // 认证身份标识
	Provider  string    `gorm:"size:20" json:"provider"`               // 认证方式
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// OAuthProviderConfig 为 OAuth2/OIDC 提供方的配置，仅用于 JSON 编解码，不直接落库。
type OAuthProviderConfig struct {
	ClientID string `json:"client_id"`
	// ClientSecret 必须由上层以 AES-GCM 可逆加密后再写入 AccessProvider.Config。
	ClientSecret string   `json:"client_secret"`
	AuthURL      string   `json:"auth_url,omitempty"`     // OAuth2 直接配置的授权端点
	TokenURL     string   `json:"token_url,omitempty"`    // OAuth2 直接配置的令牌端点
	UserInfoURL  string   `json:"userinfo_url,omitempty"` // OAuth2 直接配置的用户信息端点
	Issuer       string   `json:"issuer,omitempty"`       // 设置后使用 .well-known/openid-configuration 发现
	Scopes       []string `json:"scopes,omitempty"`
	RedirectPath string   `json:"redirect_path,omitempty"` // 默认 /__owaf/auth/callback
	UsePKCE      bool     `json:"use_pkce"`                // OIDC 默认启用
}
