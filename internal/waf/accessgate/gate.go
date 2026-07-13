// Package accessgate 实现数据面站点访问控制网关。
package accessgate

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config 访问控制运行时配置（从 snapshot 加载）。
type Config struct {
	Enabled            bool
	SiteID             uint
	SiteHost           string
	SharedPasswordHash string
	SessionTTL         int
	Providers          []ProviderConfig
	PathRules          []PathRule
}

// ProviderConfig 认证提供方运行时配置。
type ProviderConfig struct {
	ID       uint
	Type     string // "password", "oauth2", "oidc"
	Name     string
	Priority int
	OAuth    OAuthConfig
}

// OAuthConfig OAuth2/OIDC 提供方配置。
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Issuer       string
	Scopes       []string
	RedirectPath string
	UsePKCE      bool
}

// PathRule 路径访问控制规则。
type PathRule struct {
	Path     string
	Action   string // "require_auth", "allow", "deny"
	Priority int
}

// SessionInfo 会话信息。
type SessionInfo struct {
	SiteID    uint
	Token     string
	Identity  string
	Provider  string
	ExpiresAt time.Time
}

// SessionStore 会话存储接口。
type SessionStore interface {
	Create(siteID uint, identity string, provider string, ttl int) (token string, err error)
	Validate(token string) (*SessionInfo, error)
	Revoke(token string) error
	CleanExpired() error
}

// Gate 站点访问控制网关。
type Gate struct {
	config Config
	store  SessionStore
}

// NewGate 创建访问控制网关实例。
func NewGate(cfg Config, store SessionStore) *Gate {
	return &Gate{config: cfg, store: store}
}

// CheckAccess 检查请求是否已通过访问控制。
// 返回: allowed=true 放行, redirectLogin=true 需要重定向到登录页。
func (g *Gate) CheckAccess(sessionToken string, path string) (allowed bool, redirectLogin bool, denyReason string) {
	if !g.config.Enabled {
		return true, false, ""
	}

	action := g.matchPathAction(path)
	switch action {
	case "allow":
		return true, false, ""
	case "deny":
		return false, false, "access denied"
	}

	// action == "require_auth"
	if sessionToken == "" {
		return false, true, ""
	}

	session, err := g.store.Validate(sessionToken)
	if err != nil || session == nil {
		return false, true, ""
	}
	if session.SiteID != g.config.SiteID {
		return false, true, ""
	}
	if time.Now().After(session.ExpiresAt) {
		return false, true, ""
	}

	return true, false, ""
}

// matchPathAction 按优先级首匹配路径规则。
func (g *Gate) matchPathAction(path string) string {
	for _, rule := range g.config.PathRules {
		if matchPathPattern(path, rule.Path) {
			return rule.Action
		}
	}
	return "require_auth"
}

// VerifySharedPassword 验证共享密码。
func (g *Gate) VerifySharedPassword(password string) bool {
	if g.config.SharedPasswordHash == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(g.config.SharedPasswordHash), []byte(password))
	return err == nil
}

// VerifyUserPassword 验证用户名密码（需外部查询存储）。
func VerifyUserPassword(storedHash string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	return err == nil
}

// CreateSession 创建新会话。
func (g *Gate) CreateSession(identity string, provider string) (token string, err error) {
	return g.store.Create(g.config.SiteID, identity, provider, g.config.SessionTTL)
}

// HasSharedPassword 是否配置了共享密码。
func (g *Gate) HasSharedPassword() bool {
	return g.config.SharedPasswordHash != ""
}

// HasProviders 是否配置了认证提供方。
func (g *Gate) HasProviders() bool {
	return len(g.config.Providers) > 0
}

// CookieName 返回当前站点的访问控制 cookie 名称（按站点隔离）。
func (g *Gate) CookieName() string {
	return fmt.Sprintf("__owaf_access_%d", g.config.SiteID)
}

// SetSessionCookie 设置会话 cookie。
func (g *Gate) SetSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     g.CookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   g.config.SessionTTL,
	})
}

// ClearSessionCookie 清除会话 cookie。
func (g *Gate) ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     g.CookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// GenerateToken 生成安全随机 token。
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// matchPathPattern 路径模式匹配。
func matchPathPattern(path, pattern string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-2]
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, pattern[:len(pattern)-1])
	}
	return path == pattern
}
