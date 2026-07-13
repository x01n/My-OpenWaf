package access

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// validProviderTypes 认证提供方允许的类型集合。
var validProviderTypes = map[string]bool{
	store.AccessProviderPassword: true,
	store.AccessProviderOAuth2:   true,
	store.AccessProviderOIDC:     true,
}

// CreateProviderReq 创建认证提供方的请求体。
type CreateProviderReq struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Enabled  *bool  `json:"enabled,omitempty"`
	// Config 为 OAuthProviderConfig 的 JSON，仅 oauth2/oidc 类型需要。
	Config json.RawMessage `json:"config,omitempty"`
}

// UpdateProviderReq 更新认证提供方的请求体，字段为空则保持原值。
type UpdateProviderReq struct {
	Name     *string         `json:"name,omitempty"`
	Priority *int            `json:"priority,omitempty"`
	Enabled  *bool           `json:"enabled,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
}

// providerResp 认证提供方的脱敏响应体，OAuth client_secret 仅回显遮蔽值。
type providerResp struct {
	ID        uint             `json:"id"`
	SiteID    uint             `json:"site_id"`
	Type      string           `json:"type"`
	Name      string           `json:"name"`
	Priority  int              `json:"priority"`
	Enabled   bool             `json:"enabled"`
	Config    *maskedOAuthResp `json:"config,omitempty"`
	CreatedAt string           `json:"created_at,omitempty"`
	UpdatedAt string           `json:"updated_at,omitempty"`
}

// maskedOAuthResp 为 OAuthProviderConfig 的脱敏视图，client_secret 遮蔽处理。
type maskedOAuthResp struct {
	ClientID         string   `json:"client_id"`
	ClientSecretMask string   `json:"client_secret_mask,omitempty"`
	ClientSecretSet  bool     `json:"client_secret_set"`
	AuthURL          string   `json:"auth_url,omitempty"`
	TokenURL         string   `json:"token_url,omitempty"`
	UserInfoURL      string   `json:"userinfo_url,omitempty"`
	Issuer           string   `json:"issuer,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	RedirectPath     string   `json:"redirect_path,omitempty"`
	UsePKCE          bool     `json:"use_pkce"`
}

/**
 * newProviderResp 将存储模型转换为脱敏响应体，OAuth 密钥仅回显遮蔽值。
 *
 * @param p         认证提供方存储模型。
 * @param jwtSecret JWT 主密钥，用于解密后再遮蔽 client_secret。
 * @return 脱敏后的响应体。
 */
func newProviderResp(p *store.AccessProvider, jwtSecret []byte) providerResp {
	resp := providerResp{
		ID:        p.ID,
		SiteID:    p.SiteID,
		Type:      p.Type,
		Name:      p.Name,
		Priority:  p.Priority,
		Enabled:   p.Enabled,
		CreatedAt: p.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: p.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if p.Config == "" {
		return resp
	}
	var cfg store.OAuthProviderConfig
	if json.Unmarshal([]byte(p.Config), &cfg) != nil {
		return resp
	}
	plainSecret, _ := decryptClientSecret(jwtSecret, cfg.ClientSecret)
	resp.Config = &maskedOAuthResp{
		ClientID:         cfg.ClientID,
		ClientSecretMask: maskClientSecret(plainSecret),
		ClientSecretSet:  cfg.ClientSecret != "",
		AuthURL:          cfg.AuthURL,
		TokenURL:         cfg.TokenURL,
		UserInfoURL:      cfg.UserInfoURL,
		Issuer:           cfg.Issuer,
		Scopes:           cfg.Scopes,
		RedirectPath:     cfg.RedirectPath,
		UsePKCE:          cfg.UsePKCE,
	}
	return resp
}

/**
 * encodeProviderConfig 校验并加密 OAuthProviderConfig，返回可落库的 JSON。
 * client_secret 以 AES-256-GCM 加密后写入，其余字段保持明文。
 *
 * @param raw       请求中的 OAuthProviderConfig JSON。
 * @param jwtSecret JWT 主密钥，用于加密 client_secret。
 * @param prevJSON  既有配置 JSON，client_secret 为空时沿用旧密文。
 * @return 加密后的配置 JSON。
 */
func encodeProviderConfig(raw json.RawMessage, jwtSecret []byte, prevJSON string) (string, error) {
	var cfg store.OAuthProviderConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", errors.New("invalid oauth config")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return "", errors.New("client_id is required for oauth/oidc provider")
	}
	// client_secret 为空时沿用既有密文，避免更新其它字段时误清空密钥。
	if cfg.ClientSecret == "" {
		if prev := previousClientSecret(prevJSON); prev != "" {
			cfg.ClientSecret = prev
		}
	} else {
		enc, err := encryptClientSecret(jwtSecret, cfg.ClientSecret)
		if err != nil {
			return "", errors.New("failed to encrypt client_secret")
		}
		cfg.ClientSecret = enc
	}
	data, err := json.Marshal(&cfg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

/**
 * previousClientSecret 从既有配置 JSON 中取出已加密的 client_secret 密文。
 *
 * @param prevJSON 既有配置 JSON。
 * @return 既有的 client_secret 密文；无法解析时返回空字符串。
 */
func previousClientSecret(prevJSON string) string {
	if prevJSON == "" {
		return ""
	}
	var prev store.OAuthProviderConfig
	if json.Unmarshal([]byte(prevJSON), &prev) != nil {
		return ""
	}
	return prev.ClientSecret
}

/**
 * ListProviders 按优先级列出站点的认证提供方，OAuth 密钥脱敏。
 *
 * @param repo      访问控制仓库。
 * @param jwtSecret JWT 主密钥，用于解密后遮蔽 client_secret。
 * @return Hertz 处理器。
 */
func ListProviders(repo *repository.AccessControlRepo, jwtSecret []byte) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		providers, err := repo.ListAccessProviders(siteID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		out := make([]providerResp, 0, len(providers))
		for i := range providers {
			out = append(out, newProviderResp(&providers[i], jwtSecret))
		}
		c.JSON(200, map[string]any{"site_id": siteID, "providers": out})
	}
}

/**
 * CreateProvider 为站点创建认证提供方，OAuth client_secret 加密后存储。
 *
 * @param repo      访问控制仓库。
 * @param reload    snapshot 重建回调。
 * @param jwtSecret JWT 主密钥，用于加密 client_secret。
 * @return Hertz 处理器。
 */
func CreateProvider(repo *repository.AccessControlRepo, reload func() error, jwtSecret []byte) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		var req CreateProviderReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		if !validProviderTypes[req.Type] {
			c.JSON(400, map[string]string{"error": "invalid type, must be one of password, oauth2, oidc"})
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			c.JSON(400, map[string]string{"error": "name is required"})
			return
		}
		provider := &store.AccessProvider{
			SiteID:   siteID,
			Type:     req.Type,
			Name:     req.Name,
			Priority: req.Priority,
			Enabled:  true,
		}
		if req.Enabled != nil {
			provider.Enabled = *req.Enabled
		}
		if req.Type != store.AccessProviderPassword {
			if len(req.Config) == 0 {
				c.JSON(400, map[string]string{"error": "config is required for oauth/oidc provider"})
				return
			}
			cfgJSON, cerr := encodeProviderConfig(req.Config, jwtSecret, "")
			if cerr != nil {
				c.JSON(400, map[string]string{"error": cerr.Error()})
				return
			}
			provider.Config = cfgJSON
		}
		if err := repo.CreateAccessProvider(provider); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "provider created but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, newProviderResp(provider, jwtSecret))
	}
}

/**
 * UpdateProvider 更新站点认证提供方，仅覆盖请求中提供的字段。
 *
 * @param repo      访问控制仓库。
 * @param reload    snapshot 重建回调。
 * @param jwtSecret JWT 主密钥，用于加密 client_secret。
 * @return Hertz 处理器。
 */
func UpdateProvider(repo *repository.AccessControlRepo, reload func() error, jwtSecret []byte) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		providerID, err := utils.ParseUint(c.Param("pid"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid provider id"})
			return
		}
		var req UpdateProviderReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		provider, err := findSiteProvider(repo, siteID, providerID)
		if err != nil {
			c.JSON(404, map[string]string{"error": "provider not found"})
			return
		}
		if req.Name != nil {
			name := strings.TrimSpace(*req.Name)
			if name == "" {
				c.JSON(400, map[string]string{"error": "name cannot be empty"})
				return
			}
			provider.Name = name
		}
		if req.Priority != nil {
			provider.Priority = *req.Priority
		}
		if req.Enabled != nil {
			provider.Enabled = *req.Enabled
		}
		if len(req.Config) > 0 && provider.Type != store.AccessProviderPassword {
			cfgJSON, cerr := encodeProviderConfig(req.Config, jwtSecret, provider.Config)
			if cerr != nil {
				c.JSON(400, map[string]string{"error": cerr.Error()})
				return
			}
			provider.Config = cfgJSON
		}
		if err := repo.UpdateAccessProvider(provider); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "provider updated but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, newProviderResp(provider, jwtSecret))
	}
}

/**
 * DeleteProvider 删除站点认证提供方。
 *
 * @param repo   访问控制仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func DeleteProvider(repo *repository.AccessControlRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		providerID, err := utils.ParseUint(c.Param("pid"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid provider id"})
			return
		}
		if _, err := findSiteProvider(repo, siteID, providerID); err != nil {
			c.JSON(404, map[string]string{"error": "provider not found"})
			return
		}
		if err := repo.DeleteAccessProvider(providerID); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "provider deleted but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"site_id": siteID, "id": providerID, "deleted": true})
	}
}

/**
 * findSiteProvider 在指定站点范围内按 ID 查找提供方，防止跨站点越权访问。
 *
 * @param repo       访问控制仓库。
 * @param siteID     站点 ID。
 * @param providerID 提供方 ID。
 * @return 命中的提供方；未找到或不属于该站点时返回错误。
 */
func findSiteProvider(repo *repository.AccessControlRepo, siteID, providerID uint) (*store.AccessProvider, error) {
	providers, err := repo.ListAccessProviders(siteID)
	if err != nil {
		return nil, err
	}
	for i := range providers {
		if providers[i].ID == providerID {
			return &providers[i], nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}
