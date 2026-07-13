package accessgate

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// 访问控制端点路径常量，数据面路由与登录页表单 action 共用这些字面量。
const (
	// PathLogin 登录页面（GET 展示表单）。
	PathLogin = "/__owaf/access/login"
	// PathVerify 表单提交验证端点（POST，共享密码 / 用户名密码）。
	PathVerify = "/__owaf/access/verify"
	// PathOAuthStartPrefix OAuth 授权发起端点前缀，后接 providerID。
	PathOAuthStartPrefix = "/__owaf/access/oauth/start/"
	// PathOAuthCallback OAuth 回调端点。
	PathOAuthCallback = "/__owaf/access/oauth/callback"
	// PathLogout 注销端点（POST）。
	PathLogout = "/__owaf/access/logout"
)

// 表单字段名常量，登录页模板与验证端点共用。
const (
	FieldAuthType   = "auth_type"
	FieldProviderID = "provider_id"
	FieldUsername   = "username"
	FieldPassword   = "password"
	FieldReturn     = "return"

	// AuthTypeSharedPassword 共享密码验证。
	AuthTypeSharedPassword = "shared_password"
	// AuthTypeUserPassword 本地用户名密码验证。
	AuthTypeUserPassword = "user_password"
)

// errNoProvider 未找到匹配的认证提供方时返回。
var errNoProvider = errors.New("accessgate: provider not found")

// UserLookupFunc 按站点与用户名查询本地用户的 bcrypt 哈希。
// 返回 (哈希, 是否存在)。数据面注入具体的 DB 查询实现，accessgate 本身不依赖存储层。
type UserLookupFunc func(siteID uint, username string) (passwordHash string, ok bool)

// VerifyDecision 描述表单验证的处理决策，由调用方按所用框架落地为响应。
type VerifyDecision struct {
	// Authenticated 为 true 表示验证通过，应写入会话 cookie 并跳转 RedirectURL。
	Authenticated bool
	// Token 验证通过时生成的会话 token。
	Token string
	// Identity 认证身份标识（共享密码为 "shared"，用户名密码为用户名，OAuth 为 email/sub）。
	Identity string
	// Provider 认证方式标签，用于会话记录。
	Provider string
	// RedirectURL 处理完成后应跳转的地址（成功回业务路径，失败回带 error 的登录页）。
	RedirectURL string
	// ErrorMessage 面向用户的错误提示（失败时非空）。
	ErrorMessage string
}

/**
 * sanitizeReturnURL 归一化登录后回跳地址，仅允许站内绝对路径，
 * 防止开放重定向（如 //evil.com 或 https://evil.com）。
 *
 * @param raw 表单或查询参数传入的原始 return 值。
 * @return 安全的站内路径；非法输入回退为 "/"。
 */
func sanitizeReturnURL(raw string) string {
	if raw == "" {
		return "/"
	}
	// 必须是以单个 '/' 开头的站内路径，排除 "//host" 与 "/\host" 形式。
	if raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	return raw
}

/**
 * HandleVerify 处理登录表单提交（共享密码 / 本地用户名密码），返回验证决策。
 * 验证通过时已创建会话，调用方只需写入 cookie（名称取 Gate.CookieName）并跳转。
 * OAuth 提供方不经此端点，走 HandleOAuthStart / HandleOAuthCallback。
 *
 * @param authType   表单 auth_type 字段。
 * @param username   本地用户名（仅 user_password 使用）。
 * @param password   密码明文。
 * @param providerID 本地用户密码提供方 ID（用于确定站点内用户来源，可为 0）。
 * @param returnURL  登录成功后回跳地址（会做站内安全归一化）。
 * @param lookup     本地用户查询函数，可为 nil（此时 user_password 一律失败）。
 * @return 处理决策；调用方据此落地响应。
 */
func (g *Gate) HandleVerify(authType, username, password string, providerID uint, returnURL string, lookup UserLookupFunc) VerifyDecision {
	safeReturn := sanitizeReturnURL(returnURL)

	var identity string
	var verified bool

	switch authType {
	case AuthTypeSharedPassword:
		if g.VerifySharedPassword(password) {
			verified = true
			identity = "shared"
		}
	case AuthTypeUserPassword:
		if lookup != nil && username != "" {
			if hash, ok := lookup(g.config.SiteID, username); ok && VerifyUserPassword(hash, password) {
				verified = true
				identity = username
			}
		}
	default:
		return VerifyDecision{
			Authenticated: false,
			RedirectURL:   loginRedirect(""),
			ErrorMessage:  "不支持的验证方式",
		}
	}

	if !verified {
		return VerifyDecision{
			Authenticated: false,
			RedirectURL:   loginRedirectWithReturn("凭据无效", safeReturn),
			ErrorMessage:  "凭据无效",
		}
	}

	token, err := g.CreateSession(identity, authType)
	if err != nil {
		return VerifyDecision{
			Authenticated: false,
			RedirectURL:   loginRedirectWithReturn("会话创建失败", safeReturn),
			ErrorMessage:  "会话创建失败",
		}
	}

	return VerifyDecision{
		Authenticated: true,
		Token:         token,
		Identity:      identity,
		Provider:      authType,
		RedirectURL:   safeReturn,
	}
}

/**
 * findProvider 按 ID 在配置中定位认证提供方。
 *
 * @param providerID 提供方 ID。
 * @return 命中的提供方配置指针；未命中返回 (nil, errNoProvider)。
 */
func (g *Gate) findProvider(providerID uint) (*ProviderConfig, error) {
	for i := range g.config.Providers {
		if g.config.Providers[i].ID == providerID {
			return &g.config.Providers[i], nil
		}
	}
	return nil, errNoProvider
}

/**
 * NewOAuthFlow 依据提供方运行时配置构造 OAuthFlow。
 * ClientSecret 需为已解密的明文（由数据面调用 DecryptClientSecret 还原后填入 OAuthConfig）。
 * redirectURI 为拼装好的完整回调地址（scheme://host/__owaf/access/oauth/callback）。
 *
 * @param p           提供方配置，其 OAuth 字段承载端点与密钥。
 * @param redirectURI OAuth 回调完整地址。
 * @return 可用于发起授权与令牌交换的 OAuthFlow。
 */
func NewOAuthFlow(p ProviderConfig, redirectURI string) *OAuthFlow {
	oc := p.OAuth
	usePKCE := oc.UsePKCE
	// OIDC 默认启用 PKCE，除非配置显式关闭。
	if p.Type == "oidc" {
		usePKCE = true
	}
	return &OAuthFlow{
		ProviderID:   p.ID,
		ClientID:     oc.ClientID,
		ClientSecret: oc.ClientSecret,
		AuthURL:      oc.AuthURL,
		TokenURL:     oc.TokenURL,
		UserInfoURL:  oc.UserInfoURL,
		Issuer:       oc.Issuer,
		Scopes:       oc.Scopes,
		RedirectURI:  redirectURI,
		UsePKCE:      usePKCE,
	}
}

/**
 * HandleOAuthStart 发起指定提供方的 OAuth 授权流程，返回授权服务器跳转地址。
 * state 会存入 stateStore（含 PKCE code_verifier 与回跳地址），供回调阶段校验。
 *
 * @param providerID  目标 OAuth 提供方 ID。
 * @param redirectURI 本站 OAuth 回调完整地址。
 * @param returnURL   授权成功后最终回跳的业务路径（会做站内安全归一化）。
 * @param stateStore  OAuth state 存储。
 * @return 授权服务器授权地址；提供方不存在或非 OAuth 类型时返回错误。
 */
func (g *Gate) HandleOAuthStart(providerID uint, redirectURI, returnURL string, stateStore OAuthStateStore) (string, error) {
	p, err := g.findProvider(providerID)
	if err != nil {
		return "", err
	}
	if p.Type != "oauth2" && p.Type != "oidc" {
		return "", fmt.Errorf("accessgate: provider %d is not an OAuth provider", providerID)
	}
	flow := NewOAuthFlow(*p, redirectURI)
	return flow.StartAuthFlow(stateStore, g.config.SiteID, sanitizeReturnURL(returnURL))
}

/**
 * HandleOAuthCallback 处理 OAuth 回调：校验 state、换取令牌、拉取用户身份并建立会话。
 * 成功后消费（删除）state，返回可写入 cookie 的决策。
 *
 * @param stateParam  回调 state 参数。
 * @param code        回调 authorization code。
 * @param redirectURI 本站 OAuth 回调完整地址（须与发起时一致）。
 * @param stateStore  OAuth state 存储。
 * @return 处理决策；任一环节失败时 Authenticated=false 且携带错误提示。
 */
func (g *Gate) HandleOAuthCallback(stateParam, code, redirectURI string, stateStore OAuthStateStore) VerifyDecision {
	if stateParam == "" || code == "" {
		return oauthFailure("回调参数缺失", "/")
	}

	st, err := stateStore.Get(stateParam)
	if err != nil || st == nil {
		return oauthFailure("state 无效或已过期", "/")
	}
	// state 一次性消费，防重放。
	_ = stateStore.Delete(stateParam)

	if st.SiteID != g.config.SiteID {
		return oauthFailure("state 站点不匹配", "/")
	}

	returnURL := sanitizeReturnURL(st.ReturnURL)

	p, err := g.findProvider(st.ProviderID)
	if err != nil {
		return oauthFailure("认证提供方不存在", returnURL)
	}

	flow := NewOAuthFlow(*p, redirectURI)

	accessToken, err := flow.ExchangeCode(code, st)
	if err != nil {
		return oauthFailure("令牌交换失败", returnURL)
	}

	identity, err := flow.FetchUserInfo(accessToken)
	if err != nil {
		return oauthFailure("获取用户信息失败", returnURL)
	}

	token, err := g.CreateSession(identity, p.Type)
	if err != nil {
		return oauthFailure("会话创建失败", returnURL)
	}

	return VerifyDecision{
		Authenticated: true,
		Token:         token,
		Identity:      identity,
		Provider:      p.Type,
		RedirectURL:   returnURL,
	}
}

// oauthFailure 构造统一的 OAuth 失败决策，跳回登录页并附带错误提示。
func oauthFailure(msg, returnURL string) VerifyDecision {
	return VerifyDecision{
		Authenticated: false,
		RedirectURL:   loginRedirectWithReturn(msg, sanitizeReturnURL(returnURL)),
		ErrorMessage:  msg,
	}
}

// loginRedirect 构造仅带错误提示的登录页跳转地址。
func loginRedirect(errMsg string) string {
	return loginRedirectWithReturn(errMsg, "")
}

// loginRedirectWithReturn 构造带错误提示与回跳地址的登录页跳转地址。
func loginRedirectWithReturn(errMsg, returnURL string) string {
	var b strings.Builder
	b.WriteString(PathLogin)
	sep := "?"
	if errMsg != "" {
		b.WriteString(sep)
		b.WriteString("error=")
		b.WriteString(url.QueryEscape(errMsg))
		sep = "&"
	}
	if returnURL != "" && returnURL != "/" {
		b.WriteString(sep)
		b.WriteString("return=")
		b.WriteString(url.QueryEscape(returnURL))
	}
	return b.String()
}
