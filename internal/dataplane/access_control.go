package dataplane

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/accessgate"
)

// globalAccessSessionStore 全局访问控制会话存储（跨站点共享，token 唯一）。
var globalAccessSessionStore = accessgate.NewMemorySessionStore()

// globalAccessOAuthStateStore 全局 OAuth 流程 state 存储。
var globalAccessOAuthStateStore = accessgate.NewMemoryOAuthStateStore()

func init() {
	go accessSessionCleaner()
}

// accessSessionCleaner 定期清理过期会话和 OAuth state。
func accessSessionCleaner() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		_ = globalAccessSessionStore.CleanExpired()
		_ = globalAccessOAuthStateStore.CleanExpired()
	}
}

// 访问控制网关端点路径常量。
const (
	accessLoginPath         = "/__owaf/access/login"
	accessVerifyPath        = "/__owaf/access/verify"
	accessLogoutPath        = "/__owaf/access/logout"
	accessOAuthStartPrefix  = "/__owaf/access/oauth/start/"
	accessOAuthCallbackPath = "/__owaf/access/oauth/callback"
)

/**
 * buildGateConfig 将 snapshot 中的站点访问控制配置转换为网关运行时配置。
 * 仅携带路径规则与提供方展示信息；OAuth 端点/密钥在流程中按需从 DB 读取。
 *
 * @param ac   snapshot 站点访问控制配置。
 * @param site 站点运行时。
 * @param host 请求 Host。
 * @return 网关配置。
 */
func buildGateConfig(ac *snapshot.AccessControlConfig, site *snapshot.SiteRuntime, host string) accessgate.Config {
	cfg := accessgate.Config{
		Enabled:            ac.Enabled,
		SiteID:             site.Site.ID,
		SiteHost:           host,
		SharedPasswordHash: ac.SharedPasswordHash,
		SessionTTL:         ac.SessionTTL,
	}
	for _, p := range ac.Providers {
		cfg.Providers = append(cfg.Providers, accessgate.ProviderConfig{
			ID:       p.ID,
			Type:     p.Type,
			Name:     p.Name,
			Priority: p.Priority,
		})
	}
	for _, r := range ac.PathRules {
		cfg.PathRules = append(cfg.PathRules, accessgate.PathRule{
			Path:     r.Path,
			Action:   r.Action,
			Priority: r.Priority,
		})
	}
	return cfg
}

/**
 * matchSiteForAccess 独立解析当前请求命中的站点运行时，供 /__owaf/access/* 端点使用。
 *
 * @param c    Hertz 请求上下文。
 * @param opts handler 选项。
 * @return 站点运行时、Host、是否命中。
 */
func matchSiteForAccess(c *app.RequestContext, opts Options) (snapshot.SiteRuntime, string, bool) {
	sn := opts.Holder.Load()
	if sn == nil {
		return snapshot.SiteRuntime{}, "", false
	}
	host := string(c.Host())
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	rt, ok := sn.MatchSite(bind, host)
	return rt, host, ok
}

/**
 * handleAccessControlEndpoints 处理站点访问控制的登录/验证/OAuth/注销端点。
 * 必须在 serveOWAFStatic 之前调用，否则 /__owaf/access/* 会被静态处理器以 404 拦截。
 *
 * @param ctx  请求上下文。
 * @param c    Hertz 请求上下文。
 * @param opts handler 选项。
 * @return true 表示请求已被处理，调用方应直接返回。
 */
func handleAccessControlEndpoints(ctx context.Context, c *app.RequestContext, opts Options) bool {
	path := string(c.Path())
	if !strings.HasPrefix(path, "/__owaf/access/") {
		return false
	}

	rt, host, ok := matchSiteForAccess(c, opts)
	if !ok || rt.AccessControl == nil || !rt.AccessControl.Enabled {
		// 站点未启用访问控制时，这些端点不存在。
		c.String(404, "not found")
		return true
	}
	cfg := buildGateConfig(rt.AccessControl, &rt, host)
	gate := accessgate.NewGate(cfg, globalAccessSessionStore)
	method := string(c.Method())

	switch {
	case path == accessLoginPath && method == "GET":
		errMsg := string(c.QueryArgs().Peek("error"))
		c.Data(200, "text/html; charset=utf-8", accessgate.RenderLoginPage(host, cfg, errMsg))
		return true

	case path == accessVerifyPath && method == "POST":
		handleAccessVerify(c, opts, gate, cfg, host, &rt)
		return true

	case path == accessLogoutPath && method == "POST":
		cookieName := gate.CookieName()
		token := string(c.Cookie(cookieName))
		if token != "" {
			_ = globalAccessSessionStore.Revoke(token)
		}
		clearAccessSessionCookie(c, cookieName, rt.Site.TLSEnabled)
		c.Redirect(302, []byte(accessLoginPath))
		return true

	case strings.HasPrefix(path, accessOAuthStartPrefix) && method == "GET":
		handleAccessOAuthStart(c, opts, gate, &rt, host, strings.TrimPrefix(path, accessOAuthStartPrefix))
		return true

	case path == accessOAuthCallbackPath && method == "GET":
		handleAccessOAuthCallback(ctx, c, opts, gate, &rt, host)
		return true
	}

	c.String(404, "not found")
	return true
}

/**
 * handleAccessVerify 处理共享密码与用户名密码的登录验证。
 * 校验通过后创建会话、下发按站点隔离的 cookie，并重定向回原始 URL。
 */
func handleAccessVerify(c *app.RequestContext, opts Options, gate *accessgate.Gate, cfg accessgate.Config, host string, rt *snapshot.SiteRuntime) {
	authType := string(c.FormValue("auth_type"))
	password := string(c.FormValue("password"))

	var identity, provider string
	switch authType {
	case "shared_password":
		if !gate.VerifySharedPassword(password) {
			renderAccessLoginError(c, host, cfg, "访问密码错误")
			return
		}
		identity, provider = "shared", "shared_password"

	case "user_password":
		username := string(c.FormValue("username"))
		if username == "" || password == "" || opts.AccessControlRepo == nil {
			renderAccessLoginError(c, host, cfg, "用户名或密码错误")
			return
		}
		user, err := opts.AccessControlRepo.GetAccessUserByName(rt.Site.ID, username)
		if err != nil || user == nil || !user.Enabled || !accessgate.VerifyUserPassword(user.PasswordHash, password) {
			renderAccessLoginError(c, host, cfg, "用户名或密码错误")
			return
		}
		identity, provider = username, "user_password"

	default:
		renderAccessLoginError(c, host, cfg, "不支持的验证方式")
		return
	}

	token, err := gate.CreateSession(identity, provider)
	if err != nil {
		renderAccessLoginError(c, host, cfg, "会话创建失败，请重试")
		return
	}
	setAccessSessionCookie(c, gate.CookieName(), token, cfg.SessionTTL, rt.Site.TLSEnabled)
	c.Redirect(302, []byte(accessReturnURL(c)))
}

/**
 * handleAccessOAuthStart 依据 provider 配置构建授权 URL 并重定向到 IdP。
 */
func handleAccessOAuthStart(c *app.RequestContext, opts Options, gate *accessgate.Gate, rt *snapshot.SiteRuntime, host string, idStr string) {
	id64, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id64 == 0 {
		c.String(400, "invalid oauth provider")
		return
	}
	flow, _, ok := loadOAuthFlow(c, rt, host, uint(id64), opts.JWTSecret)
	if !ok {
		c.String(400, "invalid oauth provider")
		return
	}
	returnURL := accessReturnURL(c)
	authURL, err := flow.StartAuthFlow(globalAccessOAuthStateStore, rt.Site.ID, returnURL)
	if err != nil {
		c.String(502, "oauth start failed")
		return
	}
	c.Redirect(302, []byte(authURL))
}

/**
 * handleAccessOAuthCallback 处理 IdP 回调：换取令牌、拉取用户身份并建立会话。
 */
func handleAccessOAuthCallback(_ context.Context, c *app.RequestContext, opts Options, gate *accessgate.Gate, rt *snapshot.SiteRuntime, host string) {
	code := string(c.QueryArgs().Peek("code"))
	stateParam := string(c.QueryArgs().Peek("state"))
	if code == "" || stateParam == "" {
		c.String(400, "missing code or state")
		return
	}
	state, err := globalAccessOAuthStateStore.Get(stateParam)
	if err != nil || state == nil || state.SiteID != rt.Site.ID {
		c.String(400, "invalid or expired state")
		return
	}
	flow, providerName, ok := loadOAuthFlow(c, rt, host, state.ProviderID, opts.JWTSecret)
	if !ok {
		c.String(400, "invalid oauth provider")
		return
	}

	accessToken, err := flow.ExchangeCode(code, state)
	if err != nil {
		c.String(502, "oauth token exchange failed")
		return
	}
	identity, err := flow.FetchUserInfo(accessToken)
	if err != nil {
		c.String(502, "oauth userinfo failed")
		return
	}

	_ = globalAccessOAuthStateStore.Delete(stateParam)

	token, err := gate.CreateSession(identity, providerName)
	if err != nil {
		c.String(500, "session creation failed")
		return
	}
	setAccessSessionCookie(c, gate.CookieName(), token, rt.AccessControl.SessionTTL, rt.Site.TLSEnabled)

	target := state.ReturnURL
	if target == "" || !strings.HasPrefix(target, "/") {
		target = "/"
	}
	c.Redirect(302, []byte(target))
}

/**
 * loadOAuthFlow 从 snapshot 携带的 provider 配置解析出 OAuthFlow。
 * provider.Config 为 JSON；其中 ClientSecret 依赖上层加解密约定，此处按现存内容读取。
 *
 * @return OAuthFlow、提供方名称、是否成功。
 */
func loadOAuthFlow(c *app.RequestContext, rt *snapshot.SiteRuntime, host string, providerID uint, jwtSecret []byte) (*accessgate.OAuthFlow, string, bool) {
	if rt.AccessControl == nil || providerID == 0 {
		return nil, "", false
	}
	var provider *snapshot.AccessControlProvider
	for i := range rt.AccessControl.Providers {
		if rt.AccessControl.Providers[i].ID == providerID {
			provider = &rt.AccessControl.Providers[i]
			break
		}
	}
	if provider == nil {
		return nil, "", false
	}
	if provider.Type != store.AccessProviderOAuth2 && provider.Type != store.AccessProviderOIDC {
		return nil, "", false
	}

	var oc store.OAuthProviderConfig
	if err := json.Unmarshal([]byte(provider.Config), &oc); err != nil {
		return nil, "", false
	}

	scheme := requestProtoFromContext(c)
	redirectURI := scheme + "://" + host + accessOAuthCallbackPath

	flow := &accessgate.OAuthFlow{
		ProviderID:   provider.ID,
		ClientID:     oc.ClientID,
		ClientSecret: decryptOAuthSecret(oc.ClientSecret, jwtSecret),
		AuthURL:      oc.AuthURL,
		TokenURL:     oc.TokenURL,
		UserInfoURL:  oc.UserInfoURL,
		Issuer:       oc.Issuer,
		Scopes:       oc.Scopes,
		RedirectURI:  redirectURI,
		UsePKCE:      oc.UsePKCE || provider.Type == store.AccessProviderOIDC,
	}
	return flow, provider.Name, true
}

/**
 * enforceAccessControl 在 WAF pipeline 之前执行访问控制网关校验。
 * 未通过时按需重定向到登录页或返回 403，并返回 true 表示已终止请求。
 * 认证仅代表身份放行，不跳过后续 WAF 检测。
 *
 * @return true 表示已写响应，调用方应直接返回。
 */
func enforceAccessControl(c *app.RequestContext, rt *snapshot.SiteRuntime, host string, path string) bool {
	if rt.AccessControl == nil || !rt.AccessControl.Enabled {
		return false
	}
	// 访问控制自身端点不受网关拦截，避免登录死循环。
	if strings.HasPrefix(path, "/__owaf/access/") {
		return false
	}

	cfg := buildGateConfig(rt.AccessControl, rt, host)
	gate := accessgate.NewGate(cfg, globalAccessSessionStore)

	token := string(c.Cookie(gate.CookieName()))
	allowed, redirectLogin, denyReason := gate.CheckAccess(token, path)
	if allowed {
		return false
	}
	if redirectLogin {
		c.Redirect(302, []byte(accessLoginPath))
		c.Abort()
		return true
	}
	c.SetStatusCode(403)
	c.SetBodyString(denyReason)
	c.Abort()
	return true
}

// renderAccessLoginError 以 401 状态重新渲染带错误提示的登录页。
func renderAccessLoginError(c *app.RequestContext, host string, cfg accessgate.Config, msg string) {
	c.Data(401, "text/html; charset=utf-8", accessgate.RenderLoginPage(host, cfg, msg))
}

// accessReturnURL 解析验证成功后的跳转地址：优先表单 return_url，其次 Referer，否则根路径。
func accessReturnURL(c *app.RequestContext) string {
	if v := strings.TrimSpace(string(c.FormValue("return_url"))); v != "" && strings.HasPrefix(v, "/") {
		return v
	}
	if ref := strings.TrimSpace(string(c.GetHeader("Referer"))); ref != "" {
		return ref
	}
	return "/"
}

// setAccessSessionCookie 下发按站点隔离的会话 cookie，不记录 cookie 值到日志。
func setAccessSessionCookie(c *app.RequestContext, name, token string, ttl int, secure bool) {
	if ttl <= 0 {
		ttl = 86400
	}
	cookie := name + "=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + strconv.Itoa(ttl)
	if secure {
		cookie += "; Secure"
	}
	c.Response.Header.Add("Set-Cookie", cookie)
}

// clearAccessSessionCookie 清除会话 cookie。
func clearAccessSessionCookie(c *app.RequestContext, name string, secure bool) {
	cookie := name + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
	if secure {
		cookie += "; Secure"
	}
	c.Response.Header.Add("Set-Cookie", cookie)
}

// decryptOAuthSecret 解密 OAuth client_secret（密文为 AES-GCM base64 格式）。
func decryptOAuthSecret(ciphertext string, jwtSecret []byte) string {
	if ciphertext == "" || len(jwtSecret) == 0 {
		return ciphertext
	}
	plain, err := accessgate.DecryptClientSecret(jwtSecret, ciphertext)
	if err != nil {
		return ciphertext
	}
	return plain
}
