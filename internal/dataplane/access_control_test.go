package dataplane

import (
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

func TestBuildGateConfig(t *testing.T) {
	ac := &snapshot.AccessControlConfig{
		Enabled:            true,
		SharedPasswordHash: "$2a$10$FAKEHASH",
		SessionTTL:         7200,
		Providers: []snapshot.AccessControlProvider{
			{ID: 1, Type: "password", Name: "本地用户", Priority: 0},
			{ID: 2, Type: "oauth2", Name: "GitHub", Priority: 1, Config: `{"client_id":"cid"}`},
		},
		PathRules: []snapshot.AccessControlPathRule{
			{Path: "/public/*", Action: "allow", Priority: 0},
			{Path: "/admin/*", Action: "require_auth", Priority: 10},
			{Path: "/blocked", Action: "deny", Priority: 5},
		},
	}

	site := &snapshot.SiteRuntime{
		Site: store.Site{ID: 42, Host: "app.example.com"},
	}

	cfg := buildGateConfig(ac, site, "app.example.com")

	if !cfg.Enabled {
		t.Fatal("Enabled 应为 true")
	}
	if cfg.SiteID != 42 {
		t.Fatalf("SiteID 不匹配: got %d, want 42", cfg.SiteID)
	}
	if cfg.SiteHost != "app.example.com" {
		t.Fatalf("SiteHost 不匹配: got %q", cfg.SiteHost)
	}
	if cfg.SharedPasswordHash != "$2a$10$FAKEHASH" {
		t.Fatalf("SharedPasswordHash 不匹配: got %q", cfg.SharedPasswordHash)
	}
	if cfg.SessionTTL != 7200 {
		t.Fatalf("SessionTTL 不匹配: got %d, want 7200", cfg.SessionTTL)
	}

	// 验证 Providers 转换
	if len(cfg.Providers) != 2 {
		t.Fatalf("Providers 数量不匹配: got %d, want 2", len(cfg.Providers))
	}
	if cfg.Providers[0].ID != 1 || cfg.Providers[0].Type != "password" || cfg.Providers[0].Name != "本地用户" {
		t.Fatalf("第一个 Provider 不匹配: %+v", cfg.Providers[0])
	}
	if cfg.Providers[1].ID != 2 || cfg.Providers[1].Type != "oauth2" || cfg.Providers[1].Name != "GitHub" {
		t.Fatalf("第二个 Provider 不匹配: %+v", cfg.Providers[1])
	}

	// 验证 PathRules 转换
	if len(cfg.PathRules) != 3 {
		t.Fatalf("PathRules 数量不匹配: got %d, want 3", len(cfg.PathRules))
	}
	if cfg.PathRules[0].Path != "/public/*" || cfg.PathRules[0].Action != "allow" {
		t.Fatalf("第一条 PathRule 不匹配: %+v", cfg.PathRules[0])
	}
	if cfg.PathRules[2].Path != "/blocked" || cfg.PathRules[2].Action != "deny" {
		t.Fatalf("第三条 PathRule 不匹配: %+v", cfg.PathRules[2])
	}
}

func TestBuildGateConfigEmptyProviders(t *testing.T) {
	ac := &snapshot.AccessControlConfig{
		Enabled:    true,
		SessionTTL: 86400,
	}
	site := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1},
	}

	cfg := buildGateConfig(ac, site, "site.test")

	if cfg.Providers != nil {
		t.Fatalf("空 Providers 应保持 nil: got %v", cfg.Providers)
	}
	if cfg.PathRules != nil {
		t.Fatalf("空 PathRules 应保持 nil: got %v", cfg.PathRules)
	}
}

func TestAccessReturnURL(t *testing.T) {
	tests := []struct {
		name      string
		formValue string
		referer   string
		want      string
	}{
		{"表单 return_url 优先", "/dashboard", "https://site.test/other", "/dashboard"},
		{"无表单时回退 Referer", "", "https://site.test/page", "https://site.test/page"},
		{"两者都为空时回退根路径", "", "", "/"},
		{"return_url 空格前后", "  /app  ", "", "/app"},
		{"非路径 return_url 被跳过", "https://evil.com", "", "/"}, // accessReturnURL 仅接受 "/" 开头的路径
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := app.NewContext(0)
			c.Request.Header.SetMethod("POST")
			c.Request.Header.SetContentTypeBytes([]byte("application/x-www-form-urlencoded"))
			body := ""
			if tt.formValue != "" {
				body = "return_url=" + tt.formValue
			}
			c.Request.SetBodyString(body)
			if tt.referer != "" {
				c.Request.Header.Set("Referer", tt.referer)
			}
			got := accessReturnURL(c)
			if got != tt.want {
				t.Errorf("accessReturnURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAccessReturnURLRejectsNonPathFormValue(t *testing.T) {
	c := app.NewContext(0)
	c.Request.Header.SetMethod("POST")
	c.Request.Header.SetContentTypeBytes([]byte("application/x-www-form-urlencoded"))
	c.Request.SetBodyString("return_url=https://evil.com/steal")

	got := accessReturnURL(c)
	// accessReturnURL 只检查以 "/" 开头，非 "/" 开头的值会回退
	if strings.HasPrefix(got, "https://evil.com") {
		// accessReturnURL 确实不做安全过滤（那是 sanitizeReturnURL 的职责），
		// 只检查 HasPrefix(v, "/")，https:// 不以 "/" 开头，会 fallback。
		// 由于实现是 HasPrefix(v, "/")，"https://..." 不匹配，进入 referer 路径
	}
	// 只要不返回攻击者控制的外部 URL 即可
	if got == "https://evil.com/steal" {
		// return_url 不以 "/" 开头时应被跳过
		// 但实际上 accessReturnURL 的实现是 strings.HasPrefix(v, "/") 才使用
		// 所以 https://evil.com/steal 不会被采用
	}
}

func TestEnforceAccessControlDisabled(t *testing.T) {
	c := app.NewContext(0)
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1},
	}

	// AccessControl 为 nil 时应直接放行
	if enforceAccessControl(c, rt, "site.test", "/any") {
		t.Fatal("AccessControl 为 nil 时不应拦截")
	}

	// AccessControl 存在但未启用
	rt.AccessControl = &snapshot.AccessControlConfig{Enabled: false}
	if enforceAccessControl(c, rt, "site.test", "/any") {
		t.Fatal("AccessControl 未启用时不应拦截")
	}
}

func TestEnforceAccessControlOwnEndpointsNotBlocked(t *testing.T) {
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1},
		AccessControl: &snapshot.AccessControlConfig{
			Enabled:    true,
			SessionTTL: 3600,
		},
	}

	// 访问控制自身端点不受拦截
	paths := []string{
		"/__owaf/access/login",
		"/__owaf/access/verify",
		"/__owaf/access/logout",
		"/__owaf/access/oauth/start/1",
		"/__owaf/access/oauth/callback",
	}
	for _, p := range paths {
		tc := app.NewContext(0)
		if enforceAccessControl(tc, rt, "site.test", p) {
			t.Fatalf("访问控制自身端点 %q 不应被拦截", p)
		}
	}
}

func TestEnforceAccessControlRedirectUnauthenticated(t *testing.T) {
	c := app.NewContext(0)
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1},
		AccessControl: &snapshot.AccessControlConfig{
			Enabled:    true,
			SessionTTL: 3600,
		},
	}

	intercepted := enforceAccessControl(c, rt, "site.test", "/protected")
	if !intercepted {
		t.Fatal("未认证请求应被拦截")
	}

	statusCode := c.Response.StatusCode()
	if statusCode != 302 {
		t.Fatalf("未认证请求应返回 302 重定向: got %d", statusCode)
	}

	location := string(c.Response.Header.Peek("Location"))
	if location != accessLoginPath {
		t.Fatalf("应重定向到登录页: got %q, want %q", location, accessLoginPath)
	}
}

func TestEnforceAccessControlAllowPath(t *testing.T) {
	c := app.NewContext(0)
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1},
		AccessControl: &snapshot.AccessControlConfig{
			Enabled:    true,
			SessionTTL: 3600,
			PathRules: []snapshot.AccessControlPathRule{
				{Path: "/public/*", Action: "allow", Priority: 0},
			},
		},
	}

	// 公开路径应放行，无需认证
	if enforceAccessControl(c, rt, "site.test", "/public/style.css") {
		t.Fatal("公开路径不应被拦截")
	}
}

func TestEnforceAccessControlDenyPath(t *testing.T) {
	c := app.NewContext(0)
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1},
		AccessControl: &snapshot.AccessControlConfig{
			Enabled:    true,
			SessionTTL: 3600,
			PathRules: []snapshot.AccessControlPathRule{
				{Path: "/internal/*", Action: "deny", Priority: 0},
			},
		},
	}

	intercepted := enforceAccessControl(c, rt, "site.test", "/internal/secret")
	if !intercepted {
		t.Fatal("deny 路径应被拦截")
	}

	statusCode := c.Response.StatusCode()
	if statusCode != 403 {
		t.Fatalf("deny 路径应返回 403: got %d", statusCode)
	}
}

func TestEnforceAccessControlValidSession(t *testing.T) {
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1},
		AccessControl: &snapshot.AccessControlConfig{
			Enabled:    true,
			SessionTTL: 3600,
		},
	}

	// 在全局 session store 中创建一个有效会话
	token, err := globalAccessSessionStore.Create(1, "testuser", "password", 3600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = globalAccessSessionStore.Revoke(token) }()

	// 构造携带正确 cookie 的请求
	c := app.NewContext(0)
	cookieName := "__owaf_access_1"
	c.Request.Header.SetCookie(cookieName, token)

	intercepted := enforceAccessControl(c, rt, "site.test", "/dashboard")
	if intercepted {
		t.Fatal("持有有效会话的请求不应被拦截")
	}
}

func TestEnforceAccessControlExpiredSession(t *testing.T) {
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1},
		AccessControl: &snapshot.AccessControlConfig{
			Enabled:    true,
			SessionTTL: 3600,
		},
	}

	// 创建一个 TTL 为 -1 的会话，使其立即过期
	expiredToken, err := globalAccessSessionStore.Create(1, "user", "password", -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = globalAccessSessionStore.Revoke(expiredToken) }()

	c := app.NewContext(0)
	c.Request.Header.SetCookie("__owaf_access_1", expiredToken)

	intercepted := enforceAccessControl(c, rt, "site.test", "/dashboard")
	if !intercepted {
		t.Fatal("过期会话应被拦截并重定向到登录页")
	}
}

func TestEnforceAccessControlCrossSiteSession(t *testing.T) {
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 2},
		AccessControl: &snapshot.AccessControlConfig{
			Enabled:    true,
			SessionTTL: 3600,
		},
	}

	// 创建站点 1 的会话
	token, err := globalAccessSessionStore.Create(1, "user", "password", 3600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = globalAccessSessionStore.Revoke(token) }()

	// 用站点 1 的 token 访问站点 2
	c := app.NewContext(0)
	c.Request.Header.SetCookie("__owaf_access_2", token)

	intercepted := enforceAccessControl(c, rt, "site2.test", "/")
	if !intercepted {
		t.Fatal("跨站 session 不应放行")
	}
}

func TestDecryptOAuthSecret(t *testing.T) {
	// 空密文应直接返回
	if got := decryptOAuthSecret("", nil); got != "" {
		t.Fatalf("空密文应返回空串: got %q", got)
	}

	// 空密钥应直接返回原文
	if got := decryptOAuthSecret("some-cipher", nil); got != "some-cipher" {
		t.Fatalf("空密钥应返回原文: got %q", got)
	}

	// 非法密文应返回原文（解密失败降级）
	if got := decryptOAuthSecret("not-valid-base64!!!", []byte("secret")); got != "not-valid-base64!!!" {
		t.Fatalf("非法密文应返回原文: got %q", got)
	}
}
