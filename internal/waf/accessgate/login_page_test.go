package accessgate

import (
	"strings"
	"testing"
)

func TestRenderLoginPageBasicElements(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		SiteID:             1,
		SiteHost:           "app.example.com",
		SharedPasswordHash: "$2a$10$XXXXXXXXX",
		Providers: []ProviderConfig{
			{ID: 1, Type: "password", Name: "本地用户"},
			{ID: 2, Type: "oauth2", Name: "GitHub"},
		},
	}

	html := string(RenderLoginPage("app.example.com", cfg, ""))

	// 验证基本 HTML 结构
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Fatal("应包含 DOCTYPE 声明")
	}
	if !strings.Contains(html, "<html") {
		t.Fatal("应包含 html 标签")
	}
	if !strings.Contains(html, "app.example.com") {
		t.Fatal("应包含站点 Host")
	}
	if !strings.Contains(html, "访问验证") {
		t.Fatal("应包含标题文本")
	}

	// 共享密码表单
	if !strings.Contains(html, `name="auth_type" value="shared_password"`) {
		t.Fatal("应包含共享密码验证表单的 auth_type 隐藏字段")
	}
	if !strings.Contains(html, `type="password"`) {
		t.Fatal("应包含密码输入框")
	}
	if !strings.Contains(html, "访问密码") {
		t.Fatal("应包含访问密码标签")
	}

	// 本地用户登录表单
	if !strings.Contains(html, `name="username"`) {
		t.Fatal("应包含用户名输入框")
	}
	if !strings.Contains(html, `name="auth_type" value="user_password"`) {
		t.Fatal("应包含用户名密码验证的 auth_type")
	}

	// OAuth 提供方按钮
	if !strings.Contains(html, "GitHub") {
		t.Fatal("应包含 OAuth 提供方名称")
	}
	if !strings.Contains(html, "/__owaf/access/oauth/start/2") {
		t.Fatal("应包含 OAuth 发起链接")
	}

	// 表单 action
	if !strings.Contains(html, `action="/__owaf/access/verify"`) {
		t.Fatal("表单 action 应指向验证端点")
	}
}

func TestRenderLoginPageWithError(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		SiteID:             1,
		SharedPasswordHash: "hash",
	}

	html := string(RenderLoginPage("site.test", cfg, "凭据无效"))

	if !strings.Contains(html, "凭据无效") {
		t.Fatal("应显示错误信息")
	}
	if !strings.Contains(html, `class="error"`) {
		t.Fatal("错误信息应使用 error 样式类")
	}
}

func TestRenderLoginPageNoError(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		SiteID:             1,
		SharedPasswordHash: "hash",
	}

	html := string(RenderLoginPage("site.test", cfg, ""))

	if strings.Contains(html, `class="error"`) {
		t.Fatal("无错误时不应渲染 error 区块")
	}
}

func TestRenderLoginPageNoSharedPassword(t *testing.T) {
	cfg := Config{
		Enabled: true,
		SiteID:  1,
	}

	html := string(RenderLoginPage("site.test", cfg, ""))

	if strings.Contains(html, "访问密码") {
		t.Fatal("未配置共享密码时不应显示密码区域")
	}
	if strings.Contains(html, `value="shared_password"`) {
		t.Fatal("未配置共享密码时不应渲染共享密码表单")
	}
}

func TestRenderLoginPageOnlyOAuth(t *testing.T) {
	cfg := Config{
		Enabled: true,
		SiteID:  1,
		Providers: []ProviderConfig{
			{ID: 5, Type: "oidc", Name: "Google"},
		},
	}

	html := string(RenderLoginPage("site.test", cfg, ""))

	if strings.Contains(html, `value="shared_password"`) {
		t.Fatal("仅 OAuth 时不应包含共享密码表单")
	}
	if strings.Contains(html, `name="username"`) {
		t.Fatal("仅 OAuth 时不应包含用户名输入")
	}
	if !strings.Contains(html, "Google") {
		t.Fatal("应包含 OAuth 提供方名称")
	}
	if !strings.Contains(html, "/__owaf/access/oauth/start/5") {
		t.Fatal("应包含正确的 OAuth 发起链接")
	}
}

func TestRenderLoginPageXSSEscaping(t *testing.T) {
	cfg := Config{
		Enabled: true,
		SiteID:  1,
	}

	html := string(RenderLoginPage("<script>alert(1)</script>", cfg, "<img onerror=alert(1)>"))

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("Host 应被 HTML 转义")
	}
	if strings.Contains(html, "<img onerror=alert(1)>") {
		t.Fatal("错误信息应被 HTML 转义")
	}
}
