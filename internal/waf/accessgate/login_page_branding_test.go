package accessgate

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/pageconfig"
)

// TestRenderLoginPageWithBranding 验证品牌化配置注入登录页。
func TestRenderLoginPageWithBranding(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		SiteID:             1,
		SharedPasswordHash: "hash",
	}
	pageCfg := pageconfig.PageConfig{
		BrandName:    "Acme 防火墙",
		PrimaryColor: "#ff5500",
		BgGradient:   "linear-gradient(160deg,#fff7ed 0%,#fff 100%)",
		LogoURL:      "/static/logo.png",
		Title:        "成员登录",
		FooterText:   "由 Acme 防火墙保护",
		CustomCSS:    ".card{border-radius:6px}",
	}

	html := string(RenderLoginPageWithPageConfig("site.test", cfg, "", pageCfg))

	for _, fragment := range []string{
		"Acme 防火墙",
		"#ff5500",
		"linear-gradient(160deg,#fff7ed 0%,#fff 100%)",
		`src="/static/logo.png"`,
		"成员登录 - site.test",
		"由 Acme 防火墙保护",
		".card{border-radius:6px}",
	} {
		if !strings.Contains(html, fragment) {
			t.Errorf("渲染结果应包含品牌化片段 %q，实际缺失", fragment)
		}
	}
}

// TestRenderLoginPageDefaultMatchesLegacy 验证未配置品牌化时渲染与旧版默认等价。
// 旧版默认样式定义于品牌化接入前的 templates/login.html。
func TestRenderLoginPageDefaultMatchesLegacy(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		SiteID:             1,
		SharedPasswordHash: "hash",
	}
	html := string(RenderLoginPage("site.test", cfg, ""))

	assertNotContains := func(fragment, reason string) {
		t.Helper()
		if strings.Contains(html, fragment) {
			t.Errorf("默认渲染不应包含 %s：片段 %q", reason, fragment)
		}
	}
	assertNotContains(`class="logo"`, "未配置 LogoURL 时不应渲染图片标签")
	assertNotContains(`<p class="footer">`, "旧版默认页面没有页脚行")
	assertNotContains(`<p class="brand">`, "旧版默认页面没有品牌名行")
	// 旧版紫蓝渐变背景与紫色按钮保持不变。
	if !strings.Contains(html, "linear-gradient(135deg,#667eea 0%,#764ba2 100%)") {
		t.Error("默认渲染应回退到旧版紫蓝渐变背景")
	}
	if !strings.Contains(html, "background:#667eea") {
		t.Error("默认渲染按钮应保持旧版紫色 #667eea")
	}
	// 标题格式保持「访问验证 - {host}」。
	if !strings.Contains(html, ">访问验证 - site.test<") {
		t.Error("默认渲染标题应为「访问验证 - site.test」")
	}
}
