package accessgate

import (
	"embed"
	"fmt"
	"html/template"
	"strings"

	"My-OpenWaf/internal/waf/pageconfig"
)

// loginProviderData 登录方式模板数据。
type loginProviderData struct {
	ID            uint
	Type          string
	Name          string
	OAuthStartURL string
}

// loginPageData 登录页面模板数据。
type loginPageData struct {
	SiteHost          string
	HasSharedPassword bool
	Providers         []loginProviderData
	ErrorMsg          string
	LoginAction       string
	PageTitle         string
	BrandName         string
	PrimaryColor      template.CSS
	Background        template.CSS
	LogoURL           template.URL
	FooterText        string
	CustomCSS         template.CSS
}

//go:embed templates/login.html
var loginPageFS embed.FS

// loginPageTmpl 独立登录页面 HTML 模板。
var loginPageTmpl = template.Must(template.New("login.html").ParseFS(loginPageFS, "templates/login.html"))

// defaultAccessLoginTitle 品牌化字段未配置时登录页使用的默认标题前缀。
const defaultAccessLoginTitle = "访问验证"

const (
	// legacyLoginPrimaryColor/legacyLoginBgGradient 是品牌化接入前登录页的
	// 紫蓝渐变默认外观。未配置 pageconfig 时回退到这两个值，
	// 保证旧版渲染等价；配置了品牌化字段时由配置值覆盖。
	legacyLoginPrimaryColor = "#667eea"
	legacyLoginBgGradient   = "linear-gradient(135deg,#667eea 0%,#764ba2 100%)"
)

// RenderLoginPage 渲染站点访问控制登录页面（无品牌化配置）。
// 保持与品牌化接入前的旧版渲染等价：标题「访问验证 - {host}」、
// 紫蓝渐变背景与紫色按钮，且不输出品牌名行、Logo 与页脚行。
func RenderLoginPage(siteHost string, cfg Config, errorMsg string) []byte {
	return RenderLoginPageWithPageConfig(siteHost, cfg, errorMsg, pageconfig.PageConfig{})
}

// RenderLoginPageWithPageConfig 渲染带有品牌化配置的站点访问控制登录页面。
// 字段安全化与 block 页一致：颜色/背景/Logo/CSS 非法或为空时回退到旧版
// 默认外观；BrandName/Title/FooterText 未配置时由渲染层使用旧版默认文本。
func RenderLoginPageWithPageConfig(siteHost string, cfg Config, errorMsg string, pageCfg pageconfig.PageConfig) []byte {
	resolved := pageconfig.PageConfig{
		BrandName:    pageCfg.BrandName,
		PrimaryColor: pageconfig.SafePrimaryColor(pageCfg.PrimaryColor, legacyLoginPrimaryColor),
		BgGradient:   pageconfig.SafeBackground(pageCfg.BgGradient, legacyLoginBgGradient),
		LogoURL:      string(pageconfig.SafeLogoURL(pageCfg.LogoURL)),
		Title:        pageCfg.Title,
		FooterText:   pageCfg.FooterText,
		CustomCSS:    pageconfig.SanitizeCSS(pageCfg.CustomCSS),
	}
	return renderLoginPage(siteHost, cfg, errorMsg, resolved)
}

func renderLoginPage(siteHost string, cfg Config, errorMsg string, pageCfg pageconfig.PageConfig) []byte {
	providers := make([]loginProviderData, 0, len(cfg.Providers))
	for _, provider := range cfg.Providers {
		providers = append(providers, loginProviderData{
			ID:            provider.ID,
			Type:          provider.Type,
			Name:          provider.Name,
			OAuthStartURL: fmt.Sprintf("/__owaf/access/oauth/start/%d", provider.ID),
		})
	}
	pageTitle := pageCfg.Title
	if pageTitle == "" {
		pageTitle = defaultAccessLoginTitle
	}
	data := loginPageData{
		SiteHost:          siteHost,
		HasSharedPassword: cfg.SharedPasswordHash != "",
		Providers:         providers,
		ErrorMsg:          errorMsg,
		LoginAction:       "/__owaf/access/verify",
		PageTitle:         pageTitle + " - " + siteHost,
		BrandName:         pageCfg.BrandName,
		PrimaryColor:      template.CSS(pageCfg.PrimaryColor),
		Background:        template.CSS(pageCfg.BgGradient),
		LogoURL:           template.URL(pageCfg.LogoURL),
		FooterText:        pageCfg.FooterText,
		CustomCSS:         template.CSS(pageCfg.CustomCSS),
	}

	var buf strings.Builder
	if err := loginPageTmpl.Execute(&buf, data); err != nil {
		return []byte("<!DOCTYPE html><html><body><p>Unable to render access page.</p></body></html>")
	}
	return []byte(buf.String())
}
