package accessgate

import (
	"embed"
	"fmt"
	"html/template"
	"strings"
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
}

//go:embed templates/login.html
var loginPageFS embed.FS

// loginPageTmpl 独立登录页面 HTML 模板。
var loginPageTmpl = template.Must(template.New("login.html").ParseFS(loginPageFS, "templates/login.html"))

// RenderLoginPage 渲染站点访问控制登录页面。
func RenderLoginPage(siteHost string, cfg Config, errorMsg string) []byte {
	providers := make([]loginProviderData, 0, len(cfg.Providers))
	for _, provider := range cfg.Providers {
		providers = append(providers, loginProviderData{
			ID:            provider.ID,
			Type:          provider.Type,
			Name:          provider.Name,
			OAuthStartURL: fmt.Sprintf("/__owaf/access/oauth/start/%d", provider.ID),
		})
	}
	data := loginPageData{
		SiteHost:          siteHost,
		HasSharedPassword: cfg.SharedPasswordHash != "",
		Providers:         providers,
		ErrorMsg:          errorMsg,
		LoginAction:       "/__owaf/access/verify",
	}

	var buf strings.Builder
	if err := loginPageTmpl.Execute(&buf, data); err != nil {
		return []byte("<!DOCTYPE html><html><body><p>Unable to render access page.</p></body></html>")
	}
	return []byte(buf.String())
}
