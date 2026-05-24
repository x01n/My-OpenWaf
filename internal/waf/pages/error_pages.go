package pages

import (
	"context"
	"html/template"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

// ErrorPageConfig defines the configuration for a custom error page.
type ErrorPageConfig struct {
	StatusCode  int    `json:"status_code"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	HTML        string `json:"html"`
	CustomCSS   string `json:"custom_css"`
	ContentType string `json:"content_type"`
}

// defaultErrorPages provides built-in error page configurations.
var defaultErrorPages = map[int]*ErrorPageConfig{
	403: {StatusCode: 403, Title: "Access Denied", Body: "Your request has been blocked by the web application firewall.\n您的请求已被Web应用防火墙拦截。"},
	404: {StatusCode: 404, Title: "Not Found", Body: "The requested resource could not be found.\n请求的资源未找到。"},
	429: {StatusCode: 429, Title: "Too Many Requests", Body: "You have exceeded the rate limit. Please try again later.\n您的请求过于频繁，请稍后再试。"},
	502: {StatusCode: 502, Title: "Bad Gateway", Body: "The server received an invalid response from the upstream.\n上游服务器返回了无效的响应。"},
	503: {StatusCode: 503, Title: "Service Unavailable", Body: "The service is temporarily unavailable.\n服务暂时不可用，请稍后再试。"},
	504: {StatusCode: 504, Title: "Gateway Timeout", Body: "The upstream server did not respond in time.\n上游服务器未能及时响应。"},
}

// GetDefaultErrorPage returns the default error page config for a status code.
func GetDefaultErrorPage(statusCode int) *ErrorPageConfig {
	if cfg, ok := defaultErrorPages[statusCode]; ok {
		return cfg
	}
	return &ErrorPageConfig{
		StatusCode: statusCode,
		Title:      "Error",
		Body:       "An unexpected error occurred.",
	}
}

// RenderErrorPage renders an error page HTML for the given status code.
// If customConfig is provided, it overrides the default.
func RenderErrorPage(statusCode int, customConfig *ErrorPageConfig) []byte {
	cfg := *GetDefaultErrorPage(statusCode)
	if customConfig != nil {
		if customConfig.Title != "" {
			cfg.Title = customConfig.Title
		}
		if customConfig.Body != "" {
			cfg.Body = customConfig.Body
		}
		if customConfig.CustomCSS != "" {
			cfg.CustomCSS = customConfig.CustomCSS
		}
		if customConfig.HTML != "" {
			rendered := renderErrorTemplate(customConfig.HTML, statusCode, cfg.Title)
			return []byte(rendered)
		}
	}

	customStyle := ""
	if cfg.CustomCSS != "" {
		customStyle = cfg.CustomCSS
	}

	icon := "&#9888;"
	titleZh := "错误"
	switch statusCode {
	case 403:
		icon = "&#128737;"
		titleZh = "访问被拒绝"
	case 404:
		icon = "&#128269;"
		titleZh = "页面未找到"
	case 429:
		icon = "&#9203;"
		titleZh = "请求过于频繁"
	case 502:
		icon = "&#9889;"
		titleZh = "网关错误"
	case 503:
		icon = "&#128736;"
		titleZh = "服务不可用"
	case 504:
		icon = "&#9203;"
		titleZh = "网关超时"
	}

	bodyHTML := ""
	for _, line := range strings.Split(cfg.Body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			bodyHTML += `<p class="body-line">` + line + `</p>`
		}
	}

	html := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + cfg.Title + `</title><style>` +
		`*{margin:0;padding:0;box-sizing:border-box}` +
		`body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(160deg,#f0fdfa 0%,#f8fafc 40%,#f1f5f9 100%);color:#1e293b}` +
		`.card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08),0 1px 4px rgba(0,0,0,.04);text-align:center;max-width:500px;width:92%;padding:48px 40px}` +
		`.icon{font-size:48px;margin-bottom:8px;line-height:1.2}` +
		`.status-code{font-size:4rem;font-weight:800;color:#14b8a6;line-height:1;margin-bottom:4px}` +
		`.title{font-size:1.2rem;font-weight:600;color:#334155;margin-bottom:6px}` +
		`.divider{width:48px;height:3px;background:#14b8a6;border-radius:2px;margin:16px auto}` +
		`.body-line{font-size:.9rem;color:#64748b;line-height:1.6;margin-bottom:4px}` +
		`.footer{font-size:.7rem;color:#94a3b8;border-top:1px solid #f1f5f9;padding-top:16px;margin-top:24px}` +
		customStyle +
		`</style></head><body><div class="card">` +
		`<div class="icon">` + icon + `</div>` +
		`<div class="status-code">` + strconv.Itoa(statusCode) + `</div>` +
		`<div class="title">` + cfg.Title + ` / ` + titleZh + `</div>` +
		`<div class="divider"></div>` +
		bodyHTML +
		`<div class="footer">Protected by My-OpenWAF</div>` +
		`</div></body></html>`

	return []byte(html)
}

func renderErrorTemplate(html string, statusCode int, title string) string {
	tmpl, err := template.New("error_page").Parse(html)
	if err != nil {
		return html
	}
	var buf strings.Builder
	vars := map[string]any{
		"StatusCode": statusCode,
		"Message":    title,
		"Title":      title,
	}
	if err := tmpl.Execute(&buf, vars); err != nil {
		return html
	}
	return buf.String()
}

// WriteErrorPage writes an error page response directly to the Hertz context.
func WriteErrorPage(_ context.Context, c *app.RequestContext, statusCode int, customConfig *ErrorPageConfig) {
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	page := RenderErrorPage(statusCode, customConfig)
	c.Data(statusCode, "text/html; charset=utf-8", page)
}

// WriteWelcomePage renders the OpenWAF welcome page when no site matches the request.
func WriteWelcomePage(_ context.Context, c *app.RequestContext) {
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")

	html := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>My-OpenWAF</title><style>` +
		`*{margin:0;padding:0;box-sizing:border-box}` +
		`body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(160deg,#f0fdfa 0%,#f8fafc 40%,#f1f5f9 100%);color:#1e293b}` +
		`.card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08),0 1px 4px rgba(0,0,0,.04);text-align:center;max-width:500px;width:92%;padding:48px 40px}` +
		`.shield{font-size:52px;margin-bottom:8px;line-height:1.2}` +
		`.logo{font-size:2rem;font-weight:800;color:#0d9488;margin-bottom:4px}` +
		`.subtitle{font-size:1rem;color:#64748b;margin-bottom:24px}` +
		`.status-badge{display:inline-flex;align-items:center;gap:8px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:24px;padding:8px 20px;font-size:.875rem;color:#16a34a;margin-bottom:24px}` +
		`.status-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;animation:pulse 2s infinite}` +
		`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}` +
		`.divider{width:48px;height:3px;background:#14b8a6;border-radius:2px;margin:0 auto 20px}` +
		`.info{font-size:.875rem;color:#64748b;line-height:1.8}` +
		`.info p{margin-bottom:4px}` +
		`.footer{font-size:.7rem;color:#94a3b8;border-top:1px solid #f1f5f9;padding-top:16px;margin-top:24px}` +
		`</style></head><body><div class="card">` +
		`<div class="shield">&#128737;</div>` +
		`<div class="logo">My-OpenWAF</div>` +
		`<div class="subtitle">Web Application Firewall</div>` +
		`<div class="status-badge"><span class="status-dot"></span>Running</div>` +
		`<div class="divider"></div>` +
		`<div class="info">` +
		`<p>The WAF is active and protecting your applications.</p>` +
		`<p>WAF 正在运行并保护您的应用程序。</p>` +
		`<p>This page is displayed because no site is configured for this domain.</p>` +
		`</div>` +
		`<div class="footer">Protected by My-OpenWAF</div>` +
		`</div></body></html>`

	c.Data(200, "text/html; charset=utf-8", []byte(html))
}
