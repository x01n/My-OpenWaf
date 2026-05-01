package waf

import (
	"context"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"
)

// ErrorPageConfig defines the configuration for a custom error page.
type ErrorPageConfig struct {
	StatusCode int    `json:"status_code"`
	Title      string `json:"title"`
	Body       string `json:"body"`       // HTML content or plain text description
	CustomCSS  string `json:"custom_css"` // optional custom CSS
}

// defaultErrorPages provides built-in error page configurations.
var defaultErrorPages = map[int]*ErrorPageConfig{
	403: {StatusCode: 403, Title: "Access Denied", Body: "Your request has been blocked by the WAF."},
	429: {StatusCode: 429, Title: "Too Many Requests", Body: "You have exceeded the rate limit. Please try again later."},
	502: {StatusCode: 502, Title: "Bad Gateway", Body: "The server received an invalid response from the upstream."},
	503: {StatusCode: 503, Title: "Service Unavailable", Body: "The service is temporarily unavailable."},
	504: {StatusCode: 504, Title: "Gateway Timeout", Body: "The upstream server did not respond in time."},
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
	cfg := GetDefaultErrorPage(statusCode)
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
	}

	customStyle := ""
	if cfg.CustomCSS != "" {
		customStyle = cfg.CustomCSS
	}

	html := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + cfg.Title + `</title><style>` +
		`*{margin:0;padding:0;box-sizing:border-box}` +
		`body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#0f172a 100%);color:#e2e8f0}` +
		`.container{text-align:center;max-width:560px;padding:3rem 2rem}` +
		`.status-code{font-size:7rem;font-weight:900;background:linear-gradient(135deg,#f87171,#ef4444,#dc2626);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1;margin-bottom:1rem;text-shadow:0 0 80px rgba(239,68,68,0.3)}` +
		`.title{font-size:1.5rem;font-weight:600;color:#f1f5f9;margin-bottom:1rem}` +
		`.body{font-size:1rem;color:#94a3b8;line-height:1.6;margin-bottom:2rem}` +
		`.footer{font-size:0.75rem;color:#475569;border-top:1px solid #1e293b;padding-top:1.5rem;margin-top:1.5rem}` +
		`.footer span{color:#64748b}` +
		customStyle +
		`</style></head><body><div class="container">` +
		`<div class="status-code">` + strconv.Itoa(statusCode) + `</div>` +
		`<div class="title">` + cfg.Title + `</div>` +
		`<div class="body">` + cfg.Body + `</div>` +
		`<div class="footer"><span>Protected by OpenWAF</span></div>` +
		`</div></body></html>`

	return []byte(html)
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

	html := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OpenWAF</title><style>` +
		`*{margin:0;padding:0;box-sizing:border-box}` +
		`body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#0f172a 100%);color:#e2e8f0}` +
		`.container{text-align:center;max-width:560px;padding:3rem 2rem}` +
		`.logo{font-size:3.5rem;font-weight:900;background:linear-gradient(135deg,#38bdf8,#818cf8,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:0.5rem}` +
		`.subtitle{font-size:1.25rem;color:#94a3b8;margin-bottom:2rem}` +
		`.status-badge{display:inline-flex;align-items:center;gap:0.5rem;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:2rem;padding:0.5rem 1.25rem;font-size:0.875rem;color:#4ade80;margin-bottom:2rem}` +
		`.status-dot{width:8px;height:8px;border-radius:50%;background:#4ade80;animation:pulse 2s infinite}` +
		`@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}` +
		`.info{font-size:0.875rem;color:#64748b;line-height:1.8}` +
		`.footer{font-size:0.75rem;color:#475569;border-top:1px solid #1e293b;padding-top:1.5rem;margin-top:2rem}` +
		`</style></head><body><div class="container">` +
		`<div class="logo">OpenWAF</div>` +
		`<div class="subtitle">Web Application Firewall</div>` +
		`<div class="status-badge"><span class="status-dot"></span>Running</div>` +
		`<div class="info">` +
		`<p>The WAF is active and protecting your applications.</p>` +
		`<p>This page is displayed because no site is configured for this domain.</p>` +
		`</div>` +
		`<div class="footer">OpenWAF v1.0</div>` +
		`</div></body></html>`

	c.Data(200, "text/html; charset=utf-8", []byte(html))
}
