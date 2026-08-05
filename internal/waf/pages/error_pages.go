package pages

import (
	"context"
	"html/template"
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
	431: {StatusCode: 431, Title: "Request Header Field(s) Too Large", Body: "HTTP Error 431: too many request header fields.\n请求头字段过多。"},
	502: {StatusCode: 502, Title: "Bad Gateway", Body: "The server received an invalid response from the upstream.\n上游服务器返回了无效的响应。"},
	503: {StatusCode: 503, Title: "Service Unavailable", Body: "The service is temporarily unavailable, please try again later.\n服务暂时不可用，请稍后再试。"},
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

	data := errorPageTemplateData{
		StatusCode: statusCode,
		Title:      cfg.Title,
		TitleZh:    "错误",
		CustomCSS:  template.CSS(sanitizeTemplateCSS(cfg.CustomCSS)),
		Icon:       template.HTML("&#9888;"),
	}
	for _, line := range strings.Split(cfg.Body, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			data.BodyLines = append(data.BodyLines, line)
		}
	}
	switch statusCode {
	case 403:
		data.Icon = template.HTML("&#128737;")
		data.TitleZh = "访问被拒绝"
	case 404:
		data.Icon = template.HTML("&#128269;")
		data.TitleZh = "页面未找到"
	case 429:
		data.Icon = template.HTML("&#9203;")
		data.TitleZh = "请求过于频繁"
	case 431:
		data.Icon = template.HTML("&#128203;")
		data.TitleZh = "请求头字段过多"
	case 502:
		data.Icon = template.HTML("&#9889;")
		data.TitleZh = "网关错误"
	case 503:
		data.Icon = template.HTML("&#128736;")
		data.TitleZh = "服务不可用"
	case 504:
		data.Icon = template.HTML("&#9203;")
		data.TitleZh = "网关超时"
	}
	return renderBuiltInErrorPage(data)
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
	c.Data(200, "text/html; charset=utf-8", renderWelcomePage())
}
