package site

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"mime"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

type errorPageConfig struct {
	StatusCode  int    `json:"status_code"`
	Title       string `json:"title"`
	HTML        string `json:"html"`
	ContentType string `json:"content_type"`
}

var defaultErrorPages = map[int]errorPageConfig{
	403: {StatusCode: 403, Title: "Forbidden", HTML: `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access denied by WAF policy.</p></body></html>`, ContentType: "text/html"},
	404: {StatusCode: 404, Title: "Not Found", HTML: `<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body></html>`, ContentType: "text/html"},
	429: {StatusCode: 429, Title: "Too Many Requests", HTML: `<!DOCTYPE html><html><head><title>429 Too Many Requests</title></head><body><h1>429 Too Many Requests</h1><p>Rate limit exceeded.</p></body></html>`, ContentType: "text/html"},
	431: {StatusCode: 431, Title: "Request Header Fields Too Large", HTML: `<!DOCTYPE html><html><head><title>431 Request Header Fields Too Large</title></head><body><h1>431 Request Header Fields Too Large</h1><p>Request headers exceed the configured limit.</p></body></html>`, ContentType: "text/html"},
	500: {StatusCode: 500, Title: "Internal Server Error", HTML: `<!DOCTYPE html><html><head><title>500 Error</title></head><body><h1>500 Internal Server Error</h1></body></html>`, ContentType: "text/html"},
	502: {StatusCode: 502, Title: "Bad Gateway", HTML: `<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>`, ContentType: "text/html"},
	503: {StatusCode: 503, Title: "Service Unavailable", HTML: `<!DOCTYPE html><html><head><title>503 Unavailable</title></head><body><h1>503 Service Unavailable</h1></body></html>`, ContentType: "text/html"},
	504: {StatusCode: 504, Title: "Gateway Timeout", HTML: `<!DOCTYPE html><html><head><title>504 Gateway Timeout</title></head><body><h1>504 Gateway Timeout</h1></body></html>`, ContentType: "text/html"},
}

const (
	maxCustomErrorPages       = 32
	maxCustomErrorPageHTML    = 256 << 10
	maxCustomErrorPageTitle   = 256
	maxCustomErrorContentType = 128
)

func normalizeErrorPages(input map[string]errorPageConfig) (map[string]errorPageConfig, error) {
	if len(input) > maxCustomErrorPages {
		return nil, fmt.Errorf("error_pages contains more than %d pages", maxCustomErrorPages)
	}
	output := make(map[string]errorPageConfig, len(input))
	for rawCode, page := range input {
		code, err := strconv.Atoi(strings.TrimSpace(rawCode))
		if err != nil || code < 400 || code > 599 {
			return nil, fmt.Errorf("error_pages status code %q must be between 400 and 599", rawCode)
		}
		if page.StatusCode == 0 {
			page.StatusCode = code
		}
		if page.StatusCode != code {
			return nil, fmt.Errorf("error_pages status_code for %q must match its key", rawCode)
		}
		if !utf8.ValidString(page.Title) || len(page.Title) > maxCustomErrorPageTitle || strings.ContainsAny(page.Title, "\r\n") {
			return nil, fmt.Errorf("error_pages[%q] title is invalid or too long", rawCode)
		}
		if !utf8.ValidString(page.HTML) || len(page.HTML) > maxCustomErrorPageHTML {
			return nil, fmt.Errorf("error_pages[%q] html is invalid or too large", rawCode)
		}
		page.ContentType = strings.TrimSpace(page.ContentType)
		if page.ContentType == "" {
			page.ContentType = "text/html"
		}
		if len(page.ContentType) > maxCustomErrorContentType || strings.ContainsAny(page.ContentType, "\r\n") {
			return nil, fmt.Errorf("error_pages[%q] content_type is invalid", rawCode)
		}
		if _, _, err := mime.ParseMediaType(page.ContentType); err != nil {
			return nil, fmt.Errorf("error_pages[%q] content_type is invalid", rawCode)
		}
		output[strconv.Itoa(code)] = page
	}
	return output, nil
}

func GetSiteErrorPages(repo *repository.SiteRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		site, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		var pages map[string]errorPageConfig
		if site.CustomErrorPages != "" && site.CustomErrorPages != "{}" {
			_ = json.Unmarshal([]byte(site.CustomErrorPages), &pages)
		}
		if pages == nil {
			pages = make(map[string]errorPageConfig)
		}
		c.JSON(200, map[string]any{"site_id": id, "error_pages": pages})
	}
}

func UpdateSiteErrorPages(repo *repository.SiteRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		site, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		var req struct {
			ErrorPages *map[string]errorPageConfig `json:"error_pages"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		if req.ErrorPages == nil {
			c.JSON(400, map[string]string{"error": "error_pages is required"})
			return
		}
		normalized, err := normalizeErrorPages(*req.ErrorPages)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		data, err := json.Marshal(normalized)
		if err != nil {
			c.JSON(400, map[string]string{"error": "failed to encode error pages"})
			return
		}
		site.CustomErrorPages = string(data)
		if err := repo.Update(site); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"site_id": id, "error_pages": normalized})
	}
}

func GetDefaultErrorPages() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"defaults": defaultErrorPages})
	}
}

func PreviewErrorPage() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			HTML       string         `json:"html"`
			StatusCode int            `json:"status_code"`
			Variables  map[string]any `json:"variables"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		if req.HTML == "" {
			c.JSON(400, map[string]string{"error": "html field required"})
			return
		}
		if !utf8.ValidString(req.HTML) || len(req.HTML) > maxCustomErrorPageHTML {
			c.JSON(400, map[string]string{"error": "html is invalid or too large"})
			return
		}
		if req.StatusCode != 0 && (req.StatusCode < 400 || req.StatusCode > 599) {
			c.JSON(400, map[string]string{"error": "status_code must be between 400 and 599"})
			return
		}
		tmpl, err := template.New("preview").Parse(req.HTML)
		if err != nil {
			c.JSON(200, map[string]any{"rendered": req.HTML, "status_code": req.StatusCode, "parse_error": err.Error()})
			return
		}
		var buf strings.Builder
		vars := req.Variables
		if vars == nil {
			vars = map[string]any{"StatusCode": req.StatusCode, "Message": "Preview", "ClientIP": "127.0.0.1", "RequestID": "preview-request-id"}
		}
		if err := tmpl.Execute(&buf, vars); err != nil {
			c.JSON(200, map[string]any{"rendered": req.HTML, "status_code": req.StatusCode, "execute_error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"rendered": buf.String(), "status_code": req.StatusCode})
	}
}
