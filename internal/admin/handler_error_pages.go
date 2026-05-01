package admin

import (
	"context"
	"encoding/json"
	"html/template"
	"strings"

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
	500: {StatusCode: 500, Title: "Internal Server Error", HTML: `<!DOCTYPE html><html><head><title>500 Error</title></head><body><h1>500 Internal Server Error</h1></body></html>`, ContentType: "text/html"},
	502: {StatusCode: 502, Title: "Bad Gateway", HTML: `<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>`, ContentType: "text/html"},
	503: {StatusCode: 503, Title: "Service Unavailable", HTML: `<!DOCTYPE html><html><head><title>503 Unavailable</title></head><body><h1>503 Service Unavailable</h1></body></html>`, ContentType: "text/html"},
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
			ErrorPages map[string]errorPageConfig `json:"error_pages"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		data, err := json.Marshal(req.ErrorPages)
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
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"site_id": id, "error_pages": req.ErrorPages})
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
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		if req.HTML == "" {
			c.JSON(400, map[string]string{"error": "html field required"})
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
