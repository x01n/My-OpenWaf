package waf

import (
	"bytes"
	"io/fs"
	"strconv"
	"text/template"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/snapshot"
)

// WriteBlockResponse renders the intercept block page (no upstream connection).
func WriteBlockResponse(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot, res action.Result) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Set("X-WAF-Action", string(action.Normalize(res.Type)))

	statusCode := 403
	html := sn.DefaultBlockHTML

	if rt != nil {
		if rt.BlockHTML != "" {
			html = rt.BlockHTML
		}
		if rt.BlockStatus > 0 {
			statusCode = rt.BlockStatus
		}
	}

	if html != "" {
		renderTemplatePage(c, html, reqID, res.RuleID, statusCode, false)
		return
	}

	renderEmbeddedPage(c, "blocked/index.html", statusCode, reqID, strconv.FormatUint(uint64(res.RuleID), 10))
}

// WriteMaintenanceResponse renders the maintenance page (no upstream connection).
func WriteMaintenanceResponse(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot) {
	c.Response.Header.Set("X-Request-ID", reqID)

	html := ""
	statusCode := 503

	if rt != nil && rt.MaintenanceHTML != "" {
		html = rt.MaintenanceHTML
		if rt.MaintenanceStatus > 0 {
			statusCode = rt.MaintenanceStatus
		}
	} else if sn.Protection.MaintenanceGlobalHTML != "" {
		html = sn.Protection.MaintenanceGlobalHTML
		if sn.Protection.MaintenanceGlobalStatus > 0 {
			statusCode = sn.Protection.MaintenanceGlobalStatus
		}
	}

	if html != "" {
		renderTemplatePage(c, html, reqID, 0, statusCode, true)
		return
	}

	renderEmbeddedPage(c, "maintenance/index.html", statusCode, reqID, "")
}

func renderTemplatePage(c *app.RequestContext, html, reqID string, ruleID uint, statusCode int, maintenance bool) {
	tpl, err := template.New("page").Parse(html)
	if err != nil {
		c.Data(statusCode, "text/html; charset=utf-8", []byte(defaultFallbackHTML(reqID, strconv.FormatUint(uint64(ruleID), 10), maintenance)))
		return
	}
	var buf bytes.Buffer
	_ = tpl.Execute(&buf, struct {
		RequestID string
		RuleID    string
	}{RequestID: reqID, RuleID: strconv.FormatUint(uint64(ruleID), 10)})
	c.Data(statusCode, "text/html; charset=utf-8", buf.Bytes())
}

func renderEmbeddedPage(c *app.RequestContext, assetPath string, statusCode int, reqID, ruleID string) {
	page, err := loadEmbeddedPage(assetPath)
	if err != nil {
		c.Data(statusCode, "text/html; charset=utf-8", []byte(defaultFallbackHTML(reqID, ruleID, assetPath == "maintenance/index.html")))
		return
	}

	page = bytes.ReplaceAll(page, []byte("__WAF_REQUEST_ID__"), []byte(reqID))
	page = bytes.ReplaceAll(page, []byte("__WAF_RULE_ID__"), []byte(ruleID))
	page = bytes.ReplaceAll(page, []byte(`"/_next/`), []byte(`"/__owaf/_next/`))
	page = bytes.ReplaceAll(page, []byte(`'/_next/`), []byte(`'/__owaf/_next/`))
	c.Data(statusCode, "text/html; charset=utf-8", page)
}

func loadEmbeddedPage(assetPath string) ([]byte, error) {
	webFS, err := adminweb.SubFS()
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(webFS, assetPath)
}

func defaultFallbackHTML(reqID, ruleID string, maintenance bool) string {
	if maintenance {
		return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Maintenance</title></head><body><h1>Service under maintenance</h1><p>Request ID: ` + reqID + `</p></body></html>`
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Blocked</title></head><body><h1>Request blocked</h1><p>Request ID: ` + reqID + `</p><p>Rule ID: ` + ruleID + `</p></body></html>`
}
