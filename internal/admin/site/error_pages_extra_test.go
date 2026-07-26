package site

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestGetDefaultErrorPagesReturnsBuiltinTemplates(t *testing.T) {
	ctx := invokeSiteRouteHandler(t, GetDefaultErrorPages(), "GET", "/api/v1/error-pages/defaults", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Defaults map[string]errorPageConfig `json:"defaults"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode defaults: %v", err)
	}
	if len(resp.Defaults) != len(defaultErrorPages) {
		t.Fatalf("defaults length = %d, want %d", len(resp.Defaults), len(defaultErrorPages))
	}
	for code, want := range defaultErrorPages {
		got, ok := resp.Defaults[strconv.Itoa(code)]
		if !ok {
			t.Fatalf("missing default page for %d", code)
		}
		if got.StatusCode != want.StatusCode || got.Title != want.Title || got.HTML != want.HTML || got.ContentType != want.ContentType {
			t.Fatalf("default page %d mismatch: got %#v want %#v", code, got, want)
		}
	}
}

func TestGetSiteErrorPagesRejectsInvalidIDAndMissingSite(t *testing.T) {
	repo := newSiteRepoForTest(t)

	ctx := invokeSiteRouteHandler(t, GetSiteErrorPages(repo), "GET", "/api/v1/sites/abc/error-pages", idParams("abc"), nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid id")

	ctx = invokeSiteRouteHandler(t, GetSiteErrorPages(repo), "GET", "/api/v1/sites/404/error-pages", idParams("404"), nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing site status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "site not found")
}

/**
 * TestGetSiteErrorPagesNormalizesEmptyConfigurations 覆盖 custom_error_pages 为空串、
 * "{}" 以及非法 JSON 三种情况，均应返回空对象而不是 null。
 */
func TestGetSiteErrorPagesNormalizesEmptyConfigurations(t *testing.T) {
	tests := []struct {
		name  string
		saved string
	}{
		{name: "empty string", saved: ""},
		{name: "empty object", saved: "{}"},
		{name: "malformed json is ignored", saved: "not-json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			item := seedSiteWithErrorPages(t, repo, tt.saved)

			ctx := invokeSiteRouteHandler(t, GetSiteErrorPages(repo), "GET", "/api/v1/sites/1/error-pages", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			var resp struct {
				SiteID     uint                       `json:"site_id"`
				ErrorPages map[string]errorPageConfig `json:"error_pages"`
			}
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.SiteID != item.ID {
				t.Fatalf("site_id = %d, want %d", resp.SiteID, item.ID)
			}
			if resp.ErrorPages == nil || len(resp.ErrorPages) != 0 {
				t.Fatalf("error_pages = %#v, want empty object", resp.ErrorPages)
			}
		})
	}
}

func TestUpdateSiteErrorPagesRejectsInvalidIDAndMissingSite(t *testing.T) {
	repo := newSiteRepoForTest(t)
	handler := UpdateSiteErrorPages(repo, func() error { return nil })
	body := []byte(`{"error_pages":{}}`)

	ctx := invokeSiteRouteHandler(t, handler, "POST", "/api/v1/sites/abc/error-pages", idParams("abc"), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid id")

	ctx = invokeSiteRouteHandler(t, handler, "POST", "/api/v1/sites/404/error-pages", idParams("404"), body)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing site status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "site not found")
}

func TestUpdateSiteErrorPagesRejectsMalformedBody(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := seedSiteWithErrorPages(t, repo, `{}`)

	ctx := invokeSiteErrorPagesHandler(t, UpdateSiteErrorPages(repo, func() error { return nil }), item.ID, []byte(`{"error_pages":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid request body")
}

func TestUpdateSiteErrorPagesReportsReloadFailure(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := seedSiteWithErrorPages(t, repo, `{}`)

	body := []byte(`{"error_pages":{"404":{"status_code":404,"title":"Gone","html":"<p>gone</p>","content_type":"text/html"}}}`)
	ctx := invokeSiteErrorPagesHandler(t, UpdateSiteErrorPages(repo, func() error { return errTestReload }), item.ID, body)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "config applied but reload failed: "+errTestReload.Error())

	// 写库先于 reload，reload 失败不回滚。
	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	var saved map[string]errorPageConfig
	if err := json.Unmarshal([]byte(loaded.CustomErrorPages), &saved); err != nil {
		t.Fatalf("decode saved error pages: %v (raw=%s)", err, loaded.CustomErrorPages)
	}
	if saved["404"].HTML != "<p>gone</p>" {
		t.Fatalf("error pages should be persisted before reload, got %#v", saved)
	}
}

func TestPreviewErrorPageRejectsMalformedBody(t *testing.T) {
	ctx := invokeSiteRouteHandler(t, PreviewErrorPage(), "POST", "/api/v1/error-pages/preview", nil, []byte(`{"html":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid request body")
}

func TestPreviewErrorPageRequiresHTML(t *testing.T) {
	ctx := invokeSiteRouteHandler(t, PreviewErrorPage(), "POST", "/api/v1/error-pages/preview", nil, []byte(`{"status_code":403}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "html field required")
}

// TestPreviewErrorPageRendersDefaultVariables 覆盖未提供 variables 时注入的内置预览变量。
func TestPreviewErrorPageRendersDefaultVariables(t *testing.T) {
	body := []byte(`{"html":"<h1>{{.StatusCode}}</h1><p>{{.Message}}|{{.ClientIP}}|{{.RequestID}}</p>","status_code":403}`)
	ctx := invokeSiteRouteHandler(t, PreviewErrorPage(), "POST", "/api/v1/error-pages/preview", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Rendered   string `json:"rendered"`
		StatusCode int    `json:"status_code"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("status_code = %d, want 403", resp.StatusCode)
	}
	want := "<h1>403</h1><p>Preview|127.0.0.1|preview-request-id</p>"
	if resp.Rendered != want {
		t.Fatalf("rendered = %q, want %q", resp.Rendered, want)
	}
}

func TestPreviewErrorPageRendersCustomVariables(t *testing.T) {
	body := []byte(`{"html":"<p>{{.Reason}} for {{.Host}}</p>","status_code":502,"variables":{"Reason":"upstream down","Host":"api.example"}}`)
	ctx := invokeSiteRouteHandler(t, PreviewErrorPage(), "POST", "/api/v1/error-pages/preview", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Rendered string `json:"rendered"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Rendered != "<p>upstream down for api.example</p>" {
		t.Fatalf("rendered = %q", resp.Rendered)
	}
}

/**
 * TestPreviewErrorPageReportsTemplateErrors 验证模板解析/执行失败时仍返回 200，
 * 并把原始 HTML 与具体错误一起回传给前端预览面板。
 */
func TestPreviewErrorPageReportsTemplateErrors(t *testing.T) {
	tests := []struct {
		name      string
		html      string
		errorKey  string
		errorPart string
	}{
		{name: "parse error", html: "<p>{{.Title", errorKey: "parse_error", errorPart: "unclosed action"},
		// StatusCode 在默认预览变量中是 int，对其取字段会在执行期报错。
		{name: "execute error", html: "<p>{{.StatusCode.Nested}}</p>", errorKey: "execute_error", errorPart: "can't evaluate field Nested"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"html": tt.html, "status_code": 500})
			if err != nil {
				t.Fatalf("encode payload: %v", err)
			}
			ctx := invokeSiteRouteHandler(t, PreviewErrorPage(), "POST", "/api/v1/error-pages/preview", nil, payload)
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			var resp map[string]any
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp["rendered"] != tt.html {
				t.Fatalf("rendered = %v, want original html", resp["rendered"])
			}
			raw, ok := resp[tt.errorKey].(string)
			if !ok {
				t.Fatalf("missing %s in response: %#v", tt.errorKey, resp)
			}
			if !strings.Contains(raw, tt.errorPart) {
				t.Fatalf("%s = %q, want it to contain %q", tt.errorKey, raw, tt.errorPart)
			}
		})
	}
}
