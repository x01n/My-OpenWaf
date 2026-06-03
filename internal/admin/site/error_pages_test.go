package site

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func newSiteRepoForTest(t *testing.T) *repository.SiteRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}); err != nil {
		t.Fatalf("migrate sites: %v", err)
	}
	return repository.NewSiteRepo(db)
}

func invokeSiteErrorPagesHandler(t *testing.T, handler app.HandlerFunc, siteID uint, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/1/error-pages")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: strconv.FormatUint(uint64(siteID), 10)}}
	handler(context.Background(), ctx)
	return ctx
}

func seedSiteWithErrorPages(t *testing.T, repo *repository.SiteRepo, pages string) *store.Site {
	t.Helper()
	item := &store.Site{
		Host:             "example.test",
		UpstreamURLs:     `["http://127.0.0.1:8080"]`,
		Bind:             ":8081",
		Network:          "tcp",
		CustomErrorPages: pages,
	}
	if err := repo.Create(item); err != nil {
		t.Fatalf("create site: %v", err)
	}
	return item
}

func TestUpdateSiteErrorPagesRequiresErrorPagesField(t *testing.T) {
	repo := newSiteRepoForTest(t)
	original := `{"502":{"status_code":502,"title":"Bad Gateway","html":"<p>old</p>","content_type":"text/html"}}`
	item := seedSiteWithErrorPages(t, repo, original)

	for _, body := range [][]byte{[]byte(`{}`), []byte(`{"error_pages":null}`)} {
		ctx := invokeSiteErrorPagesHandler(t, UpdateSiteErrorPages(repo, func() error { return nil }), item.ID, body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("expected missing/null error_pages to be rejected, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		loaded, err := repo.Get(item.ID)
		if err != nil {
			t.Fatalf("load site: %v", err)
		}
		if loaded.CustomErrorPages != original {
			t.Fatalf("rejected request should preserve custom_error_pages, got %s", loaded.CustomErrorPages)
		}
	}
}

func TestUpdateSiteErrorPagesAllowsExplicitEmptyObject(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := seedSiteWithErrorPages(t, repo, `{"502":{"html":"<p>old</p>"}}`)

	ctx := invokeSiteErrorPagesHandler(t, UpdateSiteErrorPages(repo, func() error { return nil }), item.ID, []byte(`{"error_pages":{}}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.CustomErrorPages != "{}" {
		t.Fatalf("explicit empty error_pages should clear to {}, got %s", loaded.CustomErrorPages)
	}
}

func TestUpdateSiteErrorPagesPersistsConfiguredPage(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := seedSiteWithErrorPages(t, repo, `{}`)

	body := []byte(`{"error_pages":{"502":{"status_code":502,"title":"Bad Gateway","html":"<p>new</p>","content_type":"text/html"}}}`)
	ctx := invokeSiteErrorPagesHandler(t, UpdateSiteErrorPages(repo, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		ErrorPages map[string]errorPageConfig `json:"error_pages"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	page, ok := resp.ErrorPages["502"]
	if !ok || page.StatusCode != 502 || page.Title != "Bad Gateway" || page.HTML != "<p>new</p>" || page.ContentType != "text/html" {
		t.Fatalf("unexpected response error_pages: %#v", resp.ErrorPages)
	}

	getCtx := invokeSiteErrorPagesHandler(t, GetSiteErrorPages(repo), item.ID, nil)
	if getCtx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected get status %d: %s", getCtx.Response.StatusCode(), bytes.TrimSpace(getCtx.Response.Body()))
	}
	var getResp struct {
		ErrorPages map[string]errorPageConfig `json:"error_pages"`
	}
	if err := json.Unmarshal(getCtx.Response.Body(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getResp.ErrorPages["502"].HTML != "<p>new</p>" {
		t.Fatalf("GET should return saved 502 page, got %#v", getResp.ErrorPages)
	}
}
