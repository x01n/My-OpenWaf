package event

import (
	"context"
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newEventDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SecurityEvent{}, &store.AccessLog{}, &store.Site{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func invokeHandler(handler app.HandlerFunc, method, uri string, body []byte, ps param.Params) *app.RequestContext {
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	if ps != nil {
		ctx.Params = ps
	}
	handler(context.Background(), ctx)
	return ctx
}

// ---------- SecurityEvent 处理器测试 ----------

func TestListSecurityEventsReturns200(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(ListSecurityEvents(repo), "GET", "/api/v1/security-events", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d", ctx.Response.StatusCode())
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["items"] == nil {
		t.Error("expected items field in response")
	}
}

func TestGetSecurityEventInvalidIDReturns400(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(GetSecurityEvent(repo), "GET", "/api/v1/security-events/abc",
		nil, param.Params{{Key: "id", Value: "abc"}})
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid id, got %d", ctx.Response.StatusCode())
	}
}

func TestGetSecurityEventNotFoundReturns404(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(GetSecurityEvent(repo), "GET", "/api/v1/security-events/9999",
		nil, param.Params{{Key: "id", Value: "9999"}})
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 for missing event, got %d", ctx.Response.StatusCode())
	}
}

func TestSecurityEventStatsReturns200(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(SecurityEventStats(repo), "GET", "/api/v1/security-events/stats", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d", ctx.Response.StatusCode())
	}
}

func TestSecurityEventStatsCustomHours(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(SecurityEventStats(repo), "GET", "/api/v1/security-events/stats?hours=48", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d", ctx.Response.StatusCode())
	}
	var resp map[string]any
	json.Unmarshal(ctx.Response.Body(), &resp)
	if resp["hours"].(float64) != 48 {
		t.Errorf("hours = %v, want 48", resp["hours"])
	}
}

func TestSecurityEventTimelineReturns200(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(SecurityEventTimeline(repo), "GET", "/api/v1/security-events/timeline", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d", ctx.Response.StatusCode())
	}
}

func TestListSiteSecurityEventsSiteNotFoundReturns404(t *testing.T) {
	db := newEventDB(t)
	siteRepo := repository.NewSiteRepo(db)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(ListSiteSecurityEvents(siteRepo, repo), "GET", "/api/v1/sites/9999/security-events",
		nil, param.Params{{Key: "id", Value: "9999"}})
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 for missing site, got %d", ctx.Response.StatusCode())
	}
}

func TestListSiteSecurityEventsInvalidIDReturns400(t *testing.T) {
	db := newEventDB(t)
	siteRepo := repository.NewSiteRepo(db)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(ListSiteSecurityEvents(siteRepo, repo), "GET", "/api/v1/sites/abc/security-events",
		nil, param.Params{{Key: "id", Value: "abc"}})
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid site id, got %d", ctx.Response.StatusCode())
	}
}

func TestSiteSecurityEventStatsSiteNotFoundReturns404(t *testing.T) {
	db := newEventDB(t)
	siteRepo := repository.NewSiteRepo(db)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(SiteSecurityEventStats(siteRepo, repo), "GET", "/api/v1/sites/9999/security-events/stats",
		nil, param.Params{{Key: "id", Value: "9999"}})
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 for missing site, got %d", ctx.Response.StatusCode())
	}
}

func TestSiteSecurityEventTimelineSiteNotFoundReturns404(t *testing.T) {
	db := newEventDB(t)
	siteRepo := repository.NewSiteRepo(db)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(SiteSecurityEventTimeline(siteRepo, repo), "GET", "/api/v1/sites/9999/security-events/timeline",
		nil, param.Params{{Key: "id", Value: "9999"}})
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 for missing site, got %d", ctx.Response.StatusCode())
	}
}

// ---------- GetRequestTrace 测试 ----------

func TestGetRequestTraceEmptyIDReturns400(t *testing.T) {
	db := newEventDB(t)
	accessRepo := repository.NewAccessLogRepo(db)
	secRepo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(GetRequestTrace(accessRepo, secRepo), "GET", "/api/v1/trace/",
		nil, param.Params{{Key: "request_id", Value: ""}})
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for empty request_id, got %d", ctx.Response.StatusCode())
	}
}

func TestGetRequestTraceReturns200WithData(t *testing.T) {
	db := newEventDB(t)
	accessRepo := repository.NewAccessLogRepo(db)
	secRepo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(GetRequestTrace(accessRepo, secRepo), "GET", "/api/v1/trace/req-xyz",
		nil, param.Params{{Key: "request_id", Value: "req-xyz"}})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["request_id"] != "req-xyz" {
		t.Errorf("request_id = %v, want req-xyz", resp["request_id"])
	}
}
