package site

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// newSiteLogReposForTest 迁移站点与两类日志表，用于观测类 handler 的正常路径。
func newSiteLogReposForTest(t *testing.T) (*repository.SiteRepo, *repository.AccessLogRepo, *repository.DropEventRepo, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.AccessLog{}, &store.DropEvent{}); err != nil {
		t.Fatalf("migrate observability tables: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewAccessLogRepo(db), repository.NewDropEventRepo(db), db
}

// newSiteOnlyLogReposForTest 只迁移站点表，日志表缺失以触发 500 分支。
func newSiteOnlyLogReposForTest(t *testing.T) (*repository.SiteRepo, *repository.AccessLogRepo, *repository.DropEventRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}); err != nil {
		t.Fatalf("migrate sites: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewAccessLogRepo(db), repository.NewDropEventRepo(db)
}

func seedObservabilitySite(t *testing.T, repo *repository.SiteRepo, host string) *store.Site {
	t.Helper()
	item := &store.Site{Host: host, UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(item); err != nil {
		t.Fatalf("seed site %s: %v", host, err)
	}
	return item
}

/**
 * TestSiteObservabilityHandlersRejectInvalidIDAndMissingSite 统一覆盖四个观测
 * handler 的 400（ID 无法解析）与 404（站点不存在）前置校验分支。
 */
func TestSiteObservabilityHandlersRejectInvalidIDAndMissingSite(t *testing.T) {
	siteRepo, accessRepo, dropRepo, _ := newSiteLogReposForTest(t)

	handlers := map[string]app.HandlerFunc{
		"access-logs":       ListSiteAccessLogs(siteRepo, accessRepo),
		"access-logs/stats": SiteAccessLogStats(siteRepo, accessRepo),
		"drop-events":       ListSiteDropEvents(siteRepo, dropRepo),
		"drop-stats":        SiteDropStats(siteRepo, dropRepo),
	}

	for name, handler := range handlers {
		t.Run(name+" invalid id", func(t *testing.T) {
			ctx := invokeSiteRouteHandler(t, handler, "GET", "/api/v1/sites/abc/"+name, idParams("abc"), nil)
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("status = %d, want 400, body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			requireErrorMessage(t, ctx.Response.Body(), "invalid id")
		})
		t.Run(name+" missing site", func(t *testing.T) {
			ctx := invokeSiteRouteHandler(t, handler, "GET", "/api/v1/sites/404/"+name, idParams("404"), nil)
			if ctx.Response.StatusCode() != 404 {
				t.Fatalf("status = %d, want 404, body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			requireErrorMessage(t, ctx.Response.Body(), "site not found")
		})
	}
}

func TestSiteObservabilityHandlersReturn500WhenQueryFails(t *testing.T) {
	siteRepo, accessRepo, dropRepo := newSiteOnlyLogReposForTest(t)
	item := seedObservabilitySite(t, siteRepo, "observability-error.example")
	rawID := strconv.FormatUint(uint64(item.ID), 10)

	handlers := map[string]app.HandlerFunc{
		"access-logs":       ListSiteAccessLogs(siteRepo, accessRepo),
		"access-logs/stats": SiteAccessLogStats(siteRepo, accessRepo),
		"drop-events":       ListSiteDropEvents(siteRepo, dropRepo),
		"drop-stats":        SiteDropStats(siteRepo, dropRepo),
	}

	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			ctx := invokeSiteRouteHandler(t, handler, "GET", "/api/v1/sites/1/"+name, idParams(rawID), nil)
			if ctx.Response.StatusCode() != 500 {
				t.Fatalf("status = %d, want 500, body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
		})
	}
}

// TestListSiteAccessLogsFiltersByLogID 覆盖 `id` 查询参数（与路由参数同名但含义不同）。
func TestListSiteAccessLogsFiltersByLogID(t *testing.T) {
	siteRepo, accessRepo, _, db := newSiteLogReposForTest(t)
	item := seedObservabilitySite(t, siteRepo, "access-log-id.example")

	now := time.Now()
	logs := []store.AccessLog{
		{SiteID: item.ID, CreatedAt: now, ClientIP: "203.0.113.1", Path: "/first", Method: "GET", StatusCode: 200},
		{SiteID: item.ID, CreatedAt: now, ClientIP: "203.0.113.2", Path: "/second", Method: "GET", StatusCode: 200},
	}
	if err := db.Create(&logs).Error; err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	ctx := invokeSiteGetHandler(t, ListSiteAccessLogs(siteRepo, accessRepo), item.ID, "/api/v1/sites/1/access-logs", url.Values{
		"id": {strconv.FormatUint(uint64(logs[1].ID), 10)},
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected single log, total=%d items=%d", resp.Total, len(resp.Items))
	}
	if resp.Items[0].Path != "/second" {
		t.Fatalf("unexpected log path %q", resp.Items[0].Path)
	}
	if resp.Page != 1 {
		t.Fatalf("page = %d, want 1", resp.Page)
	}
}

func TestListSiteAccessLogsFiltersBySinceAndUntil(t *testing.T) {
	siteRepo, accessRepo, _, db := newSiteLogReposForTest(t)
	item := seedObservabilitySite(t, siteRepo, "access-log-window.example")

	base := time.Date(2026, 6, 8, 10, 0, 0, 0, time.UTC)
	logs := []store.AccessLog{
		{SiteID: item.ID, CreatedAt: base.Add(-time.Hour), Path: "/before", Method: "GET", StatusCode: 200},
		{SiteID: item.ID, CreatedAt: base.Add(30 * time.Minute), Path: "/inside", Method: "GET", StatusCode: 200},
		{SiteID: item.ID, CreatedAt: base.Add(5 * time.Hour), Path: "/after", Method: "GET", StatusCode: 200},
	}
	if err := db.Create(&logs).Error; err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	ctx := invokeSiteGetHandler(t, ListSiteAccessLogs(siteRepo, accessRepo), item.ID, "/api/v1/sites/1/access-logs", url.Values{
		"since": {base.Format(time.RFC3339)},
		"until": {base.Add(2 * time.Hour).Format(time.RFC3339)},
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].Path != "/inside" {
		t.Fatalf("time window filter mismatch: total=%d items=%#v", resp.Total, resp.Items)
	}
}

/**
 * TestSiteAccessLogStatsClampsHoursWindow 覆盖 hours 参数的三个分支：
 * 合法值直接使用，<=0 与 >720 均回落到 24 小时。
 */
func TestSiteAccessLogStatsClampsHoursWindow(t *testing.T) {
	siteRepo, accessRepo, _, db := newSiteLogReposForTest(t)
	item := seedObservabilitySite(t, siteRepo, "access-log-hours.example")

	now := time.Now()
	logs := []store.AccessLog{
		{SiteID: item.ID, CreatedAt: now.Add(-time.Hour), Path: "/recent", Method: "GET", StatusCode: 200, WAFAction: "intercept", CacheState: "hit"},
		{SiteID: item.ID, CreatedAt: now.Add(-100 * time.Hour), Path: "/old", Method: "GET", StatusCode: 200, WAFAction: "observe", CacheState: "miss"},
	}
	if err := db.Create(&logs).Error; err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	tests := []struct {
		name         string
		hours        string
		wantRequests int64
	}{
		{name: "default window", hours: "", wantRequests: 1},
		{name: "zero falls back to 24h", hours: "0", wantRequests: 1},
		{name: "negative falls back to 24h", hours: "-5", wantRequests: 1},
		{name: "above 30 days falls back to 24h", hours: "1000", wantRequests: 1},
		{name: "explicit wide window", hours: "200", wantRequests: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := url.Values{}
			if tt.hours != "" {
				query.Set("hours", tt.hours)
			}
			ctx := invokeSiteGetHandler(t, SiteAccessLogStats(siteRepo, accessRepo), item.ID, "/api/v1/sites/1/access-logs/stats", query)
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			var stats repository.SiteAccessLogStats
			if err := json.Unmarshal(ctx.Response.Body(), &stats); err != nil {
				t.Fatalf("decode stats: %v", err)
			}
			if stats.Requests != tt.wantRequests {
				t.Fatalf("requests = %d, want %d (stats=%#v)", stats.Requests, tt.wantRequests, stats)
			}
		})
	}
}

func TestSiteDropStatsAggregatesLast24Hours(t *testing.T) {
	siteRepo, _, dropRepo, db := newSiteLogReposForTest(t)
	item := seedObservabilitySite(t, siteRepo, "drop-stats.example")
	other := seedObservabilitySite(t, siteRepo, "drop-stats-other.example")

	now := time.Now()
	events := []store.DropEvent{
		{SiteID: item.ID, ClientIP: "203.0.113.1", Source: "bot", CreatedAt: now.Add(-time.Hour)},
		{SiteID: item.ID, ClientIP: "203.0.113.2", Source: "bot", CreatedAt: now.Add(-2 * time.Hour)},
		{SiteID: item.ID, ClientIP: "203.0.113.3", Source: "cve", CreatedAt: now.Add(-3 * time.Hour)},
		{SiteID: item.ID, ClientIP: "203.0.113.4", Source: "rule", CreatedAt: now.Add(-4 * time.Hour)},
		{SiteID: item.ID, ClientIP: "203.0.113.5", Source: "ip_reputation", CreatedAt: now.Add(-5 * time.Hour)},
		// 超过 24 小时窗口，应被排除。
		{SiteID: item.ID, ClientIP: "203.0.113.6", Source: "bot", CreatedAt: now.Add(-30 * time.Hour)},
		// 属于其他站点，应被排除。
		{SiteID: other.ID, ClientIP: "203.0.113.7", Source: "bot", CreatedAt: now.Add(-time.Hour)},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatalf("seed drop events: %v", err)
	}

	ctx := invokeSiteGetHandler(t, SiteDropStats(siteRepo, dropRepo), item.ID, "/api/v1/sites/1/drop-stats", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var stats repository.DropStatsSummary
	if err := json.Unmarshal(ctx.Response.Body(), &stats); err != nil {
		t.Fatalf("decode drop stats: %v", err)
	}
	if stats.Total24h != 5 {
		t.Fatalf("total_24h = %d, want 5 (stats=%#v)", stats.Total24h, stats)
	}
	if stats.ByBot != 2 || stats.ByCVE != 1 || stats.ByRule != 1 || stats.ByIPReputation != 1 {
		t.Fatalf("drop stats breakdown mismatch: %#v", stats)
	}
}

func TestListSiteDropEventsAppliesPagination(t *testing.T) {
	siteRepo, _, dropRepo, db := newSiteLogReposForTest(t)
	item := seedObservabilitySite(t, siteRepo, "drop-events-page.example")

	now := time.Now()
	events := make([]store.DropEvent, 0, 3)
	for i := 0; i < 3; i++ {
		events = append(events, store.DropEvent{SiteID: item.ID, ClientIP: "203.0.113.1", Source: "bot", Path: "/p" + strconv.Itoa(i), CreatedAt: now.Add(-time.Duration(i) * time.Minute)})
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatalf("seed drop events: %v", err)
	}

	ctx := invokeSiteGetHandler(t, ListSiteDropEvents(siteRepo, dropRepo), item.ID, "/api/v1/sites/1/drop-events", url.Values{
		"page":      {"2"},
		"page_size": {"2"},
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []store.DropEvent `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 3 {
		t.Fatalf("total = %d, want 3", resp.Total)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("second page should hold one event, got %#v", resp.Items)
	}
	if resp.Page != 2 {
		t.Fatalf("page = %d, want 2", resp.Page)
	}
}
