package protect

import (
	"bytes"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/**
 * newDropEventRepoForTest 建立内存库并迁移 DropEvent 表。
 */
func newDropEventRepoForTest(t *testing.T) *repository.DropEventRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.DropEvent{}); err != nil {
		t.Fatalf("migrate drop event: %v", err)
	}
	return repository.NewDropEventRepo(db)
}

/**
 * seedDropEvents 写入覆盖全部 source 分类的 drop 事件。
 */
func seedDropEvents(t *testing.T, repo *repository.DropEventRepo) {
	t.Helper()
	now := time.Now()
	items := []store.DropEvent{
		{ClientIP: "203.0.113.10", Source: "bot", RuleID: "bot-1", Host: "a.example.com", Path: "/x", CreatedAt: now.Add(-1 * time.Hour)},
		{ClientIP: "203.0.113.11", Source: "cve", RuleID: "cve-1", Host: "a.example.com", Path: "/y", CreatedAt: now.Add(-2 * time.Hour)},
		{ClientIP: "203.0.113.12", Source: "rule", RuleID: "rule-1", Host: "b.example.com", Path: "/z", CreatedAt: now.Add(-3 * time.Hour)},
		{ClientIP: "203.0.113.13", Source: "ip_reputation", RuleID: "iprep-1", Host: "b.example.com", Path: "/w", CreatedAt: now.Add(-4 * time.Hour)},
		{ClientIP: "203.0.113.10", Source: "bot", RuleID: "bot-2", Host: "a.example.com", Path: "/old", CreatedAt: now.Add(-30 * time.Hour)},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("seed drop events: %v", err)
	}
}

// TestGetDropStatsAggregatesBySource 验证 drop 统计按 source 分桶且只覆盖 24 小时窗口。
func TestGetDropStatsAggregatesBySource(t *testing.T) {
	repo := newDropEventRepoForTest(t)
	seedDropEvents(t, repo)

	ctx := invokeProtectHandler(t, GetDropStats(repo), "GET", "/api/v1/drop-stats", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var stats repository.DropStatsSummary
	if err := json.Unmarshal(ctx.Response.Body(), &stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	// 第五条记录创建于 30 小时前，应被排除。
	if stats.Total24h != 4 {
		t.Fatalf("Total24h = %d, want 4", stats.Total24h)
	}
	if stats.ByBot != 1 || stats.ByCVE != 1 || stats.ByRule != 1 || stats.ByIPReputation != 1 {
		t.Fatalf("source buckets mismatch: %#v", stats)
	}
}

// TestGetDropStatsReturns500OnRepoError 验证底层表缺失时返回 500。
func TestGetDropStatsReturns500OnRepoError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := repository.NewDropEventRepo(db)

	ctx := invokeProtectHandler(t, GetDropStats(repo), "GET", "/api/v1/drop-stats", nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when drop_events table is missing, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestGetDropEventsAppliesQueryFilters 验证 ip/source 过滤参数映射到 DropEventFilter。
func TestGetDropEventsAppliesQueryFilters(t *testing.T) {
	repo := newDropEventRepoForTest(t)
	seedDropEvents(t, repo)

	cases := []struct {
		name  string
		query string
		want  int64
	}{
		{"no_filter", "", 5},
		{"ip", "?ip=203.0.113.10", 2},
		{"source_bot", "?source=bot", 2},
		{"source_cve", "?source=cve", 1},
		{"source_ip_reputation", "?source=ip_reputation", 1},
		{"ip_and_source", "?ip=203.0.113.10&source=bot", 2},
		{"unmatched_ip", "?ip=198.51.100.1", 0},
	}
	for _, tc := range cases {
		ctx := invokeProtectHandler(t, GetDropEvents(repo), "GET", "/api/v1/drop-events"+tc.query, nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: unexpected status %d: %s", tc.name, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		if _, total := decodeListResponse(t, ctx.Response.Body()); total != tc.want {
			t.Errorf("%s: total = %d, want %d", tc.name, total, tc.want)
		}
	}
}

// TestGetDropEventsAppliesTimeRangeFilters 验证 RFC3339 时间窗口过滤生效。
func TestGetDropEventsAppliesTimeRangeFilters(t *testing.T) {
	repo := newDropEventRepoForTest(t)
	seedDropEvents(t, repo)

	// RFC3339 的 +08:00 偏移必须转义，否则查询串里的 "+" 会被解码成空格。
	start := url.QueryEscape(time.Now().Add(-150 * time.Minute).Format(time.RFC3339))
	ctx := invokeProtectHandler(t, GetDropEvents(repo), "GET", "/api/v1/drop-events?start_time="+start, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, total := decodeListResponse(t, ctx.Response.Body()); total != 2 {
		t.Fatalf("start_time filter total = %d, want 2", total)
	}

	end := url.QueryEscape(time.Now().Add(-150 * time.Minute).Format(time.RFC3339))
	ctx = invokeProtectHandler(t, GetDropEvents(repo), "GET", "/api/v1/drop-events?end_time="+end, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, total := decodeListResponse(t, ctx.Response.Body()); total != 3 {
		t.Fatalf("end_time filter total = %d, want 3", total)
	}
}

// TestGetDropEventsIgnoresMalformedTimeValues 验证非法时间值被忽略而不是报错。
func TestGetDropEventsIgnoresMalformedTimeValues(t *testing.T) {
	repo := newDropEventRepoForTest(t)
	seedDropEvents(t, repo)

	ctx := invokeProtectHandler(t, GetDropEvents(repo), "GET", "/api/v1/drop-events?start_time=nope&end_time=nope", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, total := decodeListResponse(t, ctx.Response.Body()); total != 5 {
		t.Fatalf("malformed time filters should be ignored, total = %d want 5", total)
	}
}

// TestGetDropEventsPaginates 验证分页参数与非法分页值的兜底行为。
func TestGetDropEventsPaginates(t *testing.T) {
	repo := newDropEventRepoForTest(t)
	seedDropEvents(t, repo)

	ctx := invokeProtectHandler(t, GetDropEvents(repo), "GET", "/api/v1/drop-events?page=1&page_size=3", nil)
	items, total := decodeListResponse(t, ctx.Response.Body())
	if total != 5 || len(items) != 3 {
		t.Fatalf("page 1: total=%d len=%d, want 5/3", total, len(items))
	}

	ctx = invokeProtectHandler(t, GetDropEvents(repo), "GET", "/api/v1/drop-events?page=2&page_size=3", nil)
	items, total = decodeListResponse(t, ctx.Response.Body())
	if total != 5 || len(items) != 2 {
		t.Fatalf("page 2: total=%d len=%d, want 5/2", total, len(items))
	}

	ctx = invokeProtectHandler(t, GetDropEvents(repo), "GET", "/api/v1/drop-events?page=&page_size=notanumber", nil)
	items, total = decodeListResponse(t, ctx.Response.Body())
	if total != 5 || len(items) != 5 {
		t.Fatalf("invalid pagination: total=%d len=%d, want 5/5", total, len(items))
	}
}

// TestGetDropEventsReturns500OnRepoError 验证底层表缺失时返回 500。
func TestGetDropEventsReturns500OnRepoError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := repository.NewDropEventRepo(db)

	ctx := invokeProtectHandler(t, GetDropEvents(repo), "GET", "/api/v1/drop-events", nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when drop_events table is missing, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}
