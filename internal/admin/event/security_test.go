package event

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

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

func TestListSecurityEventRequestsReturns200(t *testing.T) {
	db := newEventDB(t)
	repo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(ListSecurityEventRequests(repo), "GET", "/api/v1/security-events/requests", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["items"] == nil {
		t.Error("expected items field in response")
	}
}

func TestListSecurityEventRequestsAppliesActionFilter(t *testing.T) {
	db := newEventDB(t)
	now := time.Now()
	events := []store.SecurityEvent{
		{RequestID: "req-a", Action: "intercept", CreatedAt: now.Add(-2 * time.Minute)},
		{RequestID: "req-a", Action: "observe", CreatedAt: now.Add(-time.Minute)},
		{RequestID: "req-b", Action: "observe", CreatedAt: now},
	}
	for i := range events {
		if err := db.Create(&events[i]).Error; err != nil {
			t.Fatalf("create event: %v", err)
		}
	}
	repo := repository.NewSecurityEventRepo(db)

	ctx := invokeHandler(ListSecurityEventRequests(repo), "GET",
		"/api/v1/security-events/requests?action=intercept", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		Items []repository.SecurityEventRequest `json:"items"`
		Total int64                             `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// 仅 req-a 有 intercept 事件，req-b 应被过滤掉。
	if resp.Total != 1 {
		t.Fatalf("total = %d, want 1", resp.Total)
	}
	if len(resp.Items) != 1 || resp.Items[0].RequestID != "req-a" {
		t.Fatalf("items = %+v, want only req-a", resp.Items)
	}
}

func TestListSecurityEventRequestsPageSize(t *testing.T) {
	db := newEventDB(t)
	now := time.Now()
	events := []store.SecurityEvent{
		{RequestID: "req-a", Action: "intercept", CreatedAt: now.Add(-2 * time.Minute)},
		{RequestID: "req-b", Action: "intercept", CreatedAt: now.Add(-time.Minute)},
		{RequestID: "req-c", Action: "intercept", CreatedAt: now},
	}
	for i := range events {
		if err := db.Create(&events[i]).Error; err != nil {
			t.Fatalf("create event: %v", err)
		}
	}
	repo := repository.NewSecurityEventRepo(db)

	ctx := invokeHandler(ListSecurityEventRequests(repo), "GET",
		"/api/v1/security-events/requests?page_size=1", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		Items []repository.SecurityEventRequest `json:"items"`
		Total int64                             `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("items = %d, want 1 (page_size=1)", len(resp.Items))
	}
	if resp.Total != 3 {
		t.Fatalf("total = %d, want 3 (all distinct request_id)", resp.Total)
	}
	// last_seen DESC 下首条应是最新的 req-c。
	if resp.Items[0].RequestID != "req-c" {
		t.Errorf("first item = %s, want req-c", resp.Items[0].RequestID)
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
	ctx := invokeHandler(GetRequestTrace(accessRepo, secRepo, nil), "GET", "/api/v1/trace/",
		nil, param.Params{{Key: "request_id", Value: ""}})
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for empty request_id, got %d", ctx.Response.StatusCode())
	}
}

func TestGetRequestTraceReturns200WithData(t *testing.T) {
	db := newEventDB(t)
	accessRepo := repository.NewAccessLogRepo(db)
	secRepo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(GetRequestTrace(accessRepo, secRepo, nil), "GET", "/api/v1/trace/req-xyz",
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

// TestGetRequestTraceReturnsEmptyBotScoresWhenRepoNil 固化 botScoreRepo 为 nil 时的降级契约。
//
// Bot 评分表位于日志库，未启用时 Dependencies.BotScore 可能为 nil。此时 bot_scores
// 必须是空数组而不是 null，前端才能直接 .map 而无需判空。
func TestGetRequestTraceReturnsEmptyBotScoresWhenRepoNil(t *testing.T) {
	db := newEventDB(t)
	accessRepo := repository.NewAccessLogRepo(db)
	secRepo := repository.NewSecurityEventRepo(db)
	ctx := invokeHandler(GetRequestTrace(accessRepo, secRepo, nil), "GET", "/api/v1/trace/req-nil-bot",
		nil, param.Params{{Key: "request_id", Value: "req-nil-bot"}})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		BotScores []store.BotScoreLog `json:"bot_scores"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.BotScores == nil {
		t.Fatal("bot_scores 必须是空数组而不是 null")
	}
	if len(resp.BotScores) != 0 {
		t.Fatalf("bot_scores = %+v, want empty", resp.BotScores)
	}
	if !strings.Contains(string(ctx.Response.Body()), `"bot_scores":[]`) {
		t.Fatalf("bot_scores 应序列化为 []，实际响应：%s", ctx.Response.Body())
	}
}

// TestGetRequestTraceReturnsBotScoreForSameRequestID 验证 Bot 评分按 request_id 关联返回。
//
// 「人机访问概率」的数据源就是这里的 total_score 与四个分项，前端据此展示判定依据，
// 不新增任何数据库字段。
func TestGetRequestTraceReturnsBotScoreForSameRequestID(t *testing.T) {
	db := newEventDB(t)
	if err := db.AutoMigrate(&store.BotScoreLog{}); err != nil {
		t.Fatalf("migrate bot score log: %v", err)
	}
	accessRepo := repository.NewAccessLogRepo(db)
	secRepo := repository.NewSecurityEventRepo(db)
	botRepo := repository.NewBotScoreRepo(db)

	if err := botRepo.Create(&store.BotScoreLog{
		RequestID:        "req-bot-1",
		ClientIP:         "203.0.113.9",
		TotalScore:       82,
		GeoIPScore:       10,
		FingerprintScore: 40,
		BehaviorScore:    22,
		IPRepScore:       10,
		IsHighRisk:       true,
		Action:           "intercept",
		CreatedAt:        time.Now(),
	}); err != nil {
		t.Fatalf("create bot score: %v", err)
	}
	if err := botRepo.Create(&store.BotScoreLog{
		RequestID:  "req-bot-other",
		TotalScore: 5,
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("create unrelated bot score: %v", err)
	}

	ctx := invokeHandler(GetRequestTrace(accessRepo, secRepo, botRepo), "GET", "/api/v1/trace/req-bot-1",
		nil, param.Params{{Key: "request_id", Value: "req-bot-1"}})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		BotScores []store.BotScoreLog `json:"bot_scores"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.BotScores) != 1 {
		t.Fatalf("bot_scores 应只含本 request_id 的 1 条，实际 %d 条：%+v", len(resp.BotScores), resp.BotScores)
	}
	got := resp.BotScores[0]
	if got.RequestID != "req-bot-1" {
		t.Errorf("request_id = %q, want req-bot-1", got.RequestID)
	}
	if got.TotalScore != 82 || got.FingerprintScore != 40 || got.BehaviorScore != 22 {
		t.Errorf("评分分项未完整返回：%+v", got)
	}
	if !got.IsHighRisk {
		t.Error("is_high_risk 应为 true")
	}
}
