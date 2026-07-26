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
 * newBotScoreRepoForTest 建立内存库并迁移 BotScoreLog 表。
 */
func newBotScoreRepoForTest(t *testing.T) *repository.BotScoreRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.BotScoreLog{}); err != nil {
		t.Fatalf("migrate bot score log: %v", err)
	}
	return repository.NewBotScoreRepo(db)
}

/**
 * seedBotScoreLogs 写入一组固定的 bot 评分日志用于过滤器断言。
 */
func seedBotScoreLogs(t *testing.T, repo *repository.BotScoreRepo) {
	t.Helper()
	now := time.Now()
	items := []store.BotScoreLog{
		{
			RequestID: "req-alpha", ClientIP: "203.0.113.10", Host: "alpha.example.com", Path: "/login",
			UserAgent: "curl/8.0", TLSJA3Hash: "ja3alpha", TLSJA4: "ja4alpha", TLSSNI: "alpha.example.com",
			TotalScore: 95, IsHighRisk: true, Action: "block", CreatedAt: now.Add(-1 * time.Hour),
		},
		{
			RequestID: "req-beta", ClientIP: "198.51.100.20", Host: "beta.example.com", Path: "/api/data",
			UserAgent: "Mozilla/5.0", TLSJA3Hash: "ja3beta", TLSJA4: "ja4beta", TLSSNI: "beta.example.com",
			TotalScore: 30, IsHighRisk: false, Action: "observe", CreatedAt: now.Add(-2 * time.Hour),
		},
		{
			RequestID: "req-gamma", ClientIP: "203.0.113.10", Host: "alpha.example.com", Path: "/admin",
			UserAgent: "python-requests/2.31", TLSJA3Hash: "ja3gamma", TLSJA4: "ja4gamma", TLSSNI: "alpha.example.com",
			TotalScore: 70, IsHighRisk: true, Action: "drop", CreatedAt: now.Add(-30 * time.Hour),
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("seed bot score logs: %v", err)
	}
}

/**
 * decodeListResponse 解析 {"items":[...],"total":N} 形式的列表响应。
 */
func decodeListResponse(t *testing.T, body []byte) ([]map[string]any, int64) {
	t.Helper()
	var resp struct {
		Items []map[string]any `json:"items"`
		Total int64            `json:"total"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode list response: %v; raw=%s", err, body)
	}
	return resp.Items, resp.Total
}

// TestGetBotStatsReturns24hAggregates 验证 bot 统计仅聚合 24 小时内的记录。
func TestGetBotStatsReturns24hAggregates(t *testing.T) {
	repo := newBotScoreRepoForTest(t)
	seedBotScoreLogs(t, repo)

	ctx := invokeProtectHandler(t, GetBotStats(repo), "GET", "/api/v1/bot-stats", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var stats repository.BotScoreStats
	if err := json.Unmarshal(ctx.Response.Body(), &stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	// 第三条记录创建于 30 小时前，应被排除。
	if stats.Total24h != 2 {
		t.Fatalf("Total24h = %d, want 2", stats.Total24h)
	}
	if stats.Blocked24h != 1 {
		t.Fatalf("Blocked24h = %d, want 1", stats.Blocked24h)
	}
	if stats.HighRisk24h != 1 {
		t.Fatalf("HighRisk24h = %d, want 1", stats.HighRisk24h)
	}
	if stats.AvgScore24h <= 0 {
		t.Fatalf("AvgScore24h = %f, want > 0", stats.AvgScore24h)
	}
}

// TestGetBotStatsReturns500OnRepoError 验证底层表缺失时返回 500。
func TestGetBotStatsReturns500OnRepoError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := repository.NewBotScoreRepo(db)

	ctx := invokeProtectHandler(t, GetBotStats(repo), "GET", "/api/v1/bot-stats", nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when bot_score_logs table is missing, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestGetBotScoresReturnsAllWithoutFilters 验证不带过滤条件时返回全部记录。
func TestGetBotScoresReturnsAllWithoutFilters(t *testing.T) {
	repo := newBotScoreRepoForTest(t)
	seedBotScoreLogs(t, repo)

	ctx := invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	items, total := decodeListResponse(t, ctx.Response.Body())
	if total != 3 || len(items) != 3 {
		t.Fatalf("total=%d len(items)=%d, want 3/3", total, len(items))
	}
}

// TestGetBotScoresAppliesQueryFilters 验证各查询参数被正确映射到 BotScoreFilter。
func TestGetBotScoresAppliesQueryFilters(t *testing.T) {
	repo := newBotScoreRepoForTest(t)
	seedBotScoreLogs(t, repo)

	cases := []struct {
		name  string
		query string
		want  int64
	}{
		{"ip", "?ip=203.0.113.10", 2},
		{"host", "?host=beta.example.com", 1},
		{"path", "?path=/admin", 1},
		{"user_agent", "?user_agent=python-requests", 1},
		{"request_id", "?request_id=req-beta", 1},
		{"ja3_hash", "?ja3_hash=ja3alpha", 1},
		{"ja4", "?ja4=ja4gamma", 1},
		{"tls_sni", "?tls_sni=alpha.example.com", 2},
		{"high_risk_true", "?high_risk=true", 2},
		{"high_risk_false", "?high_risk=false", 1},
		{"min_score", "?min_score=70", 2},
		{"max_score", "?max_score=50", 1},
		{"min_and_max", "?min_score=50&max_score=80", 1},
		{"ip_and_path", "?ip=203.0.113.10&path=/login", 1},
	}
	for _, tc := range cases {
		ctx := invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores"+tc.query, nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: unexpected status %d: %s", tc.name, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		_, total := decodeListResponse(t, ctx.Response.Body())
		if total != tc.want {
			t.Errorf("%s: total = %d, want %d", tc.name, total, tc.want)
		}
	}
}

// TestGetBotScoresAppliesTimeRangeFilters 验证 RFC3339 时间窗口过滤生效。
func TestGetBotScoresAppliesTimeRangeFilters(t *testing.T) {
	repo := newBotScoreRepoForTest(t)
	seedBotScoreLogs(t, repo)

	// RFC3339 的 +08:00 偏移必须转义，否则查询串里的 "+" 会被解码成空格。
	start := url.QueryEscape(time.Now().Add(-3 * time.Hour).Format(time.RFC3339))
	ctx := invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores?start_time="+start, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, total := decodeListResponse(t, ctx.Response.Body()); total != 2 {
		t.Fatalf("start_time filter total = %d, want 2", total)
	}

	end := url.QueryEscape(time.Now().Add(-90 * time.Minute).Format(time.RFC3339))
	ctx = invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores?end_time="+end, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, total := decodeListResponse(t, ctx.Response.Body()); total != 2 {
		t.Fatalf("end_time filter total = %d, want 2", total)
	}
}

// TestGetBotScoresIgnoresMalformedFilterValues 验证非法过滤值被忽略而不是报错。
func TestGetBotScoresIgnoresMalformedFilterValues(t *testing.T) {
	repo := newBotScoreRepoForTest(t)
	seedBotScoreLogs(t, repo)

	const query = "?high_risk=notabool&min_score=abc&max_score=xyz&start_time=badtime&end_time=badtime"
	ctx := invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores"+query, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, total := decodeListResponse(t, ctx.Response.Body()); total != 3 {
		t.Fatalf("malformed filters should be ignored, total = %d want 3", total)
	}
}

// TestGetBotScoresPaginates 验证分页参数与非法分页值的兜底行为。
func TestGetBotScoresPaginates(t *testing.T) {
	repo := newBotScoreRepoForTest(t)
	seedBotScoreLogs(t, repo)

	ctx := invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores?page=1&page_size=2", nil)
	items, total := decodeListResponse(t, ctx.Response.Body())
	if total != 3 || len(items) != 2 {
		t.Fatalf("page 1: total=%d len=%d, want 3/2", total, len(items))
	}

	ctx = invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores?page=2&page_size=2", nil)
	items, total = decodeListResponse(t, ctx.Response.Body())
	if total != 3 || len(items) != 1 {
		t.Fatalf("page 2: total=%d len=%d, want 3/1", total, len(items))
	}

	// 非法分页参数经 utils.Paginate 兜底为 page=1/page_size=20。
	ctx = invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores?page=abc&page_size=-5", nil)
	items, total = decodeListResponse(t, ctx.Response.Body())
	if total != 3 || len(items) != 3 {
		t.Fatalf("invalid pagination: total=%d len=%d, want 3/3", total, len(items))
	}
}

// TestGetBotScoresReturns500OnRepoError 验证底层表缺失时返回 500。
func TestGetBotScoresReturns500OnRepoError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := repository.NewBotScoreRepo(db)

	ctx := invokeProtectHandler(t, GetBotScores(repo), "GET", "/api/v1/bot-scores", nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when bot_score_logs table is missing, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}
