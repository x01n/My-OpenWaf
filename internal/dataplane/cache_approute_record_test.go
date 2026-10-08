package dataplane

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/approute"
	"My-OpenWaf/internal/store/repository"
)

// TestHandlerCachePathRecordsUpstreamResponseHeader 覆盖 H-4 的实际行为差异：
// 走站点响应缓存路径（default 分支）后，应用路由资源记录必须以上游原始响应头为材料。
//
// 区分标记选在两个方向上互斥的两个头：
//   - Keep-Alive：上游发送，但 copyResponseHeaders 按 hop-by-hop 从本进程响应头剥离，
//     因此只在「上游原始响应头」里可见；
//   - X-Request-ID：WAF 写在本进程响应头上，上游不发送。
//
// 修复前 default 分支用 := 遮蔽外层 bufferedResp，外层变量恒为 nil，
// BuildMaterialFromRequestBody 转走 captureRecordedResponseHeaders 分支，
// 于是命中规则 22 而非规则 21，落库的 response_headers_json 也不含上游头。
func TestHandlerCachePathRecordsUpstreamResponseHeader(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache_approute.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	if err := db.AutoMigrate(&approute.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resources: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("cache-path-body"))
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 2, Host: "cache.example.com", Bind: ":80"},
		Bind:                ":80",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
		CacheEnabled:        true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cached", TTL: 300},
		},
		// response_headers_full 不在 shouldRecordAppRouteResponseBody 的判定集合里，
		// 因此带这两条规则的站点仍会走 default 缓存分支——遮蔽正在该路径上。
		AppRouteRules: []appresource.CompiledRule{
			{ID: 21, Target: approute.AppRouteTargetResponseHeadersFull, Op: approute.AppRouteOpFuzzy, Pattern: "keep-alive: timeout=5"},
			{ID: 22, Target: approute.AppRouteTargetResponseHeadersFull, Op: approute.AppRouteOpFuzzy, Pattern: "x-request-id"},
		},
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
		},
	})

	resourceAgg := NewRecordedResourceAggregator(repository.NewRecordedResourceRepo(db), slog.Default())
	defer resourceAgg.Close()

	handler := Handler(Options{
		Holder:             holder,
		Engine:             engine.New(holder, nil, nil, nil),
		Log:                slog.Default(),
		Bind:               ":80",
		ResponseCache:      cache.NewResponseCache(16, 60),
		ResourceAggregator: resourceAgg,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/cached/page")
	ctx.Request.Header.SetHost("cache.example.com")
	ctx.Request.Header.Set("User-Agent", "cache-approute-test")
	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := string(ctx.Response.Body()); got != "cache-path-body" {
		t.Fatalf("body = %q, want upstream body", got)
	}

	// 前置条件探针：captureResponse=true 且 upstreamHeader 非 nil 时，
	// 材料必须采用上游响应头（这是 tryRecordAppRouteResource 期望传入的形态）。
	probeCtx := app.NewContext(0)
	probeCtx.Request.Header.SetMethod(http.MethodGet)
	probeHeader := http.Header{}
	probeHeader.Set("Keep-Alive", "timeout=5")
	probeMat := appresource.BuildMaterialFromRequestBody(probeCtx, nil, appresource.TLSMetadata{}, nil, nil, probeHeader, true)
	probeFull := strings.ToLower(probeMat.ResponseHeadersFull)
	if !strings.Contains(probeFull, "keep-alive") {
		t.Fatalf("探针前置条件不成立：upstreamHeader 非 nil 时必须采用上游头, got %q", probeMat.ResponseHeadersFull)
	}
	if strings.Contains(probeFull, "x-request-id") {
		t.Fatalf("探针前置条件不成立：上游头探针不应含本进程头, got %q", probeMat.ResponseHeadersFull)
	}

	resourceAgg.Close()

	var rec approute.RecordedResource
	if err := db.Where("site_id = ? AND path = ?", 2, "/cached/page").First(&rec).Error; err != nil {
		t.Fatalf("load recorded resource: %v", err)
	}
	if rec.MatchedRuleIDs != "21" {
		t.Fatalf("MatchedRuleIDs = %q, want \"21\"——命中 22 说明记录材料退化为本进程响应头", rec.MatchedRuleIDs)
	}
	if !strings.Contains(rec.ResponseHeadersJSON, "timeout=5") {
		t.Fatalf("ResponseHeadersJSON = %q, want 上游 Keep-Alive 值（仅上游头可见）", rec.ResponseHeadersJSON)
	}
	if strings.Contains(rec.ResponseHeadersJSON, "x-request-id") {
		t.Fatalf("ResponseHeadersJSON = %q, want 上游头而非本进程头", rec.ResponseHeadersJSON)
	}
}
