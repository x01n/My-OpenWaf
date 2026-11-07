package dataplane

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

/**
 * dpSiteIsolationLimiter 是本包内最小限流后端替身：按 key 计数、配额固定。
 */
type dpSiteIsolationLimiter struct {
	max    int
	counts map[string]int
}

func (l *dpSiteIsolationLimiter) Enabled() bool                { return true }
func (l *dpSiteIsolationLimiter) Reconfigure(_, _ int, _ bool) {}
func (l *dpSiteIsolationLimiter) Close()                       {}
func (l *dpSiteIsolationLimiter) IsOverLimit(key string) bool  { return l.counts[key] > l.max }
func (l *dpSiteIsolationLimiter) Increment(key string) int64 {
	l.counts[key]++
	return int64(l.counts[key])
}
func (l *dpSiteIsolationLimiter) Allow(key string) bool {
	l.counts[key]++
	return l.counts[key] <= l.max
}

/**
 * TestHandlerRateLimitCountsPerSiteAcrossBinds 是数据面端到端隔离验证。
 *
 * 场：两个站点行同 Host `isolation.example.test`，bind 分别 :25500 / :25501，
 * 全局请求限流配额 3 / 窗口 60s。
 * 判据：在 :25500 上打满窗口后，:25501 的第一次请求必须仍在配额内——
 * 若两站点共用同一计数桶，它会直接被判超限。
 */
func TestHandlerRateLimitCountsPerSiteAcrossBinds(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.RequestRateLimitEnabled = true
	protection.RequestRateLimitWindow = 60
	protection.RequestRateLimitMax = 3
	protection.RequestRateLimitAction = "rate_limit"

	const host = "isolation.example.test"
	rtA := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: host, Bind: ":25500"},
		Bind:                ":25500",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	rtB := snapshot.SiteRuntime{
		Site:                store.Site{ID: 2, Host: host, Bind: ":25501"},
		Bind:                ":25501",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":25500", host): &rtA,
			snapshot.SiteMapKey(":25501", host): &rtB,
		},
	})

	var upstreamHits atomic.Int64
	limiter := &dpSiteIsolationLimiter{max: 3, counts: map[string]int{}}
	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, limiter, nil, nil),
		Writer:                nil,
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		AccessLogSamplingRate: 0,
	})

	call := func(bind string) int {
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI("/isolation")
		ctx.Request.Header.SetHost(host)
		ctx.Set(bindContextKey, bind)
		handler(context.Background(), ctx)
		if ctx.Response.StatusCode() == http.StatusOK {
			upstreamHits.Add(1)
		}
		return ctx.Response.StatusCode()
	}

	// bind A 用满配额：前 3 次放行。
	for i := 1; i <= 3; i++ {
		if got := call(":25500"); got != http.StatusOK {
			t.Fatalf("A 第 %d 次在配额内，status = %d, want 200", i, got)
		}
	}
	// bind A 第四次：越限。
	if got := call(":25500"); got != http.StatusTooManyRequests {
		t.Fatalf("A 第 4 次应被限流，status = %d, want 429", got)
	}
	// bind B 首次：必须独立计数。
	if got := call(":25501"); got != http.StatusOK {
		t.Fatalf("B 首次请求应独立计数并放行，status = %d, want 200——两个站点共用了同一计数桶", got)
	}

	// 键必须与 rules.RateLimitKey 同源：两站点各自一个桶，且桶前缀是 bind + siteID。
	// 测试客户端的 RemoteAddr 为空，hertz 解析出的客户端 IP 为 0.0.0.0，故此处
	// 断言键前缀与计数，而不是硬编码整串。
	if len(limiter.counts) != 2 {
		t.Fatalf("两个站点必须各占一个计数桶，实得 %v", limiter.counts)
	}
	for _, want := range []struct {
		prefix string
		count  int
	}{
		{prefix: ":25500|1|isolation.example.test|", count: 4},
		{prefix: ":25501|2|isolation.example.test|", count: 1},
	} {
		found := ""
		for k := range limiter.counts {
			if strings.HasPrefix(k, want.prefix) {
				found = k
				break
			}
		}
		if found == "" {
			t.Fatalf("未找到以 %q 开头的计数键，实得 %v", want.prefix, limiter.counts)
		}
		if got := limiter.counts[found]; got != want.count {
			t.Fatalf("键 %q 计数 = %d, want %d", found, got, want.count)
		}
	}
}
