package dataplane

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/ratelimit"
)

/**
 * TestHandlerErrorRateLimitCountsPerSiteAcrossBinds 验证错误限流计数键的站点隔离。
 *
 * 场：两个站点行同 Host `err-isolation.example.test`，bind 分别 :25510 / :25511，
 * 错误限流 60s / 配额 1 / 只计 4xx / 动作 rate_limit；上游恒回 404。
 *
 * 语义（与 ratelimit.RateLimiter.IsOverLimit 的 `count > max` 一致）：第 N 次请求
 * 之前先看历史计数是否已越限。配额 1 时，前两次 4xx 原样透传（计数 1、2），
 * 第三次请求起被判超限并转 429。
 *
 * 判据：站点 A 在 :25510 上打到 429 之后，站点 B 在 :25511 上的第一次 4xx
 * 应仍是 404——两个站点若共用一个错误计数桶，B 的这次请求会被误判为超限。
 */
func TestHandlerErrorRateLimitCountsPerSiteAcrossBinds(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.ErrorRateLimitEnabled = true
	protection.ErrorRateLimitWindow = 60
	protection.ErrorRateLimitMax = 1
	protection.ErrorRateLimitCount4xx = true
	protection.ErrorRateLimitCount5xx = false
	protection.ErrorRateLimitCountBlock = false
	protection.ErrorRateLimitAction = "rate_limit"

	const host = "err-isolation.example.test"
	rtA := snapshot.SiteRuntime{
		Site:                store.Site{ID: 11, Host: host, Bind: ":25510"},
		Bind:                ":25510",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	rtB := snapshot.SiteRuntime{
		Site:                store.Site{ID: 12, Host: host, Bind: ":25511"},
		Bind:                ":25511",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":25510", host): &rtA,
			snapshot.SiteMapKey(":25511", host): &rtB,
		},
	})

	errLimiter := ratelimit.NewRateLimiter(protection.ErrorRateLimitWindow, protection.ErrorRateLimitMax, true)
	defer errLimiter.Close()
	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, errLimiter, nil),
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		AccessLogSamplingRate: 0,
	})

	call := func(bind string) int {
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI("/err-isolation")
		ctx.Request.Header.SetHost(host)
		ctx.Set(bindContextKey, bind)
		handler(context.Background(), ctx)
		return ctx.Response.StatusCode()
	}

	// 站点 A：前两次 4xx 透传，第三次起越限转 429。
	for i := 1; i <= 2; i++ {
		if got := call(":25510"); got != http.StatusNotFound {
			t.Fatalf("A 第 %d 次 4xx 尚未越限，status = %d, want 404", i, got)
		}
	}
	if got := call(":25510"); got != http.StatusTooManyRequests {
		t.Fatalf("A 第三次请求应越限，status = %d, want 429", got)
	}
	// 站点 B 第一次 4xx：必须独立计数，仍应原样透传 404。
	if got := call(":25511"); got != http.StatusNotFound {
		t.Fatalf("B 第一次 4xx 应独立计数并透传，status = %d, want 404——两个站点共用了同一错误计数桶", got)
	}
}
