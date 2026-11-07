package dataplane

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/ratelimit"
)

/**
 * 本文件锁定错误限流对白名单 IP 的豁免。
 *
 * 错误限流在管道之前判定（internal/dataplane/handler.go 的错误限流分支），
 * 修复前该分支直接返回 429，会绕过管道内的全局白名单短路与站点白名单的非终止
 * 放行语义 —— 被加进白名单的 IP 本意是完全不受 WAF 干预，却被错误限流拦下。
 *
 * 现场约定：客户端 IP 走 X-Forwarded-For + TrustedCIDR（与 handler_test.go 的
 * 既有写法一致），因为 hertz 的测试上下文没有真实远端地址；全局白名单用
 * iprep.SetLists 注入，站点白名单挂在 SiteRuntime.SiteIPWhitelist 上。
 */
func newErrorRateLimitWhitelistField(t *testing.T, siteWhitelist []iprep.IPListEntry, globalWhitelist []iprep.IPListEntry) (app.HandlerFunc, string) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	t.Cleanup(upstream.Close)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.ErrorRateLimitEnabled = true
	protection.ErrorRateLimitWindow = 60
	protection.ErrorRateLimitMax = 1
	protection.ErrorRateLimitCount4xx = true
	protection.ErrorRateLimitCount5xx = false
	protection.ErrorRateLimitCountBlock = false
	protection.ErrorRateLimitAction = "rate_limit"

	const host = "err-whitelist.example.test"
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 21, Host: host, Bind: ":25520"},
		Bind:                ":25520",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
		// 客户端 IP 从 XFF 解析：只信任代理网段，取最外层地址。
		XFFMode:             store.XFFModeTrustOuter,
		TrustedCIDR:         "192.0.2.0/24",
		ClientIPHeaderOrder: []string{store.ClientIPHeaderXForwardedFor},
	}
	if len(siteWhitelist) > 0 {
		rt.SiteIPWhitelist = siteWhitelist
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":25520", host): &rt,
		},
	})

	rep := iprep.NewIPReputation()
	rep.SetLists(nil, globalWhitelist)
	t.Cleanup(rep.Close)

	errLimiter := ratelimit.NewRateLimiter(protection.ErrorRateLimitWindow, protection.ErrorRateLimitMax, true)
	t.Cleanup(errLimiter.Close)

	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, errLimiter, rep),
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		AccessLogSamplingRate: 0,
	})
	return handler, host
}

// callErrorRateLimitField 打一次必定 4xx 的请求，客户端 IP 经 XFF 指定。
//
// 必须挂上带 remoteAddr 的连接：XFF 只有在来源地址落在 TrustedCIDR 内才会被
// 采信，否则 hertz 解析出的客户端 IP 恒为空/0.0.0.0，白名单自然匹配不上。
// 与 handler_test.go 的既有写法保持一致（代理 IP 固定 192.0.2.10）。
func callErrorRateLimitField(t *testing.T, handler app.HandlerFunc, host, clientIP string) int {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/err-whitelist")
	ctx.Request.Header.SetHost(host)
	ctx.Request.Header.Set("X-Forwarded-For", clientIP)
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8443},
	})
	ctx.Set(bindContextKey, ":25520")
	handler(context.Background(), ctx)
	return ctx.Response.StatusCode()
}

// TestErrorRateLimitExemptsGlobalWhitelistIP 锁定全局白名单 IP 不被错误限流 429。
//
// 现实场景：监控探针或内网出口加入全局白名单后，例行探测持续产出 404，几分钟后
// 整段被 429，白名单形同虚设。修复后白名单 IP 回落到管道（而不是直接放行到
// 上游），因此其余检测阶段照常执行。
func TestErrorRateLimitExemptsGlobalWhitelistIP(t *testing.T) {
	const ip = "203.0.113.77"
	handler, host := newErrorRateLimitWhitelistField(t, nil, []iprep.IPListEntry{{
		Single: net.ParseIP(ip), Note: "monitoring probe",
	}})

	// 配额 1：前两次 4xx 透传，之后越限；白名单 IP 越限后仍必须是 404。
	for i := 1; i <= 2; i++ {
		if got := callErrorRateLimitField(t, handler, host, ip); got != http.StatusNotFound {
			t.Fatalf("第 %d 次请求 status = %d, want 404", i, got)
		}
	}
	for i := 3; i <= 5; i++ {
		if got := callErrorRateLimitField(t, handler, host, ip); got != http.StatusNotFound {
			t.Fatalf("全局白名单 IP 第 %d 次请求被错误限流，status = %d, want 404", i, got)
		}
	}
}

// TestErrorRateLimitExemptsSiteWhitelistIP 锁定站点白名单 IP 不被错误限流 429。
//
// 站点白名单在管道内是非终止放行（只跳过 IP 声誉，不短路后续检测），因此错误
// 限流也应回落到管道，而不是直接 429。
func TestErrorRateLimitExemptsSiteWhitelistIP(t *testing.T) {
	const ip = "203.0.113.88"
	_, cidr, err := net.ParseCIDR(ip + "/32")
	if err != nil {
		t.Fatalf("parse whitelist CIDR: %v", err)
	}
	handler, host := newErrorRateLimitWhitelistField(t, []iprep.IPListEntry{{
		CIDR: cidr, Note: "office egress",
	}}, nil)

	for i := 1; i <= 5; i++ {
		if got := callErrorRateLimitField(t, handler, host, ip); got != http.StatusNotFound {
			t.Fatalf("站点白名单 IP 第 %d 次请求被错误限流，status = %d, want 404", i, got)
		}
	}
}

// TestErrorRateLimitStillBlocksNonWhitelistedIP 是对照组：非白名单 IP 越限后必须 429。
//
// 没有这条，上面两个用例在「错误限流整体失效」的实现下也会通过。
func TestErrorRateLimitStillBlocksNonWhitelistedIP(t *testing.T) {
	const ip = "198.51.100.9"
	handler, host := newErrorRateLimitWhitelistField(t, nil, nil)

	for i := 1; i <= 2; i++ {
		if got := callErrorRateLimitField(t, handler, host, ip); got != http.StatusNotFound {
			t.Fatalf("第 %d 次请求 status = %d, want 404", i, got)
		}
	}
	if got := callErrorRateLimitField(t, handler, host, ip); got != http.StatusTooManyRequests {
		t.Fatalf("非白名单 IP 越限后 status = %d, want 429", got)
	}
}
