package accessgate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestOAuthOutboundClientHasFiniteTimeout 固定 OAuth 出站客户端的超时配置。
//
// 修复前 ExchangeCode / FetchUserInfo 走 http.DefaultClient（Timeout 为 0，永不超时），
// 两者都在数据面请求路径上（internal/dataplane/access_control.go 的 OAuth 回调），
// IdP 端点挂起会永久占住 hertz 工作 goroutine。
//
// 这里同时钉住三点：超时为有限正值、客户端自身携带该超时、客户端不是全进程共享的
// http.DefaultClient（改后者会波及所有 http.Get / http.Post 调用点）。
func TestOAuthOutboundClientHasFiniteTimeout(t *testing.T) {
	if oauthOutboundClient == nil {
		t.Fatal("oauthOutboundClient 为 nil")
	}
	if oauthOutboundClient == http.DefaultClient {
		t.Fatal("OAuth 出站调用不得复用 http.DefaultClient：其 Timeout 为 0，会让挂起的 IdP 永久占用数据面工作 goroutine")
	}
	if oauthOutboundTimeout <= 0 {
		t.Fatalf("oauthOutboundTimeout = %v, want > 0", oauthOutboundTimeout)
	}
	if oauthOutboundClient.Timeout != oauthOutboundTimeout {
		t.Fatalf("oauthOutboundClient.Timeout = %v, want %v", oauthOutboundClient.Timeout, oauthOutboundTimeout)
	}
}

// oauthHangingCallResult 是一次挂起端点调用的观测结果。
type oauthHangingCallResult struct {
	// stage 标识调用点（token / userinfo）。
	stage string
	// elapsed 是调用耗时。
	elapsed time.Duration
	// err 是调用返回的错误。
	err error
}

// TestOAuthOutboundCallsUseTimeoutClient 证明不响应的 IdP 端点不会永久占用调用方 goroutine。
//
// 端点收到请求后既不写响应头也不关闭连接，模拟挂起 / 黑洞 / 恶意慢端点。
// 测试把包级客户端临时换成 300ms 超时的实例：调用走带超时的客户端时会毫秒级返回
// 超时错误；若有人把调用改回 http.PostForm 或 http.DefaultClient（Timeout 为 0），
// 两个 goroutine 都不会返回，watchdog 分支失败 —— 那正是修复前的形态。
//
// 该包内测试串行执行（无 t.Parallel），临时替换包级客户端不会与其他用例竞争。
func TestOAuthOutboundCallsUseTimeoutClient(t *testing.T) {
	const clientTimeout = 300 * time.Millisecond
	const watchdog = 5 * time.Second

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	originalClient := oauthOutboundClient
	oauthOutboundClient = &http.Client{Timeout: clientTimeout}
	defer func() { oauthOutboundClient = originalClient }()

	calls := []struct {
		stage string
		call  func() error
	}{
		{"token", func() error {
			_, err := (&OAuthFlow{TokenURL: srv.URL}).ExchangeCode("code", &OAuthState{})
			return err
		}},
		{"userinfo", func() error {
			_, err := (&OAuthFlow{UserInfoURL: srv.URL}).FetchUserInfo("access-token")
			return err
		}},
	}

	done := make(chan oauthHangingCallResult, len(calls))
	for _, c := range calls {
		go func() {
			start := time.Now()
			err := c.call()
			done <- oauthHangingCallResult{stage: c.stage, elapsed: time.Since(start), err: err}
		}()
	}

	for i := range calls {
		select {
		case got := <-done:
			if got.err == nil {
				t.Fatalf("%s: 挂起端点应返回错误，而不是成功", got.stage)
			}
			if !errors.Is(got.err, context.DeadlineExceeded) {
				t.Fatalf("%s: 错误应为超时，got %v", got.stage, got.err)
			}
			if !strings.Contains(got.err.Error(), got.stage+" request failed") {
				t.Fatalf("%s: 错误应来自对应的请求阶段，got %v", got.stage, got.err)
			}
			if got.elapsed > watchdog {
				t.Fatalf("%s: 耗时 %v 超过 watchdog %v", got.stage, got.elapsed, watchdog)
			}
		case <-time.After(watchdog):
			t.Fatalf("第 %d 次调用在 %v 内没有返回：出站调用未使用带超时的客户端（修复前走 http.DefaultClient，永不超时）", i+1, watchdog)
		}
	}
}
