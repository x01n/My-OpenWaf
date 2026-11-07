package transport

// 本文件锁定「hertz h2c 上游按 host 的在飞请求闸门」（任务 2）。
//
// 存在的理由：hertz 的 WithMaxConnsPerHost 只喂给 http1 工厂
// （hertz@v0.10.6 pkg/app/client/client.go:508 的 newHttp1OptionFromClient 只在
// clientFactory == nil 时被调用），而本路径在 sharedHertzH2CClient 里已
// SetClientFactory；x01n/http2 fork 的 config.ClientConfig 也没有连接数旋钮。
// 因此 h2c 此前没有并发上限。
//
// 断言两层：
//   - 机制断言：容量 N 的闸门下，N 个请求占满后第 N+1 个必须在名额释放前不返回
//     （用一个可控的慢上游驱动真实 DoHertzUpstream，而不是只看字段存在）；
//   - 释放点断言：第 N+1 个请求在【第一个响应体被 Close】之后才继续，证明释放
//     点在响应体关闭而不是 Do 返回 —— 若在 Do 返回时释放，第一个请求拿到响应头
//     后闸门就空出名额，第 N+1 个会立刻返回。
import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/snapshot"
)

// hertzGateTestUpstream 启动一个 h2c 上游：先回响应头并把 body 刷给客户端，再
// 阻塞在 release 上，直到测试关闭 release 才结束响应体。
//
// 该类上游正是闸门要约束的对象：Do 在响应头到达时就返回，响应传输仍在进行。
func hertzGateTestUpstream(t *testing.T) (base string, release chan struct{}) {
	t.Helper()
	release = make(chan struct{})
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "a")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
		_, _ = io.WriteString(w, "b")
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(false)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	t.Cleanup(upstream.Close)
	return "h2c://" + upstream.Listener.Addr().String(), release
}

// newHertzGateTestRequest 构造一个指向 base（h2c://）的 GET 请求。
//
// DoHertzUpstream 以 req.URL.Host 作为闸门键，URL 必须是标准 http(s) 形式，
// 与 internal/proxy 的 buildUpstreamRequest 对 h2c 上游的归一结果一致。
func newHertzGateTestRequest(t *testing.T, base string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+strings.TrimPrefix(base, "h2c://")+"/gate", nil)
	if err != nil {
		t.Fatalf("build hertz gate test request: %v", err)
	}
	return req
}

// TestHertzH2CGateBlocksRequestBeyondCapacity 验证容量 N 的闸门下第 N+1 个请求被阻塞。
func TestHertzH2CGateBlocksRequestBeyondCapacity(t *testing.T) {
	savedCapacity := hertzH2CUpstreamGateCapacity
	hertzH2CUpstreamGateCapacity = 1
	t.Cleanup(func() { hertzH2CUpstreamGateCapacity = savedCapacity })
	resetHertzH2CUpstreamGates()
	t.Cleanup(resetHertzH2CUpstreamGates)

	base, release := hertzGateTestUpstream(t)
	defer close(release)

	first := newHertzGateTestRequest(t, base)
	firstResp, firstReq, firstDone, firstCancel, err := DoHertzUpstream(context.Background(), snapshot.SiteRuntime{}, base, first)
	if err != nil {
		t.Fatalf("first DoHertzUpstream returned error: %v", err)
	}
	firstBody := HertzResponseToHTTPResponse(base, firstResp, firstReq, firstDone, firstCancel)

	secondReturned := make(chan error, 1)
	go func() {
		second := newHertzGateTestRequest(t, base)
		resp, hreq, done, cancel, err := DoHertzUpstream(context.Background(), snapshot.SiteRuntime{}, base, second)
		if err == nil {
			_ = HertzResponseToHTTPResponse(base, resp, hreq, done, cancel).Body.Close()
		}
		secondReturned <- err
	}()

	select {
	case err := <-secondReturned:
		t.Fatalf("second DoHertzUpstream returned (err=%v) while the only gate slot was still held by an unclosed body", err)
	case <-time.After(250 * time.Millisecond):
	}

	// 释放点必须在响应体关闭：先只关闭第一个 body，第二个应当立刻能拿到名额。
	// Close 的返回错误不影响本断言：调用方不依赖它（internal/proxy 的流式路径
	// 同样忽略），这里只关心名额是否随之释放。
	_ = firstBody.Body.Close()
	select {
	case err := <-secondReturned:
		if err != nil {
			t.Fatalf("second DoHertzUpstream returned error after gate release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second DoHertzUpstream was still blocked after the first response body closed")
	}
}

// TestHertzH2CGateDoesNotBlockWithinCapacity 验证容量 N 时前 N 个请求互不阻塞。
//
// 与上一条测试互补：上一条证明第 N+1 个会被挡，这一条证明闸门不会过早拦截 ——
// 两个请求同时在飞、且都拿到响应头，闸门容量为 2。
func TestHertzH2CGateDoesNotBlockWithinCapacity(t *testing.T) {
	savedCapacity := hertzH2CUpstreamGateCapacity
	hertzH2CUpstreamGateCapacity = 2
	t.Cleanup(func() { hertzH2CUpstreamGateCapacity = savedCapacity })
	resetHertzH2CUpstreamGates()
	t.Cleanup(resetHertzH2CUpstreamGates)

	base, release := hertzGateTestUpstream(t)
	defer close(release)

	bodies := make([]*http.Response, 0, 2)
	for i := 0; i < 2; i++ {
		returned := make(chan *http.Response, 1)
		go func() {
			req := newHertzGateTestRequest(t, base)
			resp, hreq, done, cancel, err := DoHertzUpstream(context.Background(), snapshot.SiteRuntime{}, base, req)
			if err != nil {
				returned <- nil
				return
			}
			returned <- HertzResponseToHTTPResponse(base, resp, hreq, done, cancel)
		}()
		select {
		case resp := <-returned:
			if resp == nil {
				t.Fatalf("in-flight request %d failed while the gate had a free slot", i+1)
			}
			bodies = append(bodies, resp)
		case <-time.After(3 * time.Second):
			t.Fatalf("in-flight request %d did not return within capacity", i+1)
		}
	}
	for _, resp := range bodies {
		_ = resp.Body.Close()
	}
}

// TestHertzH2CGateReleasesOnRequestError 验证 Do 失败路径不会泄漏闸门名额。
func TestHertzH2CGateReleasesOnRequestError(t *testing.T) {
	savedCapacity := hertzH2CUpstreamGateCapacity
	hertzH2CUpstreamGateCapacity = 1
	t.Cleanup(func() { hertzH2CUpstreamGateCapacity = savedCapacity })
	resetHertzH2CUpstreamGates()
	t.Cleanup(resetHertzH2CUpstreamGates)

	// 监听后立即关闭：Dial 会连接被拒，Do 必然失败。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dead upstream: %v", err)
	}
	base := "h2c://" + ln.Addr().String()
	host := ln.Addr().String()
	_ = ln.Close()

	for attempt := 1; attempt <= 3; attempt++ {
		req := newHertzGateTestRequest(t, base)
		if _, _, _, _, err := DoHertzUpstream(context.Background(), snapshot.SiteRuntime{}, base, req); err == nil {
			t.Fatalf("attempt %d: DoHertzUpstream to a closed listener unexpectedly succeeded", attempt)
		}
	}

	// 三次失败若各泄漏一个名额，容量 1 的闸门早已占满，后续请求会一直阻塞。
	hertzH2CGateMu.Lock()
	gate := hertzH2CGates[host]
	hertzH2CGateMu.Unlock()
	if gate == nil {
		t.Fatal("gate for the dead upstream host was not created")
	}
	if len(gate) != 0 {
		t.Fatalf("gate occupancy after failed requests = %d, want 0 (names must be released on the error path)", len(gate))
	}
}

// TestHertzH2CGateWaitsForContextCancellation 验证等待名额期间 ctx 取消能立刻返回。
func TestHertzH2CGateWaitsForContextCancellation(t *testing.T) {
	savedCapacity := hertzH2CUpstreamGateCapacity
	hertzH2CUpstreamGateCapacity = 1
	t.Cleanup(func() { hertzH2CUpstreamGateCapacity = savedCapacity })
	resetHertzH2CUpstreamGates()
	t.Cleanup(resetHertzH2CUpstreamGates)

	base, release := hertzGateTestUpstream(t)
	defer close(release)

	first := newHertzGateTestRequest(t, base)
	firstResp, firstReq, firstDone, firstCancel, err := DoHertzUpstream(context.Background(), snapshot.SiteRuntime{}, base, first)
	if err != nil {
		t.Fatalf("first DoHertzUpstream returned error: %v", err)
	}
	defer func() {
		_ = HertzResponseToHTTPResponse(base, firstResp, firstReq, firstDone, firstCancel).Body.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, _, _, _, err = DoHertzUpstream(ctx, snapshot.SiteRuntime{}, base, newHertzGateTestRequest(t, base))
	if err == nil {
		t.Fatal("DoHertzUpstream returned nil error after its context was cancelled while waiting for a gate slot")
	}
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("gate wait after context cancellation returned after %s, want an immediate return", elapsed)
	}
}
