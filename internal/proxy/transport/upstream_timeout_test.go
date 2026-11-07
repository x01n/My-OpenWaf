package transport

// 本文件锁定「用户请求路径」共享 transport 的连接建立/握手/响应头超时（任务 1）。
//
// 断言分两层：
//   - 位置断言：三个字段非零且等于选定值，拨号器自身带 Timeout/KeepAlive；
//   - 机制断言：把 upstreamResponseHeaderTimeout 调小后，真实 `net.Listen` 上
//     一个只 accept 不回头的上游必须在远早于客户端整体超时之前被打断。
//
// 超时常量表在实现里是 var（见 transport.go 的 upstreamDialTimeout 块），
// 目的是让本文件能以短超时驱动真实超时行为；测试串行执行（包内无 t.Parallel），
// 覆盖与还原都在 t.Cleanup 内完成。
import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"My-OpenWaf/internal/snapshot"
)

// swapTransportPoolForTest 用空池临时替换共享 transport 池。
//
// 目的：位置断言之外还要驱动「短超时」的真实行为，而池化过的 transport 会带着
// 旧超时值命中缓存。替换为空池保证被测 transport 一定由当前代码现场构造。
// 同一测试可多次调用：每次调用立即清空一次池，恢复在 t.Cleanup 中按 LIFO 执行。
func swapTransportPoolForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(clearTransportPoolForTest())
}

// clearTransportPoolForTest 立即清空共享 transport 池并返回恢复函数。
func clearTransportPoolForTest() func() {
	transportMu.Lock()
	saved := transportPool
	transportPool = make(map[transportKey]*http.Transport)
	transportMu.Unlock()
	return func() {
		transportMu.Lock()
		transportPool = saved
		transportMu.Unlock()
	}
}

// TestSharedTransportForUpstreamWiresDialTLSAndResponseHeaderTimeouts 锁定三个超时字段的选定值。
//
// 取值依据（与探活路径 internal/upstream/health.go 同量级）：
//   - 拨号 10s / TCP keepalive 30s：对应 health.go 的 defaultHTTPProbeTLSHandshakeTimeout
//     与 defaultHTTPProbeTCPKeepAlive，见实现里 newUpstreamDialer；
//   - TLS 握手 10s：对应 defaultHTTPProbeTLSHandshakeTimeout；
//   - 响应头等待 30s：与缓冲路径客户端整体超时（internal/proxy/proxy.go 的
//     SharedPooledClient 30s 档）同级。
//
// 三者若为零值即为「无超时」：拨号交给内核 SYN 重传（Linux 约 130s）、TLS 握手
// 与响应头等待永不超时，用户请求路径比探活路径约束更松。
func TestSharedTransportForUpstreamWiresDialTLSAndResponseHeaderTimeouts(t *testing.T) {
	dialer := newUpstreamDialer()
	if dialer.Timeout != 10*time.Second {
		t.Fatalf("upstream dialer Timeout = %s, want %s", dialer.Timeout, 10*time.Second)
	}
	if dialer.KeepAlive != 30*time.Second {
		t.Fatalf("upstream dialer KeepAlive = %s, want %s", dialer.KeepAlive, 30*time.Second)
	}

	for _, base := range []string{"http://127.0.0.1:8080", "https://127.0.0.1:8443"} {
		tr := SharedTransportForUpstream(snapshot.SiteRuntime{}, base)
		if tr.DialContext == nil {
			t.Fatalf("%s: DialContext is nil, want the bounded upstream dialer", base)
		}
		if tr.TLSHandshakeTimeout != 10*time.Second {
			t.Fatalf("%s: TLSHandshakeTimeout = %s, want %s", base, tr.TLSHandshakeTimeout, 10*time.Second)
		}
		if tr.ResponseHeaderTimeout != 30*time.Second {
			t.Fatalf("%s: ResponseHeaderTimeout = %s, want %s", base, tr.ResponseHeaderTimeout, 30*time.Second)
		}
	}
}

// TestSharedTransportForUpstreamResponseHeaderTimeoutInterruptsStalledUpstream 驱动真实的响应头超时。
//
// 上游只完成 TCP accept、不发任何响应字节；把 upstreamResponseHeaderTimeout 调到
// 150ms 后，请求必须在 150ms 量级失败，而不是拖到客户端 3s 整体超时。
func TestSharedTransportForUpstreamResponseHeaderTimeoutInterruptsStalledUpstream(t *testing.T) {
	swapTransportPoolForTest(t)

	savedResponseHeaderTimeout := upstreamResponseHeaderTimeout
	savedDialTimeout := upstreamDialTimeout
	upstreamResponseHeaderTimeout = 150 * time.Millisecond
	upstreamDialTimeout = 150 * time.Millisecond
	t.Cleanup(func() {
		upstreamResponseHeaderTimeout = savedResponseHeaderTimeout
		upstreamDialTimeout = savedDialTimeout
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stalled upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			// 只 accept，不回任何字节；连接在 listener 关闭时由内核回收。
			_ = conn
		}
	}()

	tr := SharedTransportForUpstream(snapshot.SiteRuntime{}, "http://"+ln.Addr().String())
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	start := time.Now()
	resp, err := client.Get("http://" + ln.Addr().String() + "/stall")
	elapsed := time.Since(start)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("stalled upstream returned status %d, want a response header timeout", resp.StatusCode)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("stalled upstream error = %v, want a net.Error timeout", err)
	}
	if elapsed >= time.Second {
		t.Fatalf("stalled upstream failed after %s, want the 150ms ResponseHeaderTimeout to fire well before the 3s client timeout", elapsed)
	}
}

// TestSharedTransportForUpstreamDialTimeoutIsWiredIntoDialContext 驱动真实的拨号超时。
//
// 本机禁用了 IPv6，且出网口对任意 TCP 目标都可能立即回 SYN-ACK（传统
// 192.0.2.0/24 / 240.0.0.0/4 等黑洞地址在本机实测均可 connect），因此不能用
// 「不可达地址」来制造拨号停顿。改用可控变量：把上游拨号超时压到极短，对一个
// 【一定可连】的本地监听地址拨号。
//
//   - 超时极短时：tr.DialContext 必须立即失败且是 net.Error 超时 —— 证明
//     transport.DialContext 确实由带 Timeout 的 net.Dialer 提供；
//   - 超时还原为运行期取值（10s）后重新构造 transport：同一地址必须连通 ——
//     证明上一次失败来自超时本身，而非地址不可达或 Dialer 被写坏。
//
// 变异「删掉 DialContext 字段」会让第一段落到 Go 的默认拨号器：默认拨号器对
// 本地监听地址会立刻连接成功，err == nil，测试变红。
func TestSharedTransportForUpstreamDialTimeoutIsWiredIntoDialContext(t *testing.T) {
	swapTransportPoolForTest(t)

	savedDialTimeout := upstreamDialTimeout
	t.Cleanup(func() { upstreamDialTimeout = savedDialTimeout })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local probe target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	target := ln.Addr().String()

	upstreamDialTimeout = time.Nanosecond
	bounded := SharedTransportForUpstream(snapshot.SiteRuntime{}, "http://"+target)
	if bounded.DialContext == nil {
		t.Fatal("DialContext is nil, want the bounded upstream dialer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	conn, dialErr := bounded.DialContext(ctx, "tcp", target)
	elapsed := time.Since(start)
	if dialErr == nil {
		_ = conn.Close()
		t.Fatalf("dial with %s dialer timeout unexpectedly succeeded; DialContext is not bounded by upstreamDialTimeout", upstreamDialTimeout)
	}
	var netErr net.Error
	if !errors.As(dialErr, &netErr) || !netErr.Timeout() {
		t.Fatalf("bounded dial error = %v, want a net.Error timeout", dialErr)
	}
	if elapsed >= time.Second {
		t.Fatalf("bounded dial failed after %s, want the sub-microsecond dialer timeout to fire immediately", elapsed)
	}

	upstreamDialTimeout = 10 * time.Second
	// 短超时那次拨号构造的 transport 已进池（键相同），必须再清一次池，
	// 否则第二次取到的是带 1ns 超时的旧实例。
	defer clearTransportPoolForTest()()
	restored := SharedTransportForUpstream(snapshot.SiteRuntime{}, "http://"+target)
	conn, dialErr = restored.DialContext(ctx, "tcp", target)
	if dialErr != nil {
		t.Fatalf("dial with the runtime dialer timeout failed: %v", dialErr)
	}
	_ = conn.Close()
}
