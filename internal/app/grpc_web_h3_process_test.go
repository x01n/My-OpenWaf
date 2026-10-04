package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	adminsystem "My-OpenWaf/internal/admin/system"
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// appProcGRPCDataFrame 构造一个 gRPC-Web DATA 帧：1 字节帧标志，
// 大端 uint32 负载长度，然后是负载本身。
func appProcGRPCDataFrame(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// appProcGRPCMessage 用一个 gRPC 长度前缀包裹 unary 消息：
// 1 字节压缩标志（0）、大端 uint32 长度，然后是消息。
func appProcGRPCMessage(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// appProcGRPCWebTrailers 构造 gRPC-Web 的 Envoy 风格服务端
// 体内 trailer 帧：标志 0x80，负载为
// "grpc-status:<code>" 加可选 message 与额外条目。这种形式下
// grpc-status 不走 HTTP Trailer 段。
func appProcGRPCWebTrailers(status int, message string) []byte {
	payload := fmt.Sprintf("grpc-status:%d", status)
	if message != "" {
		payload += "\r\ngrpc-message:" + message
	}
	return appProcGRPCDataFrame(0x80, []byte(payload))
}

// appProcGRPCWebUnaryBody 组装一个 unary 消息帧，外加
// 挂在 body 末尾的 trailers 帧。
func appProcGRPCWebUnaryBody(message string) []byte {
	body := append([]byte{}, appProcGRPCDataFrame(0, appProcGRPCMessage([]byte(message)))...)
	return append(body, appProcGRPCWebTrailers(0, "")...)
}

// appProcEnableH2H3Network 写入本文件所有站点共用的系统设置：
// 启用 HTTP/2 + HTTP/3、指定 QUIC 预留的 UDP bind，
// 以及自签 TLS 默认值。
func appProcEnableH2H3Network(db *gorm.DB, udpBind string) error {
	networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      udpBind,
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	})
	if err != nil {
		return fmt.Errorf("marshal network_config: %w", err)
	}
	tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
		MinVersion:               "TLS12",
		MaxVersion:               "TLS13",
		DefaultALPN:              "h2,h3,http/1.1",
		CurvePreferences:         "X25519,CurveP256,CurveP384",
		PreferServerCipherSuites: true,
		SelfSignedOnIP:           true,
	})
	if err != nil {
		return fmt.Errorf("marshal tls_default_config: %w", err)
	}
	settings := []store.SystemSettings{
		{Key: "network_config", Value: string(networkCfgBytes)},
		{Key: "tls_default_config", Value: string(tlsCfgBytes)},
	}
	for _, item := range settings {
		if err := db.Create(&item).Error; err != nil {
			return fmt.Errorf("create system setting %q: %w", item.Key, err)
		}
	}
	return nil
}

// appProcHTTP2Client 通过 TLS 连接 WAF 数据面，并强制 ALPN 为 "h2"。
func appProcHTTP2Client(t *testing.T, appProc *appProcessHarness, bind string, host string, path string) (*http.Response, []byte) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2"},
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if exited, err := appProc.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP/2 request: %v\n%s", err, appProc.output.String())
		}
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTP/2 request: %v", err)
		}
		req.Host = host
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read HTTP/2 response body: %v", readErr)
			}
			return resp, body
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("HTTP/2 endpoint did not become ready for host=%q path=%q", host, path)
	return nil, nil
}

// TestRunGRPCWebUnaryOverH2InSeparateProcess 把一条 Envoy 风格的
// gRPC-Web unary 响应（消息帧 + 携带 grpc-status 的体内 trailers 帧）
// 从 H2 上游经 WAF 代理到 H2 客户端，
// 要求帧逐字节一致、content-type 正确，且不带
// Content-Encoding。
func TestRunGRPCWebUnaryOverH2InSeparateProcess(t *testing.T) {
	wantBody := appProcGRPCWebUnaryBody("grpc-web-unary-blackbox")
	var upstreamRequests atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/grpc.web.Echo/Echo" {
			http.NotFound(w, r)
			return
		}
		upstreamRequests.Add(1)
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		_, _ = w.Write(wantBody)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "grpc-web-h2.blackbox.example.test"
	const requestPath = "/grpc.web.Echo/Echo"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := appProcEnableH2H3Network(db, udpBind); err != nil {
			return err
		}
		if err := db.Create(&store.SystemSettings{Key: "response_compression_enabled", Value: "true"}).Error; err != nil {
			return fmt.Errorf("create compression setting: %w", err)
		}
		if err := db.Create(&store.SystemSettings{Key: "response_compression_gzip_enabled", Value: "true"}).Error; err != nil {
			return fmt.Errorf("create gzip setting: %w", err)
		}
		if err := db.Create(&store.SystemSettings{Key: "response_compression_min_bytes", Value: "1024"}).Error; err != nil {
			return fmt.Errorf("create min bytes setting: %w", err)
		}
		site := store.Site{
			Host:                  siteHost,
			UpstreamURLs:          upstream.URL,
			UpstreamTLSSkipVerify: true,
			Bind:                  tcpBind,
			Network:               "tcp",
			Enabled:               true,
			TLSEnabled:            true,
			ALPN:                  "h2,h3,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProcHTTP2Client(t, appProc, tcpBind, siteHost, requestPath)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grpc-web unary status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("grpc-web unary proto major = %d, want 2", resp.ProtoMajor)
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Type")); got != "application/grpc-web+proto" {
		t.Fatalf("grpc-web unary content-type = %q, want %q", got, "application/grpc-web+proto")
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("grpc-web unary Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(body, wantBody) {
		t.Fatalf("grpc-web unary body mismatch: got %d bytes, want %d", len(body), len(wantBody))
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream request count = %d, want 1", got)
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("grpc-web unary missing X-Request-ID header")
	}
	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	if accessLog.StatusCode != http.StatusOK {
		t.Fatalf("grpc-web unary access log status_code = %d, want %d", accessLog.StatusCode, http.StatusOK)
	}
	if accessLog.HTTPProtocol != "h2" {
		t.Fatalf("grpc-web unary access log http_protocol = %q, want %q", accessLog.HTTPProtocol, "h2")
	}
	if accessLog.UpstreamHTTPProtocol != "HTTP/2.0" {
		t.Fatalf("grpc-web unary access log upstream_http_protocol = %q, want %q", accessLog.UpstreamHTTPProtocol, "HTTP/2.0")
	}
	if accessLog.TLSALPN != "h2" {
		t.Fatalf("grpc-web unary access log tls_alpn = %q, want %q", accessLog.TLSALPN, "h2")
	}
}

// TestRunGRPCWebServerStreamOverH2InSeparateProcess 代理一条多消息的
// gRPC-Web 服务端流，trailers 帧位于 body 末尾，
// 要求完整帧序列逐字节存活。
func TestRunGRPCWebServerStreamOverH2InSeparateProcess(t *testing.T) {
	var frames []byte
	for index := 0; index < 4; index++ {
		frames = append(frames, appProcGRPCDataFrame(0, appProcGRPCMessage([]byte(fmt.Sprintf("web-stream-%d", index))))...)
	}
	frames = append(frames, appProcGRPCWebTrailers(0, "")...)

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/grpc.web.Echo/ServerStream" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		_, _ = w.Write(frames)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "grpc-web-stream.blackbox.example.test"
	const requestPath = "/grpc.web.Echo/ServerStream"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := appProcEnableH2H3Network(db, udpBind); err != nil {
			return err
		}
		site := store.Site{
			Host:                  siteHost,
			UpstreamURLs:          upstream.URL,
			UpstreamTLSSkipVerify: true,
			Bind:                  tcpBind,
			Network:               "tcp",
			Enabled:               true,
			TLSEnabled:            true,
			ALPN:                  "h2,h3,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	resp, body := appProcHTTP2Client(t, appProc, tcpBind, siteHost, requestPath)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grpc-web server-stream status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Type")); got != "application/grpc-web+proto" {
		t.Fatalf("grpc-web server-stream content-type = %q, want %q", got, "application/grpc-web+proto")
	}
	if !bytes.Equal(body, frames) {
		t.Fatalf("grpc-web server-stream body mismatch: got %d bytes, want %d", len(body), len(frames))
	}
}

// TestRunGRPCoverHTTP3InSeparateProcess 驱动一个真实的 H3 gRPC 回显上游：
// WAF 的 H3 监听把请求送到 http3.Server 上游，
// 消息帧逐字节返回，grpc-status 出现在
// H3 trailer 段。访问日志必须记录入站 h3、出站 HTTP/3.0 以及
// QUIC 前缀的 JA4 元数据。
func TestRunGRPCoverHTTP3InSeparateProcess(t *testing.T) {
	wantEchoFrame := appProcGRPCDataFrame(0, appProcGRPCMessage([]byte("h3-grpc-echo-blackbox")))
	upstream, upstreamBase := startAppProcessHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/3.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
		}
		if r.URL.Path != "/grpc.Echo/Echo" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.Header().Add("Trailer", "grpc-status")
		_, _ = w.Write(wantEchoFrame)
		w.Header().Set("grpc-status", "0")
	}))
	defer closeAppProcessHTTP3UpstreamServer(t, upstream)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "grpc-h3.blackbox.example.test"
	const requestPath = "/grpc.Echo/Echo"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := appProcEnableH2H3Network(db, udpBind); err != nil {
			return err
		}
		if err := db.Create(&store.SystemSettings{Key: "response_compression_enabled", Value: "true"}).Error; err != nil {
			return fmt.Errorf("create compression setting: %w", err)
		}
		if err := db.Create(&store.SystemSettings{Key: "response_compression_gzip_enabled", Value: "true"}).Error; err != nil {
			return fmt.Errorf("create gzip setting: %w", err)
		}
		if err := db.Create(&store.SystemSettings{Key: "response_compression_min_bytes", Value: "1024"}).Error; err != nil {
			return fmt.Errorf("create min bytes setting: %w", err)
		}
		site := store.Site{
			Host:                  siteHost,
			UpstreamURLs:          upstreamBase,
			UpstreamTLSSkipVerify: true,
			Bind:                  tcpBind,
			Network:               "tcp",
			Enabled:               true,
			TLSEnabled:            true,
			ALPN:                  "h2,h3,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("h3 grpc status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("h3 grpc proto major = %d, want 3", resp.ProtoMajor)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("h3 grpc Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal([]byte(body), wantEchoFrame) {
		t.Fatalf("h3 grpc body mismatch: got %d bytes, want %d", len(body), len(wantEchoFrame))
	}
	if got := resp.Trailer.Get("grpc-status"); got != "0" {
		t.Fatalf("h3 grpc grpc-status trailer = %q, want %q", got, "0")
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("h3 grpc missing X-Request-ID header")
	}
	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	if accessLog.StatusCode != http.StatusOK {
		t.Fatalf("h3 grpc access log status_code = %d, want %d", accessLog.StatusCode, http.StatusOK)
	}
	if accessLog.HTTPProtocol != "h3" {
		t.Fatalf("h3 grpc access log http_protocol = %q, want %q", accessLog.HTTPProtocol, "h3")
	}
	if accessLog.UpstreamHTTPProtocol != "HTTP/3.0" {
		t.Fatalf("h3 grpc access log upstream_http_protocol = %q, want %q", accessLog.UpstreamHTTPProtocol, "HTTP/3.0")
	}
	if accessLog.TLSALPN != "h3" {
		t.Fatalf("h3 grpc access log tls_alpn = %q, want %q", accessLog.TLSALPN, "h3")
	}
	if accessLog.TLSSNI != siteHost {
		t.Fatalf("h3 grpc access log tls_sni = %q, want %q", accessLog.TLSSNI, siteHost)
	}
	if accessLog.TLSJA4 == "" || accessLog.TLSJA4[0] != 'q' {
		t.Fatalf("h3 grpc access log tls_ja4 = %q, want QUIC-prefixed value", accessLog.TLSJA4)
	}
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "grpc over h3")
}

// TestRunCachesGRPCWebAndGRPCTrailerBodiesInSeparateProcess 用于证实或
// 证伪该缓存缺陷：在命中前缀缓存规则且
// Cache-Control: public, max-age=60 的条件下，gRPC-Web 的体内 trailer 形式
// 与经典 in-Trailer 的 gRPC 形式都不得被缓存。第二个请求
// 必须再次到达上游（miss），而作为阳性对照的文本路径必须
// 命中缓存。
func TestRunCachesGRPCWebAndGRPCTrailerBodiesInSeparateProcess(t *testing.T) {
	webBody := appProcGRPCWebUnaryBody("grpc-web-cache-probe")
	classicFrame := appProcGRPCDataFrame(0, appProcGRPCMessage([]byte("grpc-classic-cache-probe")))
	var webCalls, classicCalls, controlCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cached/grpc.web.Echo/Echo":
			webCalls.Add(1)
			w.Header().Set("Content-Type", "application/grpc-web+proto")
			w.Header().Set("Cache-Control", "public, max-age=60")
			_, _ = w.Write(webBody)
		case "/cached/grpc.Echo/Echo":
			classicCalls.Add(1)
			w.Header().Set("Content-Type", "application/grpc+proto")
			w.Header().Set("Cache-Control", "public, max-age=60")
			_, _ = w.Write(classicFrame)
		case "/cached/control.txt":
			controlCalls.Add(1)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=60")
			_, _ = io.WriteString(w, "cache-control-positive")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "grpc-cache.blackbox.example.test"
	const webPath = "/cached/grpc.web.Echo/Echo"
	const classicPath = "/cached/grpc.Echo/Echo"
	const controlPath = "/cached/control.txt"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := appProcEnableH2H3Network(db, udpBind); err != nil {
			return err
		}
		cacheRulesBytes, err := json.Marshal([]store.SiteCacheRule{
			{Type: "prefix", Value: "/cached/", TTL: 120},
		})
		if err != nil {
			return fmt.Errorf("marshal cache rules: %w", err)
		}
		site := store.Site{
			Host:            siteHost,
			UpstreamURLs:    upstream.URL,
			Bind:            tcpBind,
			Network:         "tcp",
			Enabled:         true,
			CacheEnabled:    true,
			CacheDefaultTTL: 120,
			CacheRules:      string(cacheRulesBytes),
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	// 缓存决策与传输层无关：用普通 HTTP/1.1 驱动数据面。
	webResp, webBodyFirst := appProc.waitHTTPResponse(t, tcpBind, siteHost, webPath, nil, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK
	})
	if webResp.StatusCode != http.StatusOK || !bytes.Equal(webBodyFirst, webBody) {
		t.Fatalf("grpc-web cache first response status=%d len=%d want_len=%d", webResp.StatusCode, len(webBodyFirst), len(webBody))
	}
	classicResp, classicBodyFirst := appProc.waitHTTPResponse(t, tcpBind, siteHost, classicPath, nil, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK
	})
	if classicResp.StatusCode != http.StatusOK || !bytes.Equal(classicBodyFirst, classicFrame) {
		t.Fatalf("grpc classic cache first response status=%d len=%d want_len=%d", classicResp.StatusCode, len(classicBodyFirst), len(classicFrame))
	}
	controlResp, _ := appProc.waitHTTPResponse(t, tcpBind, siteHost, controlPath, nil, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK
	})
	if controlResp.StatusCode != http.StatusOK {
		t.Fatalf("control cache first response status = %d", controlResp.StatusCode)
	}

	webCallsAfterFirst := webCalls.Load()
	classicCallsAfterFirst := classicCalls.Load()
	controlCallsAfterFirst := controlCalls.Load()

	// 第二轮：策略正确时，上游计数只在对照文本路径上保持不变；
	// gRPC 响应必须重新回源。
	webResp2, webBodySecond := appProc.waitHTTPResponse(t, tcpBind, siteHost, webPath, nil, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK
	})
	if webResp2.StatusCode != http.StatusOK || !bytes.Equal(webBodySecond, webBody) {
		t.Fatalf("grpc-web cache second response status=%d len=%d want_len=%d", webResp2.StatusCode, len(webBodySecond), len(webBody))
	}
	classicResp2, classicBodySecond := appProc.waitHTTPResponse(t, tcpBind, siteHost, classicPath, nil, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK
	})
	if classicResp2.StatusCode != http.StatusOK || !bytes.Equal(classicBodySecond, classicFrame) {
		t.Fatalf("grpc classic cache second response status=%d len=%d want_len=%d", classicResp2.StatusCode, len(classicBodySecond), len(classicFrame))
	}
	controlResp2, controlBodySecond := appProc.waitHTTPResponse(t, tcpBind, siteHost, controlPath, nil, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK
	})
	if controlResp2.StatusCode != http.StatusOK {
		t.Fatalf("control cache second response status = %d", controlResp2.StatusCode)
	}

	webCallsAfterSecond := webCalls.Load()
	classicCallsAfterSecond := classicCalls.Load()
	controlCallsAfterSecond := controlCalls.Load()

	// 修复（internal/proxy/proxy.go ShouldCacheHTTPResponse 排除
	// application/grpc 前缀）后：gRPC-Web 与经典 gRPC 的第二次请求必须
	// 回源（计数增加），control 文本仍命中缓存作为正对照。
	if webCallsAfterSecond == webCallsAfterFirst {
		t.Fatalf("gRPC-Web response was cached: upstream calls stayed at %d across a cache rule hit", webCallsAfterFirst)
	}
	if classicCallsAfterSecond == classicCallsAfterFirst {
		t.Fatalf("gRPC classic trailer response was cached: upstream calls stayed at %d across a cache rule hit", classicCallsAfterFirst)
	}
	if controlCallsAfterSecond != controlCallsAfterFirst {
		t.Fatalf("control text response missed the cache: upstream calls %d -> %d", controlCallsAfterFirst, controlCallsAfterSecond)
	}
	if !bytes.Equal(controlBodySecond, []byte("cache-control-positive")) {
		t.Fatalf("control cache hit body = %q", controlBodySecond)
	}
}
