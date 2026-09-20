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

// appProcGRPCDataFrame builds a gRPC-Web DATA frame: one frame flag byte,
// a big-endian uint32 payload length, then the payload.
func appProcGRPCDataFrame(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// appProcGRPCMessage wraps an unary message with the gRPC length prefix:
// a zero compressed flag, a big-endian uint32 length, then the message.
func appProcGRPCMessage(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// appProcGRPCWebTrailers builds the in-body trailers frame of the
// Envoy-style server form of gRPC-Web: flag 0x80, payload
// "grpc-status:<code>" plus optional message and extra entries. In this form
// grpc-status does not travel in the HTTP Trailer segment.
func appProcGRPCWebTrailers(status int, message string) []byte {
	payload := fmt.Sprintf("grpc-status:%d", status)
	if message != "" {
		payload += "\r\ngrpc-message:" + message
	}
	return appProcGRPCDataFrame(0x80, []byte(payload))
}

// appProcGRPCWebUnaryBody assembles one unary message frame plus the
// trailers frame carried at the end of the body.
func appProcGRPCWebUnaryBody(message string) []byte {
	body := append([]byte{}, appProcGRPCDataFrame(0, appProcGRPCMessage([]byte(message)))...)
	return append(body, appProcGRPCWebTrailers(0, "")...)
}

// appProcEnableH2H3Network seeds the system settings used by every site in
// this file: HTTP/2 + HTTP/3 enabled, the reserved UDP bind for QUIC, and
// self-signed TLS defaults.
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

// appProcHTTP2Client dials the WAF data plane over TLS and forces ALPN "h2".
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

// TestRunGRPCWebUnaryOverH2InSeparateProcess proxies one Envoy-style
// gRPC-Web unary response (message frame + in-body trailers frame carrying
// grpc-status) from an H2 upstream through the WAF to an H2 client and
// requires byte-identical frames, correct content-type and no
// Content-Encoding.
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

// TestRunGRPCWebServerStreamOverH2InSeparateProcess proxies a multi-message
// gRPC-Web server stream with the trailers frame at the end of the body and
// requires the complete frame sequence to survive byte for byte.
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

// TestRunGRPCoverHTTP3InSeparateProcess drives a real H3 gRPC echo upstream:
// the WAF H3 listener carries the request to an http3.Server upstream, the
// message frame comes back byte-identical and grpc-status arrives in the
// H3 trailer segment. The access log must record h3 in, HTTP/3.0 out and
// QUIC-prefixed JA4 metadata.
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

// TestRunCachesGRPCWebAndGRPCTrailerBodiesInSeparateProcess proves or
// refutes the cache defect: with a prefix cache rule hit and
// Cache-Control: public, max-age=60, both the gRPC-Web in-body-trailer form
// and the classic in-Trailer gRPC form must NOT be stored. A second request
// must reach the upstream again (miss), while a control text path must hit
// the cache as the positive control.
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

	// Cache decisions are transport independent: drive the data plane over
	// plain HTTP/1.1.
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

	// Second pass: a correct policy keeps the upstream counts unchanged only
	// for the control text path; grpc responses must be fetched again.
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
