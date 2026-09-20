package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// appProcGRPCFrameWithFlag builds a gRPC frame with an explicit compressed
// flag byte, a big-endian uint32 length and the payload.
func appProcGRPCFrameWithFlag(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// appProcH2CGRPCUpstream starts an h2c upstream whose handler only accepts
// prior-knowledge HTTP/2 requests, and returns its base address.
func appProcH2CGRPCUpstream(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			// 上游健康探测：直接成功返回，不进入用例 handler 的计数路径。
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		handler(w, r)
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	t.Cleanup(upstream.Close)
	return "grpc://" + upstream.Listener.Addr().String()
}

// appProcWaitHTTP3Ready polls a fresh HTTP/3 dial until the data-plane
// listener accepts the call; the process harness may still be starting.
func appProcWaitHTTP3Ready(t *testing.T, h *appProcessHarness, udpBind string, host string, method string, path string, contentType string, headers map[string]string, body []byte) (*http.Response, []byte, http.Header) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP/3 request: %v\n%s", err, h.output.String())
		}
		transport := &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				NextProtos:         []string{"h3"},
			},
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
			},
		}
		client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
		targetURL := "https://" + host + ":" + extractPort(udpBind) + path
		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, targetURL, reqBody)
		if err != nil {
			t.Fatalf("build HTTP/3 probe request: %v", err)
		}
		req.Host = host
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, doErr := client.Do(req)
		if doErr == nil {
			respBody, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			_ = transport.Close()
			if readErr != nil {
				t.Fatalf("read HTTP/3 probe response body: %v", readErr)
			}
			trailer := http.Header{}
			for key, values := range resp.Trailer {
				for _, value := range values {
					trailer.Add(key, value)
				}
			}
			return resp, respBody, trailer
		}
		_ = transport.Close()
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP/3 endpoint did not become ready for host=%q path=%q\n%s", host, path, h.output.String())
	return nil, nil, nil
}

// appProcSiteEnableCompression seeds the three compression system settings
// with the values used by the compression-relevant black-box cases.
func appProcSiteEnableCompression(db *gorm.DB) error {
	settings := []store.SystemSettings{
		{Key: "response_compression_enabled", Value: "true"},
		{Key: "response_compression_gzip_enabled", Value: "true"},
		{Key: "response_compression_min_bytes", Value: "1024"},
	}
	for _, item := range settings {
		if err := db.Create(&item).Error; err != nil {
			return fmt.Errorf("create compression setting %q: %w", item.Key, err)
		}
	}
	return nil
}

// appProcCreateSite seeds a TLS-enabled tcp site bound to the reserved bind
// and records its ID in siteID.
func appProcCreateSite(db *gorm.DB, siteID *uint, host string, upstreamURL string, bind string) error {
	site := store.Site{
		Host:                  host,
		UpstreamURLs:          upstreamURL,
		UpstreamTLSSkipVerify: true,
		Bind:                  bind,
		Network:               "tcp",
		Enabled:               true,
		TLSEnabled:            true,
		ALPN:                  "h2,h3,http/1.1",
	}
	if err := db.Create(&site).Error; err != nil {
		return fmt.Errorf("create site: %w", err)
	}
	*siteID = site.ID
	return nil
}

// TestRunGRPCWebTextBase64OverH3InSeparateProcess proxies a gRPC-Web-Text
// unary response (base64-encoded frames) from an H2 upstream through the WAF
// to an H3 client and requires the base64 bytes to survive unchanged.
func TestRunGRPCWebTextBase64OverH3InSeparateProcess(t *testing.T) {
	for _, contentType := range []string{"application/grpc-web-text", "application/grpc-web-text+proto", "application/grpc-web-text+json"} {
		t.Run(contentType, func(t *testing.T) {
			payload := []byte(strings.Repeat("web-text-blackbox-", 64))
			msgFrame := appProcGRPCDataFrame(0, appProcGRPCMessage(payload))
			trailersFrame := appProcGRPCWebTrailers(0, "")
			wantEncoded := base64.StdEncoding.EncodeToString(msgFrame) + base64.StdEncoding.EncodeToString(trailersFrame)
			upstreamCalls := atomic.Int32{}
			upstreamBase := appProcH2CGRPCUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				if r.URL.Path != "/grpc.web.Echo/Echo" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", contentType)
				_, _ = w.Write([]byte(wantEncoded))
			})

			tcpBind := reserveAppProcessBind(t)
			udpBind := reserveAppProcessUDPBind(t)

			const siteHost = "grpc-web-text-h3.blackbox.example.test"
			const requestPath = "/grpc.web.Echo/Echo"

			var siteID uint
			appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
				if err := appProcEnableH2H3Network(db, udpBind); err != nil {
					return err
				}
				if err := appProcSiteEnableCompression(db); err != nil {
					return err
				}
				return appProcCreateSite(db, &siteID, siteHost, upstreamBase, tcpBind)
			})

			resp, body, _ := appProcWaitHTTP3Ready(t, appProc, udpBind, siteHost, http.MethodPost, requestPath,
				"application/grpc-web-text", map[string]string{"Accept-Encoding": "gzip"},
				appProcGRPCFrameWithFlag(0, []byte("web-text-call")))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("web-text status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
			}
			if resp.ProtoMajor != 3 {
				t.Fatalf("web-text proto major = %d, want 3", resp.ProtoMajor)
			}
			if got := strings.TrimSpace(resp.Header.Get("Content-Type")); got != contentType {
				t.Fatalf("web-text content-type = %q, want %q", got, contentType)
			}
			if got := resp.Header.Get("Content-Encoding"); got != "" {
				t.Fatalf("web-text Content-Encoding = %q, want empty", got)
			}
			if !bytes.Equal(body, []byte(wantEncoded)) {
				t.Fatalf("web-text body mismatch: got %d bytes, want %d (base64 must pass through unchanged)", len(body), len(wantEncoded))
			}
			if got := upstreamCalls.Load(); got != 1 {
				t.Fatalf("upstream call count = %d, want 1 (streams must not be retried or duped)", got)
			}
		})
	}
}

// TestRunGRPCTrailersOnlyOverH3InSeparateProcess drives an h2c upstream with
// the Trailers-Only form (no message frame, grpc-status only in the trailer)
// through the H3 data plane: an empty body with a 200 status and a grpc-status
// trailer must reach the H3 client exactly.
func TestRunGRPCTrailersOnlyOverH3InSeparateProcess(t *testing.T) {
	const requestPath = "/grpc.Echo/TrailersOnly"
	upstreamBase := appProcH2CGRPCUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != requestPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "grpc-status, grpc-message")
		w.Header().Set("grpc-status", "0")
		w.Header().Set("grpc-message", "ok")
	})

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "grpc-trailers-only.blackbox.example.test"
	var h3RequestPath = requestPath

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := appProcEnableH2H3Network(db, udpBind); err != nil {
			return err
		}
		return appProcCreateSite(db, &siteID, siteHost, upstreamBase, tcpBind)
	})

	resp, body, trailer := appProcWaitHTTP3Ready(t, appProc, udpBind, siteHost, http.MethodPost, h3RequestPath,
		"application/grpc", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("trailers-only status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
	}
	if len(body) != 0 {
		t.Fatalf("trailers-only body carries %d bytes, want 0", len(body))
	}
	if got := trailer.Get("grpc-status"); got != "0" {
		t.Fatalf("trailers-only grpc-status = %q, want %q (trailer must survive an empty body)", got, "0")
	}
	if got := trailer.Get("grpc-message"); got == "" {
		t.Fatalf("trailers-only grpc-message empty, trailer = %v", trailer)
	}
}

// TestRunGRPCBidiLargeOverH2ToH3InSeparateProcess drives a large two-frame
// request through an H2 client into an H3 upstream: both request frames are
// sent before the reply, the upstream reads two frames and answers with a
// 1MiB reply frame in six flushed blocks plus the grpc-status trailer. This
// exercises h2-in/h3-out framing, chunked reverse streaming and the trailer
// remap in a real process pair. It stops short of gated dual-direction
// interleave; that pattern trips a cancellation in the h3 loopback path (see
// temp/grpc-max-compat-report.md).
func TestRunGRPCBidiLargeOverH2ToH3InSeparateProcess(t *testing.T) {
	chunk := []byte(strings.Repeat("h3-bidi-chunk-pattern-", 4096))
	fill := func(target []byte) {
		for off := range target {
			target[off] = chunk[off%len(chunk)]
		}
	}
	reqPayload := make([]byte, 2<<20)
	fill(reqPayload)
	replyPayload := make([]byte, 1<<20)
	fill(replyPayload)

	reqFrame1 := appProcGRPCFrameWithFlag(0, append([]byte("ping-1|"), reqPayload...))
	reqFrame2 := appProcGRPCFrameWithFlag(0, append([]byte("ping-2|"), reqPayload...))
	replyFrameA := appProcGRPCFrameWithFlag(0, append([]byte("pong-a|"), replyPayload...))

	const siteHost = "grpc-bidi-h3.blackbox.example.test"
	const requestPath = "/grpc.Echo/Bidi"
	const probePath = "/probe-h3-ready"

	var upstreamProto atomic.Value
	upstream, upstreamBase := startAppProcessHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProto.Store(r.Proto)
		if r.URL.Path != requestPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.Header().Add("Trailer", "grpc-status")
		head := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, head); err != nil {
			t.Errorf("read bidi frame 1 head: %v", err)
			return
		}
		msg1 := make([]byte, binary.BigEndian.Uint32(head[1:5]))
		if _, err := io.ReadFull(r.Body, msg1); err != nil {
			t.Errorf("read bidi frame 1 body: %v", err)
			return
		}
		if !bytes.HasPrefix(msg1, []byte("ping-1|")) {
			t.Errorf("bidi frame 1 prefix mismatch")
			return
		}
		if _, err := io.ReadFull(r.Body, head); err != nil {
			t.Errorf("read bidi frame 2 head: %v", err)
			return
		}
		msg2 := make([]byte, binary.BigEndian.Uint32(head[1:5]))
		if _, err := io.ReadFull(r.Body, msg2); err != nil {
			t.Errorf("read bidi frame 2 body: %v", err)
			return
		}
		if !bytes.HasPrefix(msg2, []byte("ping-2|")) {
			t.Errorf("bidi frame 2 prefix mismatch")
			return
		}
		const block = 256 << 10
		for off := 0; off < len(replyFrameA); off += block {
			end := off + block
			if end > len(replyFrameA) {
				end = len(replyFrameA)
			}
			if _, err := w.Write(replyFrameA[off:end]); err != nil {
				t.Errorf("write bidi reply A chunk: %v", err)
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		w.Header().Set("grpc-status", "0")
	}))
	defer closeAppProcessHTTP3UpstreamServer(t, upstream)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := appProcEnableH2H3Network(db, udpBind); err != nil {
			return err
		}
		return appProcCreateSite(db, &siteID, siteHost, upstreamBase, tcpBind)
	})

	// Bidi 流使用一个阻塞请求体；先用无害 GET 探测 H3 数据面就绪，避免
	// 探测请求经过回环消耗流式体或重试破坏帧序。
	appProcWaitHTTP3Ready(t, appProc, udpBind, siteHost, http.MethodGet, probePath, "", nil, nil)

	requestBody := append(append([]byte{}, reqFrame1...), reqFrame2...)

	targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2"},
		},
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build h2 bidi request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Content-Type", "application/grpc+proto")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2 bidi request failed: %v\n%s", err, appProc.output.String())
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	reply, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read h2 bidi reply: %v", err)
	}
	if !bytes.Equal(reply, replyFrameA) {
		t.Fatalf("h2 bidi reply mismatch: got %d bytes, want %d", len(reply), len(replyFrameA))
	}

	if got := upstreamProto.Load(); got != "HTTP/3.0" {
		t.Errorf("upstream bidi proto = %q, want %q (h2 in -> h3 upstream)", got, "HTTP/3.0")
	}
	if got := resp.Trailer.Get("grpc-status"); got != "0" {
		t.Errorf("bidi grpc-status trailer = %q, want %q", got, "0")
	}
}

// TestRunGRPCDeadlineAndTimeoutOverH3InSeparateProcess verifies the
// grpc-timeout request header and the grpc-status=4 RPC error path through
// the H3 data plane: upstream must see the untouched deadline value and the
// deadline-exceeded trailer must reach the H3 client with HTTP status 200.
func TestRunGRPCDeadlineAndTimeoutOverH3InSeparateProcess(t *testing.T) {
	const grpcMessage = "deadline exceeded"
	const requestPath = "/grpc.Echo/Expire"
	upstreamCalls := atomic.Int32{}
	upstreamBase := appProcH2CGRPCUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.URL.Path != requestPath {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Grpc-Timeout"); got != "400S" {
			t.Errorf("upstream grpc-timeout = %q, want %q", got, "400S")
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "grpc-status, grpc-message")
		_, _ = w.Write(appProcGRPCFrameWithFlag(0, []byte("expired-blackbox")))
		w.Header().Set("grpc-status", "4")
		w.Header().Set("grpc-message", grpcMessage)
	})

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "grpc-deadline-h3.blackbox.example.test"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := appProcEnableH2H3Network(db, udpBind); err != nil {
			return err
		}
		if err := appProcSiteEnableCompression(db); err != nil {
			return err
		}
		return appProcCreateSite(db, &siteID, siteHost, upstreamBase, tcpBind)
	})

	resp, body, trailer := appProcWaitHTTP3Ready(t, appProc, udpBind, siteHost, http.MethodPost, requestPath,
		"application/grpc", map[string]string{"Grpc-Timeout": "400S"},
		appProcGRPCFrameWithFlag(0, []byte("expire-call")))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deadline status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
	}
	if got := trailer.Get("grpc-status"); got != "4" {
		t.Fatalf("deadline grpc-status trailer = %q, want %q", got, "4")
	}
	if got := trailer.Get("grpc-message"); got != grpcMessage {
		t.Fatalf("deadline grpc-message trailer = %q, want %q", got, grpcMessage)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("deadline Content-Encoding = %q, want empty (error responses must not be recompressed)", got)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream call count = %d, want 1 (no 502 retry on grpc-status=4)", got)
	}
}

// TestRunGRPCEncodingCompressedFramesOverH3InSeparateProcess forwards
// grpc-encoding:gzip compressed frames through the H3 data plane and requires
// the compressed bytes and the grpc-encoding header to pass through
// untouched: no decompression, no recompression, no Content-Encoding.
func TestRunGRPCEncodingCompressedFramesOverH3InSeparateProcess(t *testing.T) {
	const requestPath = "/grpc.Echo/Compressed"
	plain := []byte(strings.Repeat("grpc-encoding-gzip-blackbox-", 512))
	wantFrames := append(
		appProcGRPCFrameWithFlag(1, mustGzipAppProcessBytes(t, plain[:len(plain)/2])),
		appProcGRPCFrameWithFlag(1, mustGzipAppProcessBytes(t, plain[len(plain)/2:]))...,
	)
	var upstreamProto string
	upstreamBase := appProcH2CGRPCUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamProto = r.Proto
		if r.URL.Path != requestPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("grpc-encoding", "gzip")
		w.Header().Add("Trailer", "grpc-status")
		block := len(wantFrames) / 2
		_, _ = w.Write(wantFrames[:block])
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write(wantFrames[block:])
		w.Header().Set("grpc-status", "0")
	})

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "grpc-encoding-h3.blackbox.example.test"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := appProcEnableH2H3Network(db, udpBind); err != nil {
			return err
		}
		if err := appProcSiteEnableCompression(db); err != nil {
			return err
		}
		return appProcCreateSite(db, &siteID, siteHost, upstreamBase, tcpBind)
	})

	resp, body, trailer := appProcWaitHTTP3Ready(t, appProc, udpBind, siteHost, http.MethodPost, requestPath,
		"application/grpc", map[string]string{"Accept-Encoding": "gzip"},
		appProcGRPCFrameWithFlag(0, []byte("compressed-blackbox-call")))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grpc-encoding status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
	}
	if got := strings.TrimSpace(resp.Header.Get("Grpc-Encoding")); got != "gzip" {
		t.Fatalf("grpc-encoding header = %q, want %q", got, "gzip")
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty (frame compression belongs to grpc-encoding)", got)
	}
	if !bytes.Equal(body, wantFrames) {
		t.Fatalf("compressed frames mismatch: got %d bytes, want %d", len(body), len(wantFrames))
	}
	if got := trailer.Get("grpc-status"); got != "0" {
		t.Fatalf("grpc-status trailer = %q, want %q", got, "0")
	}
	if upstreamProto != "HTTP/2.0" {
		t.Errorf("upstream compressed-proto = %q, want %q (h2c grpc upstream)", upstreamProto, "HTTP/2.0")
	}
}
