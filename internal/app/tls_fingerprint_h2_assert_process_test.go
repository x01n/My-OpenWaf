package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

	"My-OpenWaf/internal/acme"
	adminsystem "My-OpenWaf/internal/admin/system"
	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestRunServesHTTP2RequestsWithTraceableTLSFingerprintMetadataInSeparateProcess asserts that a
// TCP/ALPN-h2 inbound connection records the full ClientHello fingerprint metadata (JA3, JA3Hash,
// JA4 with 't' prefix, TLS version, SNI, ALPN, HTTP protocol) into the per-site access log and
// security event via the request trace, mirroring the HTTP/3 coverage at
// server_process_test.go TestRunServesHTTP3RequestsWithTraceableTLSFingerprintMetadataInSeparateProcess.
func TestRunServesHTTP2RequestsWithTraceableTLSFingerprintMetadataInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream should not be reached when H2 rule intercepts")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-fingerprint.blackbox.example.test"
	const requestPath = "/h2-fingerprint-trace"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   false,
			DefaultALPN:    "h2,http/1.1",
			DefaultNetwork: "tcp",
		})
		if err != nil {
			return fmt.Errorf("marshal network_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h2-fingerprint-policy",
			Description: "validates real H2 TLS fingerprint capture in a separate process",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-h2-fingerprint-by-alpn",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h2",
			Action:   store.ActionIntercept,
			Priority: 1,
			Enabled:  true,
		}
		if err := db.Create(&rule).Error; err != nil {
			return fmt.Errorf("create rule: %w", err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTP/2 response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusForbidden, body, appProc.output.String())
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP/2 response missing X-Request-ID header")
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	if accessLog.StatusCode != http.StatusForbidden {
		t.Fatalf("access log status_code = %d, want %d", accessLog.StatusCode, http.StatusForbidden)
	}
	if accessLog.WAFAction != string(store.ActionIntercept) {
		t.Fatalf("access log waf_action = %q, want %q", accessLog.WAFAction, store.ActionIntercept)
	}
	if accessLog.HTTPProtocol != "h2" {
		t.Fatalf("access log http_protocol = %q, want %q", accessLog.HTTPProtocol, "h2")
	}
	if accessLog.TLSVersion != "TLS13" {
		t.Fatalf("access log tls_version = %q, want %q", accessLog.TLSVersion, "TLS13")
	}
	if accessLog.TLSSNI != siteHost {
		t.Fatalf("access log tls_sni = %q, want %q", accessLog.TLSSNI, siteHost)
	}
	if accessLog.TLSALPN != "h2" {
		t.Fatalf("access log tls_alpn = %q, want %q", accessLog.TLSALPN, "h2")
	}
	if accessLog.TLSJA3 == "" || accessLog.TLSJA3Hash == "" {
		t.Fatalf("access log missing JA3 metadata: %+v", accessLog)
	}
	if accessLog.TLSJA4 == "" {
		t.Fatalf("access log tls_ja4 is empty: %+v", accessLog)
	}
	if accessLog.TLSJA4[0] != 't' {
		t.Fatalf("access log tls_ja4 = %q, want TCP-prefixed value", accessLog.TLSJA4)
	}

	securityEvent := appProc.waitForSiteSecurityEvent(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	if securityEvent.Action != string(store.ActionIntercept) {
		t.Fatalf("security event action = %q, want %q", securityEvent.Action, store.ActionIntercept)
	}
	if securityEvent.TLSJA3 == "" || securityEvent.TLSJA3Hash == "" {
		t.Fatalf("security event missing JA3 metadata: %+v", securityEvent)
	}
	if securityEvent.TLSJA4 == "" || securityEvent.TLSJA4[0] != 't' {
		t.Fatalf("security event tls_ja4 = %q, want TCP-prefixed value", securityEvent.TLSJA4)
	}
	if securityEvent.TLSJA3Hash != accessLog.TLSJA3Hash || securityEvent.TLSJA4 != accessLog.TLSJA4 {
		t.Fatalf("security event fingerprint metadata mismatch: %+v vs %+v", securityEvent, accessLog)
	}

	requireAppProcessAccessLogTrace(t, appProc, accessLog, appProcessAccessLogTraceExpectation{
		label:               "HTTP/2 intercept fingerprint trace",
		requestID:           requestID,
		siteHost:            siteHost,
		statusCode:          http.StatusForbidden,
		wafAction:           string(store.ActionIntercept),
		securityEventAction: string(store.ActionIntercept),
		httpProtocol:        "h2",
		tlsALPN:             "h2",
		ja4Prefix:           't',
	})

	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTP/2 intercept fingerprint")
}

// TestRunServesHTTP11RequestsWithTraceableTLSFingerprintMetadataInSeparateProcess asserts that an
// ALPN http/1.1 keep-alive connection records the full ClientHello fingerprint metadata into the
// per-site access log, and that two requests reusing one TCP/TLS connection carry matching JA4
// values (no new handshake fingerprint between them).
func TestRunServesHTTP11RequestsWithTraceableTLSFingerprintMetadataInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http11 fingerprint upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h11-fingerprint.blackbox.example.test"
	const requestPathA = "/h11-fingerprint-trace-a"
	const requestPathB = "/h11-fingerprint-trace-b"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   false,
			DefaultALPN:    "h2,http/1.1",
			DefaultNetwork: "tcp",
		})
		if err != nil {
			return fmt.Errorf("marshal network_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h11-fingerprint-policy",
			Description: "validates HTTP/1.1 ALPN TLS fingerprint capture in a separate process",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h11-fingerprint-by-alpn",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:http/1.1",
			Action:   store.ActionObserve,
			Priority: 1,
			Enabled:  true,
		}
		if err := db.Create(&rule).Error; err != nil {
			return fmt.Errorf("create rule: %w", err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	// 同一 Transport 上的两个请求在同一 TCP/TLS 连接上串行执行：
	// 第一个请求完成后连接进入 idle pool，第二个请求复用同一条连接。
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		},
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	doRequest := func(path string) (*http.Response, string) {
		t.Helper()
		targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + path
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTP/1.1 fingerprint request: %v", err)
		}
		req.Host = siteHost
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTP/1.1 fingerprint request failed: %v\n%s", err, appProc.output.String())
		}
		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read HTTP/1.1 fingerprint response body: %v", readErr)
		}
		return resp, string(bodyBytes)
	}

	respA, bodyA := doRequest(requestPathA)
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/1.1 request A status = %d, want %d, body=%s\n%s", respA.StatusCode, http.StatusOK, bodyA, appProc.output.String())
	}
	if respA.ProtoMajor != 1 {
		t.Fatalf("HTTP/1.1 request A proto major = %d, want 1", respA.ProtoMajor)
	}
	requestIDA := strings.TrimSpace(respA.Header.Get("X-Request-ID"))
	if requestIDA == "" {
		t.Fatal("HTTP/1.1 request A response missing X-Request-ID header")
	}

	accessLogA := appProc.waitForSiteAccessLog(t, siteID, requestPathA, url.Values{
		"request_id": []string{requestIDA},
	})
	if accessLogA.HTTPProtocol != "http/1.1" {
		t.Fatalf("access log A http_protocol = %q, want %q", accessLogA.HTTPProtocol, "http/1.1")
	}
	if accessLogA.TLSVersion != "TLS13" {
		t.Fatalf("access log A tls_version = %q, want %q", accessLogA.TLSVersion, "TLS13")
	}
	if accessLogA.TLSSNI != siteHost {
		t.Fatalf("access log A tls_sni = %q, want %q", accessLogA.TLSSNI, siteHost)
	}
	if accessLogA.TLSALPN != "http/1.1" {
		t.Fatalf("access log A tls_alpn = %q, want %q", accessLogA.TLSALPN, "http/1.1")
	}
	if accessLogA.TLSJA3 == "" || accessLogA.TLSJA3Hash == "" {
		t.Fatalf("access log A missing JA3 metadata: %+v", accessLogA)
	}
	if accessLogA.TLSJA4 == "" {
		t.Fatalf("access log A tls_ja4 is empty: %+v", accessLogA)
	}
	if accessLogA.TLSJA4[0] != 't' {
		t.Fatalf("access log A tls_ja4 = %q, want TCP-prefixed value", accessLogA.TLSJA4)
	}
	appProc.requireFingerprintSummaryForAccessLog(t, accessLogA, "HTTP/1.1 request A fingerprint")

	// 两个请求之间不做 CloseIdleConnections：强制第二条请求复用第一条的 keep-alive 连接。
	respB, bodyB := doRequest(requestPathB)
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/1.1 request B status = %d, want %d, body=%s\n%s", respB.StatusCode, http.StatusOK, bodyB, appProc.output.String())
	}
	if respB.ProtoMajor != 1 {
		t.Fatalf("HTTP/1.1 request B proto major = %d, want 1", respB.ProtoMajor)
	}
	requestIDB := strings.TrimSpace(respB.Header.Get("X-Request-ID"))
	if requestIDB == "" {
		t.Fatal("HTTP/1.1 request B response missing X-Request-ID header")
	}

	accessLogB := appProc.waitForSiteAccessLog(t, siteID, requestPathB, url.Values{
		"request_id": []string{requestIDB},
	})
	if accessLogB.HTTPProtocol != "http/1.1" {
		t.Fatalf("access log B http_protocol = %q, want %q", accessLogB.HTTPProtocol, "http/1.1")
	}
	if accessLogB.TLSJA3 == "" || accessLogB.TLSJA3Hash == "" {
		t.Fatalf("access log B missing JA3 metadata: %+v", accessLogB)
	}
	if accessLogB.TLSJA4 == "" || accessLogB.TLSJA4[0] != 't' {
		t.Fatalf("access log B tls_ja4 = %q, want TCP-prefixed value", accessLogB.TLSJA4)
	}
	// 连接复用意味着握手只发生一次：两条访问日志的 JA4 与 JA3 哈希必须一致。
	if accessLogB.TLSJA4 != accessLogA.TLSJA4 {
		t.Fatalf("access log B tls_ja4 = %q, want re-used connection JA4 %q", accessLogB.TLSJA4, accessLogA.TLSJA4)
	}
	if accessLogB.TLSJA3Hash != accessLogA.TLSJA3Hash {
		t.Fatalf("access log B tls_ja3_hash = %q, want re-used connection hash %q", accessLogB.TLSJA3Hash, accessLogA.TLSJA3Hash)
	}
	appProc.requireFingerprintSummaryForAccessLog(t, accessLogB, "HTTP/1.1 request B fingerprint")
}

// TestRunServesTLSUpstreamCertificateVerificationFailureWithRecoveryInSeparateProcess asserts that
// a site with upstream_tls_skip_verify=false answering against a self-signed upstream returns 502
// (handler.go maps TLS handshake errors to 502, not 504), logs the failed attempt, and a subsequent
// request also reaches the origin instead of replaying a dirty cached failure.
func TestRunServesTLSUpstreamCertificateVerificationFailureWithRecoveryInSeparateProcess(t *testing.T) {
	var originHits int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&originHits, 1)
		w.Header().Set("Content-Type", "text/plain")
		// 505 只在真实回源时出现，保证命中计数与响应对应。
		_, _ = io.WriteString(w, "verified upstream should not be reachable:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "upstream-cert-failure.blackbox.example.test"
	const requestPath = "/upstream-cert-failure-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   false,
			DefaultALPN:    "h2,http/1.1",
			DefaultNetwork: "tcp",
		})
		if err != nil {
			return fmt.Errorf("marshal network_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		cacheRulesBytes, err := json.Marshal([]store.SiteCacheRule{
			{Type: "prefix", Value: "/upstream-cert-failure", TTL: 120},
		})
		if err != nil {
			return fmt.Errorf("marshal cache rules: %w", err)
		}

		// UpdateSite 每轮都会执行 ValidateSiteTLSCertificate：TLS 站点必须携带
		// 可解析的 cert_id，否则后续 repair 阶段的站点更新会被 400 拒绝。
		siteCertPEM, siteKeyPEM, err := acme.GenerateSelfSignedPEM(siteHost, []string{siteHost}, nil, time.Hour)
		if err != nil {
			return fmt.Errorf("generate site certificate: %w", err)
		}
		siteCert := store.Certificate{
			Name:    "upstream cert failure site certificate",
			CertPEM: siteCertPEM,
			KeyPEM:  siteKeyPEM,
		}
		if err := db.Create(&siteCert).Error; err != nil {
			return fmt.Errorf("create site certificate: %w", err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			CertID:       &siteCert.ID,
			ALPN:         "h2,http/1.1",
			// 默认目录；httptest 自签证书未被任何根信任，
			// 逐字使 InsecureSkipVerify=false，触发 x509 校验失败。
			UpstreamTLSSkipVerify: false,
			CacheEnabled:          true,
			CacheDefaultTTL:       120,
			CacheRules:            string(cacheRulesBytes),
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	// 第一个请求：握手验证失败，按 handler.go 语义必须返回 502（而非 504 或其他状态）。
	waitForUpstreamCertFailure := func() (*http.Response, string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		lastObserved := "no HTTPS response observed"
		for time.Now().Before(deadline) {
			if exited, err := appProc.pollExit(); exited {
				t.Fatalf("app helper process exited before upstream cert failure request: %v\n%s", err, appProc.output.String())
			}

			targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
			req, err := http.NewRequest(http.MethodGet, targetURL, nil)
			if err != nil {
				t.Fatalf("build upstream cert failure request: %v", err)
			}
			req.Host = siteHost

			transport := &http.Transport{
				DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
				},
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
				},
				ForceAttemptHTTP2: true,
			}
			client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
			resp, err := client.Do(req)
			if err == nil {
				bodyBytes, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				transport.CloseIdleConnections()
				if readErr != nil {
					t.Fatalf("read upstream cert failure response body: %v", readErr)
				}
				if resp.StatusCode == http.StatusBadGateway {
					return resp, string(bodyBytes)
				}
			}
			lastObserved = fmt.Sprintf("err=%v status=%d", err, 0)
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("HTTPS upstream cert failure response did not converge to 502, last=%s\n%s", lastObserved, appProc.output.String())
		return nil, ""
	}

	resp, _ := waitForUpstreamCertFailure()
	if resp.ProtoMajor != 2 {
		t.Fatalf("upstream cert failure response proto major = %d, want 2", resp.ProtoMajor)
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("502 response missing X-Request-ID header")
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	if accessLog.StatusCode != http.StatusBadGateway {
		t.Fatalf("access log status_code = %d, want %d", accessLog.StatusCode, http.StatusBadGateway)
	}
	if accessLog.WAFAction != "" && accessLog.WAFAction != "none" {
		t.Fatalf("access log waf_action = %q, want %q", accessLog.WAFAction, "none")
	}
	if accessLog.TLSSNI != siteHost {
		t.Fatalf("access log tls_sni = %q, want %q", accessLog.TLSSNI, siteHost)
	}
	if accessLog.TLSJA3Hash == "" {
		t.Fatalf("access log missing JA3 metadata: %+v", accessLog)
	}

	// 第二个请求必须再次回源（回源计数 +1）并再次拿到 502：
	// 握手失败不得在站点响应缓存中留下可回放的脏条目。
	resp2, body2 := waitForUpstreamCertFailure()
	if resp2.ProtoMajor != 2 {
		t.Fatalf("second upstream cert failure response proto major = %d, want 2", resp2.ProtoMajor)
	}
	if body2 == "" {
		t.Fatal("second 502 response body is empty")
	}
	if got := atomic.LoadInt64(&originHits); got != 0 {
		t.Fatalf("self-signed origin reachable %d times, want 0 (any hit means verification did not fail)", got)
	}

	// 修复点：把站点切到同样的自签上游但允许跳过验证，恢复 200。
	var updateResp store.Site
	appProc.postJSON(
		t,
		fmt.Sprintf("/api/v1/sites/%d/update", siteID),
		[]byte(`{"upstream_tls_skip_verify":true}`),
		&updateResp,
	)
	if !updateResp.UpstreamTLSSkipVerify {
		t.Fatal("update response upstream_tls_skip_verify = false, want true")
	}

	recoveredResp, recoveredBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if recoveredResp.StatusCode != http.StatusOK {
		t.Fatalf("recovered HTTPS response status = %d, want %d, body=%s\n%s", recoveredResp.StatusCode, http.StatusOK, recoveredBody, appProc.output.String())
	}
	if !strings.Contains(recoveredBody, "verified upstream should not be reachable") {
		t.Fatalf("recovered HTTPS response body = %q, want real upstream body", recoveredBody)
	}
}

// TestRunHotReloadsHTTPSCertificateWithoutDroppingExistingConnectionInSeparateProcess asserts that
// after a certificate hot reload, a pre-existing keep-alive TLS connection still serves requests
// (the negotiated certificate cannot change on an established connection), while new connections
// observe the updated certificate.
func TestRunHotReloadsHTTPSCertificateWithoutDroppingExistingConnectionInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "https cert reload keep-alive upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-cert-reload-keep.example.test"
	const requestPath = "/https-cert-reload-keep-check"

	certPEMBefore, keyPEMBefore, err := acme.GenerateSelfSignedPEM(siteHost, []string{siteHost}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate initial certificate: %v", err)
	}
	parsedBefore := parseAppProcessCertificatePEM(t, certPEMBefore)

	certPEMAfter, keyPEMAfter, err := acme.GenerateSelfSignedPEM(siteHost, []string{siteHost}, nil, 2*time.Hour)
	if err != nil {
		t.Fatalf("generate updated certificate: %v", err)
	}
	parsedAfter := parseAppProcessCertificatePEM(t, certPEMAfter)
	if bytes.Equal(parsedBefore.Raw, parsedAfter.Raw) {
		t.Fatal("generated certificates have identical raw bytes")
	}

	var certID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   false,
			DefaultALPN:    "h2,http/1.1",
			DefaultNetwork: "tcp",
		})
		if err != nil {
			return fmt.Errorf("marshal network_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		cert := store.Certificate{
			Name:    "https cert reload keep-alive before",
			CertPEM: certPEMBefore,
			KeyPEM:  keyPEMBefore,
		}
		if err := db.Create(&cert).Error; err != nil {
			return fmt.Errorf("create certificate: %w", err)
		}
		certID = cert.ID

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			CertID:       &cert.ID,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	conn, responseReader := appProc.dialRawHTTPSTransportForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	requestBefore := newRawTLSUpgradeRequestProcess(siteHost, requestPath)
	respBefore, certBefore := readRawUpgradeRequestResponseProcess(t, conn, responseReader, requestBefore)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial keep-alive HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, respBefore.Body, appProc.output.String())
	}
	if !bytes.Equal(certBefore, parsedBefore.Raw) {
		t.Fatal("initial keep-alive connection returned unexpected peer certificate")
	}
	if respBefore.Header.Get("Connection") == "close" {
		t.Fatal("initial response wanted keep-alive but sent Connection: close")
	}

	updatePayload, err := json.Marshal(map[string]string{
		"name":     "https cert reload keep-alive after",
		"cert_pem": certPEMAfter,
		"key_pem":  keyPEMAfter,
	})
	if err != nil {
		t.Fatalf("encode HTTPS certificate update payload: %v", err)
	}
	var updateResp store.Certificate
	appProc.postJSON(t, fmt.Sprintf("/api/v1/certificates/%d/update", certID), updatePayload, &updateResp)
	if updateResp.ID != certID {
		t.Fatalf("updated HTTPS certificate id = %d, want %d", updateResp.ID, certID)
	}

	// 新连接必须观察到新证书（reload 已生效）。
	certAfterConn, certAfterReader := appProc.dialRawHTTPSTransportForHost(t, tcpBind, siteHost)
	respAfter, certAfter := readRawUpgradeRequestResponseProcess(t, certAfterConn, certAfterReader, newRawTLSUpgradeRequestProcess(siteHost, requestPath))
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded keep-alive HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, respAfter.Body, appProc.output.String())
	}
	if !bytes.Equal(certAfter, parsedAfter.Raw) {
		t.Fatal("reloaded handshake did not return the updated certificate")
	}

	// 旧连接在 reload 后必须保持可用（第二次请求仍成功且仍带旧证书）。
	respKept, certKept := readRawUpgradeRequestResponseProcess(t, conn, responseReader, newRawTLSUpgradeRequestProcess(siteHost, requestPath+"/after-reload"))
	if respKept.StatusCode != http.StatusOK {
		t.Fatalf("kept connection HTTPS response after reload status = %d, want %d, body=%s\n%s", respKept.StatusCode, http.StatusOK, respKept.Body, appProc.output.String())
	}
	if !bytes.Equal(certKept, parsedBefore.Raw) {
		t.Fatal("kept connection peer certificate changed after reload")
	}
}

// rawTLSUpgradeRequest 是一次绕过 http.Client 的 HTTP/1.1 请求响应对，
// 用于精确控制同一 TLS 连接上的第二次请求。
type rawTLSUpgradeRequest struct {
	Host string
	Path string
}

func newRawTLSUpgradeRequestProcess(host, path string) *rawTLSUpgradeRequest {
	return &rawTLSUpgradeRequest{Host: host, Path: path}
}

func (r *rawTLSUpgradeRequest) headerBytes() []byte {
	return []byte("GET " + r.Path + " HTTP/1.1\r\n" +
		"Host: " + r.Host + "\r\n" +
		"User-Agent: my-openwaf-process-test\r\n" +
		"Accept: */*\r\n\r\n")
}

// rawTLSUpgradeResponse 是一次原始 HTTP/1.1 响应。
type rawTLSUpgradeResponse struct {
	StatusCode int
	Header     http.Header
	Body       string
}

// dialRawHTTPSTransportForHost 建立一条到数据面 bind 的排他 TLS 连接。
//
// 返回的连接只属于调用方，http.Client 不会替它做连接池或重定向。
func (h *appProcessHarness) dialRawHTTPSTransportForHost(t *testing.T, bind string, serverName string) (*tls.Conn, *bufio.Reader) {
	t.Helper()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
			ServerName:         serverName,
		},
	}
	rawConn, err := dialer.DialContext(context.Background(), "tcp", bind)
	if err != nil {
		t.Fatalf("tls dial raw for %s: %v\n%s", serverName, err, h.output.String())
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		t.Fatalf("dialed connection is %T, want *tls.Conn", rawConn)
	}
	if conn.ConnectionState().NegotiatedProtocol != "http/1.1" {
		_ = conn.Close()
		t.Fatalf("negotiated protocol = %q, want %q\n%s", conn.ConnectionState().NegotiatedProtocol, "http/1.1", h.output.String())
	}
	return conn, bufio.NewReader(conn)
}

// readRawUpgradeRequestResponseProcess 在前述连接上写一条 HTTP/1.1 请求，
// 读取完整响应（含 body），并返回响应与本次握手的叶子证书原始字节。
//
// 读 body 依赖 Content-Length 或 chunked 编码，因此可以安全地在同一连接上
// 继续发送下一个请求。
func readRawUpgradeRequestResponseProcess(t *testing.T, conn *tls.Conn, reader *bufio.Reader, req *rawTLSUpgradeRequest) (*rawTLSUpgradeResponse, []byte) {
	t.Helper()

	if err := conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := conn.Write(req.headerBytes()); err != nil {
		t.Fatalf("write raw TLS HTTP/1.1 request: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(reader, &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: req.Host, Path: req.Path},
	})
	if err != nil {
		t.Fatalf("read raw TLS HTTP/1.1 response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read raw TLS HTTP/1.1 response body: %v", err)
	}
	// 证书叶子必须从真实的握手状态取：手工构造的 *http.Request 没有
	// RequestURI 与 Proto（见标准库 client.go），ReadResponse 无法为它
	// 装配 resp.TLS，只能直接用连接侧的 TLS ConnectionState。
	handshakeState := conn.ConnectionState()
	if len(handshakeState.PeerCertificates) == 0 {
		t.Fatal("raw TLS connection state missing peer certificates")
	}
	return &rawTLSUpgradeResponse{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(body)}, handshakeState.PeerCertificates[0].Raw
}

// 占位引用，防止未使用导入的编译错误在重构中悄然出现；
// 这里列出的包在同类测试文件中都是活跃的依赖（建立 harness、解析证书与构建站点配置）。
var _ = sqlite.Open
var _ = gorm.ErrRecordNotFound
