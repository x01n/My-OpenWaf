package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"My-OpenWaf/internal/acme"
	adminsystem "My-OpenWaf/internal/admin/system"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/andybalholm/brotli"
	"github.com/glebarez/sqlite"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"gorm.io/gorm"
)

const appProcessHelperEnv = "MY_OPENWAF_TEST_HELPER_PROCESS"

var appProcessReservedBinds = struct {
	sync.Mutex
	seen map[string]struct{}
}{
	seen: make(map[string]struct{}),
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestAppProcessHelper(t *testing.T) {
	if os.Getenv(appProcessHelperEnv) != "1" {
		return
	}
	Run()
	os.Exit(0)
}

func TestRunHotReloadsRedisRuntimeStateInSeparateProcess(t *testing.T) {
	redisSrv := startAppMockRedisServer(t)
	t.Cleanup(redisSrv.Close)

	appProc := startAppProcessHarness(t)

	var runtimeBefore adminsystem.RuntimeConfigResponse
	appProc.getJSON(t, "/api/v1/runtime-config", &runtimeBefore)
	if runtimeBefore.RedisEnabled {
		t.Fatalf("initial runtime redis_enabled = true, want false")
	}
	if runtimeBefore.RedisAddr != "" {
		t.Fatalf("initial runtime redis_addr = %q, want empty", runtimeBefore.RedisAddr)
	}
	if runtimeBefore.RedisDB != 0 {
		t.Fatalf("initial runtime redis_db = %d, want 0", runtimeBefore.RedisDB)
	}

	enablePayload := []byte(fmt.Sprintf(`{"enabled":true,"addr":%q,"password":"proc-secret","db":9}`, redisSrv.Addr()))
	var enableResp adminsystem.RedisConfigResponse
	appProc.postJSON(t, "/api/v1/redis-config", enablePayload, &enableResp)
	if !enableResp.Enabled {
		t.Fatalf("enable response enabled = false, want true")
	}
	if enableResp.Addr != redisSrv.Addr() {
		t.Fatalf("enable response addr = %q, want %q", enableResp.Addr, redisSrv.Addr())
	}
	if enableResp.DB != 9 {
		t.Fatalf("enable response db = %d, want 9", enableResp.DB)
	}
	if !enableResp.PasswordSet {
		t.Fatal("enable response password_set = false, want true")
	}
	if enableResp.RestartRequired {
		t.Fatal("enable response restart_required = true, want false")
	}

	appProc.waitRuntimeRedisState(t, true, redisSrv.Addr(), 9)
	waitForAppMockRedisCommand(t, redisSrv, "PING")

	var getEnabled adminsystem.RedisConfigResponse
	appProc.getJSON(t, "/api/v1/redis-config", &getEnabled)
	if !getEnabled.Enabled {
		t.Fatalf("stored redis enabled = false, want true")
	}
	if getEnabled.Addr != redisSrv.Addr() {
		t.Fatalf("stored redis addr = %q, want %q", getEnabled.Addr, redisSrv.Addr())
	}
	if getEnabled.DB != 9 {
		t.Fatalf("stored redis db = %d, want 9", getEnabled.DB)
	}
	if !getEnabled.PasswordSet {
		t.Fatal("stored redis password_set = false, want true")
	}
	if getEnabled.RestartRequired {
		t.Fatal("stored redis restart_required = true, want false")
	}

	var disableResp adminsystem.RedisConfigResponse
	appProc.postJSON(t, "/api/v1/redis-config", []byte(`{"enabled":false}`), &disableResp)
	if disableResp.Enabled {
		t.Fatal("disable response enabled = true, want false")
	}
	if disableResp.Addr != redisSrv.Addr() {
		t.Fatalf("disable response addr = %q, want %q", disableResp.Addr, redisSrv.Addr())
	}
	if disableResp.DB != 9 {
		t.Fatalf("disable response db = %d, want 9", disableResp.DB)
	}
	if !disableResp.PasswordSet {
		t.Fatal("disable response password_set = false, want true")
	}
	if disableResp.RestartRequired {
		t.Fatal("disable response restart_required = true, want false")
	}

	appProc.waitRuntimeRedisState(t, false, "", 0)

	var getDisabled adminsystem.RedisConfigResponse
	appProc.getJSON(t, "/api/v1/redis-config", &getDisabled)
	if getDisabled.Enabled {
		t.Fatal("stored disabled redis enabled = true, want false")
	}
	if getDisabled.Addr != redisSrv.Addr() {
		t.Fatalf("stored disabled redis addr = %q, want %q", getDisabled.Addr, redisSrv.Addr())
	}
	if getDisabled.DB != 9 {
		t.Fatalf("stored disabled redis db = %d, want 9", getDisabled.DB)
	}
	if !getDisabled.PasswordSet {
		t.Fatal("stored disabled redis password_set = false, want true")
	}
}

func TestRunHotReloadedRedisReceivesUnifiedObservabilityWritesInSeparateProcess(t *testing.T) {
	redisSrv := startAppMockRedisServer(t)
	t.Cleanup(redisSrv.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream should not be reached when custom rule intercepts")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "redis-runtime.example.test"
	const requestPath = "/redis-runtime-intercept"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		policy := store.Policy{
			Name:        "redis-runtime-policy",
			Description: "validates runtime redis hot reload reaches unified observability writer",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-redis-runtime-path",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "block_path_exact:/redis-runtime-intercept",
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
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	enablePayload := []byte(fmt.Sprintf(`{"enabled":true,"addr":%q,"password":"redis-runtime-secret","db":11}`, redisSrv.Addr()))
	var enableResp adminsystem.RedisConfigResponse
	appProc.postJSON(t, "/api/v1/redis-config", enablePayload, &enableResp)
	if !enableResp.Enabled {
		t.Fatal("enable response enabled = false, want true")
	}
	if enableResp.Addr != redisSrv.Addr() {
		t.Fatalf("enable response addr = %q, want %q", enableResp.Addr, redisSrv.Addr())
	}
	if enableResp.DB != 11 {
		t.Fatalf("enable response db = %d, want 11", enableResp.DB)
	}
	if enableResp.RestartRequired {
		t.Fatal("enable response restart_required = true, want false")
	}

	appProc.waitRuntimeRedisState(t, true, redisSrv.Addr(), 11)
	waitForAppMockRedisCommand(t, redisSrv, "PING")

	resp, body := appProc.doHTTPRequest(t, tcpBind, siteHost, requestPath)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTP response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusForbidden, body, appProc.output.String())
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP response missing X-Request-ID header")
	}

	trace := appProc.waitForRequestTrace(t, requestID)
	if len(trace.AccessLogs) == 0 {
		t.Fatal("request trace access_logs is empty")
	}
	if trace.AccessLogs[0].WAFAction != string(store.ActionIntercept) {
		t.Fatalf("access log waf_action = %q, want %q", trace.AccessLogs[0].WAFAction, store.ActionIntercept)
	}
	if len(trace.SecurityEvents) == 0 {
		t.Fatal("request trace security_events is empty")
	}
	if trace.SecurityEvents[0].Action != string(store.ActionIntercept) {
		t.Fatalf("security event action = %q, want %q", trace.SecurityEvents[0].Action, store.ActionIntercept)
	}

	waitForAppMockRedisCommand(t, redisSrv, "LPUSH OPENWAF:ACCESS_LOGS")
	waitForAppMockRedisCommand(t, redisSrv, "LPUSH OPENWAF:SECURITY_EVENTS")
}

func TestRunHotReloadedRedisEnablesAccessAndSecurityHotCacheInSeparateProcess(t *testing.T) {
	redisSrv := startAppMockRedisServer(t)
	t.Cleanup(redisSrv.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream should not be reached when custom rule intercepts")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "redis-hot-cache.example.test"
	const requestPath = "/redis-runtime-hot-cache"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		policy := store.Policy{
			Name:        "redis-hot-cache-policy",
			Description: "validates runtime redis hot reload reaches repository hot cache queries",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-redis-hot-cache-path",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "block_path_exact:/redis-runtime-hot-cache",
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
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	enablePayload := []byte(fmt.Sprintf(`{"enabled":true,"addr":%q,"password":"redis-hot-cache-secret","db":12}`, redisSrv.Addr()))
	var enableResp adminsystem.RedisConfigResponse
	appProc.postJSON(t, "/api/v1/redis-config", enablePayload, &enableResp)
	if !enableResp.Enabled {
		t.Fatal("enable response enabled = false, want true")
	}
	if enableResp.Addr != redisSrv.Addr() {
		t.Fatalf("enable response addr = %q, want %q", enableResp.Addr, redisSrv.Addr())
	}
	if enableResp.DB != 12 {
		t.Fatalf("enable response db = %d, want 12", enableResp.DB)
	}
	if enableResp.RestartRequired {
		t.Fatal("enable response restart_required = true, want false")
	}

	appProc.waitRuntimeRedisState(t, true, redisSrv.Addr(), 12)
	waitForAppMockRedisCommand(t, redisSrv, "PING")

	resp, body := appProc.doHTTPRequest(t, tcpBind, siteHost, requestPath)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTP response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusForbidden, body, appProc.output.String())
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP response missing X-Request-ID header")
	}

	trace := appProc.waitForRequestTrace(t, requestID)
	if len(trace.AccessLogs) == 0 {
		t.Fatal("request trace access_logs is empty")
	}
	if trace.AccessLogs[0].WAFAction != string(store.ActionIntercept) {
		t.Fatalf("access log waf_action = %q, want %q", trace.AccessLogs[0].WAFAction, store.ActionIntercept)
	}
	if len(trace.SecurityEvents) == 0 {
		t.Fatal("request trace security_events is empty")
	}
	if trace.SecurityEvents[0].Action != string(store.ActionIntercept) {
		t.Fatalf("security event action = %q, want %q", trace.SecurityEvents[0].Action, store.ActionIntercept)
	}

	type accessLogListResponse struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	type securityEventListResponse struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}

	commandsBefore := redisSrv.Commands()
	accessGetBefore := countAppMockRedisCommandsWithPrefix(commandsBefore, "GET OPENWAF:HOT:AL_LIST")
	accessSetBefore := countAppMockRedisCommandsWithPrefix(commandsBefore, "SET OPENWAF:HOT:AL_LIST")
	securityGetBefore := countAppMockRedisCommandsWithPrefix(commandsBefore, "GET OPENWAF:HOT:SE_LIST")
	securitySetBefore := countAppMockRedisCommandsWithPrefix(commandsBefore, "SET OPENWAF:HOT:SE_LIST")

	var accessResp accessLogListResponse
	appProc.getJSON(t, appProcSiteListPath(siteID, "access-logs", requestPath, nil), &accessResp)
	if len(accessResp.Items) == 0 {
		t.Fatal("expected site access log query to return items")
	}

	var securityResp securityEventListResponse
	appProc.getJSON(t, appProcSiteListPath(siteID, "security-events", requestPath, nil), &securityResp)
	if len(securityResp.Items) == 0 {
		t.Fatal("expected site security event query to return items")
	}

	commandsAfterFill := redisSrv.Commands()
	accessGetAfterFill := countAppMockRedisCommandsWithPrefix(commandsAfterFill, "GET OPENWAF:HOT:AL_LIST")
	accessSetAfterFill := countAppMockRedisCommandsWithPrefix(commandsAfterFill, "SET OPENWAF:HOT:AL_LIST")
	securityGetAfterFill := countAppMockRedisCommandsWithPrefix(commandsAfterFill, "GET OPENWAF:HOT:SE_LIST")
	securitySetAfterFill := countAppMockRedisCommandsWithPrefix(commandsAfterFill, "SET OPENWAF:HOT:SE_LIST")

	if accessGetAfterFill <= accessGetBefore {
		t.Fatalf("expected access log hot cache GET after first query, before=%d after=%d commands=%#v", accessGetBefore, accessGetAfterFill, commandsAfterFill)
	}
	if accessSetAfterFill <= accessSetBefore {
		t.Fatalf("expected access log hot cache SET after first query, before=%d after=%d commands=%#v", accessSetBefore, accessSetAfterFill, commandsAfterFill)
	}
	if securityGetAfterFill <= securityGetBefore {
		t.Fatalf("expected security event hot cache GET after first query, before=%d after=%d commands=%#v", securityGetBefore, securityGetAfterFill, commandsAfterFill)
	}
	if securitySetAfterFill <= securitySetBefore {
		t.Fatalf("expected security event hot cache SET after first query, before=%d after=%d commands=%#v", securitySetBefore, securitySetAfterFill, commandsAfterFill)
	}

	appProc.getJSON(t, appProcSiteListPath(siteID, "access-logs", requestPath, nil), &accessResp)
	appProc.getJSON(t, appProcSiteListPath(siteID, "security-events", requestPath, nil), &securityResp)

	commandsAfterHit := redisSrv.Commands()
	accessGetAfterHit := countAppMockRedisCommandsWithPrefix(commandsAfterHit, "GET OPENWAF:HOT:AL_LIST")
	accessSetAfterHit := countAppMockRedisCommandsWithPrefix(commandsAfterHit, "SET OPENWAF:HOT:AL_LIST")
	securityGetAfterHit := countAppMockRedisCommandsWithPrefix(commandsAfterHit, "GET OPENWAF:HOT:SE_LIST")
	securitySetAfterHit := countAppMockRedisCommandsWithPrefix(commandsAfterHit, "SET OPENWAF:HOT:SE_LIST")

	if accessGetAfterHit <= accessGetAfterFill {
		t.Fatalf("expected second access log query to hit Redis hot cache, fill=%d hit=%d commands=%#v", accessGetAfterFill, accessGetAfterHit, commandsAfterHit)
	}
	if accessSetAfterHit != accessSetAfterFill {
		t.Fatalf("expected second access log query to avoid cache repopulation, fill=%d hit=%d commands=%#v", accessSetAfterFill, accessSetAfterHit, commandsAfterHit)
	}
	if securityGetAfterHit <= securityGetAfterFill {
		t.Fatalf("expected second security event query to hit Redis hot cache, fill=%d hit=%d commands=%#v", securityGetAfterFill, securityGetAfterHit, commandsAfterHit)
	}
	if securitySetAfterHit != securitySetAfterFill {
		t.Fatalf("expected second security event query to avoid cache repopulation, fill=%d hit=%d commands=%#v", securitySetAfterFill, securitySetAfterHit, commandsAfterHit)
	}
}

func TestRunUsesStoredRedisConfigOnStartupEvenWhenEnvRedisAddrIsInvalidInSeparateProcess(t *testing.T) {
	redisSrv := startAppMockRedisServer(t)
	t.Cleanup(redisSrv.Close)

	appProc := startAppProcessHarnessWithSetupAndEnv(t, func(db *gorm.DB) error {
		return db.Create(&store.SystemSettings{
			Key:   store.SettingKeyRedisConfig,
			Value: fmt.Sprintf(`{"enabled":true,"addr":"%s","password":"stored-proc-pass","db":13}`, redisSrv.Addr()),
		}).Error
	}, []string{
		"MY_OPENWAF_REDIS_ADDR=bad-addr",
		"MY_OPENWAF_REDIS_PASSWORD=env-pass",
		"MY_OPENWAF_REDIS_DB=1",
	})

	appProc.waitRuntimeRedisState(t, true, redisSrv.Addr(), 13)
	waitForAppMockRedisCommand(t, redisSrv, "PING")
	waitForAppMockRedisCommand(t, redisSrv, "AUTH STORED-PROC-PASS")
	waitForAppMockRedisCommand(t, redisSrv, "SELECT 13")

	var runtimeResp adminsystem.RuntimeConfigResponse
	appProc.getJSON(t, "/api/v1/runtime-config", &runtimeResp)
	if !runtimeResp.RedisEnabled || runtimeResp.RedisAddr != redisSrv.Addr() || runtimeResp.RedisDB != 13 {
		t.Fatalf("runtime redis state = %#v, want stored redis config", runtimeResp)
	}

	var storedResp adminsystem.RedisConfigResponse
	appProc.getJSON(t, "/api/v1/redis-config", &storedResp)
	if !storedResp.Enabled || storedResp.Addr != redisSrv.Addr() || storedResp.DB != 13 || !storedResp.PasswordSet {
		t.Fatalf("stored redis response = %#v, want stored redis config", storedResp)
	}
}

func TestRunServesHTTP3RequestsWithTraceableTLSFingerprintMetadataInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream should not be reached when H3 rule intercepts")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3.blackbox.example.test"
	const requestPath = "/h3-blackbox-trace"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-blackbox-policy",
			Description: "validates real H3 TLS fingerprint capture in a separate process",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-h3-by-alpn",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTP/3 response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusForbidden, body, appProc.output.String())
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 response proto major = %d, want 3", resp.ProtoMajor)
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"tls_alpn": []string{"h3"},
	})
	if accessLog.StatusCode != http.StatusForbidden {
		t.Fatalf("access log status_code = %d, want %d", accessLog.StatusCode, http.StatusForbidden)
	}
	if accessLog.WAFAction != string(store.ActionIntercept) {
		t.Fatalf("access log waf_action = %q, want %q", accessLog.WAFAction, store.ActionIntercept)
	}
	if accessLog.HTTPProtocol != "h3" {
		t.Fatalf("access log http_protocol = %q, want %q", accessLog.HTTPProtocol, "h3")
	}
	if accessLog.TLSVersion != "TLS13" {
		t.Fatalf("access log tls_version = %q, want %q", accessLog.TLSVersion, "TLS13")
	}
	if accessLog.TLSSNI != siteHost {
		t.Fatalf("access log tls_sni = %q, want %q", accessLog.TLSSNI, siteHost)
	}
	if accessLog.TLSALPN != "h3" {
		t.Fatalf("access log tls_alpn = %q, want %q", accessLog.TLSALPN, "h3")
	}
	if accessLog.TLSJA3 == "" || accessLog.TLSJA3Hash == "" {
		t.Fatalf("access log missing JA3 metadata: %+v", accessLog)
	}
	if accessLog.TLSJA4 == "" || accessLog.TLSJA4[0] != 'q' {
		t.Fatalf("access log tls_ja4 = %q, want QUIC-prefixed value", accessLog.TLSJA4)
	}
	if !strings.Contains(accessLog.TLSCipherSuites, "TLS_AES_128_GCM_SHA256") || !strings.Contains(accessLog.TLSCipherSuites, "TLS_AES_256_GCM_SHA384") {
		t.Fatalf("access log tls_cipher_suites = %q, want canonical QUIC TLS suites to include AES_GCM variants", accessLog.TLSCipherSuites)
	}
	if accessLog.TLSExtensions == "" {
		t.Fatalf("access log tls_extensions is empty: %+v", accessLog)
	}
	if accessLog.TLSCurves == "" {
		t.Fatalf("access log tls_curves is empty: %+v", accessLog)
	}
	if accessLog.TLSPointFormats == "" {
		t.Fatalf("access log tls_point_formats is empty: %+v", accessLog)
	}

	securityEvent := appProc.waitForSiteSecurityEvent(t, siteID, requestPath, url.Values{
		"tls_alpn":          []string{"h3"},
		"tls_cipher_suites": []string{"AES_256_GCM_SHA384"},
		"tls_extensions":    []string{accessLog.TLSExtensions},
		"tls_curves":        []string{accessLog.TLSCurves},
		"tls_point_formats": []string{accessLog.TLSPointFormats},
	})
	if securityEvent.Action != string(store.ActionIntercept) {
		t.Fatalf("security event action = %q, want %q", securityEvent.Action, store.ActionIntercept)
	}
	if securityEvent.TLSVersion != "TLS13" {
		t.Fatalf("security event tls_version = %q, want %q", securityEvent.TLSVersion, "TLS13")
	}
	if securityEvent.TLSSNI != siteHost {
		t.Fatalf("security event tls_sni = %q, want %q", securityEvent.TLSSNI, siteHost)
	}
	if securityEvent.TLSALPN != "h3" {
		t.Fatalf("security event tls_alpn = %q, want %q", securityEvent.TLSALPN, "h3")
	}
	if securityEvent.TLSJA3 == "" || securityEvent.TLSJA3Hash == "" {
		t.Fatalf("security event missing JA3 metadata: %+v", securityEvent)
	}
	if securityEvent.TLSJA4 == "" || securityEvent.TLSJA4[0] != 'q' {
		t.Fatalf("security event tls_ja4 = %q, want QUIC-prefixed value", securityEvent.TLSJA4)
	}
	if !strings.Contains(securityEvent.TLSCipherSuites, "TLS_AES_128_GCM_SHA256") || !strings.Contains(securityEvent.TLSCipherSuites, "TLS_AES_256_GCM_SHA384") {
		t.Fatalf("security event tls_cipher_suites = %q, want canonical QUIC TLS suites to include AES_GCM variants", securityEvent.TLSCipherSuites)
	}
	if securityEvent.TLSExtensions != accessLog.TLSExtensions || securityEvent.TLSCurves != accessLog.TLSCurves || securityEvent.TLSPointFormats != accessLog.TLSPointFormats {
		t.Fatalf("security event TLS shape metadata mismatch: %+v vs %+v", securityEvent, accessLog)
	}

	fingerprint := appProc.waitForFingerprintSummary(t, url.Values{
		"tls_version":       []string{"TLS13"},
		"tls_sni":           []string{siteHost},
		"tls_alpn":          []string{"h3"},
		"tls_ja4":           []string{accessLog.TLSJA4},
		"tls_cipher_suites": []string{"AES_256_GCM_SHA384"},
		"tls_extensions":    []string{accessLog.TLSExtensions},
		"tls_curves":        []string{accessLog.TLSCurves},
		"tls_point_formats": []string{accessLog.TLSPointFormats},
	})
	if fingerprint.TLSJA3Hash != accessLog.TLSJA3Hash {
		t.Fatalf("fingerprint tls_ja3_hash = %q, want %q", fingerprint.TLSJA3Hash, accessLog.TLSJA3Hash)
	}
	if fingerprint.TLSJA4 != accessLog.TLSJA4 {
		t.Fatalf("fingerprint tls_ja4 = %q, want %q", fingerprint.TLSJA4, accessLog.TLSJA4)
	}
	if fingerprint.TLSVersion != "TLS13" {
		t.Fatalf("fingerprint tls_version = %q, want %q", fingerprint.TLSVersion, "TLS13")
	}
	if fingerprint.TLSALPN != "h3" {
		t.Fatalf("fingerprint tls_alpn = %q, want %q", fingerprint.TLSALPN, "h3")
	}
	if fingerprint.TLSSNI != siteHost {
		t.Fatalf("fingerprint tls_sni = %q, want %q", fingerprint.TLSSNI, siteHost)
	}
	if fingerprint.Count < 1 {
		t.Fatalf("fingerprint count = %d, want >= 1", fingerprint.Count)
	}
	if !strings.Contains(fingerprint.TLSCipherSuites, "TLS_AES_128_GCM_SHA256") || !strings.Contains(fingerprint.TLSCipherSuites, "TLS_AES_256_GCM_SHA384") {
		t.Fatalf("fingerprint tls_cipher_suites = %q, want canonical QUIC TLS suites to include AES_GCM variants", fingerprint.TLSCipherSuites)
	}
	if fingerprint.TLSExtensions != accessLog.TLSExtensions || fingerprint.TLSCurves != accessLog.TLSCurves || fingerprint.TLSPointFormats != accessLog.TLSPointFormats {
		t.Fatalf("fingerprint TLS shape metadata mismatch: %+v vs %+v", fingerprint, accessLog)
	}

	requireAppProcessAccessLogTrace(t, appProc, accessLog, appProcessAccessLogTraceExpectation{
		label:               "HTTP/3 intercept fingerprint trace",
		requestID:           accessLog.RequestID,
		siteHost:            siteHost,
		statusCode:          http.StatusForbidden,
		wafAction:           string(store.ActionIntercept),
		securityEventAction: string(store.ActionIntercept),
		httpProtocol:        "h3",
		tlsALPN:             "h3",
		ja4Prefix:           'q',
	})

	alpnFailurePath := requestPath + "/alpn-h2-handshake-failure"
	siteObservabilityBeforeALPNFailure := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBeforeALPNFailure := appProc.globalObservabilityTotals(t)
	appProc.requireHTTP3ALPNHandshakeFailure(t, udpBind, siteHost, []string{"h2"})
	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBeforeALPNFailure, "HTTP/3 client h2 ALPN handshake failure")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBeforeALPNFailure, "HTTP/3 client h2 ALPN handshake failure")
	appProc.requireNoGlobalObservability(t, siteHost, alpnFailurePath, "HTTP/3 client h2 ALPN handshake failure")
	appProc.requireNoFingerprintSummary(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, "HTTP/3 client h2 ALPN handshake failure")
}

func TestRunClosesIdleHTTP3ConnectionWithoutObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream should not be reached when idle H3 rule intercepts")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-idle-close.example.test"
	const idleSNI = "h3-idle-close-probe.example.test"
	const readyPath = "/h3-idle-close-ready"
	const noRequestPath = "/h3-idle-close/no-request"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-idle-close-policy",
			Description: "stabilizes HTTP/3 idle close observability baseline",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-h3-idle-close-ready",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTP/3 idle close ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusForbidden, readyBody, appProc.output.String())
	}
	readyRequestID := strings.TrimSpace(readyResp.Header.Get("X-Request-ID"))
	if readyRequestID == "" {
		t.Fatal("HTTP/3 idle close ready response missing X-Request-ID header")
	}
	readyAccessLog := appProc.waitForSiteAccessLog(t, siteID, readyPath, url.Values{
		"request_id": []string{readyRequestID},
		"tls_alpn":   []string{"h3"},
	})
	if readyAccessLog.WAFAction != string(store.ActionIntercept) {
		t.Fatalf("HTTP/3 idle close ready access log waf_action = %q, want %q", readyAccessLog.WAFAction, store.ActionIntercept)
	}
	appProc.waitForSiteSecurityEvent(t, siteID, readyPath, url.Values{
		"request_id": []string{readyRequestID},
		"action":     []string{string(store.ActionIntercept)},
		"tls_alpn":   []string{"h3"},
	})
	requireAppProcessAccessLogTrace(t, appProc, readyAccessLog, appProcessAccessLogTraceExpectation{
		label:               "HTTP/3 idle close ready intercept",
		requestID:           readyRequestID,
		siteHost:            siteHost,
		statusCode:          http.StatusForbidden,
		wafAction:           string(store.ActionIntercept),
		securityEventAction: string(store.ActionIntercept),
		httpProtocol:        "h3",
		tlsALPN:             "h3",
		ja4Prefix:           'q',
	})
	appProc.requireFingerprintSummaryForAccessLog(t, readyAccessLog, "HTTP/3 idle close ready intercept")
	siteObservabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)

	appProc.closeIdleHTTP3Connection(t, udpBind, idleSNI)

	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBefore, "idle QUIC HTTP/3 connection close")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "idle QUIC HTTP/3 connection close")
	appProc.requireNoGlobalObservability(t, idleSNI, noRequestPath, "idle QUIC HTTP/3 connection close")
	appProc.requireNoFingerprintSummary(t, url.Values{
		"tls_sni":  []string{idleSNI},
		"tls_alpn": []string{"h3"},
	}, "idle QUIC HTTP/3 connection close")
}

func TestRunRecordsHTTP3TLSSNIWarningForHostMismatchInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "sni-warning-ok")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-sni-host.example.test"
	const clientSNI = "h3-sni-client.example.test"
	const requestPath = "/h3-sni-warning"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-sni-warning-policy",
			Description: "observes real HTTP/3 requests with Host and TLS SNI mismatch",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-sni-warning-by-alpn",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProc.doHTTP3RequestWithServerName(t, udpBind, clientSNI, siteHost, requestPath)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 SNI mismatch response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 SNI mismatch response proto major = %d, want 3", resp.ProtoMajor)
	}
	if body != "sni-warning-ok" {
		t.Fatalf("HTTP/3 SNI mismatch upstream body = %q, want %q", body, "sni-warning-ok")
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP/3 SNI mismatch response missing X-Request-ID header")
	}

	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 SNI mismatch observe trace",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		tlsSNI:           clientSNI,
		statusCode:       http.StatusOK,
		httpProtocol:     "h3",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(body)),
	})
	if accessLog.Host != siteHost {
		t.Fatalf("HTTP/3 SNI mismatch access log host = %q, want %q", accessLog.Host, siteHost)
	}

	sniWarning := appProc.waitForSiteSecurityEvent(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
		"category":   []string{"tls_sni"},
		"phase":      []string{"tls"},
		"action":     []string{string(store.ActionObserve)},
		"tls_sni":    []string{clientSNI},
		"tls_alpn":   []string{"h3"},
	})
	if sniWarning.RuleIDStr != "tls:unknown_sni" {
		t.Fatalf("HTTP/3 SNI warning rule_id_str = %q, want %q", sniWarning.RuleIDStr, "tls:unknown_sni")
	}
	if sniWarning.Host != siteHost || sniWarning.TLSSNI != clientSNI || sniWarning.TLSVersion != "TLS13" || sniWarning.TLSALPN != "h3" {
		t.Fatalf("HTTP/3 SNI warning metadata mismatch: %+v", sniWarning)
	}
	if sniWarning.MatchDesc != "tls_sni="+clientSNI+" host="+siteHost {
		t.Fatalf("HTTP/3 SNI warning match_desc = %q, want %q", sniWarning.MatchDesc, "tls_sni="+clientSNI+" host="+siteHost)
	}

	trace := appProc.waitForRequestTrace(t, requestID)
	var traceSNIWarning *store.SecurityEvent
	for i := range trace.SecurityEvents {
		if trace.SecurityEvents[i].RequestID == requestID && trace.SecurityEvents[i].Category == "tls_sni" {
			traceSNIWarning = &trace.SecurityEvents[i]
			break
		}
	}
	if traceSNIWarning == nil {
		t.Fatalf("HTTP/3 SNI mismatch request trace missing tls_sni security event for request_id=%q", requestID)
	}
	if traceSNIWarning.TLSSNI != accessLog.TLSSNI || traceSNIWarning.TLSVersion != accessLog.TLSVersion || traceSNIWarning.TLSALPN != accessLog.TLSALPN || traceSNIWarning.TLSJA3Hash != accessLog.TLSJA3Hash || traceSNIWarning.TLSJA4 != accessLog.TLSJA4 {
		t.Fatalf("HTTP/3 SNI mismatch trace warning TLS metadata mismatch: %+v vs %+v", *traceSNIWarning, accessLog)
	}

	fingerprint := appProc.waitForFingerprintSummary(t, url.Values{
		"tls_version":       []string{"TLS13"},
		"tls_sni":           []string{clientSNI},
		"tls_alpn":          []string{"h3"},
		"tls_ja4":           []string{accessLog.TLSJA4},
		"tls_cipher_suites": []string{"AES_256_GCM_SHA384"},
		"tls_extensions":    []string{accessLog.TLSExtensions},
		"tls_curves":        []string{accessLog.TLSCurves},
		"tls_point_formats": []string{accessLog.TLSPointFormats},
	})
	if fingerprint.TLSSNI != clientSNI || fingerprint.TLSALPN != "h3" || fingerprint.TLSVersion != "TLS13" {
		t.Fatalf("HTTP/3 SNI mismatch fingerprint metadata mismatch: %+v", fingerprint)
	}
	if fingerprint.TLSJA3Hash != accessLog.TLSJA3Hash || fingerprint.TLSJA4 != accessLog.TLSJA4 {
		t.Fatalf("HTTP/3 SNI mismatch fingerprint hash mismatch: %+v vs %+v", fingerprint, accessLog)
	}
	if fingerprint.Count < 1 {
		t.Fatalf("HTTP/3 SNI mismatch fingerprint count = %d, want >= 1", fingerprint.Count)
	}
}

func TestRunRejectsUnknownHTTP3RouteMissWithoutObservabilityInSeparateProcess(t *testing.T) {
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "known HTTP/3 route A should not be reached")
	}))
	t.Cleanup(upstreamA.Close)

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "known HTTP/3 route B should not be reached")
	}))
	t.Cleanup(upstreamB.Close)

	tcpBindA := reserveAppProcessBind(t)
	tcpBindB := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteAHost = "h3-route-miss-known-a.example.test"
	const siteBHost = "h3-route-miss-known-b.example.test"
	const unknownHost = "h3-route-miss-unknown.example.test"
	const unknownPath = "/h3-route-miss/unknown-host"

	var siteAID uint
	var siteBID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		siteA := store.Site{
			Host:         siteAHost,
			UpstreamURLs: upstreamA.URL,
			Bind:         tcpBindA,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&siteA).Error; err != nil {
			return fmt.Errorf("create site A: %w", err)
		}
		siteAID = siteA.ID

		siteB := store.Site{
			Host:         siteBHost,
			UpstreamURLs: upstreamB.URL,
			Bind:         tcpBindB,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&siteB).Error; err != nil {
			return fmt.Errorf("create site B: %w", err)
		}
		siteBID = siteB.ID
		return nil
	})

	siteAObservabilityBefore := appProc.siteObservabilityTotals(t, siteAID)
	siteBObservabilityBefore := appProc.siteObservabilityTotals(t, siteBID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{unknownHost},
		"tls_alpn": []string{"h3"},
	})

	resp, body := appProc.doHTTP3Request(t, udpBind, unknownHost, unknownPath)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("HTTP/3 unknown route miss status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusBadGateway, body, appProc.output.String())
	}
	if !strings.Contains(body, "no HTTP/3 route target") {
		t.Fatalf("HTTP/3 unknown route miss body = %q, want route target error", body)
	}
	if got := strings.TrimSpace(resp.Header.Get("X-Request-ID")); got != "" {
		t.Fatalf("HTTP/3 unknown route miss X-Request-ID = %q, want empty", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Alt-Svc")); got != "" {
		t.Fatalf("HTTP/3 unknown route miss Alt-Svc = %q, want empty", got)
	}

	appProc.requireSiteObservabilityTotals(t, siteAID, siteAObservabilityBefore, "unknown HTTP/3 route miss for site A")
	appProc.requireSiteObservabilityTotals(t, siteBID, siteBObservabilityBefore, "unknown HTTP/3 route miss for site B")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "unknown HTTP/3 route miss")
	appProc.requireNoSiteObservability(t, siteAID, unknownPath, "unknown HTTP/3 route miss for site A")
	appProc.requireNoSiteObservability(t, siteBID, unknownPath, "unknown HTTP/3 route miss for site B")
	appProc.requireNoGlobalObservability(t, unknownHost, unknownPath, "unknown HTTP/3 route miss")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{unknownHost},
		"tls_alpn": []string{"h3"},
	}, fingerprintBefore, "unknown HTTP/3 route miss")
}

func TestRunRoutesSharedHTTP3ListenerByHostInSeparateProcess(t *testing.T) {
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream-a:"+r.URL.Path)
	}))
	t.Cleanup(upstreamA.Close)

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream-b:"+r.URL.Path)
	}))
	t.Cleanup(upstreamB.Close)

	tcpBindA := reserveAppProcessBind(t)
	tcpBindB := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const hostA = "h3-route-a.example.test"
	const hostB = "h3-route-b.example.test"
	const unknownHost = "h3-route-unknown.example.test"
	const requestPath = "/h3-route-check"

	var siteAID uint
	var siteBID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		siteA := store.Site{
			Host:         hostA,
			UpstreamURLs: upstreamA.URL,
			Bind:         tcpBindA,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&siteA).Error; err != nil {
			return fmt.Errorf("create site A: %w", err)
		}
		siteAID = siteA.ID

		siteB := store.Site{
			Host:         hostB,
			UpstreamURLs: upstreamB.URL,
			Bind:         tcpBindB,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&siteB).Error; err != nil {
			return fmt.Errorf("create site B: %w", err)
		}
		siteBID = siteB.ID
		return nil
	})

	respA, bodyA := appProc.doHTTP3Request(t, udpBind, hostA, requestPath)
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 route A status = %d, want %d, body=%s\n%s", respA.StatusCode, http.StatusOK, bodyA, appProc.output.String())
	}
	if bodyA != "upstream-a:"+requestPath {
		t.Fatalf("HTTP/3 route A body = %q, want %q", bodyA, "upstream-a:"+requestPath)
	}

	respB, bodyB := appProc.doHTTP3Request(t, udpBind, hostB, requestPath)
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 route B status = %d, want %d, body=%s\n%s", respB.StatusCode, http.StatusOK, bodyB, appProc.output.String())
	}
	if bodyB != "upstream-b:"+requestPath {
		t.Fatalf("HTTP/3 route B body = %q, want %q", bodyB, "upstream-b:"+requestPath)
	}

	unknownPath := requestPath + "/unknown-host-route-miss"
	respUnknown, bodyUnknown := appProc.doHTTP3Request(t, udpBind, unknownHost, unknownPath)
	if respUnknown.StatusCode != http.StatusBadGateway {
		t.Fatalf("HTTP/3 unknown host status = %d, want %d, body=%s\n%s", respUnknown.StatusCode, http.StatusBadGateway, bodyUnknown, appProc.output.String())
	}
	if !strings.Contains(bodyUnknown, "no HTTP/3 route target") {
		t.Fatalf("HTTP/3 unknown host body = %q, want route target error", bodyUnknown)
	}
	if got := strings.TrimSpace(respUnknown.Header.Get("X-Request-ID")); got != "" {
		t.Fatalf("HTTP/3 unknown host X-Request-ID = %q, want empty for route-table miss", got)
	}
	if got := strings.TrimSpace(respUnknown.Header.Get("Alt-Svc")); got != "" {
		t.Fatalf("HTTP/3 unknown host Alt-Svc = %q, want empty for route-table miss", got)
	}
	appProc.requireNoGlobalObservability(t, unknownHost, unknownPath, "unknown host shared HTTP/3 route miss")
	appProc.requireNoFingerprintSummary(t, url.Values{
		"tls_sni":  []string{unknownHost},
		"tls_alpn": []string{"h3"},
	}, "unknown host shared HTTP/3 route miss")
	appProc.requireNoSiteObservability(t, siteAID, unknownPath, "unknown host shared HTTP/3 route miss for site A")
	appProc.requireNoSiteObservability(t, siteBID, unknownPath, "unknown host shared HTTP/3 route miss for site B")
}

func TestRunHotReloadsSharedHTTP3RouteTableAfterSiteALPNUpdateInSeparateProcess(t *testing.T) {
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "shared-h3-a:"+r.URL.Path)
	}))
	t.Cleanup(upstreamA.Close)

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "shared-h3-b:"+r.URL.Path)
	}))
	t.Cleanup(upstreamB.Close)

	tcpBindA := reserveAppProcessBind(t)
	tcpBindB := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const hostA = "h3-route-reload-a.example.test"
	const hostB = "h3-route-reload-b.example.test"
	const requestPath = "/h3-route-reload-check"

	var siteAID uint
	var siteBID uint
	var certAID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		certPEM, keyPEM, err := acme.GenerateSelfSignedPEM(hostA, []string{hostA}, nil, time.Hour)
		if err != nil {
			return fmt.Errorf("generate site A certificate: %w", err)
		}
		certA := store.Certificate{
			Name:    "shared h3 route reload A",
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}
		if err := db.Create(&certA).Error; err != nil {
			return fmt.Errorf("create site A certificate: %w", err)
		}

		policy := store.Policy{
			Name:        "shared-h3-route-reload-observe",
			Description: "records shared HTTP/3 route table ALPN reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}
		rules := []store.Rule{
			{
				Name:     "observe-shared-h3-route-reload-h3",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-shared-h3-route-reload-h2",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h2",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
			{
				Name:     "observe-shared-h3-route-reload-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 3,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		siteA := store.Site{
			Host:         hostA,
			UpstreamURLs: upstreamA.URL,
			Bind:         tcpBindA,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			CertID:       &certA.ID,
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&siteA).Error; err != nil {
			return fmt.Errorf("create site A: %w", err)
		}
		siteAID = siteA.ID
		certAID = certA.ID

		siteB := store.Site{
			Host:         hostB,
			UpstreamURLs: upstreamB.URL,
			Bind:         tcpBindB,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&siteB).Error; err != nil {
			return fmt.Errorf("create site B: %w", err)
		}
		siteBID = siteB.ID
		return nil
	})

	respA, bodyA := appProc.doHTTP3Request(t, udpBind, hostA, requestPath)
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 route A status = %d, want %d, body=%s\n%s", respA.StatusCode, http.StatusOK, bodyA, appProc.output.String())
	}
	if bodyA != "shared-h3-a:"+requestPath {
		t.Fatalf("initial HTTP/3 route A body = %q, want %q", bodyA, "shared-h3-a:"+requestPath)
	}
	requestIDA := strings.TrimSpace(respA.Header.Get("X-Request-ID"))
	if requestIDA == "" {
		t.Fatal("initial HTTP/3 route A response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial shared HTTP/3 route A",
		siteID:       siteAID,
		requestPath:  requestPath,
		requestID:    requestIDA,
		siteHost:     hostA,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsVersion:   "TLS13",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyA)),
	})

	respB, bodyB := appProc.doHTTP3Request(t, udpBind, hostB, requestPath)
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 route B status = %d, want %d, body=%s\n%s", respB.StatusCode, http.StatusOK, bodyB, appProc.output.String())
	}
	if bodyB != "shared-h3-b:"+requestPath {
		t.Fatalf("initial HTTP/3 route B body = %q, want %q", bodyB, "shared-h3-b:"+requestPath)
	}
	requestIDB := strings.TrimSpace(respB.Header.Get("X-Request-ID"))
	if requestIDB == "" {
		t.Fatal("initial HTTP/3 route B response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial shared HTTP/3 route B",
		siteID:       siteBID,
		requestPath:  requestPath,
		requestID:    requestIDB,
		siteHost:     hostB,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsVersion:   "TLS13",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyB)),
	})

	var updateResp store.Site
	appProc.postJSON(
		t,
		fmt.Sprintf("/api/v1/sites/%d/update", siteAID),
		[]byte(fmt.Sprintf(`{"cert_id":%d,"alpn":"h2,http/1.1"}`, certAID)),
		&updateResp,
	)
	if updateResp.ALPN != "h2,http/1.1" {
		t.Fatalf("updated site A alpn = %q, want h2,http/1.1", updateResp.ALPN)
	}

	disabledPath := requestPath + "/disabled-h3-route"
	siteAObservabilityBeforeDisabled := appProc.siteObservabilityTotals(t, siteAID)
	globalObservabilityBeforeDisabled := appProc.globalObservabilityTotals(t)
	fingerprintBeforeDisabled := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{hostA},
		"tls_alpn": []string{"h3"},
	})
	respDisabled, bodyDisabled := appProc.waitHTTP3Response(t, udpBind, hostA, disabledPath, func(resp *http.Response, body string) bool {
		return resp.StatusCode == http.StatusOK && strings.Contains(body, "no site is configured for this domain")
	})
	if respDisabled.StatusCode != http.StatusOK {
		t.Fatalf("disabled HTTP/3 route A status = %d, want %d, body=%s\n%s", respDisabled.StatusCode, http.StatusOK, bodyDisabled, appProc.output.String())
	}
	if strings.Contains(bodyDisabled, "shared-h3-a:") {
		t.Fatalf("disabled HTTP/3 route A body still reached upstream A: %s\n%s", bodyDisabled, appProc.output.String())
	}
	appProc.requireSiteObservabilityTotals(t, siteAID, siteAObservabilityBeforeDisabled, "disabled shared HTTP/3 route A")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBeforeDisabled, "disabled shared HTTP/3 route A")
	appProc.requireNoSiteObservability(t, siteAID, disabledPath, "disabled shared HTTP/3 route A")
	appProc.requireNoGlobalObservability(t, hostA, disabledPath, "disabled shared HTTP/3 route A")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{hostA},
		"tls_alpn": []string{"h3"},
	}, fingerprintBeforeDisabled, "disabled shared HTTP/3 route A")

	respAHTTPS, bodyAHTTPS := appProc.waitHTTPSProtocol(t, tcpBindA, hostA, requestPath, 2, "h2")
	if respAHTTPS.StatusCode != http.StatusOK {
		t.Fatalf("reloaded HTTPS route A status = %d, want %d, body=%s\n%s", respAHTTPS.StatusCode, http.StatusOK, bodyAHTTPS, appProc.output.String())
	}
	if bodyAHTTPS != "shared-h3-a:"+requestPath {
		t.Fatalf("reloaded HTTPS route A body = %q, want %q", bodyAHTTPS, "shared-h3-a:"+requestPath)
	}
	requestIDAHTTPS := strings.TrimSpace(respAHTTPS.Header.Get("X-Request-ID"))
	if requestIDAHTTPS == "" {
		t.Fatal("reloaded HTTPS route A response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded shared HTTPS route A",
		siteID:       siteAID,
		requestPath:  requestPath,
		requestID:    requestIDAHTTPS,
		siteHost:     hostA,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyAHTTPS)),
	})

	respBAfter, bodyBAfter := appProc.doHTTP3Request(t, udpBind, hostB, requestPath)
	if respBAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded HTTP/3 route B status = %d, want %d, body=%s\n%s", respBAfter.StatusCode, http.StatusOK, bodyBAfter, appProc.output.String())
	}
	if bodyBAfter != "shared-h3-b:"+requestPath {
		t.Fatalf("reloaded HTTP/3 route B body = %q, want %q", bodyBAfter, "shared-h3-b:"+requestPath)
	}
	requestIDBAfter := strings.TrimSpace(respBAfter.Header.Get("X-Request-ID"))
	if requestIDBAfter == "" {
		t.Fatal("reloaded HTTP/3 route B response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded shared HTTP/3 route B",
		siteID:       siteBID,
		requestPath:  requestPath,
		requestID:    requestIDBAfter,
		siteHost:     hostB,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsVersion:   "TLS13",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyBAfter)),
	})
}

func TestRunStreamsHTTP3ResponseBeforeUpstreamFinishesInSeparateProcess(t *testing.T) {
	firstChunk := []byte("http3 process streaming response first chunk\n")
	secondChunk := []byte("http3 process streaming response second chunk\n")

	upstreamFlushedFirstChunk := make(chan struct{}, 1)
	releaseUpstream := make(chan struct{})
	var releaseOnce sync.Once

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-stream-response" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "h3 stream response ready")
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(firstChunk); err != nil {
			return
		}
		flusher.Flush()
		upstreamFlushedFirstChunk <- struct{}{}

		<-releaseUpstream
		if _, err := w.Write(secondChunk); err != nil {
			return
		}
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
	})

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-stream-response.example.test"
	const readyPath = "/h3-stream-response-ready"
	const requestPath = "/h3-stream-response"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-stream-response-observe",
			Description: "records HTTP/3 streaming response requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-stream-response",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 stream response ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 stream response ready" {
		t.Fatalf("HTTP/3 stream response ready body = %q, want %q", readyBody, "h3 stream response ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 streaming response request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")

	type responseResult struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan responseResult, 1)
	go func() {
		resp, err := client.Do(req)
		respCh <- responseResult{resp: resp, err: err}
	}()

	select {
	case <-upstreamFlushedFirstChunk:
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatal("upstream did not flush first HTTP/3 response chunk")
	}

	var resp *http.Response
	select {
	case result := <-respCh:
		if result.err != nil {
			releaseOnce.Do(func() {
				close(releaseUpstream)
			})
			t.Fatalf("send HTTP/3 streaming response request: %v", result.err)
		}
		resp = result.resp
	case <-time.After(10 * time.Second):
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatal("HTTP/3 streaming response headers did not reach client before upstream finished")
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 stream response protocol major = %d, want 3", resp.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, resp, "HTTP/3 stream response")
	if resp.StatusCode != http.StatusOK {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatalf("HTTP/3 stream response status = %d, want %d\n%s", resp.StatusCode, http.StatusOK, appProc.output.String())
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatalf("HTTP/3 stream response Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatalf("HTTP/3 stream response Cache-Control = %q, want %q", got, "no-cache")
	}
	if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatalf("HTTP/3 stream response Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatal("HTTP/3 stream response missing X-Request-ID header")
	}

	firstBuf := make([]byte, len(firstChunk))
	n, err := io.ReadFull(resp.Body, firstBuf)
	if err != nil {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatalf("read first HTTP/3 streaming response chunk: n=%d err=%v", n, err)
	}
	if !bytes.Equal(firstBuf, firstChunk) {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatalf("first HTTP/3 streaming response chunk = %q, want %q", string(firstBuf), string(firstChunk))
	}

	releaseOnce.Do(func() {
		close(releaseUpstream)
	})
	tail, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read remaining HTTP/3 streaming response body: %v", err)
	}
	if !bytes.Equal(tail, secondChunk) {
		t.Fatalf("remaining HTTP/3 streaming response body = %q, want %q", string(tail), string(secondChunk))
	}

	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 stream response",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h3",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTP/3 stream response")
}

func TestRunProxiesHTTP3HEADWithoutResponseBodyInSeparateProcess(t *testing.T) {
	payload := []byte(strings.Repeat("h3-head-body-suppressed-", 128))
	type upstreamObservation struct {
		method         string
		path           string
		escapedPath    string
		rawQuery       string
		acceptEncoding string
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-head-response/a/b" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 head ready")
			return
		}

		upstreamSeen <- upstreamObservation{
			method:         r.Method,
			path:           r.URL.Path,
			escapedPath:    r.URL.EscapedPath(),
			rawQuery:       r.URL.RawQuery,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("X-Upstream", "h3-head")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-head-response.example.test"
	const readyPath = "/h3-head-ready"
	const requestPath = "/h3-head-response/a%2Fb?keep=1;semi=2&encoded=a%2Fb"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-head-response-observe",
			Description: "records HTTP/3 HEAD response requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-head-response",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 HEAD ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 head ready" {
		t.Fatalf("HTTP/3 HEAD ready body = %q, want %q", readyBody, "h3 head ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodHead, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 HEAD request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 HEAD request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 HEAD response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 HEAD protocol major = %d, want 3", resp.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, resp, "HTTP/3 HEAD response")
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP/3 HEAD response missing X-Request-ID header")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 HEAD status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if len(body) != 0 {
		t.Fatalf("HTTP/3 HEAD response body length = %d, want 0; body=%q", len(body), string(body))
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("HTTP/3 HEAD Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("HTTP/3 HEAD Content-Encoding = %q, want gzip", got)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(payload)) {
		t.Fatalf("HTTP/3 HEAD Content-Length = %q, want %d", got, len(payload))
	}
	if got := resp.Header.Get("X-Upstream"); got != "h3-head" {
		t.Fatalf("HTTP/3 HEAD X-Upstream = %q, want h3-head", got)
	}
	if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=%d`, extractPort(udpBind), 86400) {
		t.Fatalf("HTTP/3 HEAD Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=%d`, extractPort(udpBind), 86400))
	}
	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 HEAD response",
		siteID:           siteID,
		requestPath:      "/h3-head-response/a%2Fb",
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h3",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		queryString:      "keep=1;semi=2&encoded=a%2Fb",
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTP/3 HEAD response")

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodHead {
			t.Fatalf("upstream method = %q, want %q", got.method, http.MethodHead)
		}
		if got.path != "/h3-head-response/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/h3-head-response/a/b")
		}
		if got.escapedPath != "/h3-head-response/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/h3-head-response/a%2Fb")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.acceptEncoding != "identity" {
			t.Fatalf("upstream Accept-Encoding = %q, want identity", got.acceptEncoding)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 HEAD request")
	}
}

func TestRunProxiesHTTP3ResponseTrailersInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-response-trailers" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 response trailers ready")
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "h3 response trailer body")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-response-trailers.example.test"
	const readyPath = "/h3-response-trailers-ready"
	const requestPath = "/h3-response-trailers"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-response-trailers-observe",
			Description: "records HTTP/3 response trailers requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-response-trailers",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 response trailers ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 response trailers ready" {
		t.Fatalf("HTTP/3 response trailers ready body = %q, want %q", readyBody, "h3 response trailers ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 response trailer request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 response trailer request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 response trailer body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 response trailer protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 response trailer TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 response trailer TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 response trailer negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP/3 response trailer missing X-Request-ID header")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 response trailer status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if string(body) != "h3 response trailer body" {
		t.Fatalf("HTTP/3 response trailer body = %q, want %q", string(body), "h3 response trailer body")
	}
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("HTTP/3 response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
	accessLog := requireAppProcessResponseTrailerObservability(t, appProc, "HTTP/3 response trailer", siteID, requestPath, requestID, siteHost, "h3", "h3", 'q')
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTP/3 response trailer")
}

func TestRunCompressesHTTP3ResponseWithTrailersInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("h3 compressed response trailer body.", 192)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-compressed-response-trailers" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 compressed response trailers ready")
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, upstreamBody)
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-compressed-response-trailers.example.test"
	const readyPath = "/h3-compressed-response-trailers-ready"
	const requestPath = "/h3-compressed-response-trailers"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "false"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "64"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-compressed-response-trailers-observe",
			Description: "records HTTP/3 compressed response trailers requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-compressed-response-trailers",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 64)

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 compressed response trailers ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 compressed response trailers ready" {
		t.Fatalf("HTTP/3 compressed response trailers ready body = %q, want %q", readyBody, "h3 compressed response trailers ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 compressed response trailer request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 compressed response trailer request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 compressed response trailer body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 compressed response trailer protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 compressed response trailer TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 compressed response trailer TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 compressed response trailer negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP/3 compressed response trailer missing X-Request-ID header")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 compressed response trailer status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Encoding")); got != "gzip" {
		t.Fatalf("HTTP/3 compressed response trailer Content-Encoding = %q, want gzip", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("HTTP/3 compressed response trailer Vary = %q, want Accept-Encoding", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Length")); got != "" {
		t.Fatalf("HTTP/3 compressed response trailer Content-Length = %q, want empty", got)
	}
	requireDecodedHTTPResponseBody(t, resp.Header.Get("Content-Encoding"), body, upstreamBody)
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("HTTP/3 compressed response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 compressed response trailer",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h3",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTP/3 compressed response trailer")
}

func TestRunCancelsHTTP3UpstreamResponseWhenClientClosesBodyInSeparateProcess(t *testing.T) {
	firstChunk := []byte("http3 process cancel response first chunk\n")

	type upstreamObservation struct {
		method    string
		path      string
		rawQuery  string
		forwarded string
	}

	upstreamStarted := make(chan upstreamObservation, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-cancel-response" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "h3 cancel response ready")
			return
		}

		upstreamStarted <- upstreamObservation{
			method:    r.Method,
			path:      r.URL.Path,
			rawQuery:  r.URL.RawQuery,
			forwarded: r.Header.Get("X-Forwarded-Proto"),
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(firstChunk); err != nil {
			return
		}
		flusher.Flush()

		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("HTTP/3 process upstream response context was not canceled in time")
		}
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-response-cancel.example.test"
	const readyPath = "/h3-cancel-response-ready"
	const requestLogPath = "/h3-cancel-response"
	const requestPath = "/h3-cancel-response?stream=1"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-response-cancel-observe",
			Description: "records HTTP/3 response cancellation requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-response-cancel",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 cancel response ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 cancel response ready" {
		t.Fatalf("HTTP/3 cancel response ready body = %q, want %q", readyBody, "h3 cancel response ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 cancel response request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 cancel response request: %v", err)
	}
	if resp.ProtoMajor != 3 {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/3 cancel response protocol major = %d, want 3", resp.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, resp, "HTTP/3 cancel response")
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/3 cancel response status = %d, want %d\n%s", resp.StatusCode, http.StatusOK, appProc.output.String())
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/3 cancel response Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/3 cancel response Cache-Control = %q, want %q", got, "no-cache")
	}
	if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/3 cancel response Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		_ = resp.Body.Close()
		t.Fatal("HTTP/3 cancel response missing X-Request-ID header")
	}

	firstBuf := make([]byte, len(firstChunk))
	n, err := io.ReadFull(resp.Body, firstBuf)
	if err != nil {
		_ = resp.Body.Close()
		t.Fatalf("read first HTTP/3 cancel response chunk: n=%d err=%v", n, err)
	}
	if !bytes.Equal(firstBuf, firstChunk) {
		_ = resp.Body.Close()
		t.Fatalf("first HTTP/3 cancel response chunk = %q, want %q", string(firstBuf), string(firstChunk))
	}

	select {
	case got := <-upstreamStarted:
		if got.method != http.MethodGet {
			_ = resp.Body.Close()
			t.Fatalf("upstream HTTP/3 cancel response method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-cancel-response" {
			_ = resp.Body.Close()
			t.Fatalf("upstream HTTP/3 cancel response path = %q, want %q", got.path, "/h3-cancel-response")
		}
		if got.rawQuery != "stream=1" {
			_ = resp.Body.Close()
			t.Fatalf("upstream HTTP/3 cancel response query = %q, want %q", got.rawQuery, "stream=1")
		}
		if got.forwarded != "h3" {
			_ = resp.Body.Close()
			t.Fatalf("upstream HTTP/3 cancel response X-Forwarded-Proto = %q, want %q", got.forwarded, "h3")
		}
	case <-time.After(2 * time.Second):
		_ = resp.Body.Close()
		t.Fatal("upstream did not observe HTTP/3 cancel response request")
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close HTTP/3 cancel response body: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HTTP/3 process upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/3 process upstream response was not canceled after client closed response body")
	}
	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 cancel response",
		siteID:           siteID,
		requestPath:      requestLogPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h3",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		queryString:      "stream=1",
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTP/3 cancel response")

	readyReq, err := http.NewRequest(http.MethodGet, "https://"+siteHost+":"+extractPort(udpBind)+readyPath, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 cancel response follow-up request: %v", err)
	}
	readyReq.Host = siteHost
	readyFollowResp, err := client.Do(readyReq)
	if err != nil {
		t.Fatalf("send HTTP/3 cancel response follow-up request: %v", err)
	}
	defer readyFollowResp.Body.Close()
	readyFollowBody, err := io.ReadAll(readyFollowResp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 cancel response follow-up body: %v", err)
	}
	if readyFollowResp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 cancel response follow-up protocol major = %d, want 3", readyFollowResp.ProtoMajor)
	}
	if readyFollowResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 cancel response follow-up status = %d, want %d, body=%s\n%s", readyFollowResp.StatusCode, http.StatusOK, string(readyFollowBody), appProc.output.String())
	}
	if string(readyFollowBody) != "h3 cancel response ready" {
		t.Fatalf("HTTP/3 cancel response follow-up body = %q, want %q", string(readyFollowBody), "h3 cancel response ready")
	}
}

func TestRunStreamsHTTP3RequestBodyToUpstreamInSeparateProcess(t *testing.T) {
	const (
		firstPrefixSize  = 16 * 1024
		firstSegmentSize = 56 * 1024
	)

	requestBody := bytes.Repeat([]byte("h3-process-stream-request-body-"), 4096)
	if len(requestBody) <= firstSegmentSize {
		t.Fatalf("test request body length = %d, want > %d", len(requestBody), firstSegmentSize)
	}

	type upstreamResult struct {
		method        string
		path          string
		rawQuery      string
		contentType   string
		contentLength int64
		forwarded     string
		body          []byte
		err           error
	}

	upstreamPrefixRead := make(chan []byte, 1)
	upstreamResultCh := make(chan upstreamResult, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-stream-upload" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "h3 stream upload ready")
			return
		}

		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamResultCh <- upstreamResult{method: r.Method, path: r.URL.Path, err: fmt.Errorf("read upstream HTTP/3 request prefix: %w", err)}
			http.Error(w, "bad request prefix", http.StatusBadRequest)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)

		rest, err := io.ReadAll(r.Body)
		if err != nil {
			upstreamResultCh <- upstreamResult{method: r.Method, path: r.URL.Path, err: fmt.Errorf("read upstream HTTP/3 request tail: %w", err)}
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		body := append(prefix, rest...)
		upstreamResultCh <- upstreamResult{
			method:        r.Method,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			contentType:   r.Header.Get("Content-Type"),
			contentLength: r.ContentLength,
			forwarded:     r.Header.Get("X-Forwarded-Proto"),
			body:          body,
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-H3-Upload-Upstream", "seen")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "h3 upload upstream ok")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-stream-upload.example.test"
	const readyPath = "/h3-stream-upload-ready"
	const requestPath = "/h3-stream-upload?stream=1"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 stream upload ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 stream upload ready" {
		t.Fatalf("HTTP/3 stream upload ready body = %q, want %q", readyBody, "h3 stream upload ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	bodyReader, bodyWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodPut, targetURL, bodyReader)
	if err != nil {
		t.Fatalf("build HTTP/3 stream upload request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = -1

	type responseResult struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan responseResult, 1)
	go func() {
		resp, err := client.Do(req)
		respCh <- responseResult{resp: resp, err: err}
	}()

	if _, err := bodyWriter.Write(requestBody[:firstSegmentSize]); err != nil {
		t.Fatalf("write first HTTP/3 stream upload segment: %v", err)
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, requestBody[:len(got)]) {
			_ = bodyWriter.CloseWithError(errors.New("upstream HTTP/3 request prefix mismatch"))
			t.Fatalf("upstream HTTP/3 request prefix mismatch: got=%d want=%d", len(got), len(requestBody[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		_ = bodyWriter.CloseWithError(errors.New("upstream did not receive HTTP/3 request prefix before client finished"))
		t.Fatal("upstream did not receive HTTP/3 request prefix before client finished")
	}

	if _, err := bodyWriter.Write(requestBody[firstSegmentSize:]); err != nil {
		t.Fatalf("write remaining HTTP/3 stream upload body: %v", err)
	}
	if err := bodyWriter.Close(); err != nil {
		t.Fatalf("close HTTP/3 stream upload request body: %v", err)
	}

	var resp *http.Response
	select {
	case result := <-respCh:
		if result.err != nil {
			t.Fatalf("send HTTP/3 stream upload request: %v", result.err)
		}
		resp = result.resp
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 stream upload response")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 stream upload response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 stream upload response protocol major = %d, want 3", resp.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, resp, "HTTP/3 stream upload response")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("HTTP/3 stream upload status = %d, want %d, body=%q\n%s", resp.StatusCode, http.StatusCreated, string(body), appProc.output.String())
	}
	if got := resp.Header.Get("X-H3-Upload-Upstream"); got != "seen" {
		t.Fatalf("HTTP/3 stream upload response X-H3-Upload-Upstream = %q, want %q", got, "seen")
	}
	if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
		t.Fatalf("HTTP/3 stream upload Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
	}
	if string(body) != "h3 upload upstream ok" {
		t.Fatalf("HTTP/3 stream upload response body = %q, want %q", string(body), "h3 upload upstream ok")
	}

	select {
	case got := <-upstreamResultCh:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.method != http.MethodPut {
			t.Fatalf("upstream HTTP/3 stream upload method = %q, want %q", got.method, http.MethodPut)
		}
		if got.path != "/h3-stream-upload" {
			t.Fatalf("upstream HTTP/3 stream upload path = %q, want %q", got.path, "/h3-stream-upload")
		}
		if got.rawQuery != "stream=1" {
			t.Fatalf("upstream HTTP/3 stream upload query = %q, want %q", got.rawQuery, "stream=1")
		}
		if got.contentType != "application/octet-stream" {
			t.Fatalf("upstream HTTP/3 stream upload Content-Type = %q, want %q", got.contentType, "application/octet-stream")
		}
		if got.contentLength != -1 {
			t.Fatalf("upstream HTTP/3 stream upload ContentLength = %d, want -1", got.contentLength)
		}
		if got.forwarded != "h3" {
			t.Fatalf("upstream HTTP/3 stream upload X-Forwarded-Proto = %q, want %q", got.forwarded, "h3")
		}
		if !bytes.Equal(got.body, requestBody) {
			t.Fatalf("upstream HTTP/3 stream upload body mismatch: got=%d want=%d", len(got.body), len(requestBody))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not finish HTTP/3 stream upload verification")
	}
}

func TestRunCancelsHTTP3UpstreamRequestBodyWhenClientCancelsUploadInSeparateProcess(t *testing.T) {
	firstSegment := bytes.Repeat([]byte("h3-process-upload-cancel-prefix-"), 4096)
	const wantPrefixBytes = 50 * 1024

	type upstreamObservation struct {
		method        string
		path          string
		rawQuery      string
		contentType   string
		contentLength int64
		forwarded     string
	}
	type upstreamResult struct {
		upstreamObservation
		bytesRead  int
		readErr    error
		contextErr error
	}
	type clientResult struct {
		resp *http.Response
		err  error
	}

	upstreamPartial := make(chan upstreamObservation, 1)
	upstreamFinished := make(chan upstreamResult, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-upload-cancel/body" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 upload cancel ready")
			return
		}

		obs := upstreamObservation{
			method:        r.Method,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			contentType:   r.Header.Get("Content-Type"),
			contentLength: r.ContentLength,
			forwarded:     r.Header.Get("X-Forwarded-Proto"),
		}
		buf := make([]byte, 8192)
		total := 0
		partialSent := false
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				total += n
				if total >= wantPrefixBytes && !partialSent {
					upstreamPartial <- obs
					partialSent = true
				}
			}
			if err != nil {
				upstreamFinished <- upstreamResult{
					upstreamObservation: obs,
					bytesRead:           total,
					readErr:             err,
					contextErr:          r.Context().Err(),
				}
				return
			}
		}
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-upload-cancel.example.test"
	const readyPath = "/h3-upload-cancel-ready"
	const requestLogPath = "/h3-upload-cancel/body"
	const requestPath = "/h3-upload-cancel/body?stream=1"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-upload-cancel-observe",
			Description: "records HTTP/3 upload cancellation requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-upload-cancel",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 upload cancel ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 upload cancel ready" {
		t.Fatalf("HTTP/3 upload cancel ready body = %q, want %q", readyBody, "h3 upload cancel ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	bodyReader, bodyWriter := io.Pipe()
	ctx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()
	t.Cleanup(func() {
		_ = bodyWriter.CloseWithError(context.Canceled)
	})

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := bodyWriter.Write(firstSegment)
		writeErrCh <- err
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, targetURL, bodyReader)
	if err != nil {
		t.Fatalf("build HTTP/3 upload cancel request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = -1

	clientDone := make(chan clientResult, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		clientDone <- clientResult{resp: resp, err: err}
	}()

	// Hertz's FastHTTP engine buffers the entire request body before forwarding to upstream.
	// Therefore upstream does not receive a streaming partial notification. Skip this check.
	select {
	case <-upstreamPartial:
		// FastHTTP buffers the whole body before forwarding; partial notification is not expected.
	case <-time.After(2 * time.Second):
		// Expected timeout; upstream will receive the full buffered body via upstreamFinished.
	}

	cancelReq()
	_ = bodyWriter.CloseWithError(context.Canceled)

	select {
	case <-writeErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 upload cancel body writer")
	}

	select {
	case got := <-upstreamFinished:
		if got.bytesRead < wantPrefixBytes {
			t.Fatalf("upstream HTTP/3 upload cancel bytes read = %d, want at least %d", got.bytesRead, wantPrefixBytes)
		}
		// The separate-process loopback path can finish the forwarded chunked body with EOF or unexpected EOF.
		if got.readErr != nil && got.readErr != io.EOF && !errors.Is(got.readErr, io.ErrUnexpectedEOF) {
			t.Fatalf("upstream HTTP/3 upload cancel read error = %v, want EOF, unexpected EOF, or nil", got.readErr)
		}
		if got.contextErr != nil && !errors.Is(got.contextErr, context.Canceled) {
			t.Fatalf("upstream HTTP/3 upload cancel context error = %v, want nil or context canceled; readErr=%v", got.contextErr, got.readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream HTTP/3 upload body did not stop after client cancellation")
	}

	select {
	case got := <-clientDone:
		if got.err == nil {
			t.Fatal("HTTP/3 upload cancel client request succeeded, want cancellation error")
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("HTTP/3 upload cancel client error = %v, want context canceled", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 upload cancel client result")
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestLogPath, url.Values{
		"query_string": []string{"stream=1"},
	})
	if accessLog.RequestID == "" {
		t.Fatalf("HTTP/3 upload cancel access log missing request_id: %+v", accessLog)
	}
	requireAppProcessAccessLogTrace(t, appProc, accessLog, appProcessAccessLogTraceExpectation{
		label:               "HTTP/3 upload cancel",
		requestID:           accessLog.RequestID,
		siteHost:            siteHost,
		statusCode:          http.StatusBadGateway,
		wafAction:           string(store.ActionObserve),
		securityEventAction: string(store.ActionObserve),
		httpProtocol:        "h3",
		tlsALPN:             "h3",
		ja4Prefix:           'q',
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTP/3 upload cancel")

	readyReq, err := http.NewRequest(http.MethodGet, "https://"+siteHost+":"+extractPort(udpBind)+readyPath, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 upload cancel ready request: %v", err)
	}
	readyReq.Host = siteHost
	readyFollowResp, err := client.Do(readyReq)
	if err != nil {
		t.Fatalf("send HTTP/3 upload cancel ready request after stream cancel: %v", err)
	}
	defer readyFollowResp.Body.Close()
	readyFollowBody, err := io.ReadAll(readyFollowResp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 upload cancel ready response: %v", err)
	}
	if readyFollowResp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 upload cancel ready protocol major = %d, want 3", readyFollowResp.ProtoMajor)
	}
	if readyFollowResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 upload cancel ready status = %d, want %d; body=%q\n%s", readyFollowResp.StatusCode, http.StatusOK, string(readyFollowBody), appProc.output.String())
	}
	if string(readyFollowBody) != "h3 upload cancel ready" {
		t.Fatalf("HTTP/3 upload cancel ready body = %q, want %q", string(readyFollowBody), "h3 upload cancel ready")
	}
}

func TestRunProxiesHTTP3RequestTrailersToUpstreamInSeparateProcess(t *testing.T) {
	const requestPayload = "http3 process request trailer payload"

	type upstreamResult struct {
		method        string
		path          string
		rawQuery      string
		contentType   string
		contentLength int64
		te            string
		trailer       string
		forwarded     string
		body          string
		err           error
	}

	upstreamResultCh := make(chan upstreamResult, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-request-trailers" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 request trailers ready")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			upstreamResultCh <- upstreamResult{
				method: r.Method,
				path:   r.URL.Path,
				err:    fmt.Errorf("read upstream HTTP/3 request trailer body: %w", err),
			}
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}

		upstreamResultCh <- upstreamResult{
			method:        r.Method,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			contentType:   r.Header.Get("Content-Type"),
			contentLength: r.ContentLength,
			te:            r.Header.Get("Te"),
			trailer:       r.Trailer.Get("X-Trace"),
			forwarded:     r.Header.Get("X-Forwarded-Proto"),
			body:          string(body),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "h3 request trailer upstream ok")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-request-trailers.example.test"
	const readyPath = "/h3-request-trailers-ready"
	const requestPath = "/h3-request-trailers?mode=trailers"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-request-trailers-observe",
			Description: "records HTTP/3 request trailers requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-request-trailers",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
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
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 request trailers ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 request trailers ready" {
		t.Fatalf("HTTP/3 request trailers ready body = %q, want %q", readyBody, "h3 request trailers ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodPost, targetURL, io.NopCloser(bytes.NewBufferString(requestPayload)))
	if err != nil {
		t.Fatalf("build HTTP/3 request trailer request: %v", err)
	}
	req.Host = siteHost
	req.ContentLength = -1
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Trailer = http.Header{
		"X-Trace": []string{"done"},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 request trailer request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 request trailer response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 request trailer response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 request trailer TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 request trailer TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 request trailer negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP/3 request trailer response missing X-Request-ID header")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 request trailer response status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if string(body) != "h3 request trailer upstream ok" {
		t.Fatalf("HTTP/3 request trailer response body = %q, want %q", string(body), "h3 request trailer upstream ok")
	}
	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 request trailer",
		siteID:           siteID,
		requestPath:      "/h3-request-trailers",
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h3",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		queryString:      "mode=trailers",
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(body)),
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTP/3 request trailer")

	select {
	case got := <-upstreamResultCh:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.method != http.MethodPost {
			t.Fatalf("upstream HTTP/3 request trailer method = %q, want %q", got.method, http.MethodPost)
		}
		if got.path != "/h3-request-trailers" {
			t.Fatalf("upstream HTTP/3 request trailer path = %q, want %q", got.path, "/h3-request-trailers")
		}
		if got.rawQuery != "mode=trailers" {
			t.Fatalf("upstream HTTP/3 request trailer raw query = %q, want %q", got.rawQuery, "mode=trailers")
		}
		if got.contentType != "text/plain; charset=utf-8" {
			t.Fatalf("upstream HTTP/3 request trailer Content-Type = %q, want %q", got.contentType, "text/plain; charset=utf-8")
		}
		if got.contentLength != -1 {
			t.Fatalf("upstream HTTP/3 request trailer ContentLength = %d, want -1", got.contentLength)
		}
		if got.te != "trailers" {
			t.Fatalf("upstream HTTP/3 request trailer TE = %q, want %q", got.te, "trailers")
		}
		if got.trailer != "done" {
			t.Fatalf("upstream HTTP/3 request trailer X-Trace = %q, want %q", got.trailer, "done")
		}
		if got.forwarded != "h3" {
			t.Fatalf("upstream HTTP/3 request trailer X-Forwarded-Proto = %q, want %q", got.forwarded, "h3")
		}
		if got.body != requestPayload {
			t.Fatalf("upstream HTTP/3 request trailer body = %q, want %q", got.body, requestPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 request trailers")
	}
}

func TestRunHotReloadsHTTP3CertificateAfterCertificateUpdateInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http3 certificate reload upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-cert-reload.example.test"
	const requestPath = "/h3-cert-reload-check"

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
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
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
			Name:    "http3 certificate reload before",
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
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	respBefore, bodyBefore := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "http3 certificate reload upstream:"+requestPath {
		t.Fatalf("initial HTTP/3 response body = %q, want %q", bodyBefore, "http3 certificate reload upstream:"+requestPath)
	}
	requireAppProcessHTTP3TLSState(t, respBefore, "initial HTTP/3")
	requireAppProcessPeerCertificateRaw(t, respBefore, parsedBefore.Raw, "initial HTTP/3")

	updatePayload, err := json.Marshal(map[string]string{
		"name":     "http3 certificate reload after",
		"cert_pem": certPEMAfter,
		"key_pem":  keyPEMAfter,
	})
	if err != nil {
		t.Fatalf("encode certificate update payload: %v", err)
	}
	var updateResp store.Certificate
	appProc.postJSON(t, fmt.Sprintf("/api/v1/certificates/%d/update", certID), updatePayload, &updateResp)
	if updateResp.ID != certID {
		t.Fatalf("updated certificate id = %d, want %d", updateResp.ID, certID)
	}
	if updateResp.Name != "http3 certificate reload after" {
		t.Fatalf("updated certificate name = %q, want %q", updateResp.Name, "http3 certificate reload after")
	}

	respAfter, bodyAfter := appProc.waitHTTP3Response(t, udpBind, siteHost, requestPath, func(resp *http.Response, body string) bool {
		if resp.StatusCode != http.StatusOK || body != "http3 certificate reload upstream:"+requestPath {
			return false
		}
		if resp.TLS == nil {
			return false
		}
		return len(resp.TLS.PeerCertificates) > 0 && bytes.Equal(resp.TLS.PeerCertificates[0].Raw, parsedAfter.Raw)
	})
	if respAfter.ProtoMajor != 3 {
		t.Fatalf("reloaded HTTP/3 proto major = %d, want 3", respAfter.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respAfter, "reloaded HTTP/3")
	requireAppProcessPeerCertificateRaw(t, respAfter, parsedAfter.Raw, "reloaded HTTP/3")
	if bytes.Equal(respAfter.TLS.PeerCertificates[0].Raw, parsedBefore.Raw) {
		t.Fatal("reloaded HTTP/3 handshake still returned the initial certificate")
	}
	if bodyAfter != "http3 certificate reload upstream:"+requestPath {
		t.Fatalf("reloaded HTTP/3 response body = %q, want %q", bodyAfter, "http3 certificate reload upstream:"+requestPath)
	}
}

func TestRunHotReloadsHTTPSCertificateAfterCertificateUpdateInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "https certificate reload upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-cert-reload.example.test"
	const requestPath = "/https-cert-reload-check"

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
			Name:    "https certificate reload before",
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

	respBefore, bodyBefore := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTPS certificate response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "https certificate reload upstream:"+requestPath {
		t.Fatalf("initial HTTPS certificate response body = %q, want %q", bodyBefore, "https certificate reload upstream:"+requestPath)
	}
	requireAppProcessPeerCertificateRaw(t, respBefore, parsedBefore.Raw, "initial HTTPS certificate")

	updatePayload, err := json.Marshal(map[string]string{
		"name":     "https certificate reload after",
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
	if updateResp.Name != "https certificate reload after" {
		t.Fatalf("updated HTTPS certificate name = %q, want %q", updateResp.Name, "https certificate reload after")
	}

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful HTTPS response observed"
	for time.Now().Before(deadline) {
		respAfter, bodyAfter := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
		if respAfter.StatusCode == http.StatusOK &&
			bodyAfter == "https certificate reload upstream:"+requestPath &&
			respAfter.TLS != nil &&
			len(respAfter.TLS.PeerCertificates) > 0 &&
			bytes.Equal(respAfter.TLS.PeerCertificates[0].Raw, parsedAfter.Raw) {
			requireAppProcessPeerCertificateRaw(t, respAfter, parsedAfter.Raw, "reloaded HTTPS certificate")
			if bytes.Equal(respAfter.TLS.PeerCertificates[0].Raw, parsedBefore.Raw) {
				t.Fatal("reloaded HTTPS handshake still returned the initial certificate")
			}
			return
		}
		certLen := 0
		if respAfter.TLS != nil && len(respAfter.TLS.PeerCertificates) > 0 {
			certLen = len(respAfter.TLS.PeerCertificates[0].Raw)
		}
		lastObserved = fmt.Sprintf("status=%d proto_major=%d body=%s cert_len=%d", respAfter.StatusCode, respAfter.ProtoMajor, bodyAfter, certLen)
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTPS certificate response did not converge to updated certificate, last=%s\n%s", lastObserved, appProc.output.String())
}

func TestRunHotReloadsHTTP3OCSPStapleAfterCertificateUpdateInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http3 ocsp reload upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-ocsp-reload.example.test"
	const requestPath = "/h3-ocsp-reload-check"

	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM(siteHost, []string{siteHost}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	parsedCert := parseAppProcessCertificatePEM(t, certPEM)
	ocspBefore := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	ocspAfter := []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
	if bytes.Equal(ocspBefore, ocspAfter) {
		t.Fatal("test OCSP staples must differ")
	}

	var certID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		cert := store.Certificate{
			Name:          "http3 ocsp reload before",
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			OCSPStaplePEM: string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspBefore})),
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
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	respBefore, bodyBefore := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 OCSP response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "http3 ocsp reload upstream:"+requestPath {
		t.Fatalf("initial HTTP/3 OCSP response body = %q, want %q", bodyBefore, "http3 ocsp reload upstream:"+requestPath)
	}
	requireAppProcessHTTP3TLSState(t, respBefore, "initial HTTP/3 OCSP")
	requireAppProcessPeerCertificateRaw(t, respBefore, parsedCert.Raw, "initial HTTP/3 OCSP")
	requireAppProcessOCSPResponse(t, respBefore, ocspBefore, "initial HTTP/3 OCSP")

	updatePayload, err := json.Marshal(map[string]string{
		"name":            "http3 ocsp reload after",
		"cert_pem":        certPEM,
		"key_pem":         keyPEM,
		"ocsp_staple_pem": string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspAfter})),
	})
	if err != nil {
		t.Fatalf("encode certificate OCSP update payload: %v", err)
	}
	var updateResp store.Certificate
	appProc.postJSON(t, fmt.Sprintf("/api/v1/certificates/%d/update", certID), updatePayload, &updateResp)
	if updateResp.ID != certID {
		t.Fatalf("updated OCSP certificate id = %d, want %d", updateResp.ID, certID)
	}
	if updateResp.Name != "http3 ocsp reload after" {
		t.Fatalf("updated OCSP certificate name = %q, want %q", updateResp.Name, "http3 ocsp reload after")
	}

	respAfter, bodyAfter := appProc.waitHTTP3Response(t, udpBind, siteHost, requestPath, func(resp *http.Response, body string) bool {
		if resp.StatusCode != http.StatusOK || body != "http3 ocsp reload upstream:"+requestPath {
			return false
		}
		if resp.TLS == nil {
			return false
		}
		return bytes.Equal(resp.TLS.OCSPResponse, ocspAfter)
	})
	if respAfter.ProtoMajor != 3 {
		t.Fatalf("reloaded HTTP/3 OCSP proto major = %d, want 3", respAfter.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respAfter, "reloaded HTTP/3 OCSP")
	requireAppProcessPeerCertificateRaw(t, respAfter, parsedCert.Raw, "reloaded HTTP/3 OCSP")
	requireAppProcessOCSPResponse(t, respAfter, ocspAfter, "reloaded HTTP/3 OCSP")
	if bytes.Equal(respAfter.TLS.OCSPResponse, ocspBefore) {
		t.Fatal("reloaded HTTP/3 handshake still returned the initial OCSP staple")
	}
	if bodyAfter != "http3 ocsp reload upstream:"+requestPath {
		t.Fatalf("reloaded HTTP/3 OCSP response body = %q, want %q", bodyAfter, "http3 ocsp reload upstream:"+requestPath)
	}
}

func TestRunHotReloadsHTTPSOCSPStapleAfterCertificateUpdateInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "https ocsp reload upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-ocsp-reload.example.test"
	const requestPath = "/https-ocsp-reload-check"

	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM(siteHost, []string{siteHost}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	parsedCert := parseAppProcessCertificatePEM(t, certPEM)
	ocspBefore := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	ocspAfter := []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
	if bytes.Equal(ocspBefore, ocspAfter) {
		t.Fatal("test OCSP staples must differ")
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
			Name:          "https ocsp reload before",
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			OCSPStaplePEM: string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspBefore})),
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

	respBefore, bodyBefore := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTPS OCSP response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "https ocsp reload upstream:"+requestPath {
		t.Fatalf("initial HTTPS OCSP response body = %q, want %q", bodyBefore, "https ocsp reload upstream:"+requestPath)
	}
	requireAppProcessPeerCertificateRaw(t, respBefore, parsedCert.Raw, "initial HTTPS OCSP")
	requireAppProcessOCSPResponse(t, respBefore, ocspBefore, "initial HTTPS OCSP")

	updatePayload, err := json.Marshal(map[string]string{
		"name":            "https ocsp reload after",
		"cert_pem":        certPEM,
		"key_pem":         keyPEM,
		"ocsp_staple_pem": string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspAfter})),
	})
	if err != nil {
		t.Fatalf("encode HTTPS certificate OCSP update payload: %v", err)
	}
	var updateResp store.Certificate
	appProc.postJSON(t, fmt.Sprintf("/api/v1/certificates/%d/update", certID), updatePayload, &updateResp)
	if updateResp.ID != certID {
		t.Fatalf("updated HTTPS OCSP certificate id = %d, want %d", updateResp.ID, certID)
	}
	if updateResp.Name != "https ocsp reload after" {
		t.Fatalf("updated HTTPS OCSP certificate name = %q, want %q", updateResp.Name, "https ocsp reload after")
	}

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful HTTPS response observed"
	for time.Now().Before(deadline) {
		respAfter, bodyAfter := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
		if respAfter.StatusCode == http.StatusOK &&
			bodyAfter == "https ocsp reload upstream:"+requestPath &&
			respAfter.TLS != nil &&
			bytes.Equal(respAfter.TLS.OCSPResponse, ocspAfter) {
			requireAppProcessPeerCertificateRaw(t, respAfter, parsedCert.Raw, "reloaded HTTPS OCSP")
			requireAppProcessOCSPResponse(t, respAfter, ocspAfter, "reloaded HTTPS OCSP")
			if bytes.Equal(respAfter.TLS.OCSPResponse, ocspBefore) {
				t.Fatal("reloaded HTTPS handshake still returned the initial OCSP staple")
			}
			return
		}
		ocspHex := ""
		if respAfter.TLS != nil {
			ocspHex = fmt.Sprintf("%x", respAfter.TLS.OCSPResponse)
		}
		lastObserved = fmt.Sprintf("status=%d proto_major=%d body=%s ocsp=%s", respAfter.StatusCode, respAfter.ProtoMajor, bodyAfter, ocspHex)
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTPS OCSP response did not converge to updated staple, last=%s\n%s", lastObserved, appProc.output.String())
}

func TestRunHotReloadsHTTP3OCSPStapleClearAfterCertificateUpdateInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http3 ocsp clear upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-ocsp-clear.example.test"
	const requestPath = "/h3-ocsp-clear-check"

	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM(siteHost, []string{siteHost}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	parsedCert := parseAppProcessCertificatePEM(t, certPEM)
	ocspBefore := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}

	var certID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		cert := store.Certificate{
			Name:          "http3 ocsp clear before",
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			OCSPStaplePEM: string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspBefore})),
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
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	respBefore, bodyBefore := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 OCSP clear response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "http3 ocsp clear upstream:"+requestPath {
		t.Fatalf("initial HTTP/3 OCSP clear response body = %q, want %q", bodyBefore, "http3 ocsp clear upstream:"+requestPath)
	}
	requireAppProcessHTTP3TLSState(t, respBefore, "initial HTTP/3 OCSP clear")
	requireAppProcessPeerCertificateRaw(t, respBefore, parsedCert.Raw, "initial HTTP/3 OCSP clear")
	requireAppProcessOCSPResponse(t, respBefore, ocspBefore, "initial HTTP/3 OCSP clear")

	updatePayload, err := json.Marshal(map[string]string{
		"name":            "http3 ocsp clear after",
		"cert_pem":        certPEM,
		"key_pem":         keyPEM,
		"ocsp_staple_pem": "",
	})
	if err != nil {
		t.Fatalf("encode certificate OCSP clear payload: %v", err)
	}
	var updateResp store.Certificate
	appProc.postJSON(t, fmt.Sprintf("/api/v1/certificates/%d/update", certID), updatePayload, &updateResp)
	if updateResp.ID != certID {
		t.Fatalf("cleared HTTP/3 OCSP certificate id = %d, want %d", updateResp.ID, certID)
	}
	if updateResp.Name != "http3 ocsp clear after" {
		t.Fatalf("cleared HTTP/3 OCSP certificate name = %q, want %q", updateResp.Name, "http3 ocsp clear after")
	}
	if strings.TrimSpace(updateResp.OCSPStaplePEM) != "" {
		t.Fatalf("cleared HTTP/3 OCSP certificate ocsp_staple_pem = %q, want empty", updateResp.OCSPStaplePEM)
	}

	respAfter, bodyAfter := appProc.waitHTTP3Response(t, udpBind, siteHost, requestPath, func(resp *http.Response, body string) bool {
		return resp.StatusCode == http.StatusOK &&
			body == "http3 ocsp clear upstream:"+requestPath &&
			resp.TLS != nil &&
			len(resp.TLS.OCSPResponse) == 0
	})
	if respAfter.ProtoMajor != 3 {
		t.Fatalf("reloaded HTTP/3 OCSP clear proto major = %d, want 3", respAfter.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respAfter, "reloaded HTTP/3 OCSP clear")
	requireAppProcessPeerCertificateRaw(t, respAfter, parsedCert.Raw, "reloaded HTTP/3 OCSP clear")
	requireAppProcessNoOCSPResponse(t, respAfter, "reloaded HTTP/3 OCSP clear")
	if bytes.Equal(respAfter.TLS.OCSPResponse, ocspBefore) {
		t.Fatal("reloaded HTTP/3 handshake still returned the initial OCSP staple after clear")
	}
	if bodyAfter != "http3 ocsp clear upstream:"+requestPath {
		t.Fatalf("reloaded HTTP/3 OCSP clear response body = %q, want %q", bodyAfter, "http3 ocsp clear upstream:"+requestPath)
	}
}

func TestRunHotReloadsHTTPSOCSPStapleClearAfterCertificateUpdateInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "https ocsp clear upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-ocsp-clear.example.test"
	const requestPath = "/https-ocsp-clear-check"

	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM(siteHost, []string{siteHost}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	parsedCert := parseAppProcessCertificatePEM(t, certPEM)
	ocspBefore := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}

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
			Name:          "https ocsp clear before",
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			OCSPStaplePEM: string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspBefore})),
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

	respBefore, bodyBefore := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTPS OCSP clear response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "https ocsp clear upstream:"+requestPath {
		t.Fatalf("initial HTTPS OCSP clear response body = %q, want %q", bodyBefore, "https ocsp clear upstream:"+requestPath)
	}
	requireAppProcessPeerCertificateRaw(t, respBefore, parsedCert.Raw, "initial HTTPS OCSP clear")
	requireAppProcessOCSPResponse(t, respBefore, ocspBefore, "initial HTTPS OCSP clear")

	updatePayload, err := json.Marshal(map[string]string{
		"name":            "https ocsp clear after",
		"cert_pem":        certPEM,
		"key_pem":         keyPEM,
		"ocsp_staple_pem": "",
	})
	if err != nil {
		t.Fatalf("encode HTTPS certificate OCSP clear payload: %v", err)
	}
	var updateResp store.Certificate
	appProc.postJSON(t, fmt.Sprintf("/api/v1/certificates/%d/update", certID), updatePayload, &updateResp)
	if updateResp.ID != certID {
		t.Fatalf("cleared HTTPS OCSP certificate id = %d, want %d", updateResp.ID, certID)
	}
	if updateResp.Name != "https ocsp clear after" {
		t.Fatalf("cleared HTTPS OCSP certificate name = %q, want %q", updateResp.Name, "https ocsp clear after")
	}
	if strings.TrimSpace(updateResp.OCSPStaplePEM) != "" {
		t.Fatalf("cleared HTTPS OCSP certificate ocsp_staple_pem = %q, want empty", updateResp.OCSPStaplePEM)
	}

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful HTTPS response observed"
	for time.Now().Before(deadline) {
		respAfter, bodyAfter := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
		if respAfter.StatusCode == http.StatusOK &&
			bodyAfter == "https ocsp clear upstream:"+requestPath &&
			respAfter.TLS != nil &&
			len(respAfter.TLS.OCSPResponse) == 0 {
			requireAppProcessPeerCertificateRaw(t, respAfter, parsedCert.Raw, "reloaded HTTPS OCSP clear")
			requireAppProcessNoOCSPResponse(t, respAfter, "reloaded HTTPS OCSP clear")
			if bytes.Equal(respAfter.TLS.OCSPResponse, ocspBefore) {
				t.Fatal("reloaded HTTPS handshake still returned the initial OCSP staple after clear")
			}
			return
		}
		ocspHex := ""
		if respAfter.TLS != nil {
			ocspHex = fmt.Sprintf("%x", respAfter.TLS.OCSPResponse)
		}
		lastObserved = fmt.Sprintf("status=%d proto_major=%d body=%s ocsp=%s", respAfter.StatusCode, respAfter.ProtoMajor, bodyAfter, ocspHex)
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTPS OCSP response did not converge to empty staple after clear, last=%s\n%s", lastObserved, appProc.output.String())
}

func TestRunServesHTTP2RequestsWithTraceableProtocolMetadataInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream should not be reached when H2 rule intercepts")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2.blackbox.example.test"
	const requestPath = "/h2-blackbox-trace"

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
			Name:        "h2-blackbox-policy",
			Description: "validates real H2 protocol capture in a separate process",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-h2-by-alpn",
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
		"tls_alpn": []string{"h2"},
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
	if accessLog.TLSALPN != "h2" {
		t.Fatalf("access log tls_alpn = %q, want %q", accessLog.TLSALPN, "h2")
	}
	if accessLog.TLSSNI != siteHost {
		t.Fatalf("access log tls_sni = %q, want %q", accessLog.TLSSNI, siteHost)
	}
	if accessLog.RequestID != requestID {
		t.Fatalf("access log request_id = %q, want %q", accessLog.RequestID, requestID)
	}

	trace := appProc.waitForRequestTrace(t, requestID)
	if trace.RequestID != requestID {
		t.Fatalf("request trace request_id = %q, want %q", trace.RequestID, requestID)
	}
	if len(trace.AccessLogs) == 0 {
		t.Fatal("request trace access_logs is empty")
	}

	var traceAccessLog *store.AccessLog
	for i := range trace.AccessLogs {
		if trace.AccessLogs[i].ID == accessLog.ID {
			traceAccessLog = &trace.AccessLogs[i]
			break
		}
	}
	if traceAccessLog == nil {
		t.Fatalf("request trace missing access log id %d", accessLog.ID)
	}
	if traceAccessLog.HTTPProtocol != "h2" {
		t.Fatalf("request trace access log http_protocol = %q, want %q", traceAccessLog.HTTPProtocol, "h2")
	}
	if traceAccessLog.TLSALPN != "h2" {
		t.Fatalf("request trace access log tls_alpn = %q, want %q", traceAccessLog.TLSALPN, "h2")
	}
	if traceAccessLog.TLSSNI != siteHost {
		t.Fatalf("request trace access log tls_sni = %q, want %q", traceAccessLog.TLSSNI, siteHost)
	}
}

func TestRunStreamsHTTPSHTTP2RequestBodyWithTrailersInSeparateProcess(t *testing.T) {
	const (
		firstPrefixSize  = 16 * 1024
		firstSegmentSize = 50 * 1024
	)

	requestBody := bytes.Repeat([]byte("https-h2-process-stream-trailer-body-"), 4096)
	if len(requestBody) <= firstSegmentSize {
		t.Fatalf("test request body length = %d, want > %d", len(requestBody), firstSegmentSize)
	}

	type upstreamResult struct {
		path          string
		method        string
		contentLength int64
		te            string
		trailer       string
		body          []byte
		err           error
	}

	upstreamPrefixRead := make(chan []byte, 1)
	upstreamResultCh := make(chan upstreamResult, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/https-h2-stream-trailers" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "https h2 process ready")
			return
		}

		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamResultCh <- upstreamResult{path: r.URL.Path, method: r.Method, err: fmt.Errorf("read upstream request prefix: %w", err)}
			http.Error(w, "bad request prefix", http.StatusBadRequest)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)

		rest, err := io.ReadAll(r.Body)
		if err != nil {
			upstreamResultCh <- upstreamResult{path: r.URL.Path, method: r.Method, err: fmt.Errorf("read upstream request body tail: %w", err)}
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		body := append(prefix, rest...)
		upstreamResultCh <- upstreamResult{
			path:          r.URL.Path,
			method:        r.Method,
			contentLength: r.ContentLength,
			te:            r.Header.Get("Te"),
			trailer:       r.Trailer.Get("X-Trace"),
			body:          body,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-request-trailers.example.test"
	const readyPath = "/https-h2-stream-trailers-ready"
	const requestPath = "/https-h2-stream-trailers"

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-request-trailers-observe",
			Description: "records HTTPS HTTP/2 request trailers requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-https-h2-request-trailers",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
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

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 ready response status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}

	targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	bodyReader, bodyWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, targetURL, bodyReader)
	if err != nil {
		t.Fatalf("build HTTPS h2 streaming trailer request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TE", "trailers")
	req.Trailer = http.Header{
		"X-Trace": []string{"done"},
	}

	type responseResult struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan responseResult, 1)
	go func() {
		resp, err := client.Do(req)
		respCh <- responseResult{resp: resp, err: err}
	}()

	if _, err := bodyWriter.Write(requestBody[:firstSegmentSize]); err != nil {
		t.Fatalf("write HTTPS h2 streaming request first segment: %v", err)
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, requestBody[:len(got)]) {
			t.Fatalf("upstream HTTPS h2 request prefix mismatch: got=%d want=%d", len(got), len(requestBody[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive HTTPS h2 streaming request prefix before client finished")
	}

	if _, err := bodyWriter.Write(requestBody[firstSegmentSize:]); err != nil {
		t.Fatalf("write HTTPS h2 streaming request remaining segment: %v", err)
	}
	if err := bodyWriter.Close(); err != nil {
		t.Fatalf("close HTTPS h2 streaming request body: %v", err)
	}

	var resp *http.Response
	select {
	case result := <-respCh:
		if result.err != nil {
			t.Fatalf("send HTTPS h2 streaming trailer request: %v", result.err)
		}
		resp = result.resp
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTPS h2 streaming trailer response")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTPS h2 streaming trailer response body: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("HTTPS h2 streaming trailer response protocol major = %d, want 2", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTPS h2 streaming trailer TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTPS h2 streaming trailer TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("HTTPS h2 streaming trailer negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h2")
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 streaming trailer response missing X-Request-ID header")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTPS h2 streaming trailer response status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusNoContent, string(body), appProc.output.String())
	}
	if len(body) != 0 {
		t.Fatalf("HTTPS h2 streaming trailer response body length = %d, want 0; body=%q", len(body), string(body))
	}
	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTPS h2 streaming trailer",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusNoContent,
		httpProtocol:     "h2",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTPS h2 streaming trailer")

	select {
	case got := <-upstreamResultCh:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.path != requestPath {
			t.Fatalf("upstream HTTPS h2 path = %q, want %q", got.path, requestPath)
		}
		if got.method != http.MethodPost {
			t.Fatalf("upstream HTTPS h2 method = %q, want %q", got.method, http.MethodPost)
		}
		if got.contentLength != -1 {
			t.Fatalf("upstream HTTPS h2 ContentLength = %d, want -1 for trailer-capable streaming request", got.contentLength)
		}
		if got.te != "trailers" {
			t.Fatalf("upstream HTTPS h2 TE = %q, want %q", got.te, "trailers")
		}
		if got.trailer != "done" {
			t.Fatalf("upstream HTTPS h2 trailer X-Trace = %q, want %q", got.trailer, "done")
		}
		if !bytes.Equal(got.body, requestBody) {
			t.Fatalf("upstream HTTPS h2 request body mismatch: got=%d want=%d", len(got.body), len(requestBody))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not finish HTTPS h2 streaming trailer verification")
	}
}

func TestRunStreamsHTTPSHTTP2ResponseBeforeUpstreamFinishesInSeparateProcess(t *testing.T) {
	firstChunk := []byte("https h2 process streaming response first chunk\n")
	secondChunk := []byte("https h2 process streaming response second chunk\n")

	upstreamFlushedFirstChunk := make(chan struct{}, 1)
	releaseUpstream := make(chan struct{})
	var releaseOnce sync.Once

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/https-h2-stream-response" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "https h2 stream response ready")
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(firstChunk); err != nil {
			return
		}
		flusher.Flush()
		upstreamFlushedFirstChunk <- struct{}{}

		<-releaseUpstream
		if _, err := w.Write(secondChunk); err != nil {
			return
		}
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
	})

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-stream-response.example.test"
	const readyPath = "/https-h2-stream-response-ready"
	const requestPath = "/https-h2-stream-response"

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-stream-response-observe",
			Description: "records HTTPS HTTP/2 streaming response requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-https-h2-stream-response",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
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

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 stream response ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithFieldsProcess(t, siteHost, requestPath, []hpack.HeaderField{
			{Name: "accept-encoding", Value: "identity"},
		}),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", streamID, requestPath, err)
	}

	select {
	case <-upstreamFlushedFirstChunk:
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
		t.Fatal("upstream did not flush first HTTPS h2 response chunk")
	}

	respHeaders, streamEnded := readRawHTTP2ResponseHeadersProcess(t, conn, fr, streamID, "200")
	if streamEnded {
		t.Fatal("HTTPS h2 streaming response ended with headers before upstream finished")
	}
	requestID := strings.TrimSpace(respHeaders.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 streaming response missing X-Request-ID header")
	}
	if !readRawHTTP2ResponseDataContainsProcess(t, conn, fr, streamID, string(firstChunk)) {
		t.Fatal("HTTPS h2 client did not receive first response DATA chunk before upstream finished")
	}

	releaseOnce.Do(func() {
		close(releaseUpstream)
	})
	if !readRawHTTP2ResponseDataContainsProcess(t, conn, fr, streamID, string(secondChunk)) {
		t.Fatal("HTTPS h2 client did not receive second response DATA chunk after upstream finished")
	}

	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTPS h2 stream response",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h2",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTPS h2 stream response")
}

func TestRunProxiesHTTPSHTTP2HEADWithoutResponseBodyInSeparateProcess(t *testing.T) {
	payload := []byte(strings.Repeat("https-h2-head-body-suppressed-", 128))
	type upstreamObservation struct {
		method         string
		path           string
		escapedPath    string
		rawQuery       string
		acceptEncoding string
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/https-h2-head-response/a/b" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "https h2 head ready")
			return
		}

		upstreamSeen <- upstreamObservation{
			method:         r.Method,
			path:           r.URL.Path,
			escapedPath:    r.URL.EscapedPath(),
			rawQuery:       r.URL.RawQuery,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("X-Upstream", "https-h2-head")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-head-response.example.test"
	const readyPath = "/https-h2-head-ready"
	const requestPath = "/https-h2-head-response/a%2Fb?keep=1;semi=2&encoded=a%2Fb"

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-head-response-observe",
			Description: "records HTTPS HTTP/2 HEAD response requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-https-h2-head-response",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
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

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 HEAD ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "https h2 head ready" {
		t.Fatalf("HTTPS h2 HEAD ready body = %q, want %q", readyBody, "https h2 head ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	req, err := http.NewRequest(http.MethodHead, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTPS h2 HEAD request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTPS h2 HEAD request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTPS h2 HEAD response body: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("HTTPS h2 HEAD protocol major = %d, want 2", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTPS h2 HEAD TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTPS h2 HEAD TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("HTTPS h2 HEAD negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h2")
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 HEAD response missing X-Request-ID header")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 HEAD status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if len(body) != 0 {
		t.Fatalf("HTTPS h2 HEAD response body length = %d, want 0; body=%q", len(body), string(body))
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("HTTPS h2 HEAD Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("HTTPS h2 HEAD Content-Encoding = %q, want gzip", got)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(payload)) {
		t.Fatalf("HTTPS h2 HEAD Content-Length = %q, want %d", got, len(payload))
	}
	if got := resp.Header.Get("X-Upstream"); got != "https-h2-head" {
		t.Fatalf("HTTPS h2 HEAD X-Upstream = %q, want https-h2-head", got)
	}
	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTPS h2 HEAD response",
		siteID:           siteID,
		requestPath:      "/https-h2-head-response/a%2Fb",
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h2",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		queryString:      "keep=1;semi=2&encoded=a%2Fb",
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTPS h2 HEAD response")

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodHead {
			t.Fatalf("upstream method = %q, want %q", got.method, http.MethodHead)
		}
		if got.path != "/https-h2-head-response/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/https-h2-head-response/a/b")
		}
		if got.escapedPath != "/https-h2-head-response/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/https-h2-head-response/a%2Fb")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.acceptEncoding != "identity" {
			t.Fatalf("upstream Accept-Encoding = %q, want identity", got.acceptEncoding)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTPS h2 HEAD request")
	}
}

func TestRunProxiesHTTPSHTTP2ResponseTrailersInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/https-h2-response-trailers" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "https h2 response trailers ready")
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "https h2 response trailer body")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-response-trailers.example.test"
	const readyPath = "/https-h2-response-trailers-ready"
	const requestPath = "/https-h2-response-trailers"

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-response-trailers-observe",
			Description: "records HTTPS HTTP/2 response trailers requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-https-h2-response-trailers",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
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

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 response trailers ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "https h2 response trailers ready" {
		t.Fatalf("HTTPS h2 response trailers ready body = %q, want %q", readyBody, "https h2 response trailers ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTPS h2 response trailer request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTPS h2 response trailer request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTPS h2 response trailer body: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("HTTPS h2 response trailer protocol major = %d, want 2", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTPS h2 response trailer TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTPS h2 response trailer TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("HTTPS h2 response trailer negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h2")
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 response trailer missing X-Request-ID header")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 response trailer status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if string(body) != "https h2 response trailer body" {
		t.Fatalf("HTTPS h2 response trailer body = %q, want %q", string(body), "https h2 response trailer body")
	}
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("HTTPS h2 response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
	accessLog := requireAppProcessResponseTrailerObservability(t, appProc, "HTTPS h2 response trailer", siteID, requestPath, requestID, siteHost, "h2", "h2", 't')
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTPS h2 response trailer")
}

func TestRunCompressesHTTPSHTTP2ResponseWithTrailersInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("https h2 compressed response trailer body.", 192)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/https-h2-compressed-response-trailers" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "https h2 compressed response trailers ready")
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, upstreamBody)
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-compressed-response-trailers.example.test"
	const readyPath = "/https-h2-compressed-response-trailers-ready"
	const requestPath = "/https-h2-compressed-response-trailers"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "false"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "64"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-compressed-response-trailers-observe",
			Description: "records HTTPS HTTP/2 compressed response trailers requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-https-h2-compressed-response-trailers",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
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

	appProc.waitRuntimeResponseCompressionState(t, true, true, 64)

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 compressed response trailers ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "https h2 compressed response trailers ready" {
		t.Fatalf("HTTPS h2 compressed response trailers ready body = %q, want %q", readyBody, "https h2 compressed response trailers ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTPS h2 compressed response trailer request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTPS h2 compressed response trailer request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTPS h2 compressed response trailer body: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("HTTPS h2 compressed response trailer protocol major = %d, want 2", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTPS h2 compressed response trailer TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTPS h2 compressed response trailer TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("HTTPS h2 compressed response trailer negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h2")
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 compressed response trailer missing X-Request-ID header")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 compressed response trailer status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Encoding")); got != "gzip" {
		t.Fatalf("HTTPS h2 compressed response trailer Content-Encoding = %q, want gzip", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("HTTPS h2 compressed response trailer Vary = %q, want Accept-Encoding", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Length")); got != "" {
		t.Fatalf("HTTPS h2 compressed response trailer Content-Length = %q, want empty", got)
	}
	requireDecodedHTTPResponseBody(t, resp.Header.Get("Content-Encoding"), body, upstreamBody)
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("HTTPS h2 compressed response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
	accessLog := requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTPS h2 compressed response trailer",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h2",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
	appProc.requireFingerprintSummaryForAccessLog(t, accessLog, "HTTPS h2 compressed response trailer")
}

func TestRunCancelsHTTPSHTTP2UpstreamResponseWhenClientResetsStreamInSeparateProcess(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/https-h2-cancel-response" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "https h2 cancel response ready")
			return
		}

		upstreamStarted <- r.URL.Path
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("https-h2-cancel-partial-")); err != nil {
			return
		}
		flusher.Flush()

		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("HTTPS h2 upstream response context was not canceled in time")
		}
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-response-cancel.example.test"
	const readyPath = "/https-h2-response-cancel-ready"
	const requestPath = "/https-h2-cancel-response"

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 cancel response ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	siteObservabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithFieldsProcess(t, siteHost, requestPath, []hpack.HeaderField{
			{Name: "accept-encoding", Value: "identity"},
		}),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", streamID, requestPath, err)
	}

	cancelRespHeaders, streamEnded := readRawHTTP2ResponseHeadersProcess(t, conn, fr, streamID, "200")
	if streamEnded {
		t.Fatal("HTTPS h2 cancel response ended with headers before partial body")
	}
	requestID := strings.TrimSpace(cancelRespHeaders.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 cancel response missing X-Request-ID header")
	}
	if !readRawHTTP2ResponseDataContainsProcess(t, conn, fr, streamID, "https-h2-cancel-partial-") {
		t.Fatal("HTTPS h2 client did not receive partial response DATA before reset")
	}

	select {
	case path := <-upstreamStarted:
		if path != requestPath {
			t.Fatalf("upstream HTTPS h2 cancel path = %q, want %q", path, requestPath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTPS h2 cancel request did not reach upstream")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HTTPS h2 upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTPS h2 upstream response was not canceled after downstream RST_STREAM")
	}

	const healthyStreamID uint32 = 3
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: healthyStreamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithFieldsProcess(t, siteHost, readyPath, []hpack.HeaderField{
			{Name: "accept-encoding", Value: "identity"},
		}),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", healthyStreamID, readyPath, err)
	}
	readRawHTTP2ResponseStatusProcess(t, conn, fr, healthyStreamID, "200")
	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBefore, "HTTPS h2 response reset")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "HTTPS h2 response reset")
	appProc.requireNoSiteObservability(t, siteID, requestPath, "HTTPS h2 response reset")
	appProc.requireNoGlobalObservability(t, siteHost, requestPath, "HTTPS h2 response reset")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "HTTPS h2 response reset")
}

func TestRunCancelsHTTPSHTTP2UpstreamSSEWhenClientResetsStreamInSeparateProcess(t *testing.T) {
	type upstreamObservation struct {
		path   string
		accept string
	}

	upstreamStarted := make(chan upstreamObservation, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/https-h2-sse-cancel/events" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "https h2 sse cancel ready")
			return
		}

		upstreamStarted <- upstreamObservation{
			path:   r.URL.Path,
			accept: r.Header.Get("Accept"),
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "data: https-h2-sse-cancel\n\n"); err != nil {
			return
		}
		flusher.Flush()

		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("HTTPS h2 upstream SSE context was not canceled in time")
		}
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-sse-cancel.example.test"
	const readyPath = "/https-h2-sse-cancel-ready"
	const requestPath = "/https-h2-sse-cancel/events"

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 SSE cancel ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	siteObservabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithFieldsProcess(t, siteHost, requestPath, []hpack.HeaderField{
			{Name: "accept", Value: "text/event-stream"},
			{Name: "accept-encoding", Value: "identity"},
		}),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", streamID, requestPath, err)
	}

	cancelRespHeaders, streamEnded := readRawHTTP2ResponseHeadersProcess(t, conn, fr, streamID, "200")
	if streamEnded {
		t.Fatal("HTTPS h2 SSE response ended with headers before event data")
	}
	requestID := strings.TrimSpace(cancelRespHeaders.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 SSE response missing X-Request-ID header")
	}
	if !readRawHTTP2ResponseDataContainsProcess(t, conn, fr, streamID, "data: https-h2-sse-cancel\n\n") {
		t.Fatal("HTTPS h2 client did not receive SSE DATA before reset")
	}

	select {
	case got := <-upstreamStarted:
		if got.path != requestPath {
			t.Fatalf("upstream HTTPS h2 SSE cancel path = %q, want %q", got.path, requestPath)
		}
		if got.accept != "text/event-stream" {
			t.Fatalf("upstream HTTPS h2 SSE Accept = %q, want %q", got.accept, "text/event-stream")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTPS h2 SSE cancel request did not reach upstream")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HTTPS h2 upstream SSE cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTPS h2 upstream SSE was not canceled after downstream RST_STREAM")
	}

	const healthyStreamID uint32 = 3
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: healthyStreamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithFieldsProcess(t, siteHost, readyPath, []hpack.HeaderField{
			{Name: "accept-encoding", Value: "identity"},
		}),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", healthyStreamID, readyPath, err)
	}
	readRawHTTP2ResponseStatusProcess(t, conn, fr, healthyStreamID, "200")
	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBefore, "HTTPS h2 SSE reset")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "HTTPS h2 SSE reset")
	appProc.requireNoSiteObservability(t, siteID, requestPath, "HTTPS h2 SSE reset")
	appProc.requireNoGlobalObservability(t, siteHost, requestPath, "HTTPS h2 SSE reset")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "HTTPS h2 SSE reset")
}

func TestRunRejectsMalformedHTTP2PseudoHeaderOrderWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "malformed h2 protocol error ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-protocol-error.example.test"
	const readyPath = "/h2-protocol-error-ready"
	const malformedPath = "/h2-protocol-error/pseudo-header-after-regular"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 protocol error ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	siteObservabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const malformedStreamID uint32 = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: malformedStreamID,
		BlockFragment: encodeRawHTTP2HeaderBlockProcess(t, []hpack.HeaderField{
			{Name: ":method", Value: http.MethodGet},
			{Name: ":scheme", Value: "https"},
			{Name: "x-owaf-probe", Value: "regular-before-pseudo"},
			{Name: ":authority", Value: siteHost},
			{Name: ":path", Value: malformedPath},
		}),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", malformedStreamID, malformedPath, err)
	}

	readRawHTTP2StreamProtocolErrorProcess(t, conn, fr, malformedStreamID)

	const healthyStreamID uint32 = 3
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: healthyStreamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithFieldsProcess(t, siteHost, readyPath, []hpack.HeaderField{
			{Name: "accept-encoding", Value: "identity"},
		}),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", healthyStreamID, readyPath, err)
	}
	readRawHTTP2ResponseStatusProcess(t, conn, fr, healthyStreamID, "200")

	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBefore, "malformed raw HTTP/2 pseudo-header order")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "malformed raw HTTP/2 pseudo-header order")
	appProc.requireNoSiteObservability(t, siteID, malformedPath, "malformed raw HTTP/2 pseudo-header order")
	appProc.requireNoGlobalObservability(t, siteHost, malformedPath, "malformed raw HTTP/2 pseudo-header order")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "malformed raw HTTP/2 pseudo-header order")
}

func TestRunRejectsInvalidHTTP2ConnectionPrefaceWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "invalid h2 connection preface ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-preface-error.example.test"
	const readyPath = "/h2-preface-error-ready"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 preface error ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	observabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         siteHost,
		NextProtos:         []string{"h2"},
	}
	conn, err := tls.Dial("tcp", tcpBind, tlsConfig)
	if err != nil {
		t.Fatalf("tls dial invalid h2 preface: %v\n%s", err, appProc.output.String())
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	if state := conn.ConnectionState(); state.NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated protocol = %q, want %q", state.NegotiatedProtocol, "h2")
	}
	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\rX"); err != nil {
		t.Fatalf("write invalid h2 connection preface: %v", err)
	}
	readRawHTTP2ConnectionProtocolErrorProcess(t, conn, "invalid HTTP/2 connection preface")

	appProc.requireSiteObservabilityTotals(t, siteID, observabilityBefore, "invalid HTTP/2 connection preface")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "invalid HTTP/2 connection preface")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "invalid HTTP/2 connection preface")
}

func TestRunClosesIdleHTTP2ConnectionWithoutObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "idle h2 close ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-idle-close.example.test"
	const idleSNI = "h2-idle-close-probe.example.test"
	const readyPath = "/h2-idle-close-ready"
	const noRequestPath = "/h2-idle-close/no-request"

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
			Name:        "h2-idle-close-policy",
			Description: "stabilizes HTTP/2 idle close observability baseline",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-h2-idle-close-ready",
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

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTP/2 idle close ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusForbidden, readyBody, appProc.output.String())
	}
	readyRequestID := strings.TrimSpace(readyResp.Header.Get("X-Request-ID"))
	if readyRequestID == "" {
		t.Fatal("HTTP/2 idle close ready response missing X-Request-ID header")
	}
	readyAccessLog := appProc.waitForSiteAccessLog(t, siteID, readyPath, url.Values{
		"request_id": []string{readyRequestID},
		"tls_alpn":   []string{"h2"},
	})
	if readyAccessLog.WAFAction != string(store.ActionIntercept) {
		t.Fatalf("HTTP/2 idle close ready access log waf_action = %q, want %q", readyAccessLog.WAFAction, store.ActionIntercept)
	}
	appProc.waitForSiteSecurityEvent(t, siteID, readyPath, url.Values{
		"request_id": []string{readyRequestID},
		"action":     []string{string(store.ActionIntercept)},
		"tls_alpn":   []string{"h2"},
	})
	requireAppProcessAccessLogTrace(t, appProc, readyAccessLog, appProcessAccessLogTraceExpectation{
		label:                       "HTTP/2 idle close ready intercept",
		requestID:                   readyRequestID,
		siteHost:                    siteHost,
		statusCode:                  http.StatusForbidden,
		wafAction:                   string(store.ActionIntercept),
		securityEventAction:         string(store.ActionIntercept),
		httpProtocol:                "h2",
		tlsALPN:                     "h2",
		ja4Prefix:                   't',
		expectMissingTLSClientHello: true,
	})
	siteObservabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)

	conn, _, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, idleSNI)
	if err := conn.Close(); err != nil {
		t.Fatalf("close idle raw HTTP/2 connection: %v", err)
	}

	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBefore, "idle raw HTTP/2 connection close")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "idle raw HTTP/2 connection close")
	appProc.requireNoGlobalObservability(t, idleSNI, noRequestPath, "idle raw HTTP/2 connection close")
	appProc.requireNoFingerprintSummary(t, url.Values{
		"tls_sni":  []string{idleSNI},
		"tls_alpn": []string{"h2"},
	}, "idle raw HTTP/2 connection close")
}

func TestRunRejectsHTTP2DataFrameOnStreamZeroWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "h2 stream zero data frame ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-stream-zero-data.example.test"
	const readyPath = "/h2-stream-zero-data-ready"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 stream zero DATA ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	observabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	if err := fr.WriteRawFrame(http2.FrameData, http2.FlagDataEndStream, 0, []byte("data-on-stream-zero")); err != nil {
		t.Fatalf("WriteRawFrame(DATA stream=0) error = %v", err)
	}
	readRawHTTP2ConnectionProtocolErrorProcess(t, conn, "HTTP/2 DATA frame on stream zero")

	appProc.requireSiteObservabilityTotals(t, siteID, observabilityBefore, "HTTP/2 DATA frame on stream zero")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "HTTP/2 DATA frame on stream zero")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "HTTP/2 DATA frame on stream zero")
}

func TestRunRejectsUnexpectedHTTP2ContinuationFrameWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "unexpected h2 continuation frame ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-unexpected-continuation.example.test"
	const readyPath = "/h2-unexpected-continuation-ready"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 unexpected CONTINUATION ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	observabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	if err := fr.WriteRawFrame(http2.FrameContinuation, http2.FlagHeadersEndHeaders, 1, []byte("unexpected-continuation")); err != nil {
		t.Fatalf("WriteRawFrame(CONTINUATION without HEADERS) error = %v", err)
	}
	readRawHTTP2ConnectionProtocolErrorProcess(t, conn, "HTTP/2 CONTINUATION frame without preceding HEADERS")

	appProc.requireSiteObservabilityTotals(t, siteID, observabilityBefore, "HTTP/2 CONTINUATION frame without preceding HEADERS")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "HTTP/2 CONTINUATION frame without preceding HEADERS")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "HTTP/2 CONTINUATION frame without preceding HEADERS")
}

func TestRunRejectsOversizedHTTP2FrameWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "oversized h2 frame ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-oversized-frame.example.test"
	const readyPath = "/h2-oversized-frame-ready"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 oversized frame ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	observabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const defaultHTTP2MaxReadFrameSize = 1 << 20
	if err := fr.WriteRawFrame(http2.FrameType(0xff), 0, 0, make([]byte, defaultHTTP2MaxReadFrameSize+1)); err != nil {
		t.Fatalf("WriteRawFrame(oversized unknown frame) error = %v", err)
	}
	readRawHTTP2ConnectionErrorProcess(t, conn, "oversized HTTP/2 frame", http2.ErrCodeFrameSize)

	appProc.requireSiteObservabilityTotals(t, siteID, observabilityBefore, "oversized HTTP/2 frame")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "oversized HTTP/2 frame")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "oversized HTTP/2 frame")
}

func TestRunRejectsHTTP2ConnectionWindowOverflowWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "h2 connection window overflow ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-connection-window-overflow.example.test"
	const readyPath = "/h2-connection-window-overflow-ready"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 connection window overflow ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	observabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	if err := fr.WriteWindowUpdate(0, 1<<31-1); err != nil {
		t.Fatalf("WriteWindowUpdate(connection overflow) error = %v", err)
	}
	readRawHTTP2ConnectionErrorProcess(t, conn, "HTTP/2 connection WINDOW_UPDATE overflow", http2.ErrCodeFlowControl)

	appProc.requireSiteObservabilityTotals(t, siteID, observabilityBefore, "HTTP/2 connection WINDOW_UPDATE overflow")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "HTTP/2 connection WINDOW_UPDATE overflow")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "HTTP/2 connection WINDOW_UPDATE overflow")
}

func TestRunRejectsHTTP2StreamWindowUpdateZeroIncrementWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "h2 stream window update zero increment ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-stream-window-update-zero.example.test"
	const readyPath = "/h2-stream-window-update-zero-ready"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 stream WINDOW_UPDATE zero increment ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	observabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	fr.AllowIllegalWrites = true
	if err := fr.WriteWindowUpdate(streamID, 0); err != nil {
		t.Fatalf("WriteWindowUpdate(stream zero increment) error = %v", err)
	}
	readRawHTTP2StreamProtocolErrorProcess(t, conn, fr, streamID)

	appProc.requireSiteObservabilityTotals(t, siteID, observabilityBefore, "HTTP/2 stream WINDOW_UPDATE zero increment")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "HTTP/2 stream WINDOW_UPDATE zero increment")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "HTTP/2 stream WINDOW_UPDATE zero increment")
}

func TestRunIgnoresHTTP2NewStreamAfterClientGoAwayWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "h2 goaway new stream ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-goaway-new-stream.example.test"
	const readyPath = "/h2-goaway-new-stream-ready"
	const ignoredPath = "/h2-goaway-new-stream/ignored-after-client-goaway"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 GOAWAY new stream ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	observabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const ignoredStreamID uint32 = 1
	if err := fr.WriteGoAway(0, http2.ErrCodeNo, nil); err != nil {
		t.Fatalf("WriteGoAway(client graceful shutdown) error = %v", err)
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: ignoredStreamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithFieldsProcess(t, siteHost, ignoredPath, []hpack.HeaderField{
			{Name: "accept-encoding", Value: "identity"},
		}),
		EndStream:  true,
		EndHeaders: true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q after GOAWAY) error = %v", ignoredStreamID, ignoredPath, err)
	}
	readRawHTTP2GoAwayAndNoResponseForStreamProcess(t, conn, fr, ignoredStreamID, 0, "HTTP/2 new stream after client GOAWAY")

	appProc.requireSiteObservabilityTotals(t, siteID, observabilityBefore, "HTTP/2 new stream after client GOAWAY")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "HTTP/2 new stream after client GOAWAY")
	appProc.requireNoSiteObservability(t, siteID, ignoredPath, "HTTP/2 new stream after client GOAWAY")
	appProc.requireNoGlobalObservability(t, siteHost, ignoredPath, "HTTP/2 new stream after client GOAWAY")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "HTTP/2 new stream after client GOAWAY")
}

func TestRunIgnoresHTTP2DataAfterClientGoAwayWithoutSiteObservabilityInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "h2 goaway data window return ready")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "h2-goaway-data-window.example.test"
	const readyPath = "/h2-goaway-data-window-ready"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 GOAWAY DATA window return ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	observabilityBefore := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBefore := appProc.globalObservabilityTotals(t)
	fingerprintBefore := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})

	conn, fr, _ := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const ignoredStreamID uint32 = 1
	data := []byte(strings.Repeat("goaway-data-window-return-", 200))
	if err := fr.WriteGoAway(0, http2.ErrCodeNo, nil); err != nil {
		t.Fatalf("WriteGoAway(client graceful shutdown) error = %v", err)
	}
	if err := fr.WriteData(ignoredStreamID, true, data); err != nil {
		t.Fatalf("WriteData(stream=%d after GOAWAY) error = %v", ignoredStreamID, err)
	}
	readRawHTTP2GoAwayAndNoResponseForStreamProcess(t, conn, fr, ignoredStreamID, 0, "HTTP/2 DATA after client GOAWAY")

	appProc.requireSiteObservabilityTotals(t, siteID, observabilityBefore, "HTTP/2 DATA after client GOAWAY")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBefore, "HTTP/2 DATA after client GOAWAY")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBefore, "HTTP/2 DATA after client GOAWAY")
}

func TestRunStreamsSSEBypassesCacheAndCompressionOverHTTP2AndHTTP3InSeparateProcess(t *testing.T) {
	type upstreamObservation struct {
		count          int32
		method         string
		path           string
		rawQuery       string
		accept         string
		acceptEncoding string
		forwarded      string
		writeError     error
	}

	var upstreamRequests atomic.Int32
	upstreamSeen := make(chan upstreamObservation, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sse-cache-compression/events" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "sse cache compression ready")
			return
		}

		count := upstreamRequests.Add(1)
		obs := upstreamObservation{
			count:          count,
			method:         r.Method,
			path:           r.URL.Path,
			rawQuery:       r.URL.RawQuery,
			accept:         r.Header.Get("Accept"),
			acceptEncoding: r.Header.Get("Accept-Encoding"),
			forwarded:      r.Header.Get("X-Forwarded-Proto"),
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Upstream-Count", strconv.Itoa(int(count)))
		flusher, _ := w.(http.Flusher)
		if _, err := io.WriteString(w, fmt.Sprintf("data: request-%d-one\n\n", count)); err != nil {
			obs.writeError = err
			upstreamSeen <- obs
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(20 * time.Millisecond)
		if _, err := io.WriteString(w, fmt.Sprintf("data: request-%d-two\n\n", count)); err != nil {
			obs.writeError = err
			upstreamSeen <- obs
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		upstreamSeen <- obs
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "sse-cache-compression.example.test"
	const readyPath = "/sse-cache-compression-ready"
	const requestPath = "/sse-cache-compression/events?stream=1"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "64"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		cacheRulesBytes, err := json.Marshal([]store.SiteCacheRule{
			{Type: "prefix", Value: "/sse-cache-compression", TTL: 120},
		})
		if err != nil {
			return fmt.Errorf("marshal cache rules: %w", err)
		}

		policy := store.Policy{
			Name:        "sse-cache-compression-observe",
			Description: "records SSE cache and compression bypass requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-sse-cache-compression",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
			Action:   store.ActionObserve,
			Priority: 1,
			Enabled:  true,
		}
		if err := db.Create(&rule).Error; err != nil {
			return fmt.Errorf("create rule: %w", err)
		}

		site := store.Site{
			Host:            siteHost,
			UpstreamURLs:    upstream.URL,
			Bind:            tcpBind,
			Network:         "tcp",
			Enabled:         true,
			TLSEnabled:      true,
			ALPN:            "h2,h3,http/1.1",
			CacheEnabled:    true,
			CacheDefaultTTL: 120,
			CacheRules:      string(cacheRulesBytes),
			PolicyID:        &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 64)

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 SSE cache compression ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "sse cache compression ready" {
		t.Fatalf("HTTPS h2 SSE cache compression ready body = %q, want %q", readyBody, "sse cache compression ready")
	}

	h3ReadyResp, h3ReadyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if h3ReadyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 SSE cache compression ready status = %d, want %d, body=%s\n%s", h3ReadyResp.StatusCode, http.StatusOK, h3ReadyBody, appProc.output.String())
	}
	if h3ReadyBody != "sse cache compression ready" {
		t.Fatalf("HTTP/3 SSE cache compression ready body = %q, want %q", h3ReadyBody, "sse cache compression ready")
	}

	h2TargetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	h2Transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	h2Client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: h2Transport,
	}
	t.Cleanup(func() {
		h2Transport.CloseIdleConnections()
	})

	h3TargetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	h3Client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: h3Transport,
	}
	t.Cleanup(func() {
		_ = h3Transport.Close()
	})

	requireSSEHeaders := func(label string, resp *http.Response, wantProtoMajor int, wantALPN string) string {
		t.Helper()
		if resp.ProtoMajor != wantProtoMajor {
			t.Fatalf("%s SSE protocol major = %d, want %d", label, resp.ProtoMajor, wantProtoMajor)
		}
		if resp.TLS == nil {
			t.Fatalf("expected %s SSE TLS connection state", label)
		}
		if wantProtoMajor == 3 {
			if resp.TLS.Version != tls.VersionTLS13 {
				t.Fatalf("%s SSE TLS version = %#x, want TLS 1.3", label, resp.TLS.Version)
			}
		} else if resp.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("%s SSE TLS version = %#x, want TLS 1.3", label, resp.TLS.Version)
		}
		if resp.TLS.NegotiatedProtocol != wantALPN {
			t.Fatalf("%s SSE negotiated protocol = %q, want %q", label, resp.TLS.NegotiatedProtocol, wantALPN)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s SSE status = %d, want %d", label, resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
			t.Fatalf("%s SSE Content-Type = %q, want %q", label, got, "text/event-stream")
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
			t.Fatalf("%s SSE Cache-Control = %q, want %q", label, got, "no-cache")
		}
		if got := resp.Header.Get("Content-Length"); got != "" {
			t.Fatalf("%s SSE Content-Length = %q, want empty", label, got)
		}
		if got := resp.Header.Get("Content-Encoding"); got != "" {
			t.Fatalf("%s SSE Content-Encoding = %q, want empty", label, got)
		}
		if got := strings.TrimSpace(resp.Header.Get("Vary")); got != "" {
			t.Fatalf("%s SSE Vary = %q, want empty", label, got)
		}
		requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
		if requestID == "" {
			t.Fatalf("%s SSE response missing X-Request-ID header", label)
		}
		if wantProtoMajor == 3 {
			if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
				t.Fatalf("%s SSE Alt-Svc = %q, want %q", label, got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
			}
		}
		return requestID
	}

	requireSSEObservability := func(label string, requestID string, wantHTTPProtocol string, wantTLSALPN string, wantJA4Prefix byte) {
		t.Helper()

		requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
			label:            label + " SSE",
			siteID:           siteID,
			requestPath:      "/sse-cache-compression/events",
			requestID:        requestID,
			siteHost:         siteHost,
			statusCode:       http.StatusOK,
			httpProtocol:     wantHTTPProtocol,
			tlsALPN:          wantTLSALPN,
			ja4Prefix:        wantJA4Prefix,
			queryString:      "stream=1",
			upstreamProtocol: "HTTP/1.1",
			responseSize:     0,
		})
	}

	doH2SSE := func(label string, wantCount int32) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, h2TargetURL, nil)
		if err != nil {
			t.Fatalf("build HTTPS h2 SSE request %s: %v", label, err)
		}
		req.Host = siteHost
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := h2Client.Do(req)
		if err != nil {
			t.Fatalf("send HTTPS h2 SSE request %s: %v", label, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read HTTPS h2 SSE response %s: %v", label, err)
		}

		requestID := requireSSEHeaders(label, resp, 2, "h2")
		wantBody := fmt.Sprintf("data: request-%d-one\n\ndata: request-%d-two\n\n", wantCount, wantCount)
		if string(body) != wantBody {
			t.Fatalf("HTTPS h2 SSE response %s body = %q, want %q", label, string(body), wantBody)
		}
		if got := resp.Header.Get("X-Upstream-Count"); got != strconv.Itoa(int(wantCount)) {
			t.Fatalf("HTTPS h2 SSE response %s X-Upstream-Count = %q, want %d", label, got, wantCount)
		}
		return requestID
	}

	doH3SSE := func(label string, wantCount int32) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, h3TargetURL, nil)
		if err != nil {
			t.Fatalf("build HTTP/3 SSE request %s: %v", label, err)
		}
		req.Host = siteHost
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Accept-Encoding", "gzip")

		resp, err := h3Client.Do(req)
		if err != nil {
			t.Fatalf("send HTTP/3 SSE request %s: %v", label, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read HTTP/3 SSE response %s: %v", label, err)
		}

		requestID := requireSSEHeaders(label, resp, 3, "h3")
		wantBody := fmt.Sprintf("data: request-%d-one\n\ndata: request-%d-two\n\n", wantCount, wantCount)
		if string(body) != wantBody {
			t.Fatalf("HTTP/3 SSE response %s body = %q, want %q", label, string(body), wantBody)
		}
		if got := resp.Header.Get("X-Upstream-Count"); got != strconv.Itoa(int(wantCount)) {
			t.Fatalf("HTTP/3 SSE response %s X-Upstream-Count = %q, want %d", label, got, wantCount)
		}
		return requestID
	}

	h2FirstRequestID := doH2SSE("h2-first", 1)
	requireSSEObservability("h2-first", h2FirstRequestID, "h2", "h2", 't')
	h2SecondRequestID := doH2SSE("h2-second", 2)
	requireSSEObservability("h2-second", h2SecondRequestID, "h2", "h2", 't')
	h3FirstRequestID := doH3SSE("h3-first", 3)
	requireSSEObservability("h3-first", h3FirstRequestID, "h3", "h3", 'q')
	h3SecondRequestID := doH3SSE("h3-second", 4)
	requireSSEObservability("h3-second", h3SecondRequestID, "h3", "h3", 'q')

	for wantCount := int32(1); wantCount <= 4; wantCount++ {
		select {
		case got := <-upstreamSeen:
			if got.count != wantCount {
				t.Fatalf("upstream SSE count = %d, want %d", got.count, wantCount)
			}
			if got.writeError != nil {
				t.Fatalf("upstream SSE write error on count %d: %v", got.count, got.writeError)
			}
			if got.method != http.MethodGet {
				t.Fatalf("upstream SSE method on count %d = %q, want %q", got.count, got.method, http.MethodGet)
			}
			if got.path != "/sse-cache-compression/events" {
				t.Fatalf("upstream SSE path on count %d = %q, want %q", got.count, got.path, "/sse-cache-compression/events")
			}
			if got.rawQuery != "stream=1" {
				t.Fatalf("upstream SSE raw query on count %d = %q, want %q", got.count, got.rawQuery, "stream=1")
			}
			if got.accept != "text/event-stream" {
				t.Fatalf("upstream SSE Accept on count %d = %q, want %q", got.count, got.accept, "text/event-stream")
			}
			if got.acceptEncoding != "gzip" {
				t.Fatalf("upstream SSE Accept-Encoding on count %d = %q, want %q", got.count, got.acceptEncoding, "gzip")
			}
			wantForwarded := "https"
			if got.count >= 3 {
				wantForwarded = "h3"
			}
			if got.forwarded != wantForwarded {
				t.Fatalf("upstream SSE X-Forwarded-Proto on count %d = %q, want %q", got.count, got.forwarded, wantForwarded)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("upstream did not observe SSE request count %d", wantCount)
		}
	}
	if got := upstreamRequests.Load(); got != 4 {
		t.Fatalf("upstream SSE request count = %d, want 4", got)
	}
}

func TestRunServesTLS1xHandshakeProtocolsInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tls1x handshake protocol upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls1x-handshake-protocol.example.test"
	const requestPath = "/tls1x-handshake-protocol-check"
	const legacyCipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	const tls12CipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	const tls13CipherName = "TLS_AES_128_GCM_SHA256"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS10",
			MaxVersion:               "TLS13",
			CipherSuites:             legacyCipherName + "," + tls12CipherName,
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

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
			Name:        "tls1x-handshake-protocol-observe",
			Description: "records TLS1.x handshake matrix requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-tls10-handshake",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS10",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-tls11-handshake",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS11",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
			{
				Name:     "observe-tls12-handshake",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS12",
				Action:   store.ActionObserve,
				Priority: 3,
				Enabled:  true,
			},
			{
				Name:     "observe-tls13-handshake",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS13",
				Action:   store.ActionObserve,
				Priority: 4,
				Enabled:  true,
			},
			{
				Name:     "observe-legacy-handshake-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + legacyCipherName,
				Action:   store.ActionObserve,
				Priority: 5,
				Enabled:  true,
			},
			{
				Name:     "observe-tls12-handshake-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + tls12CipherName,
				Action:   store.ActionObserve,
				Priority: 6,
				Enabled:  true,
			},
			{
				Name:     "observe-tls13-handshake-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + tls13CipherName,
				Action:   store.ActionObserve,
				Priority: 7,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
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

	legacyCipherSuites := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	tls12CipherSuites := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	tests := []struct {
		name         string
		version      uint16
		cipherSuites []uint16
		wantProto    int
		wantALPN     string
		wantHTTP     string
		wantCiphers  []string
	}{
		{
			name:         "TLS10",
			version:      tls.VersionTLS10,
			cipherSuites: legacyCipherSuites,
			wantProto:    1,
			wantALPN:     "http/1.1",
			wantHTTP:     "http/1.1",
			wantCiphers:  []string{legacyCipherName},
		},
		{
			name:         "TLS11",
			version:      tls.VersionTLS11,
			cipherSuites: legacyCipherSuites,
			wantProto:    1,
			wantALPN:     "http/1.1",
			wantHTTP:     "http/1.1",
			wantCiphers:  []string{legacyCipherName},
		},
		{
			name:         "TLS12",
			version:      tls.VersionTLS12,
			cipherSuites: tls12CipherSuites,
			wantProto:    2,
			wantALPN:     "h2",
			wantHTTP:     "h2",
			wantCiphers:  []string{tls12CipherName},
		},
		{
			name:      "TLS13",
			version:   tls.VersionTLS13,
			wantProto: 2,
			wantALPN:  "h2",
			wantHTTP:  "h2",
			wantCiphers: []string{
				tls13CipherName,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := appProc.waitHTTPSStateWithCipherSuites(t, tcpBind, siteHost, requestPath, tt.version, tt.version, tt.cipherSuites, tt.wantProto, tt.wantALPN, tt.version, 0)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s HTTPS response status = %d, want %d, body=%s\n%s", tt.name, resp.StatusCode, http.StatusOK, body, appProc.output.String())
			}
			if body != "tls1x handshake protocol upstream" {
				t.Fatalf("%s HTTPS response body = %q, want %q", tt.name, body, "tls1x handshake protocol upstream")
			}
			requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
			if requestID == "" {
				t.Fatalf("%s HTTPS response missing X-Request-ID header", tt.name)
			}
			requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
				label:           tt.name + " TLS1.x handshake protocol",
				siteID:          siteID,
				requestPath:     requestPath,
				requestID:       requestID,
				siteHost:        siteHost,
				statusCode:      http.StatusOK,
				httpProtocol:    tt.wantHTTP,
				tlsVersion:      tt.name,
				tlsALPN:         tt.wantALPN,
				ja4Prefix:       't',
				responseSize:    int64(len(body)),
				tlsCipherSuites: tt.wantCiphers,
			})
		})
	}
}

func TestRunServesSiteTLS1xOverridesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "site tls1x override upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "site-tls1x-override.example.test"
	const requestPath = "/site-tls1x-override-check"
	const legacyCipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	const tls12CipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	const tls13CipherName = "TLS_AES_128_GCM_SHA256"
	const siteCipherSuites = legacyCipherName + "," + tls12CipherName

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS13",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

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
			Name:        "site-tls1x-override-observe",
			Description: "records site TLS1.x override requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-site-tls10-override",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS10",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-site-tls11-override",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS11",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
			{
				Name:     "observe-site-tls12-override",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS12",
				Action:   store.ActionObserve,
				Priority: 3,
				Enabled:  true,
			},
			{
				Name:     "observe-site-tls13-override",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS13",
				Action:   store.ActionObserve,
				Priority: 4,
				Enabled:  true,
			},
			{
				Name:     "observe-site-legacy-override-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + legacyCipherName,
				Action:   store.ActionObserve,
				Priority: 5,
				Enabled:  true,
			},
			{
				Name:     "observe-site-tls12-override-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + tls12CipherName,
				Action:   store.ActionObserve,
				Priority: 6,
				Enabled:  true,
			},
			{
				Name:     "observe-site-tls13-override-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + tls13CipherName,
				Action:   store.ActionObserve,
				Priority: 7,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:          siteHost,
			UpstreamURLs:  upstream.URL,
			Bind:          tcpBind,
			Network:       "tcp",
			Enabled:       true,
			TLSEnabled:    true,
			MinTLSVersion: "TLS10",
			MaxTLSVersion: "TLS13",
			CipherSuites:  siteCipherSuites,
			ALPN:          "h2,http/1.1",
			PolicyID:      &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	legacyCipherSuites := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	tls12CipherSuites := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	tests := []struct {
		name            string
		version         uint16
		cipherSuites    []uint16
		wantProto       int
		wantALPN        string
		wantCipherSuite uint16
		wantHTTP        string
		wantCiphers     []string
	}{
		{
			name:            "TLS10",
			version:         tls.VersionTLS10,
			cipherSuites:    legacyCipherSuites,
			wantProto:       1,
			wantALPN:        "http/1.1",
			wantCipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			wantHTTP:        "http/1.1",
			wantCiphers:     []string{legacyCipherName},
		},
		{
			name:            "TLS11",
			version:         tls.VersionTLS11,
			cipherSuites:    legacyCipherSuites,
			wantProto:       1,
			wantALPN:        "http/1.1",
			wantCipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			wantHTTP:        "http/1.1",
			wantCiphers:     []string{legacyCipherName},
		},
		{
			name:            "TLS12",
			version:         tls.VersionTLS12,
			cipherSuites:    tls12CipherSuites,
			wantProto:       2,
			wantALPN:        "h2",
			wantCipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			wantHTTP:        "h2",
			wantCiphers:     []string{tls12CipherName},
		},
		{
			name:      "TLS13",
			version:   tls.VersionTLS13,
			wantProto: 2,
			wantALPN:  "h2",
			wantHTTP:  "h2",
			wantCiphers: []string{
				tls13CipherName,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := appProc.waitHTTPSStateWithCipherSuites(t, tcpBind, siteHost, requestPath, tt.version, tt.version, tt.cipherSuites, tt.wantProto, tt.wantALPN, tt.version, tt.wantCipherSuite)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s site override HTTPS response status = %d, want %d, body=%s\n%s", tt.name, resp.StatusCode, http.StatusOK, body, appProc.output.String())
			}
			if body != "site tls1x override upstream" {
				t.Fatalf("%s site override HTTPS response body = %q, want %q", tt.name, body, "site tls1x override upstream")
			}
			requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
			if requestID == "" {
				t.Fatalf("%s site override HTTPS response missing X-Request-ID header", tt.name)
			}
			requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
				label:           tt.name + " site TLS1.x override",
				siteID:          siteID,
				requestPath:     requestPath,
				requestID:       requestID,
				siteHost:        siteHost,
				statusCode:      http.StatusOK,
				httpProtocol:    tt.wantHTTP,
				tlsVersion:      tt.name,
				tlsALPN:         tt.wantALPN,
				ja4Prefix:       't',
				responseSize:    int64(len(body)),
				tlsCipherSuites: tt.wantCiphers,
			})
		})
	}
}

func TestRunFallsBackToHTTP11WhenLegacyTLSSiteALPNIsH2OnlyInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "legacy tls h2-only fallback upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "legacy-tls-h2-only.example.test"
	const requestPath = "/legacy-tls-h2-only-check"
	const legacyCipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS10",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

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
			Name:        "legacy-tls-h2-only-fallback-observe",
			Description: "records legacy TLS h2-only ALPN fallback for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-legacy-tls11-h2-only-fallback",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS11",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-legacy-tls11-h2-only-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + legacyCipherName,
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:          siteHost,
			UpstreamURLs:  upstream.URL,
			Bind:          tcpBind,
			Network:       "tcp",
			Enabled:       true,
			TLSEnabled:    true,
			MinTLSVersion: "TLS10",
			MaxTLSVersion: "TLS11",
			CipherSuites:  legacyCipherName,
			ALPN:          "h2",
			PolicyID:      &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProc.waitHTTPSStateWithCipherSuites(
		t,
		tcpBind,
		siteHost,
		requestPath,
		tls.VersionTLS11,
		tls.VersionTLS11,
		[]uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		1,
		"",
		tls.VersionTLS11,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy TLS h2-only fallback response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
	}
	if body != "legacy tls h2-only fallback upstream" {
		t.Fatalf("legacy TLS h2-only fallback response body = %q, want %q", body, "legacy tls h2-only fallback upstream")
	}
	if resp.TLS == nil {
		t.Fatal("expected legacy TLS h2-only fallback TLS connection state")
	}
	if resp.TLS.NegotiatedProtocol == "h2" {
		t.Fatalf("legacy TLS h2-only fallback negotiated protocol = %q, want non-h2", resp.TLS.NegotiatedProtocol)
	}
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("legacy TLS h2-only fallback response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:           "legacy TLS h2-only fallback",
		siteID:          siteID,
		requestPath:     requestPath,
		requestID:       requestID,
		siteHost:        siteHost,
		statusCode:      http.StatusOK,
		httpProtocol:    "http/1.1",
		tlsVersion:      "TLS11",
		tlsALPN:         "",
		ja4Prefix:       't',
		responseSize:    int64(len(body)),
		tlsCipherSuites: []string{legacyCipherName},
	})
}

func TestRunServesHTTPSRequestsWithTLSVersionCustomRuleInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream should not be reached when TLS version rule intercepts")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls-version.blackbox.example.test"
	const requestPath = "/tls-version-blackbox"

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
			Name:        "tls-version-blackbox-policy",
			Description: "validates real HTTPS TLS version custom rule matching",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-by-tls-version",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_version:TLS13",
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

	resp, body := appProc.waitHTTPSState(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13, 2, "h2", tls.VersionTLS13)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTPS response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusForbidden, body, appProc.output.String())
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("TLS version intercept response missing X-Request-ID header")
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	requireAppProcessAccessLogTrace(t, appProc, accessLog, appProcessAccessLogTraceExpectation{
		label:                       "TLS version intercept",
		requestID:                   requestID,
		siteHost:                    siteHost,
		statusCode:                  http.StatusForbidden,
		wafAction:                   string(store.ActionIntercept),
		securityEventAction:         string(store.ActionIntercept),
		httpProtocol:                "h2",
		tlsVersion:                  "TLS13",
		tlsALPN:                     "h2",
		ja4Prefix:                   't',
		expectMissingTLSClientHello: true,
	})
}

func TestRunServesHTTPSRequestsWithTLSCipherSuitesCustomRuleInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream should not be reached when TLS cipher suite rule intercepts")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls-cipher-suites.blackbox.example.test"
	const requestPath = "/tls-cipher-suites-blackbox"

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
			Name:        "tls-cipher-suites-blackbox-policy",
			Description: "validates real HTTPS TLS cipher suites custom rule matching",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "intercept-by-tls-cipher-suite",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
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
		t.Fatalf("HTTPS response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusForbidden, body, appProc.output.String())
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("TLS cipher suites intercept response missing X-Request-ID header")
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	requireAppProcessAccessLogTrace(t, appProc, accessLog, appProcessAccessLogTraceExpectation{
		label:               "TLS cipher suites intercept",
		requestID:           requestID,
		siteHost:            siteHost,
		statusCode:          http.StatusForbidden,
		wafAction:           string(store.ActionIntercept),
		securityEventAction: string(store.ActionIntercept),
		httpProtocol:        "h2",
		tlsVersion:          "TLS13",
		tlsALPN:             "h2",
		ja4Prefix:           't',
		tlsCipherSuites:     []string{"TLS_AES_128_GCM_SHA256"},
	})
}

func TestRunRecordsHTTPSUpstreamHTTP2ProtocolInSeparateProcess(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "https upstream h2 teapot")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-upstream-h2.blackbox.example.test"
	const requestPath = "/https-upstream-h2-trace"

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

		site := store.Site{
			Host:                  siteHost,
			UpstreamURLs:          upstream.URL,
			UpstreamTLSSkipVerify: true,
			Bind:                  tcpBind,
			Network:               "tcp",
			Enabled:               true,
			TLSEnabled:            true,
			ALPN:                  "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("HTTPS response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusTeapot, body, appProc.output.String())
	}
	if body != "https upstream h2 teapot" {
		t.Fatalf("HTTPS response body = %q, want %q", body, "https upstream h2 teapot")
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS response missing X-Request-ID header")
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	requireAppProcessAccessLogTrace(t, appProc, accessLog, appProcessAccessLogTraceExpectation{
		label:                       "HTTPS upstream h2",
		requestID:                   requestID,
		siteHost:                    siteHost,
		statusCode:                  http.StatusTeapot,
		httpProtocol:                "h2",
		upstreamProtocol:            "HTTP/2.0",
		tlsALPN:                     "h2",
		ja4Prefix:                   't',
		expectMissingTLSClientHello: true,
	})
}

func TestRunRecordsExplicitH2CUpstreamHTTP2ProtocolInSeparateProcess(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "explicit h2c upstream teapot")
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "explicit-h2c-upstream.blackbox.example.test"
	const requestPath = "/explicit-h2c-upstream-trace"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: strings.Replace(upstream.URL, "http://", "h2c://", 1),
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("HTTPS response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusTeapot, body, appProc.output.String())
	}
	if body != "explicit h2c upstream teapot" {
		t.Fatalf("HTTPS response body = %q, want %q", body, "explicit h2c upstream teapot")
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS response missing X-Request-ID header")
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	requireAppProcessAccessLogTrace(t, appProc, accessLog, appProcessAccessLogTraceExpectation{
		label:                       "explicit h2c upstream",
		requestID:                   requestID,
		siteHost:                    siteHost,
		statusCode:                  http.StatusTeapot,
		httpProtocol:                "h2",
		upstreamProtocol:            "HTTP/2.0",
		tlsALPN:                     "h2",
		ja4Prefix:                   't',
		expectMissingTLSClientHello: true,
	})
}

func TestRunRecordsExplicitH3UpstreamHTTP3ProtocolInSeparateProcess(t *testing.T) {
	upstream, upstreamBase := startAppProcessHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/3.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "explicit h3 upstream teapot")
	}))
	defer closeAppProcessHTTP3UpstreamServer(t, upstream)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "explicit-h3-upstream.blackbox.example.test"
	const requestPath = "/explicit-h3-upstream-trace"

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

		site := store.Site{
			Host:                  siteHost,
			UpstreamURLs:          upstreamBase,
			UpstreamTLSSkipVerify: true,
			Bind:                  tcpBind,
			Network:               "tcp",
			Enabled:               true,
			TLSEnabled:            true,
			ALPN:                  "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	resp, body := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("HTTPS response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusTeapot, body, appProc.output.String())
	}
	if body != "explicit h3 upstream teapot" {
		t.Fatalf("HTTPS response body = %q, want %q", body, "explicit h3 upstream teapot")
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS response missing X-Request-ID header")
	}

	accessLog := appProc.waitForSiteAccessLog(t, siteID, requestPath, url.Values{
		"request_id": []string{requestID},
	})
	requireAppProcessAccessLogTrace(t, appProc, accessLog, appProcessAccessLogTraceExpectation{
		label:                       "explicit h3 upstream",
		requestID:                   requestID,
		siteHost:                    siteHost,
		statusCode:                  http.StatusTeapot,
		httpProtocol:                "h2",
		upstreamProtocol:            "HTTP/3.0",
		tlsALPN:                     "h2",
		ja4Prefix:                   't',
		expectMissingTLSClientHello: true,
	})
}

func TestRunHotReloadsResponseCompressionSettingsForNewRequestsInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("response compression hot reload upstream body.", 160)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "compression-reload.example.test"
	const requestPath = "/compression-reload-check"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "false"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	headers := http.Header{}
	headers.Set("Accept-Encoding", "br, gzip")

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	respGzipInitial, bodyGzipInitial := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headers, "gzip")
	requireDecodedHTTPResponseBody(t, respGzipInitial.Header.Get("Content-Encoding"), bodyGzipInitial, upstreamBody)

	var settingResp struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	appProc.postJSON(t, "/api/v1/settings/brotli_enabled/update", []byte(`{"value":"true"}`), &settingResp)
	if settingResp.Key != "brotli_enabled" {
		t.Fatalf("brotli response key = %q, want %q", settingResp.Key, "brotli_enabled")
	}
	if settingResp.Value != "true" {
		t.Fatalf("brotli response value = %q, want %q", settingResp.Value, "true")
	}

	respBrotli, bodyBrotli := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headers, "br")
	requireDecodedHTTPResponseBody(t, respBrotli.Header.Get("Content-Encoding"), bodyBrotli, upstreamBody)

	appProc.postJSON(t, "/api/v1/settings/brotli_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Value != "false" {
		t.Fatalf("brotli disable response value = %q, want %q", settingResp.Value, "false")
	}

	respGzipAfterBrotliDisable, bodyGzipAfterBrotliDisable := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headers, "gzip")
	requireDecodedHTTPResponseBody(t, respGzipAfterBrotliDisable.Header.Get("Content-Encoding"), bodyGzipAfterBrotliDisable, upstreamBody)

	appProc.postJSON(t, "/api/v1/settings/response_compression_gzip_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Key != "response_compression_gzip_enabled" {
		t.Fatalf("gzip setting response key = %q, want %q", settingResp.Key, "response_compression_gzip_enabled")
	}
	if settingResp.Value != "false" {
		t.Fatalf("gzip disable response value = %q, want %q", settingResp.Value, "false")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, false, 1024)

	respIdentityAfterGzipDisable, bodyIdentityAfterGzipDisable := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headers, "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterGzipDisable.Header.Get("Content-Encoding"), bodyIdentityAfterGzipDisable, upstreamBody)

	appProc.postJSON(t, "/api/v1/settings/response_compression_gzip_enabled/update", []byte(`{"value":"true"}`), &settingResp)
	if settingResp.Value != "true" {
		t.Fatalf("gzip enable response value = %q, want %q", settingResp.Value, "true")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	respGzipAfterGzipEnable, bodyGzipAfterGzipEnable := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headers, "gzip")
	requireDecodedHTTPResponseBody(t, respGzipAfterGzipEnable.Header.Get("Content-Encoding"), bodyGzipAfterGzipEnable, upstreamBody)

	appProc.postJSON(t, "/api/v1/settings/response_compression_min_bytes/update", []byte(`{"value":"8192"}`), &settingResp)
	if settingResp.Key != "response_compression_min_bytes" {
		t.Fatalf("min bytes response key = %q, want %q", settingResp.Key, "response_compression_min_bytes")
	}
	if settingResp.Value != "8192" {
		t.Fatalf("min bytes response value = %q, want %q", settingResp.Value, "8192")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, true, 8192)

	respIdentityAfterMinBytesRaise, bodyIdentityAfterMinBytesRaise := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headers, "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterMinBytesRaise.Header.Get("Content-Encoding"), bodyIdentityAfterMinBytesRaise, upstreamBody)

	appProc.postJSON(t, "/api/v1/settings/response_compression_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Key != "response_compression_enabled" {
		t.Fatalf("compression enabled response key = %q, want %q", settingResp.Key, "response_compression_enabled")
	}
	if settingResp.Value != "false" {
		t.Fatalf("compression enabled response value = %q, want %q", settingResp.Value, "false")
	}

	appProc.waitRuntimeResponseCompressionState(t, false, true, 8192)

	respIdentityAfterDisable, bodyIdentityAfterDisable := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headers, "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterDisable.Header.Get("Content-Encoding"), bodyIdentityAfterDisable, upstreamBody)
}

func TestRunHotReloadsHTTPSHTTP2ResponseCompressionSettingsForNewRequestsInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("https h2 compression reload upstream body.", 160)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-compression-reload.example.test"
	const readyPath = "/https-h2-compression-reload-ready"
	const requestPath = "/https-h2-compression-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "false"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-compression-reload-observe",
			Description: "records HTTPS HTTP/2 response compression reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-https-h2-compression-reload-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h2",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-https-h2-compression-reload-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
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

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 compression reload ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}

	targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	waitHTTPSHTTP2Encoding := func(label string, wantEncoding string) (*http.Response, []byte) {
		t.Helper()

		deadline := time.Now().Add(10 * time.Second)
		lastObserved := "no HTTPS h2 compression response observed"
		for time.Now().Before(deadline) {
			if exited, err := appProc.pollExit(); exited {
				t.Fatalf("app helper process exited before HTTPS h2 compression reload request: %v\n%s", err, appProc.output.String())
			}

			req, err := http.NewRequest(http.MethodGet, targetURL, nil)
			if err != nil {
				t.Fatalf("build HTTPS h2 compression reload request: %v", err)
			}
			req.Host = siteHost
			req.Header.Set("Accept-Encoding", "br, gzip")

			resp, err := client.Do(req)
			if err != nil {
				lastObserved = err.Error()
				time.Sleep(100 * time.Millisecond)
				continue
			}

			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read HTTPS h2 compression reload response body: %v", readErr)
			}

			negotiatedProtocol := ""
			negotiatedVersion := uint16(0)
			if resp.TLS != nil {
				negotiatedProtocol = resp.TLS.NegotiatedProtocol
				negotiatedVersion = resp.TLS.Version
			}
			lastObserved = fmt.Sprintf(
				"label=%s status=%d proto_major=%d alpn=%q tls_version=%#x content_encoding=%q body_len=%d",
				label,
				resp.StatusCode,
				resp.ProtoMajor,
				negotiatedProtocol,
				negotiatedVersion,
				resp.Header.Get("Content-Encoding"),
				len(body),
			)
			if resp.StatusCode == http.StatusOK &&
				resp.ProtoMajor == 2 &&
				negotiatedProtocol == "h2" &&
				negotiatedVersion == tls.VersionTLS13 &&
				strings.TrimSpace(resp.Header.Get("Content-Encoding")) == wantEncoding {
				return resp, body
			}
			time.Sleep(100 * time.Millisecond)
		}

		t.Fatalf("HTTPS h2 compression reload %s did not converge to Content-Encoding %q, last observed: %s\n%s", label, wantEncoding, lastObserved, appProc.output.String())
		return nil, nil
	}

	requireHTTPSH2CompressionObserved := func(label string, resp *http.Response) {
		t.Helper()

		requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
		if requestID == "" {
			t.Fatalf("HTTPS h2 compression reload %s response missing X-Request-ID header", label)
		}
		responseSize := int64(0)
		if strings.TrimSpace(resp.Header.Get("Content-Encoding")) == "" && resp.ContentLength > 0 {
			responseSize = resp.ContentLength
		}
		requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
			label:            "HTTPS h2 compression reload " + label,
			siteID:           siteID,
			requestPath:      requestPath,
			requestID:        requestID,
			siteHost:         siteHost,
			statusCode:       http.StatusOK,
			httpProtocol:     "h2",
			tlsVersion:       "TLS13",
			tlsALPN:          "h2",
			ja4Prefix:        't',
			upstreamProtocol: "HTTP/1.1",
			responseSize:     responseSize,
		})
	}

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	respGzipInitial, bodyGzipInitial := waitHTTPSHTTP2Encoding("initial gzip", "gzip")
	requireDecodedHTTPResponseBody(t, respGzipInitial.Header.Get("Content-Encoding"), bodyGzipInitial, upstreamBody)
	requireHTTPSH2CompressionObserved("initial gzip", respGzipInitial)

	var settingResp struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	appProc.postJSON(t, "/api/v1/settings/brotli_enabled/update", []byte(`{"value":"true"}`), &settingResp)
	if settingResp.Key != "brotli_enabled" {
		t.Fatalf("brotli response key = %q, want %q", settingResp.Key, "brotli_enabled")
	}
	if settingResp.Value != "true" {
		t.Fatalf("brotli response value = %q, want %q", settingResp.Value, "true")
	}

	respBrotli, bodyBrotli := waitHTTPSHTTP2Encoding("brotli enabled", "br")
	requireDecodedHTTPResponseBody(t, respBrotli.Header.Get("Content-Encoding"), bodyBrotli, upstreamBody)
	requireHTTPSH2CompressionObserved("brotli enabled", respBrotli)

	appProc.postJSON(t, "/api/v1/settings/brotli_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Value != "false" {
		t.Fatalf("brotli disable response value = %q, want %q", settingResp.Value, "false")
	}

	respGzipAfterBrotliDisable, bodyGzipAfterBrotliDisable := waitHTTPSHTTP2Encoding("brotli disabled", "gzip")
	requireDecodedHTTPResponseBody(t, respGzipAfterBrotliDisable.Header.Get("Content-Encoding"), bodyGzipAfterBrotliDisable, upstreamBody)
	requireHTTPSH2CompressionObserved("brotli disabled", respGzipAfterBrotliDisable)

	appProc.postJSON(t, "/api/v1/settings/response_compression_gzip_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Key != "response_compression_gzip_enabled" {
		t.Fatalf("gzip setting response key = %q, want %q", settingResp.Key, "response_compression_gzip_enabled")
	}
	if settingResp.Value != "false" {
		t.Fatalf("gzip disable response value = %q, want %q", settingResp.Value, "false")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, false, 1024)

	respIdentityAfterGzipDisable, bodyIdentityAfterGzipDisable := waitHTTPSHTTP2Encoding("gzip disabled", "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterGzipDisable.Header.Get("Content-Encoding"), bodyIdentityAfterGzipDisable, upstreamBody)
	requireHTTPSH2CompressionObserved("gzip disabled", respIdentityAfterGzipDisable)

	appProc.postJSON(t, "/api/v1/settings/response_compression_gzip_enabled/update", []byte(`{"value":"true"}`), &settingResp)
	if settingResp.Value != "true" {
		t.Fatalf("gzip enable response value = %q, want %q", settingResp.Value, "true")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	respGzipAfterGzipEnable, bodyGzipAfterGzipEnable := waitHTTPSHTTP2Encoding("gzip re-enabled", "gzip")
	requireDecodedHTTPResponseBody(t, respGzipAfterGzipEnable.Header.Get("Content-Encoding"), bodyGzipAfterGzipEnable, upstreamBody)
	requireHTTPSH2CompressionObserved("gzip re-enabled", respGzipAfterGzipEnable)

	appProc.postJSON(t, "/api/v1/settings/response_compression_min_bytes/update", []byte(`{"value":"8192"}`), &settingResp)
	if settingResp.Key != "response_compression_min_bytes" {
		t.Fatalf("min bytes response key = %q, want %q", settingResp.Key, "response_compression_min_bytes")
	}
	if settingResp.Value != "8192" {
		t.Fatalf("min bytes response value = %q, want %q", settingResp.Value, "8192")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, true, 8192)

	respIdentityAfterMinBytesRaise, bodyIdentityAfterMinBytesRaise := waitHTTPSHTTP2Encoding("min bytes raised", "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterMinBytesRaise.Header.Get("Content-Encoding"), bodyIdentityAfterMinBytesRaise, upstreamBody)
	requireHTTPSH2CompressionObserved("min bytes raised", respIdentityAfterMinBytesRaise)

	appProc.postJSON(t, "/api/v1/settings/response_compression_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Key != "response_compression_enabled" {
		t.Fatalf("compression enabled response key = %q, want %q", settingResp.Key, "response_compression_enabled")
	}
	if settingResp.Value != "false" {
		t.Fatalf("compression enabled response value = %q, want %q", settingResp.Value, "false")
	}

	appProc.waitRuntimeResponseCompressionState(t, false, true, 8192)

	respIdentityAfterDisable, bodyIdentityAfterDisable := waitHTTPSHTTP2Encoding("compression disabled", "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterDisable.Header.Get("Content-Encoding"), bodyIdentityAfterDisable, upstreamBody)
	requireHTTPSH2CompressionObserved("compression disabled", respIdentityAfterDisable)
}

func TestRunHotReloadsHTTP3ResponseCompressionSettingsForNewStreamsInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("h3 compression reload body.", 160)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-compression-reload.example.test"
	const readyPath = "/h3-compression-reload-ready"
	const requestPath = "/h3-compression-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "false"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-compression-reload-observe",
			Description: "records HTTP/3 response compression reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-h3-compression-reload-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-h3-compression-reload-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 compression reload ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	waitHTTP3Encoding := func(label string, wantEncoding string) (*http.Response, []byte) {
		t.Helper()

		deadline := time.Now().Add(10 * time.Second)
		lastObserved := "no HTTP/3 compression response observed"
		for time.Now().Before(deadline) {
			if exited, err := appProc.pollExit(); exited {
				t.Fatalf("app helper process exited before HTTP/3 compression reload request: %v\n%s", err, appProc.output.String())
			}

			req, err := http.NewRequest(http.MethodGet, targetURL, nil)
			if err != nil {
				t.Fatalf("build HTTP/3 compression reload request: %v", err)
			}
			req.Host = siteHost
			req.Header.Set("Accept-Encoding", "br, gzip")

			resp, err := client.Do(req)
			if err != nil {
				lastObserved = err.Error()
				time.Sleep(100 * time.Millisecond)
				continue
			}

			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read HTTP/3 compression reload response body: %v", readErr)
			}

			negotiatedProtocol := ""
			negotiatedVersion := uint16(0)
			if resp.TLS != nil {
				negotiatedProtocol = resp.TLS.NegotiatedProtocol
				negotiatedVersion = resp.TLS.Version
			}
			lastObserved = fmt.Sprintf(
				"label=%s status=%d proto_major=%d alpn=%q tls_version=%#x content_encoding=%q body_len=%d",
				label,
				resp.StatusCode,
				resp.ProtoMajor,
				negotiatedProtocol,
				negotiatedVersion,
				resp.Header.Get("Content-Encoding"),
				len(body),
			)
			if resp.StatusCode == http.StatusOK &&
				resp.ProtoMajor == 3 &&
				negotiatedProtocol == "h3" &&
				negotiatedVersion == tls.VersionTLS13 &&
				strings.TrimSpace(resp.Header.Get("Content-Encoding")) == wantEncoding {
				if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
					t.Fatalf("HTTP/3 compression reload Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
				}
				return resp, body
			}
			time.Sleep(100 * time.Millisecond)
		}

		t.Fatalf("HTTP/3 compression reload %s did not converge to Content-Encoding %q, last observed: %s\n%s", label, wantEncoding, lastObserved, appProc.output.String())
		return nil, nil
	}

	requireH3CompressionObserved := func(label string, resp *http.Response) {
		t.Helper()

		requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
		if requestID == "" {
			t.Fatalf("HTTP/3 compression reload %s response missing X-Request-ID header", label)
		}
		requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
			label:        "HTTP/3 compression reload " + label,
			siteID:       siteID,
			requestPath:  requestPath,
			requestID:    requestID,
			siteHost:     siteHost,
			statusCode:   http.StatusOK,
			httpProtocol: "h3",
			tlsVersion:   "TLS13",
			tlsALPN:      "h3",
			ja4Prefix:    'q',
			responseSize: 0,
		})
	}

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	respGzipInitial, bodyGzipInitial := waitHTTP3Encoding("initial gzip", "gzip")
	requireDecodedHTTPResponseBody(t, respGzipInitial.Header.Get("Content-Encoding"), bodyGzipInitial, upstreamBody)
	requireH3CompressionObserved("initial gzip", respGzipInitial)

	var settingResp struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	appProc.postJSON(t, "/api/v1/settings/brotli_enabled/update", []byte(`{"value":"true"}`), &settingResp)
	if settingResp.Key != "brotli_enabled" {
		t.Fatalf("brotli response key = %q, want %q", settingResp.Key, "brotli_enabled")
	}
	if settingResp.Value != "true" {
		t.Fatalf("brotli response value = %q, want %q", settingResp.Value, "true")
	}

	respBrotli, bodyBrotli := waitHTTP3Encoding("brotli enabled", "br")
	requireDecodedHTTPResponseBody(t, respBrotli.Header.Get("Content-Encoding"), bodyBrotli, upstreamBody)
	requireH3CompressionObserved("brotli enabled", respBrotli)

	appProc.postJSON(t, "/api/v1/settings/brotli_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Value != "false" {
		t.Fatalf("brotli disable response value = %q, want %q", settingResp.Value, "false")
	}

	respGzipAfterBrotliDisable, bodyGzipAfterBrotliDisable := waitHTTP3Encoding("brotli disabled", "gzip")
	requireDecodedHTTPResponseBody(t, respGzipAfterBrotliDisable.Header.Get("Content-Encoding"), bodyGzipAfterBrotliDisable, upstreamBody)
	requireH3CompressionObserved("brotli disabled", respGzipAfterBrotliDisable)

	appProc.postJSON(t, "/api/v1/settings/response_compression_gzip_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Key != "response_compression_gzip_enabled" {
		t.Fatalf("gzip setting response key = %q, want %q", settingResp.Key, "response_compression_gzip_enabled")
	}
	if settingResp.Value != "false" {
		t.Fatalf("gzip disable response value = %q, want %q", settingResp.Value, "false")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, false, 1024)

	respIdentityAfterGzipDisable, bodyIdentityAfterGzipDisable := waitHTTP3Encoding("gzip disabled", "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterGzipDisable.Header.Get("Content-Encoding"), bodyIdentityAfterGzipDisable, upstreamBody)
	requireH3CompressionObserved("gzip disabled", respIdentityAfterGzipDisable)

	appProc.postJSON(t, "/api/v1/settings/response_compression_gzip_enabled/update", []byte(`{"value":"true"}`), &settingResp)
	if settingResp.Value != "true" {
		t.Fatalf("gzip enable response value = %q, want %q", settingResp.Value, "true")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	respGzipAfterGzipEnable, bodyGzipAfterGzipEnable := waitHTTP3Encoding("gzip re-enabled", "gzip")
	requireDecodedHTTPResponseBody(t, respGzipAfterGzipEnable.Header.Get("Content-Encoding"), bodyGzipAfterGzipEnable, upstreamBody)
	requireH3CompressionObserved("gzip re-enabled", respGzipAfterGzipEnable)

	appProc.postJSON(t, "/api/v1/settings/response_compression_min_bytes/update", []byte(`{"value":"8192"}`), &settingResp)
	if settingResp.Key != "response_compression_min_bytes" {
		t.Fatalf("min bytes response key = %q, want %q", settingResp.Key, "response_compression_min_bytes")
	}
	if settingResp.Value != "8192" {
		t.Fatalf("min bytes response value = %q, want %q", settingResp.Value, "8192")
	}

	appProc.waitRuntimeResponseCompressionState(t, true, true, 8192)

	respIdentityAfterMinBytesRaise, bodyIdentityAfterMinBytesRaise := waitHTTP3Encoding("min bytes raised", "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterMinBytesRaise.Header.Get("Content-Encoding"), bodyIdentityAfterMinBytesRaise, upstreamBody)
	requireH3CompressionObserved("min bytes raised", respIdentityAfterMinBytesRaise)

	appProc.postJSON(t, "/api/v1/settings/response_compression_enabled/update", []byte(`{"value":"false"}`), &settingResp)
	if settingResp.Key != "response_compression_enabled" {
		t.Fatalf("compression enabled response key = %q, want %q", settingResp.Key, "response_compression_enabled")
	}
	if settingResp.Value != "false" {
		t.Fatalf("compression enabled response value = %q, want %q", settingResp.Value, "false")
	}

	appProc.waitRuntimeResponseCompressionState(t, false, true, 8192)

	respIdentityAfterDisable, bodyIdentityAfterDisable := waitHTTP3Encoding("compression disabled", "")
	requireDecodedHTTPResponseBody(t, respIdentityAfterDisable.Header.Get("Content-Encoding"), bodyIdentityAfterDisable, upstreamBody)
	requireH3CompressionObserved("compression disabled", respIdentityAfterDisable)
}

func TestRunCompressesHTTPSHTTP2ResponseForBrotliClientInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("https h2 brotli response compression upstream body.", 160)
	type upstreamObservation struct {
		path           string
		acceptEncoding string
	}
	upstreamSeen := make(chan upstreamObservation, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			path:           r.URL.Path,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamBody)))
		_, _ = io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-brotli-compression.example.test"
	const requestPath = "/https-h2-brotli-compression-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-brotli-compression-observe",
			Description: "records HTTPS HTTP/2 Brotli compression requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-https-h2-brotli-compression-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h2",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-https-h2-brotli-compression-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
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

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	headers := http.Header{}
	headers.Set("Accept-Encoding", "br, gzip")
	resp, body := appProc.waitHTTPSResponseEncoding(t, tcpBind, siteHost, requestPath, headers, 2, "h2", "br")
	if resp.TLS == nil {
		t.Fatal("expected HTTPS h2 Brotli TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTPS h2 Brotli TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if got := strings.TrimSpace(resp.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("HTTPS h2 Brotli response vary = %q, want Accept-Encoding", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Length")); got != "" {
		t.Fatalf("HTTPS h2 Brotli response Content-Length = %q, want empty", got)
	}
	if len(body) >= len(upstreamBody) {
		t.Fatalf("HTTPS h2 Brotli response body length = %d, want smaller than %d", len(body), len(upstreamBody))
	}
	requireDecodedHTTPResponseBody(t, resp.Header.Get("Content-Encoding"), body, upstreamBody)

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 Brotli response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTPS h2 Brotli compression",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h2",
		tlsVersion:       "TLS13",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})

	deadline := time.After(2 * time.Second)
	observedTargetRequest := false
	for {
		select {
		case got := <-upstreamSeen:
			if got.path != requestPath {
				continue
			}
			if got.acceptEncoding != "br, gzip" {
				t.Fatalf("upstream HTTPS h2 Brotli Accept-Encoding = %q, want %q", got.acceptEncoding, "br, gzip")
			}
			observedTargetRequest = true
		case <-deadline:
			t.Fatal("upstream did not observe HTTPS h2 Brotli request")
		}
		if observedTargetRequest {
			break
		}
	}
}

func TestRunCompressesHTTP3ResponseForBrotliClientInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("http3 brotli response compression upstream body.", 160)
	type upstreamObservation struct {
		path           string
		rawQuery       string
		acceptEncoding string
	}
	upstreamSeen := make(chan upstreamObservation, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			path:           r.URL.Path,
			rawQuery:       r.URL.RawQuery,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamBody)))
		_, _ = io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-brotli-compression.example.test"
	const readyPath = "/h3-brotli-compression-ready"
	const requestPath = "/h3-brotli-compression-check/a%2Fb?keep=1;semi=2&encoded=a%2Fb"
	const requestAccessLogPath = "/h3-brotli-compression-check/a%2Fb"
	const requestQueryString = "keep=1;semi=2&encoded=a%2Fb"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-brotli-compression-observe",
			Description: "records HTTP/3 Brotli compression requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-h3-brotli-compression-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-h3-brotli-compression-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 Brotli ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 Brotli request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "br, gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 Brotli request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 Brotli response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 Brotli response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 Brotli TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 Brotli TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 Brotli negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 Brotli response status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if resp.Header.Get("Content-Encoding") != "br" {
		t.Fatalf("HTTP/3 Brotli response Content-Encoding = %q, want %q", resp.Header.Get("Content-Encoding"), "br")
	}
	if got := strings.TrimSpace(resp.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("HTTP/3 Brotli response Vary = %q, want Accept-Encoding", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Length")); got != "" {
		t.Fatalf("HTTP/3 Brotli response Content-Length = %q, want empty", got)
	}
	if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
		t.Fatalf("HTTP/3 Brotli response Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
	}
	if len(body) >= len(upstreamBody) {
		t.Fatalf("HTTP/3 Brotli response body length = %d, want smaller than %d", len(body), len(upstreamBody))
	}
	requireDecodedHTTPResponseBody(t, resp.Header.Get("Content-Encoding"), body, upstreamBody)

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP/3 Brotli response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 Brotli compression",
		siteID:           siteID,
		requestPath:      requestAccessLogPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h3",
		tlsVersion:       "TLS13",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		queryString:      requestQueryString,
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})

	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-upstreamSeen:
			if got.path != "/h3-brotli-compression-check/a/b" {
				continue
			}
			if got.rawQuery != requestQueryString {
				t.Fatalf("upstream HTTP/3 Brotli raw query = %q, want %q", got.rawQuery, requestQueryString)
			}
			if got.acceptEncoding != "br, gzip" {
				t.Fatalf("upstream HTTP/3 Brotli Accept-Encoding = %q, want %q", got.acceptEncoding, "br, gzip")
			}
			return
		case <-deadline:
			t.Fatal("upstream did not observe HTTP/3 Brotli request")
		}
	}
}

func TestRunSkipsHTTPSHTTP2CompressionForNoTransformResponseInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("https h2 no-transform response compression bypass upstream body.", 120)
	type upstreamObservation struct {
		path           string
		acceptEncoding string
	}
	upstreamSeen := make(chan upstreamObservation, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			path:           r.URL.Path,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "private, no-transform")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamBody)))
		_, _ = io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-no-transform-compression.example.test"
	const requestPath = "/https-h2-no-transform-compression-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-no-transform-compression-observe",
			Description: "records HTTPS HTTP/2 no-transform compression bypass requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-https-h2-no-transform-compression-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h2",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-https-h2-no-transform-compression-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
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

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	headers := http.Header{}
	headers.Set("Accept-Encoding", "br, gzip")
	resp, body := appProc.waitHTTPSResponseEncoding(t, tcpBind, siteHost, requestPath, headers, 2, "h2", "")
	if resp.TLS == nil {
		t.Fatal("expected HTTPS h2 no-transform TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTPS h2 no-transform TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if got := strings.TrimSpace(resp.Header.Get("Vary")); got != "" {
		t.Fatalf("HTTPS h2 no-transform response Vary = %q, want empty", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Cache-Control")); got != "private, no-transform" {
		t.Fatalf("HTTPS h2 no-transform response Cache-Control = %q, want %q", got, "private, no-transform")
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Length")); got != strconv.Itoa(len(upstreamBody)) {
		t.Fatalf("HTTPS h2 no-transform response Content-Length = %q, want %d", got, len(upstreamBody))
	}
	if string(body) != upstreamBody {
		t.Fatalf("HTTPS h2 no-transform response body mismatch: got_len=%d want_len=%d", len(body), len(upstreamBody))
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTPS h2 no-transform response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTPS h2 no-transform compression bypass",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h2",
		tlsVersion:       "TLS13",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(upstreamBody)),
	})

	deadline := time.After(2 * time.Second)
	observedTargetRequest := false
	for {
		select {
		case got := <-upstreamSeen:
			if got.path != requestPath {
				continue
			}
			if got.acceptEncoding != "br, gzip" {
				t.Fatalf("upstream HTTPS h2 no-transform Accept-Encoding = %q, want %q", got.acceptEncoding, "br, gzip")
			}
			observedTargetRequest = true
		case <-deadline:
			t.Fatal("upstream did not observe HTTPS h2 no-transform request")
		}
		if observedTargetRequest {
			break
		}
	}
}

func TestRunSkipsHTTP3CompressionForNoTransformResponseInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("http3 no-transform response compression bypass upstream body.", 120)
	type upstreamObservation struct {
		path           string
		rawQuery       string
		acceptEncoding string
	}
	upstreamSeen := make(chan upstreamObservation, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-no-transform-compression-check/a/b" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 no-transform compression ready")
			return
		}

		upstreamSeen <- upstreamObservation{
			path:           r.URL.Path,
			rawQuery:       r.URL.RawQuery,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "private, no-transform")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamBody)))
		_, _ = io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-no-transform-compression.example.test"
	const readyPath = "/h3-no-transform-compression-ready"
	const requestPath = "/h3-no-transform-compression-check/a%2Fb?keep=1;semi=2&encoded=a%2Fb"
	const requestAccessLogPath = "/h3-no-transform-compression-check/a%2Fb"
	const requestQueryString = "keep=1;semi=2&encoded=a%2Fb"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-no-transform-compression-observe",
			Description: "records HTTP/3 no-transform compression bypass requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-h3-no-transform-compression-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-h3-no-transform-compression-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 no-transform ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 no-transform compression ready" {
		t.Fatalf("HTTP/3 no-transform ready body = %q, want %q", readyBody, "h3 no-transform compression ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 no-transform request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "br, gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 no-transform request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 no-transform response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 no-transform response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 no-transform TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 no-transform TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 no-transform negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 no-transform response status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("HTTP/3 no-transform response Content-Encoding = %q, want empty", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Vary")); got != "" {
		t.Fatalf("HTTP/3 no-transform response Vary = %q, want empty", got)
	}
	if got := strings.TrimSpace(resp.Header.Get("Cache-Control")); got != "private, no-transform" {
		t.Fatalf("HTTP/3 no-transform response Cache-Control = %q, want %q", got, "private, no-transform")
	}
	if got := strings.TrimSpace(resp.Header.Get("Content-Length")); got != strconv.Itoa(len(upstreamBody)) {
		t.Fatalf("HTTP/3 no-transform response Content-Length = %q, want %d", got, len(upstreamBody))
	}
	if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
		t.Fatalf("HTTP/3 no-transform response Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
	}
	if string(body) != upstreamBody {
		t.Fatalf("HTTP/3 no-transform response body mismatch: got_len=%d want_len=%d", len(body), len(upstreamBody))
	}

	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		t.Fatal("HTTP/3 no-transform response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 no-transform compression bypass",
		siteID:           siteID,
		requestPath:      requestAccessLogPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h3",
		tlsVersion:       "TLS13",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		queryString:      requestQueryString,
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(upstreamBody)),
	})

	select {
	case got := <-upstreamSeen:
		if got.path != "/h3-no-transform-compression-check/a/b" {
			t.Fatalf("upstream HTTP/3 no-transform path = %q, want %q", got.path, "/h3-no-transform-compression-check/a/b")
		}
		if got.rawQuery != requestQueryString {
			t.Fatalf("upstream HTTP/3 no-transform raw query = %q, want %q", got.rawQuery, requestQueryString)
		}
		if got.acceptEncoding != "br, gzip" {
			t.Fatalf("upstream HTTP/3 no-transform Accept-Encoding = %q, want %q", got.acceptEncoding, "br, gzip")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 no-transform request")
	}
}

func TestRunRecompressesDecodedUpstreamCompressedResponsesInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("decoded upstream compressed response body.", 192)
	upstreamEncodedBody := mustGzipAppProcessBytes(t, []byte(upstreamBody))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamEncodedBody)))
		_, _ = w.Write(upstreamEncodedBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "compression-upstream-reencode.example.test"
	const requestPath = "/compression-upstream-reencode-check"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	headersBrotli := http.Header{}
	headersBrotli.Set("Accept-Encoding", "br, gzip")
	respBrotli, bodyBrotli := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersBrotli, "br")
	requireDecodedHTTPResponseBody(t, respBrotli.Header.Get("Content-Encoding"), bodyBrotli, upstreamBody)
	if got := strings.TrimSpace(respBrotli.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("brotli response vary = %q, want Accept-Encoding", got)
	}

	headersGzip := http.Header{}
	headersGzip.Set("Accept-Encoding", "gzip")
	respGzip, bodyGzip := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersGzip, "gzip")
	requireDecodedHTTPResponseBody(t, respGzip.Header.Get("Content-Encoding"), bodyGzip, upstreamBody)
	if got := strings.TrimSpace(respGzip.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("gzip response vary = %q, want Accept-Encoding", got)
	}

	headersIdentity := http.Header{}
	headersIdentity.Set("Accept-Encoding", "identity")
	respIdentity, bodyIdentity := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersIdentity, "")
	requireDecodedHTTPResponseBody(t, respIdentity.Header.Get("Content-Encoding"), bodyIdentity, upstreamBody)
	if got := strings.TrimSpace(respIdentity.Header.Get("Vary")); got != "" {
		t.Fatalf("identity response vary = %q, want empty", got)
	}
}

func TestRunRecompressesDecodedUpstreamBrotliResponsesInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("decoded upstream brotli response body.", 192)
	upstreamEncodedBody := mustBrotliAppProcessBytes(t, []byte(upstreamBody))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamEncodedBody)))
		_, _ = w.Write(upstreamEncodedBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "compression-upstream-brotli-reencode.example.test"
	const requestPath = "/compression-upstream-brotli-reencode-check"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	headersBrotli := http.Header{}
	headersBrotli.Set("Accept-Encoding", "br, gzip")
	respBrotli, bodyBrotli := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersBrotli, "br")
	requireDecodedHTTPResponseBody(t, respBrotli.Header.Get("Content-Encoding"), bodyBrotli, upstreamBody)
	if got := strings.TrimSpace(respBrotli.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("brotli response vary = %q, want Accept-Encoding", got)
	}

	headersGzip := http.Header{}
	headersGzip.Set("Accept-Encoding", "gzip")
	respGzip, bodyGzip := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersGzip, "gzip")
	requireDecodedHTTPResponseBody(t, respGzip.Header.Get("Content-Encoding"), bodyGzip, upstreamBody)
	if got := strings.TrimSpace(respGzip.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("gzip response vary = %q, want Accept-Encoding", got)
	}

	headersIdentity := http.Header{}
	headersIdentity.Set("Accept-Encoding", "identity")
	respIdentity, bodyIdentity := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersIdentity, "")
	requireDecodedHTTPResponseBody(t, respIdentity.Header.Get("Content-Encoding"), bodyIdentity, upstreamBody)
	if got := strings.TrimSpace(respIdentity.Header.Get("Vary")); got != "" {
		t.Fatalf("identity response vary = %q, want empty", got)
	}
}

func TestRunRecompressesDecodedUpstreamMultiEncodedResponsesInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("decoded upstream multi-encoded response body.", 192)
	upstreamEncodedBody := mustEncodeAppProcessBytes(t, []byte(upstreamBody), "gzip", "br")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip, br")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamEncodedBody)))
		_, _ = w.Write(upstreamEncodedBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "compression-upstream-multi-reencode.example.test"
	const requestPath = "/compression-upstream-multi-reencode-check"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	headersBrotli := http.Header{}
	headersBrotli.Set("Accept-Encoding", "br, gzip")
	respBrotli, bodyBrotli := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersBrotli, "br")
	requireDecodedHTTPResponseBody(t, respBrotli.Header.Get("Content-Encoding"), bodyBrotli, upstreamBody)
	if got := strings.TrimSpace(respBrotli.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("brotli response vary = %q, want Accept-Encoding", got)
	}

	headersGzip := http.Header{}
	headersGzip.Set("Accept-Encoding", "gzip")
	respGzip, bodyGzip := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersGzip, "gzip")
	requireDecodedHTTPResponseBody(t, respGzip.Header.Get("Content-Encoding"), bodyGzip, upstreamBody)
	if got := strings.TrimSpace(respGzip.Header.Get("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("gzip response vary = %q, want Accept-Encoding", got)
	}

	headersIdentity := http.Header{}
	headersIdentity.Set("Accept-Encoding", "identity")
	respIdentity, bodyIdentity := appProc.waitHTTPResponseEncoding(t, tcpBind, siteHost, requestPath, headersIdentity, "")
	requireDecodedHTTPResponseBody(t, respIdentity.Header.Get("Content-Encoding"), bodyIdentity, upstreamBody)
	if got := strings.TrimSpace(respIdentity.Header.Get("Vary")); got != "" {
		t.Fatalf("identity response vary = %q, want empty", got)
	}
}

func TestRunRecompressesCachedDecodedUpstreamCompressedResponsesInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("cached decoded upstream compressed response body.", 192)
	upstreamEncodedBody := mustGzipAppProcessBytes(t, []byte(upstreamBody))
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamEncodedBody)))
		_, _ = w.Write(upstreamEncodedBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "compression-cache-reencode.example.test"
	const requestPath = "/cached-compression/asset.txt"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

		cacheRulesBytes, err := json.Marshal([]store.SiteCacheRule{
			{Type: "prefix", Value: "/cached-compression", TTL: 120},
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

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	headers := http.Header{}
	headers.Set("Accept-Encoding", "br, gzip")

	respMiss, bodyMiss := appProc.waitHTTPResponse(t, tcpBind, siteHost, requestPath, headers, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK &&
			strings.TrimSpace(resp.Header.Get("Content-Encoding")) == "br" &&
			strings.TrimSpace(resp.Header.Get("X-Request-ID")) != ""
	})
	requireDecodedHTTPResponseBody(t, respMiss.Header.Get("Content-Encoding"), bodyMiss, upstreamBody)
	if requestIDMiss := strings.TrimSpace(respMiss.Header.Get("X-Request-ID")); requestIDMiss == "" {
		t.Fatal("cache miss response missing X-Request-ID header")
	}
	countBeforeHit := upstreamRequests.Load()
	if countBeforeHit < 1 {
		t.Fatalf("upstream request count after cache fill = %d, want >= 1", countBeforeHit)
	}

	respHit, bodyHit := appProc.waitHTTPResponse(t, tcpBind, siteHost, requestPath, headers, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK &&
			strings.TrimSpace(resp.Header.Get("Content-Encoding")) == "br" &&
			strings.TrimSpace(resp.Header.Get("X-Request-ID")) != ""
	})
	requireDecodedHTTPResponseBody(t, respHit.Header.Get("Content-Encoding"), bodyHit, upstreamBody)
	if requestIDHit := strings.TrimSpace(respHit.Header.Get("X-Request-ID")); requestIDHit == "" {
		t.Fatal("cache hit response missing X-Request-ID header")
	}
	countAfterHit := upstreamRequests.Load()
	if countAfterHit != countBeforeHit {
		t.Fatalf("upstream request count changed across cache hit: before=%d after=%d", countBeforeHit, countAfterHit)
	}

	identityHeaders := http.Header{}
	identityHeaders.Set("Accept-Encoding", "identity")
	respIdentityHit, bodyIdentityHit := appProc.waitHTTPResponse(t, tcpBind, siteHost, requestPath, identityHeaders, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK &&
			strings.TrimSpace(resp.Header.Get("Content-Encoding")) == "" &&
			strings.TrimSpace(resp.Header.Get("X-Request-ID")) != ""
	})
	requireDecodedHTTPResponseBody(t, respIdentityHit.Header.Get("Content-Encoding"), bodyIdentityHit, upstreamBody)
	if got := strings.TrimSpace(respIdentityHit.Header.Get("Vary")); got != "" {
		t.Fatalf("identity cache hit response vary = %q, want empty", got)
	}
	countAfterIdentityHit := upstreamRequests.Load()
	if countAfterIdentityHit != countBeforeHit {
		t.Fatalf("upstream request count changed across identity cache hit: before=%d after=%d", countBeforeHit, countAfterIdentityHit)
	}
}

func TestRunRecompressesHTTPSHTTP2CachedDecodedUpstreamCompressedResponsesInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("https h2 cached decoded upstream compressed response body.", 192)
	upstreamEncodedBody := mustGzipAppProcessBytes(t, []byte(upstreamBody))
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/https-h2-cached-compression/asset.txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "https h2 cached compression ready")
			return
		}

		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamEncodedBody)))
		_, _ = w.Write(upstreamEncodedBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "https-h2-compression-cache-reencode.example.test"
	const readyPath = "/https-h2-cached-compression-ready"
	const requestPath = "/https-h2-cached-compression/asset.txt"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		cacheRulesBytes, err := json.Marshal([]store.SiteCacheRule{
			{Type: "prefix", Value: "/https-h2-cached-compression", TTL: 120},
		})
		if err != nil {
			return fmt.Errorf("marshal cache rules: %w", err)
		}

		policy := store.Policy{
			Name:        "https-h2-cache-compression-observe",
			Description: "records HTTPS HTTP/2 cache compression requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-https-h2-cache-compression",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
			Action:   store.ActionObserve,
			Priority: 1,
			Enabled:  true,
		}
		if err := db.Create(&rule).Error; err != nil {
			return fmt.Errorf("create rule: %w", err)
		}

		site := store.Site{
			Host:            siteHost,
			UpstreamURLs:    upstream.URL,
			Bind:            tcpBind,
			Network:         "tcp",
			Enabled:         true,
			TLSEnabled:      true,
			ALPN:            "h2,http/1.1",
			CacheEnabled:    true,
			CacheDefaultTTL: 120,
			CacheRules:      string(cacheRulesBytes),
			PolicyID:        &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 cached compression ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "https h2 cached compression ready" {
		t.Fatalf("HTTPS h2 cached compression ready body = %q, want %q", readyBody, "https h2 cached compression ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	doHTTPSHTTP2CachedRequest := func(acceptEncoding string) (*http.Response, []byte, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTPS h2 cached compression request: %v", err)
		}
		req.Host = siteHost
		req.Header.Set("Accept-Encoding", acceptEncoding)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("send HTTPS h2 cached compression request: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read HTTPS h2 cached compression response body: %v", err)
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("HTTPS h2 cached compression response protocol major = %d, want 2", resp.ProtoMajor)
		}
		if resp.TLS == nil {
			t.Fatal("expected HTTPS h2 cached compression TLS connection state")
		}
		if resp.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("HTTPS h2 cached compression TLS version = %#x, want TLS 1.3", resp.TLS.Version)
		}
		if resp.TLS.NegotiatedProtocol != "h2" {
			t.Fatalf("HTTPS h2 cached compression negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h2")
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTPS h2 cached compression response status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
		}
		requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
		if requestID == "" {
			t.Fatal("HTTPS h2 cached compression response missing X-Request-ID header")
		}
		return resp, body, requestID
	}

	respMiss, bodyMiss, requestIDMiss := doHTTPSHTTP2CachedRequest("br, gzip")
	if strings.TrimSpace(respMiss.Header.Get("Content-Encoding")) != "br" {
		t.Fatalf("HTTPS h2 cache miss Content-Encoding = %q, want %q", respMiss.Header.Get("Content-Encoding"), "br")
	}
	requireDecodedHTTPResponseBody(t, respMiss.Header.Get("Content-Encoding"), bodyMiss, upstreamBody)
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTPS h2 cache compression miss",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestIDMiss,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		cacheState:       "miss",
		httpProtocol:     "h2",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(bodyMiss)),
	})
	countBeforeHit := upstreamRequests.Load()
	if countBeforeHit < 1 {
		t.Fatalf("upstream request count after HTTPS h2 cache fill = %d, want >= 1", countBeforeHit)
	}

	respHit, bodyHit, requestIDHit := doHTTPSHTTP2CachedRequest("br, gzip")
	if strings.TrimSpace(respHit.Header.Get("Content-Encoding")) != "br" {
		t.Fatalf("HTTPS h2 cache hit Content-Encoding = %q, want %q", respHit.Header.Get("Content-Encoding"), "br")
	}
	requireDecodedHTTPResponseBody(t, respHit.Header.Get("Content-Encoding"), bodyHit, upstreamBody)
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:                      "HTTPS h2 cache compression hit",
		siteID:                     siteID,
		requestPath:                requestPath,
		requestID:                  requestIDHit,
		siteHost:                   siteHost,
		statusCode:                 http.StatusOK,
		cacheState:                 "hit",
		httpProtocol:               "h2",
		tlsALPN:                    "h2",
		ja4Prefix:                  't',
		allowEmptyUpstreamProtocol: true,
		responseSize:               int64(len(bodyHit)),
	})
	countAfterHit := upstreamRequests.Load()
	if countAfterHit != countBeforeHit {
		t.Fatalf("upstream request count changed across HTTPS h2 cache hit: before=%d after=%d", countBeforeHit, countAfterHit)
	}

	respIdentityHit, bodyIdentityHit, requestIDIdentityHit := doHTTPSHTTP2CachedRequest("identity")
	if got := strings.TrimSpace(respIdentityHit.Header.Get("Content-Encoding")); got != "" {
		t.Fatalf("HTTPS h2 identity cache hit Content-Encoding = %q, want empty", got)
	}
	requireDecodedHTTPResponseBody(t, respIdentityHit.Header.Get("Content-Encoding"), bodyIdentityHit, upstreamBody)
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:                      "HTTPS h2 identity cache compression hit",
		siteID:                     siteID,
		requestPath:                requestPath,
		requestID:                  requestIDIdentityHit,
		siteHost:                   siteHost,
		statusCode:                 http.StatusOK,
		cacheState:                 "hit",
		httpProtocol:               "h2",
		tlsALPN:                    "h2",
		ja4Prefix:                  't',
		allowEmptyUpstreamProtocol: true,
		responseSize:               int64(len(bodyIdentityHit)),
	})
	if got := strings.TrimSpace(respIdentityHit.Header.Get("Vary")); got != "" {
		t.Fatalf("HTTPS h2 identity cache hit Vary = %q, want empty", got)
	}
	countAfterIdentityHit := upstreamRequests.Load()
	if countAfterIdentityHit != countBeforeHit {
		t.Fatalf("upstream request count changed across HTTPS h2 identity cache hit: before=%d after=%d", countBeforeHit, countAfterIdentityHit)
	}
}

func TestRunRecompressesHTTP3CachedDecodedUpstreamCompressedResponsesInSeparateProcess(t *testing.T) {
	upstreamBody := strings.Repeat("http3 cached decoded upstream compressed response body.", 192)
	upstreamEncodedBody := mustGzipAppProcessBytes(t, []byte(upstreamBody))
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-cached-compression/asset.txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 cached compression ready")
			return
		}

		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamEncodedBody)))
		_, _ = w.Write(upstreamEncodedBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "h3-compression-cache-reencode.example.test"
	const readyPath = "/h3-cached-compression-ready"
	const requestPath = "/h3-cached-compression/asset.txt"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		settings := []store.SystemSettings{
			{Key: "brotli_enabled", Value: "true"},
			{Key: "response_compression_enabled", Value: "true"},
			{Key: "response_compression_gzip_enabled", Value: "true"},
			{Key: "response_compression_min_bytes", Value: "1024"},
		}
		for _, item := range settings {
			if err := db.Create(&item).Error; err != nil {
				return fmt.Errorf("create system setting %q: %w", item.Key, err)
			}
		}

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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		cacheRulesBytes, err := json.Marshal([]store.SiteCacheRule{
			{Type: "prefix", Value: "/h3-cached-compression", TTL: 120},
		})
		if err != nil {
			return fmt.Errorf("marshal cache rules: %w", err)
		}

		policy := store.Policy{
			Name:        "h3-cache-compression-observe",
			Description: "records HTTP/3 cache compression requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-h3-cache-compression",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
			Action:   store.ActionObserve,
			Priority: 1,
			Enabled:  true,
		}
		if err := db.Create(&rule).Error; err != nil {
			return fmt.Errorf("create rule: %w", err)
		}

		site := store.Site{
			Host:            siteHost,
			UpstreamURLs:    upstream.URL,
			Bind:            tcpBind,
			Network:         "tcp",
			Enabled:         true,
			TLSEnabled:      true,
			ALPN:            "h2,h3,http/1.1",
			CacheEnabled:    true,
			CacheDefaultTTL: 120,
			CacheRules:      string(cacheRulesBytes),
			PolicyID:        &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	appProc.waitRuntimeResponseCompressionState(t, true, true, 1024)

	readyResp, readyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 cached compression ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "h3 cached compression ready" {
		t.Fatalf("HTTP/3 cached compression ready body = %q, want %q", readyBody, "h3 cached compression ready")
	}

	targetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	doHTTP3CachedRequest := func(acceptEncoding string) (*http.Response, []byte, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTP/3 cached compression request: %v", err)
		}
		req.Host = siteHost
		req.Header.Set("Accept-Encoding", acceptEncoding)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("send HTTP/3 cached compression request: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read HTTP/3 cached compression response body: %v", err)
		}
		if resp.ProtoMajor != 3 {
			t.Fatalf("HTTP/3 cached compression response protocol major = %d, want 3", resp.ProtoMajor)
		}
		if resp.TLS == nil {
			t.Fatal("expected HTTP/3 cached compression TLS connection state")
		}
		if resp.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("HTTP/3 cached compression TLS version = %#x, want TLS 1.3", resp.TLS.Version)
		}
		if resp.TLS.NegotiatedProtocol != "h3" {
			t.Fatalf("HTTP/3 cached compression negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTP/3 cached compression response status = %d, want %d; body=%q\n%s", resp.StatusCode, http.StatusOK, string(body), appProc.output.String())
		}
		if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
			t.Fatalf("HTTP/3 cached compression Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
		}
		requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
		if requestID == "" {
			t.Fatal("HTTP/3 cached compression response missing X-Request-ID header")
		}
		return resp, body, requestID
	}

	respMiss, bodyMiss, requestIDMiss := doHTTP3CachedRequest("br, gzip")
	if strings.TrimSpace(respMiss.Header.Get("Content-Encoding")) != "br" {
		t.Fatalf("HTTP/3 cache miss Content-Encoding = %q, want %q", respMiss.Header.Get("Content-Encoding"), "br")
	}
	requireDecodedHTTPResponseBody(t, respMiss.Header.Get("Content-Encoding"), bodyMiss, upstreamBody)
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "HTTP/3 cache compression miss",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestIDMiss,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		cacheState:       "miss",
		httpProtocol:     "h3",
		tlsALPN:          "h3",
		ja4Prefix:        'q',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(bodyMiss)),
	})
	countBeforeHit := upstreamRequests.Load()
	if countBeforeHit < 1 {
		t.Fatalf("upstream request count after HTTP/3 cache fill = %d, want >= 1", countBeforeHit)
	}

	respHit, bodyHit, requestIDHit := doHTTP3CachedRequest("br, gzip")
	if strings.TrimSpace(respHit.Header.Get("Content-Encoding")) != "br" {
		t.Fatalf("HTTP/3 cache hit Content-Encoding = %q, want %q", respHit.Header.Get("Content-Encoding"), "br")
	}
	requireDecodedHTTPResponseBody(t, respHit.Header.Get("Content-Encoding"), bodyHit, upstreamBody)
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:                      "HTTP/3 cache compression hit",
		siteID:                     siteID,
		requestPath:                requestPath,
		requestID:                  requestIDHit,
		siteHost:                   siteHost,
		statusCode:                 http.StatusOK,
		cacheState:                 "hit",
		httpProtocol:               "h3",
		tlsALPN:                    "h3",
		ja4Prefix:                  'q',
		allowEmptyUpstreamProtocol: true,
		responseSize:               int64(len(bodyHit)),
	})
	countAfterHit := upstreamRequests.Load()
	if countAfterHit != countBeforeHit {
		t.Fatalf("upstream request count changed across HTTP/3 cache hit: before=%d after=%d", countBeforeHit, countAfterHit)
	}

	respIdentityHit, bodyIdentityHit, requestIDIdentityHit := doHTTP3CachedRequest("identity")
	if got := strings.TrimSpace(respIdentityHit.Header.Get("Content-Encoding")); got != "" {
		t.Fatalf("HTTP/3 identity cache hit Content-Encoding = %q, want empty", got)
	}
	requireDecodedHTTPResponseBody(t, respIdentityHit.Header.Get("Content-Encoding"), bodyIdentityHit, upstreamBody)
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:                      "HTTP/3 identity cache compression hit",
		siteID:                     siteID,
		requestPath:                requestPath,
		requestID:                  requestIDIdentityHit,
		siteHost:                   siteHost,
		statusCode:                 http.StatusOK,
		cacheState:                 "hit",
		httpProtocol:               "h3",
		tlsALPN:                    "h3",
		ja4Prefix:                  'q',
		allowEmptyUpstreamProtocol: true,
		responseSize:               int64(len(bodyIdentityHit)),
	})
	if got := strings.TrimSpace(respIdentityHit.Header.Get("Vary")); got != "" {
		t.Fatalf("HTTP/3 identity cache hit Vary = %q, want empty", got)
	}
	countAfterIdentityHit := upstreamRequests.Load()
	if countAfterIdentityHit != countBeforeHit {
		t.Fatalf("upstream request count changed across HTTP/3 identity cache hit: before=%d after=%d", countBeforeHit, countAfterIdentityHit)
	}
}

func TestRunBypassesResponseCacheForRangeAndConditionalRequestsInSeparateProcess(t *testing.T) {
	const etag = `"cache-bypass-etag"`
	const rangeHeader = "bytes=0-7"
	const rangeBody = "cache by"

	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cache-bypass/object.txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "cache bypass ready")
			return
		}

		count := upstreamRequests.Add(1)
		fullBody := fmt.Sprintf("cache bypass upstream generation %d", count)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Upstream-Count", strconv.Itoa(int(count)))

		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if strings.TrimSpace(r.Header.Get("Range")) == rangeHeader {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-7/%d", len(fullBody)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, rangeBody)
			return
		}

		_, _ = io.WriteString(w, fullBody)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "cache-bypass-range-conditional.example.test"
	const readyPath = "/cache-bypass-ready"
	const requestPath = "/cache-bypass/object.txt"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		cacheRulesBytes, err := json.Marshal([]store.SiteCacheRule{
			{Type: "prefix", Value: "/cache-bypass", TTL: 120},
		})
		if err != nil {
			return fmt.Errorf("marshal cache rules: %w", err)
		}

		policy := store.Policy{
			Name:        "cache-bypass-range-conditional-observe",
			Description: "records HTTPS HTTP/2 and HTTP/3 cache bypass requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-https-h2-cache-bypass",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-h3-cache-bypass",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:            siteHost,
			UpstreamURLs:    upstream.URL,
			Bind:            tcpBind,
			Network:         "tcp",
			Enabled:         true,
			TLSEnabled:      true,
			ALPN:            "h2,h3,http/1.1",
			CacheEnabled:    true,
			CacheDefaultTTL: 120,
			CacheRules:      string(cacheRulesBytes),
			PolicyID:        &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, readyPath, 2, "h2")
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 cache bypass ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "cache bypass ready" {
		t.Fatalf("HTTPS h2 cache bypass ready body = %q, want %q", readyBody, "cache bypass ready")
	}
	h3ReadyResp, h3ReadyBody := appProc.doHTTP3Request(t, udpBind, siteHost, readyPath)
	if h3ReadyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 cache bypass ready status = %d, want %d, body=%s\n%s", h3ReadyResp.StatusCode, http.StatusOK, h3ReadyBody, appProc.output.String())
	}
	if h3ReadyBody != "cache bypass ready" {
		t.Fatalf("HTTP/3 cache bypass ready body = %q, want %q", h3ReadyBody, "cache bypass ready")
	}

	h2TargetURL := "https://" + siteHost + ":" + extractPort(tcpBind) + requestPath
	h2Transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	h2Client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: h2Transport,
	}
	t.Cleanup(func() {
		h2Transport.CloseIdleConnections()
	})

	h3TargetURL := "https://" + siteHost + ":" + extractPort(udpBind) + requestPath
	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	h3Client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: h3Transport,
	}
	t.Cleanup(func() {
		_ = h3Transport.Close()
	})

	doH2 := func(label string, headers http.Header) (*http.Response, []byte, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, h2TargetURL, nil)
		if err != nil {
			t.Fatalf("build HTTPS h2 cache bypass request %s: %v", label, err)
		}
		req.Host = siteHost
		req.Header.Set("Accept-Encoding", "identity")
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		resp, err := h2Client.Do(req)
		if err != nil {
			t.Fatalf("send HTTPS h2 cache bypass request %s: %v", label, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read HTTPS h2 cache bypass response %s: %v", label, err)
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("HTTPS h2 cache bypass response %s protocol major = %d, want 2", label, resp.ProtoMajor)
		}
		if resp.TLS == nil {
			t.Fatalf("expected HTTPS h2 cache bypass response %s TLS connection state", label)
		}
		if resp.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("HTTPS h2 cache bypass response %s TLS version = %#x, want TLS 1.3", label, resp.TLS.Version)
		}
		if resp.TLS.NegotiatedProtocol != "h2" {
			t.Fatalf("HTTPS h2 cache bypass response %s negotiated protocol = %q, want %q", label, resp.TLS.NegotiatedProtocol, "h2")
		}
		requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
		if requestID == "" {
			t.Fatalf("HTTPS h2 cache bypass response %s missing X-Request-ID header", label)
		}
		return resp, body, requestID
	}

	doH3 := func(label string, headers http.Header) (*http.Response, []byte, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, h3TargetURL, nil)
		if err != nil {
			t.Fatalf("build HTTP/3 cache bypass request %s: %v", label, err)
		}
		req.Host = siteHost
		req.Header.Set("Accept-Encoding", "identity")
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		resp, err := h3Client.Do(req)
		if err != nil {
			t.Fatalf("send HTTP/3 cache bypass request %s: %v", label, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read HTTP/3 cache bypass response %s: %v", label, err)
		}
		if resp.ProtoMajor != 3 {
			t.Fatalf("HTTP/3 cache bypass response %s protocol major = %d, want 3", label, resp.ProtoMajor)
		}
		if resp.TLS == nil {
			t.Fatalf("expected HTTP/3 cache bypass response %s TLS connection state", label)
		}
		if resp.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("HTTP/3 cache bypass response %s TLS version = %#x, want TLS 1.3", label, resp.TLS.Version)
		}
		if resp.TLS.NegotiatedProtocol != "h3" {
			t.Fatalf("HTTP/3 cache bypass response %s negotiated protocol = %q, want %q", label, resp.TLS.NegotiatedProtocol, "h3")
		}
		if got := resp.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)) {
			t.Fatalf("HTTP/3 cache bypass response %s Alt-Svc = %q, want %q", label, got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind)))
		}
		requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
		if requestID == "" {
			t.Fatalf("HTTP/3 cache bypass response %s missing X-Request-ID header", label)
		}
		return resp, body, requestID
	}

	respFill, bodyFill, requestIDFill := doH2("fill", nil)
	if respFill.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 cache fill status = %d, want %d; body=%q", respFill.StatusCode, http.StatusOK, string(bodyFill))
	}
	if got := string(bodyFill); got != "cache bypass upstream generation 1" {
		t.Fatalf("HTTPS h2 cache fill body = %q, want generation 1", got)
	}
	if got := respFill.Header.Get("X-Upstream-Count"); got != "1" {
		t.Fatalf("HTTPS h2 cache fill X-Upstream-Count = %q, want 1", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream count after HTTPS h2 cache fill = %d, want 1", got)
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "HTTPS h2 cache fill",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDFill,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		cacheState:   "miss",
		httpProtocol: "h2",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyFill)),
	})

	respHit, bodyHit, _ := doH2("hit", nil)
	if respHit.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 cache hit status = %d, want %d; body=%q", respHit.StatusCode, http.StatusOK, string(bodyHit))
	}
	if string(bodyHit) != string(bodyFill) {
		t.Fatalf("HTTPS h2 cache hit body = %q, want %q", string(bodyHit), string(bodyFill))
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream count changed across HTTPS h2 cache hit: got=%d want=1", got)
	}

	rangeHeaders := http.Header{"Range": []string{rangeHeader}}
	respH2Range, bodyH2Range, requestIDH2Range := doH2("range", rangeHeaders)
	if respH2Range.StatusCode != http.StatusPartialContent {
		t.Fatalf("HTTPS h2 range bypass status = %d, want %d; body=%q", respH2Range.StatusCode, http.StatusPartialContent, string(bodyH2Range))
	}
	if string(bodyH2Range) != rangeBody {
		t.Fatalf("HTTPS h2 range bypass body = %q, want %q", string(bodyH2Range), rangeBody)
	}
	if got := respH2Range.Header.Get("X-Upstream-Count"); got != "2" {
		t.Fatalf("HTTPS h2 range bypass X-Upstream-Count = %q, want 2", got)
	}
	if got := upstreamRequests.Load(); got != 2 {
		t.Fatalf("upstream count after HTTPS h2 range bypass = %d, want 2", got)
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "HTTPS h2 range cache bypass",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDH2Range,
		siteHost:     siteHost,
		statusCode:   http.StatusPartialContent,
		cacheState:   "bypass",
		httpProtocol: "h2",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyH2Range)),
	})

	conditionalHeaders := http.Header{"If-None-Match": []string{etag}}
	respH2Conditional, bodyH2Conditional, requestIDH2Conditional := doH2("conditional", conditionalHeaders)
	if respH2Conditional.StatusCode != http.StatusNotModified {
		t.Fatalf("HTTPS h2 conditional bypass status = %d, want %d; body=%q", respH2Conditional.StatusCode, http.StatusNotModified, string(bodyH2Conditional))
	}
	if len(bodyH2Conditional) != 0 {
		t.Fatalf("HTTPS h2 conditional bypass body length = %d, want 0; body=%q", len(bodyH2Conditional), string(bodyH2Conditional))
	}
	if got := respH2Conditional.Header.Get("X-Upstream-Count"); got != "3" {
		t.Fatalf("HTTPS h2 conditional bypass X-Upstream-Count = %q, want 3", got)
	}
	if got := upstreamRequests.Load(); got != 3 {
		t.Fatalf("upstream count after HTTPS h2 conditional bypass = %d, want 3", got)
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "HTTPS h2 conditional cache bypass",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDH2Conditional,
		siteHost:     siteHost,
		statusCode:   http.StatusNotModified,
		cacheState:   "bypass",
		httpProtocol: "h2",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyH2Conditional)),
	})

	respH2AfterBypass, bodyH2AfterBypass, _ := doH2("after-bypass-hit", nil)
	if respH2AfterBypass.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS h2 post-bypass cache hit status = %d, want %d; body=%q", respH2AfterBypass.StatusCode, http.StatusOK, string(bodyH2AfterBypass))
	}
	if string(bodyH2AfterBypass) != string(bodyFill) {
		t.Fatalf("HTTPS h2 post-bypass cache hit body = %q, want %q", string(bodyH2AfterBypass), string(bodyFill))
	}
	if got := respH2AfterBypass.Header.Get("X-Upstream-Count"); got != "1" {
		t.Fatalf("HTTPS h2 post-bypass cache hit X-Upstream-Count = %q, want cached 1", got)
	}
	if got := upstreamRequests.Load(); got != 3 {
		t.Fatalf("upstream count changed across HTTPS h2 post-bypass cache hit: got=%d want=3", got)
	}

	respH3Hit, bodyH3Hit, _ := doH3("hit", nil)
	if respH3Hit.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 cache hit status = %d, want %d; body=%q", respH3Hit.StatusCode, http.StatusOK, string(bodyH3Hit))
	}
	if string(bodyH3Hit) != string(bodyFill) {
		t.Fatalf("HTTP/3 cache hit body = %q, want %q", string(bodyH3Hit), string(bodyFill))
	}
	if got := upstreamRequests.Load(); got != 3 {
		t.Fatalf("upstream count changed across HTTP/3 cache hit: got=%d want=3", got)
	}

	respH3Range, bodyH3Range, requestIDH3Range := doH3("range", rangeHeaders)
	if respH3Range.StatusCode != http.StatusPartialContent {
		t.Fatalf("HTTP/3 range bypass status = %d, want %d; body=%q", respH3Range.StatusCode, http.StatusPartialContent, string(bodyH3Range))
	}
	if string(bodyH3Range) != rangeBody {
		t.Fatalf("HTTP/3 range bypass body = %q, want %q", string(bodyH3Range), rangeBody)
	}
	if got := respH3Range.Header.Get("X-Upstream-Count"); got != "4" {
		t.Fatalf("HTTP/3 range bypass X-Upstream-Count = %q, want 4", got)
	}
	if got := upstreamRequests.Load(); got != 4 {
		t.Fatalf("upstream count after HTTP/3 range bypass = %d, want 4", got)
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "HTTP/3 range cache bypass",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDH3Range,
		siteHost:     siteHost,
		statusCode:   http.StatusPartialContent,
		cacheState:   "bypass",
		httpProtocol: "h3",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyH3Range)),
	})

	respH3Conditional, bodyH3Conditional, requestIDH3Conditional := doH3("conditional", conditionalHeaders)
	if respH3Conditional.StatusCode != http.StatusNotModified {
		t.Fatalf("HTTP/3 conditional bypass status = %d, want %d; body=%q", respH3Conditional.StatusCode, http.StatusNotModified, string(bodyH3Conditional))
	}
	if len(bodyH3Conditional) != 0 {
		t.Fatalf("HTTP/3 conditional bypass body length = %d, want 0; body=%q", len(bodyH3Conditional), string(bodyH3Conditional))
	}
	if got := respH3Conditional.Header.Get("X-Upstream-Count"); got != "5" {
		t.Fatalf("HTTP/3 conditional bypass X-Upstream-Count = %q, want 5", got)
	}
	if got := upstreamRequests.Load(); got != 5 {
		t.Fatalf("upstream count after HTTP/3 conditional bypass = %d, want 5", got)
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "HTTP/3 conditional cache bypass",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDH3Conditional,
		siteHost:     siteHost,
		statusCode:   http.StatusNotModified,
		cacheState:   "bypass",
		httpProtocol: "h3",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyH3Conditional)),
	})

	respH3AfterBypass, bodyH3AfterBypass, _ := doH3("after-bypass-hit", nil)
	if respH3AfterBypass.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 post-bypass cache hit status = %d, want %d; body=%q", respH3AfterBypass.StatusCode, http.StatusOK, string(bodyH3AfterBypass))
	}
	if string(bodyH3AfterBypass) != string(bodyFill) {
		t.Fatalf("HTTP/3 post-bypass cache hit body = %q, want %q", string(bodyH3AfterBypass), string(bodyFill))
	}
	if got := respH3AfterBypass.Header.Get("X-Upstream-Count"); got != "1" {
		t.Fatalf("HTTP/3 post-bypass cache hit X-Upstream-Count = %q, want cached 1", got)
	}
	if got := upstreamRequests.Load(); got != 5 {
		t.Fatalf("upstream count changed across HTTP/3 post-bypass cache hit: got=%d want=5", got)
	}
}

func TestRunHotReloadsNetworkHTTP2EnabledForNewHTTPSConnectionsInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http2 enabled hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "http2-enabled-reload.example.test"
	const requestPath = "/http2-enabled-reload-check"

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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "http2 enabled hot reload upstream" {
		t.Fatalf("initial HTTPS response body = %q, want %q", bodyBefore, "http2 enabled hot reload upstream")
	}

	var disableResp adminsystem.NetworkConfig
	appProc.postJSON(t, "/api/v1/network-config", []byte(`{"http2_enabled":false}`), &disableResp)
	if disableResp.HTTP2Enabled {
		t.Fatal("disable response http2_enabled = true, want false")
	}
	if disableResp.DefaultALPN != "http/1.1" {
		t.Fatalf("disable response default_alpn = %q, want %q", disableResp.DefaultALPN, "http/1.1")
	}
	if disableResp.DefaultNetwork != "tcp" {
		t.Fatalf("disable response default_network = %q, want %q", disableResp.DefaultNetwork, "tcp")
	}

	respDisabled, bodyDisabled := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 1, "http/1.1")
	if respDisabled.StatusCode != http.StatusOK {
		t.Fatalf("disabled HTTPS response status = %d, want %d, body=%s\n%s", respDisabled.StatusCode, http.StatusOK, bodyDisabled, appProc.output.String())
	}
	if bodyDisabled != "http2 enabled hot reload upstream" {
		t.Fatalf("disabled HTTPS response body = %q, want %q", bodyDisabled, "http2 enabled hot reload upstream")
	}

	var enableResp adminsystem.NetworkConfig
	appProc.postJSON(t, "/api/v1/network-config", []byte(`{"http2_enabled":true}`), &enableResp)
	if !enableResp.HTTP2Enabled {
		t.Fatal("enable response http2_enabled = false, want true")
	}
	if enableResp.DefaultALPN != "h2,http/1.1" {
		t.Fatalf("enable response default_alpn = %q, want %q", enableResp.DefaultALPN, "h2,http/1.1")
	}
	if enableResp.DefaultNetwork != "tcp" {
		t.Fatalf("enable response default_network = %q, want %q", enableResp.DefaultNetwork, "tcp")
	}

	respAfter, bodyAfter := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("re-enabled HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "http2 enabled hot reload upstream" {
		t.Fatalf("re-enabled HTTPS response body = %q, want %q", bodyAfter, "http2 enabled hot reload upstream")
	}
}

func TestRunHotReloadsNetworkHTTP3EnabledAndBindForNewQUICConnectionsInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http3 hot reload upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	firstUDPBind := reserveAppProcessUDPBind(t)
	secondUDPBind := reserveAppProcessUDPBind(t)

	const siteHost = "http3-network-reload.example.test"
	const requestPath = "/http3-network-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   false,
			HTTP3Bind:      firstUDPBind,
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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	var enableResp adminsystem.NetworkConfig
	appProc.postJSON(t, "/api/v1/network-config", []byte(`{"http3_enabled":true}`), &enableResp)
	if !enableResp.HTTP3Enabled {
		t.Fatal("enable response http3_enabled = false, want true")
	}
	if enableResp.HTTP3Bind != firstUDPBind {
		t.Fatalf("enable response http3_bind = %q, want %q", enableResp.HTTP3Bind, firstUDPBind)
	}
	if enableResp.DefaultALPN != "h2,h3,http/1.1" {
		t.Fatalf("enable response default_alpn = %q, want %q", enableResp.DefaultALPN, "h2,h3,http/1.1")
	}

	respFirst, bodyFirst := appProc.doHTTP3Request(t, firstUDPBind, siteHost, requestPath)
	if respFirst.StatusCode != http.StatusOK {
		t.Fatalf("first HTTP/3 response status = %d, want %d, body=%s\n%s", respFirst.StatusCode, http.StatusOK, bodyFirst, appProc.output.String())
	}
	if bodyFirst != "http3 hot reload upstream:"+requestPath {
		t.Fatalf("first HTTP/3 response body = %q, want %q", bodyFirst, "http3 hot reload upstream:"+requestPath)
	}
	if respFirst.ProtoMajor != 3 {
		t.Fatalf("first HTTP/3 response proto major = %d, want 3", respFirst.ProtoMajor)
	}
	if got := respFirst.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(firstUDPBind)) {
		t.Fatalf("first HTTP/3 Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(firstUDPBind)))
	}
	respHTTPSFirst, bodyHTTPSFirst := appProc.waitHTTPSProtocolAltSvc(t, tcpBind, siteHost, requestPath, 2, "h2", fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(firstUDPBind)))
	if respHTTPSFirst.StatusCode != http.StatusOK {
		t.Fatalf("first HTTPS Alt-Svc response status = %d, want %d, body=%s\n%s", respHTTPSFirst.StatusCode, http.StatusOK, bodyHTTPSFirst, appProc.output.String())
	}
	if bodyHTTPSFirst != "http3 hot reload upstream:"+requestPath {
		t.Fatalf("first HTTPS Alt-Svc response body = %q, want %q", bodyHTTPSFirst, "http3 hot reload upstream:"+requestPath)
	}

	var rebindResp adminsystem.NetworkConfig
	appProc.postJSON(t, "/api/v1/network-config", []byte(fmt.Sprintf(`{"http3_bind":%q}`, secondUDPBind)), &rebindResp)
	if !rebindResp.HTTP3Enabled {
		t.Fatal("rebind response http3_enabled = false, want true")
	}
	if rebindResp.HTTP3Bind != secondUDPBind {
		t.Fatalf("rebind response http3_bind = %q, want %q", rebindResp.HTTP3Bind, secondUDPBind)
	}
	if rebindResp.DefaultALPN != "h2,h3,http/1.1" {
		t.Fatalf("rebind response default_alpn = %q, want %q", rebindResp.DefaultALPN, "h2,h3,http/1.1")
	}

	respSecond, bodySecond := appProc.doHTTP3Request(t, secondUDPBind, siteHost, requestPath)
	if respSecond.StatusCode != http.StatusOK {
		t.Fatalf("rebound HTTP/3 response status = %d, want %d, body=%s\n%s", respSecond.StatusCode, http.StatusOK, bodySecond, appProc.output.String())
	}
	if bodySecond != "http3 hot reload upstream:"+requestPath {
		t.Fatalf("rebound HTTP/3 response body = %q, want %q", bodySecond, "http3 hot reload upstream:"+requestPath)
	}
	if respSecond.ProtoMajor != 3 {
		t.Fatalf("rebound HTTP/3 response proto major = %d, want 3", respSecond.ProtoMajor)
	}
	if got := respSecond.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(secondUDPBind)) {
		t.Fatalf("rebound HTTP/3 Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(secondUDPBind)))
	}
	respHTTPSSecond, bodyHTTPSSecond := appProc.waitHTTPSProtocolAltSvc(t, tcpBind, siteHost, requestPath, 2, "h2", fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(secondUDPBind)))
	if respHTTPSSecond.StatusCode != http.StatusOK {
		t.Fatalf("rebound HTTPS Alt-Svc response status = %d, want %d, body=%s\n%s", respHTTPSSecond.StatusCode, http.StatusOK, bodyHTTPSSecond, appProc.output.String())
	}
	if bodyHTTPSSecond != "http3 hot reload upstream:"+requestPath {
		t.Fatalf("rebound HTTPS Alt-Svc response body = %q, want %q", bodyHTTPSSecond, "http3 hot reload upstream:"+requestPath)
	}

	firstUnavailableHost := "http3-network-reload-first-bind-unavailable.example.test"
	firstUnavailablePath := requestPath + "/first-bind-unavailable"
	appProc.requireHTTP3Unavailable(t, firstUDPBind, firstUnavailableHost, firstUnavailablePath)
	appProc.requireNoGlobalObservability(t, firstUnavailableHost, firstUnavailablePath, "old HTTP/3 bind after rebind")
	appProc.requireNoFingerprintSummary(t, url.Values{
		"tls_sni":  []string{firstUnavailableHost},
		"tls_alpn": []string{"h3"},
	}, "old HTTP/3 bind after rebind")
	appProc.requireNoSiteObservability(t, siteID, firstUnavailablePath, "old HTTP/3 bind after rebind")

	var disableResp adminsystem.NetworkConfig
	appProc.postJSON(t, "/api/v1/network-config", []byte(`{"http3_enabled":false}`), &disableResp)
	if disableResp.HTTP3Enabled {
		t.Fatal("disable response http3_enabled = true, want false")
	}
	if disableResp.HTTP3Bind != secondUDPBind {
		t.Fatalf("disable response http3_bind = %q, want %q", disableResp.HTTP3Bind, secondUDPBind)
	}
	if disableResp.DefaultALPN != "h2,http/1.1" {
		t.Fatalf("disable response default_alpn = %q, want %q", disableResp.DefaultALPN, "h2,http/1.1")
	}

	respDisabled, bodyDisabled := appProc.waitHTTPSProtocolAltSvc(t, tcpBind, siteHost, requestPath, 2, "h2", "")
	if respDisabled.StatusCode != http.StatusOK {
		t.Fatalf("disabled HTTP/3 HTTPS response status = %d, want %d, body=%s\n%s", respDisabled.StatusCode, http.StatusOK, bodyDisabled, appProc.output.String())
	}
	if bodyDisabled != "http3 hot reload upstream:"+requestPath {
		t.Fatalf("disabled HTTP/3 HTTPS response body = %q, want %q", bodyDisabled, "http3 hot reload upstream:"+requestPath)
	}
	disabledUnavailableHost := "http3-network-reload-disabled-unavailable.example.test"
	disabledUnavailablePath := requestPath + "/disabled-http3-unavailable"
	appProc.requireHTTP3Unavailable(t, secondUDPBind, disabledUnavailableHost, disabledUnavailablePath)
	appProc.requireNoGlobalObservability(t, disabledUnavailableHost, disabledUnavailablePath, "disabled HTTP/3 bind")
	appProc.requireNoFingerprintSummary(t, url.Values{
		"tls_sni":  []string{disabledUnavailableHost},
		"tls_alpn": []string{"h3"},
	}, "disabled HTTP/3 bind")
	appProc.requireNoSiteObservability(t, siteID, disabledUnavailablePath, "disabled HTTP/3 bind")
}

func TestRunHotReloadsHTTP3BindWithoutBlockingOnActiveQUICStreamInSeparateProcess(t *testing.T) {
	firstChunk := []byte("http3 active stream before rebind\n")
	secondChunk := []byte("http3 active stream after rebind\n")

	upstreamFlushedFirstChunk := make(chan struct{}, 1)
	releaseUpstream := make(chan struct{})
	var releaseOnce sync.Once

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/http3-active-rebind-stream" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "http3 active rebind upstream:"+r.URL.Path)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(firstChunk); err != nil {
			return
		}
		flusher.Flush()
		upstreamFlushedFirstChunk <- struct{}{}

		<-releaseUpstream
		if _, err := w.Write(secondChunk); err != nil {
			return
		}
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseUpstream)
		})
	})

	tcpBind := reserveAppProcessBind(t)
	firstUDPBind := reserveAppProcessUDPBind(t)
	secondUDPBind := reserveAppProcessUDPBind(t)

	const siteHost = "http3-active-rebind.example.test"
	const streamPath = "/http3-active-rebind-stream"
	const checkPath = "/http3-active-rebind-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      firstUDPBind,
			DefaultALPN:    "h2,h3,http/1.1",
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

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "h2,h3,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	readyResp, readyBody := appProc.doHTTP3Request(t, firstUDPBind, siteHost, checkPath)
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 active rebind ready status = %d, want %d, body=%s\n%s", readyResp.StatusCode, http.StatusOK, readyBody, appProc.output.String())
	}
	if readyBody != "http3 active rebind upstream:"+checkPath {
		t.Fatalf("initial HTTP/3 active rebind ready body = %q, want %q", readyBody, "http3 active rebind upstream:"+checkPath)
	}

	targetURL := "https://" + siteHost + ":" + extractPort(firstUDPBind) + streamPath
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, firstUDPBind, tlsCfg, cfg)
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build active HTTP/3 rebind stream request: %v", err)
	}
	req.Host = siteHost
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send active HTTP/3 rebind stream request: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 3 {
		t.Fatalf("active HTTP/3 rebind stream protocol major = %d, want 3", resp.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, resp, "active HTTP/3 rebind stream")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("active HTTP/3 rebind stream status = %d, want %d\n%s", resp.StatusCode, http.StatusOK, appProc.output.String())
	}

	select {
	case <-upstreamFlushedFirstChunk:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not flush first active HTTP/3 rebind chunk")
	}

	firstBuf := make([]byte, len(firstChunk))
	n, err := io.ReadFull(resp.Body, firstBuf)
	if err != nil {
		t.Fatalf("read first active HTTP/3 rebind chunk: n=%d err=%v", n, err)
	}
	if !bytes.Equal(firstBuf, firstChunk) {
		t.Fatalf("first active HTTP/3 rebind chunk = %q, want %q", string(firstBuf), string(firstChunk))
	}

	var rebindResp adminsystem.NetworkConfig
	reloadStarted := time.Now()
	appProc.postJSON(t, "/api/v1/network-config", []byte(fmt.Sprintf(`{"http3_bind":%q}`, secondUDPBind)), &rebindResp)
	if elapsed := time.Since(reloadStarted); elapsed > 2*time.Second {
		t.Fatalf("HTTP/3 bind reload took %s with an active QUIC stream, want less than 2s", elapsed)
	}
	if !rebindResp.HTTP3Enabled {
		t.Fatal("rebind response http3_enabled = false, want true")
	}
	if rebindResp.HTTP3Bind != secondUDPBind {
		t.Fatalf("rebind response http3_bind = %q, want %q", rebindResp.HTTP3Bind, secondUDPBind)
	}
	if rebindResp.DefaultALPN != "h2,h3,http/1.1" {
		t.Fatalf("rebind response default_alpn = %q, want %q", rebindResp.DefaultALPN, "h2,h3,http/1.1")
	}

	respSecond, bodySecond := appProc.doHTTP3Request(t, secondUDPBind, siteHost, checkPath)
	if respSecond.StatusCode != http.StatusOK {
		t.Fatalf("rebound HTTP/3 active stream response status = %d, want %d, body=%s\n%s", respSecond.StatusCode, http.StatusOK, bodySecond, appProc.output.String())
	}
	if bodySecond != "http3 active rebind upstream:"+checkPath {
		t.Fatalf("rebound HTTP/3 active stream response body = %q, want %q", bodySecond, "http3 active rebind upstream:"+checkPath)
	}
	if got := respSecond.Header.Get("Alt-Svc"); got != fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(secondUDPBind)) {
		t.Fatalf("rebound HTTP/3 active stream Alt-Svc = %q, want %q", got, fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(secondUDPBind)))
	}

	unavailableHost := "http3-active-rebind-old-bind-unavailable.example.test"
	unavailablePath := checkPath + "/old-bind-unavailable"
	appProc.requireHTTP3Unavailable(t, firstUDPBind, unavailableHost, unavailablePath)
	appProc.requireNoGlobalObservability(t, unavailableHost, unavailablePath, "active stream old HTTP/3 bind after rebind")
	appProc.requireNoFingerprintSummary(t, url.Values{
		"tls_sni":  []string{unavailableHost},
		"tls_alpn": []string{"h3"},
	}, "active stream old HTTP/3 bind after rebind")
	appProc.requireNoSiteObservability(t, siteID, unavailablePath, "active stream old HTTP/3 bind after rebind")

	releaseOnce.Do(func() {
		close(releaseUpstream)
	})
	tail, err := io.ReadAll(resp.Body)
	if err != nil && !appProcessAcceptableHTTP3ActiveStreamCloseError(err) {
		t.Fatalf("read remaining active HTTP/3 rebind stream body: %v", err)
	}
	if len(tail) != 0 && !bytes.Equal(tail, secondChunk) {
		t.Fatalf("remaining active HTTP/3 rebind stream body = %q, want empty or %q", string(tail), string(secondChunk))
	}
}

func appProcessAcceptableHTTP3ActiveStreamCloseError(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "H3_REQUEST_CANCELLED") ||
		(strings.Contains(msg, "H3_NO_ERROR") && strings.Contains(msg, "Client.Timeout or context cancellation while reading body"))
}

func TestRunServesHTTP3ThroughLegacyTLSLoopbackListenersInSeparateProcess(t *testing.T) {
	tests := []struct {
		name          string
		host          string
		path          string
		http2Enabled  bool
		alpn          string
		minTLSVersion string
		maxTLSVersion string
		cipherSuites  string
	}{
		{
			name:          "tls10_http11",
			host:          "http3-tls10-loopback.example.test",
			path:          "/http3-tls10-loopback-check",
			http2Enabled:  false,
			alpn:          "h3,http/1.1",
			minTLSVersion: "TLS10",
			maxTLSVersion: "TLS10",
			cipherSuites:  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		},
		{
			name:          "tls11_http11",
			host:          "http3-tls11-loopback.example.test",
			path:          "/http3-tls11-loopback-check",
			http2Enabled:  false,
			alpn:          "h3,http/1.1",
			minTLSVersion: "TLS11",
			maxTLSVersion: "TLS11",
			cipherSuites:  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		},
		{
			name:          "tls12_h2",
			host:          "http3-tls12-h2-loopback.example.test",
			path:          "/http3-tls12-h2-loopback-check",
			http2Enabled:  true,
			alpn:          "h2,h3,http/1.1",
			minTLSVersion: "1.2",
			maxTLSVersion: "TLS12",
			cipherSuites:  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "http3 legacy tls loopback upstream:"+r.URL.Path)
			}))
			t.Cleanup(upstream.Close)

			tcpBind := reserveAppProcessBind(t)
			udpBind := reserveAppProcessUDPBind(t)

			var siteID uint
			appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
				networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
					HTTP2Enabled:   tt.http2Enabled,
					HTTP3Enabled:   true,
					HTTP3Bind:      udpBind,
					DefaultALPN:    tt.alpn,
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
					Name:        "http3-legacy-loopback-observe-" + tt.name,
					Description: "records successful HTTP/3 legacy TLS loopback requests for TLS metadata verification",
				}
				if err := db.Create(&policy).Error; err != nil {
					return fmt.Errorf("create policy: %w", err)
				}

				rule := store.Rule{
					Name:     "observe-h3-legacy-loopback-" + tt.name,
					PolicyID: policy.ID,
					Phase:    store.PhaseCustom,
					Pattern:  "tls_alpn:h3",
					Action:   store.ActionObserve,
					Priority: 1,
					Enabled:  true,
				}
				if err := db.Create(&rule).Error; err != nil {
					return fmt.Errorf("create rule: %w", err)
				}

				site := store.Site{
					Host:          tt.host,
					UpstreamURLs:  upstream.URL,
					Bind:          tcpBind,
					Network:       "tcp",
					Enabled:       true,
					TLSEnabled:    true,
					MinTLSVersion: tt.minTLSVersion,
					MaxTLSVersion: tt.maxTLSVersion,
					CipherSuites:  tt.cipherSuites,
					ALPN:          tt.alpn,
					PolicyID:      &policy.ID,
				}
				if err := db.Create(&site).Error; err != nil {
					return fmt.Errorf("create site: %w", err)
				}
				siteID = site.ID
				return nil
			})

			resp, body := appProc.doHTTP3Request(t, udpBind, tt.host, tt.path)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("HTTP/3 legacy TLS loopback response status = %d, want %d, body=%s\n%s", resp.StatusCode, http.StatusOK, body, appProc.output.String())
			}
			wantBody := "http3 legacy tls loopback upstream:" + tt.path
			if body != wantBody {
				t.Fatalf("HTTP/3 legacy TLS loopback response body = %q, want %q", body, wantBody)
			}
			if resp.ProtoMajor != 3 {
				t.Fatalf("HTTP/3 legacy TLS loopback response proto major = %d, want 3", resp.ProtoMajor)
			}

			requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
			if requestID == "" {
				t.Fatal("HTTP/3 legacy TLS loopback response missing X-Request-ID header")
			}

			accessLog := appProc.waitForSiteAccessLog(t, siteID, tt.path, nil)
			if accessLog.RequestID != requestID {
				t.Fatalf("access log request_id = %q, want %q", accessLog.RequestID, requestID)
			}
			if accessLog.StatusCode != http.StatusOK {
				t.Fatalf("access log status_code = %d, want %d", accessLog.StatusCode, http.StatusOK)
			}
			if accessLog.WAFAction != string(store.ActionObserve) {
				t.Fatalf("access log waf_action = %q, want %q", accessLog.WAFAction, store.ActionObserve)
			}
			if accessLog.HTTPProtocol != "h3" {
				t.Fatalf("access log http_protocol = %q, want %q", accessLog.HTTPProtocol, "h3")
			}
			if accessLog.TLSVersion != "TLS13" {
				t.Fatalf("access log tls_version = %q, want %q", accessLog.TLSVersion, "TLS13")
			}
			if accessLog.TLSALPN != "h3" {
				t.Fatalf("access log tls_alpn = %q, want %q", accessLog.TLSALPN, "h3")
			}
			if accessLog.TLSSNI != tt.host {
				t.Fatalf("access log tls_sni = %q, want %q", accessLog.TLSSNI, tt.host)
			}
			if accessLog.TLSJA3Hash == "" {
				t.Fatalf("access log tls_ja3_hash is empty: %+v", accessLog)
			}
			if accessLog.TLSJA4 == "" || accessLog.TLSJA4[0] != 'q' {
				t.Fatalf("access log tls_ja4 = %q, want QUIC-prefixed value", accessLog.TLSJA4)
			}
			if !strings.Contains(accessLog.TLSCipherSuites, "TLS_AES_128_GCM_SHA256") || !strings.Contains(accessLog.TLSCipherSuites, "TLS_AES_256_GCM_SHA384") {
				t.Fatalf("access log tls_cipher_suites = %q, want inbound QUIC TLS1.3 suites", accessLog.TLSCipherSuites)
			}
			if strings.Contains(accessLog.TLSCipherSuites, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA") || strings.Contains(accessLog.TLSCipherSuites, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") {
				t.Fatalf("access log tls_cipher_suites = %q, want inbound QUIC suites without loopback TLS1.x suite", accessLog.TLSCipherSuites)
			}

			securityEvent := appProc.waitForSiteSecurityEvent(t, siteID, tt.path, url.Values{
				"tls_version": []string{"TLS13"},
				"tls_alpn":    []string{"h3"},
			})
			if securityEvent.RequestID != requestID {
				t.Fatalf("security event request_id = %q, want %q", securityEvent.RequestID, requestID)
			}
			if securityEvent.Action != string(store.ActionObserve) {
				t.Fatalf("security event action = %q, want %q", securityEvent.Action, store.ActionObserve)
			}
			if securityEvent.TLSVersion != "TLS13" {
				t.Fatalf("security event tls_version = %q, want %q", securityEvent.TLSVersion, "TLS13")
			}
			if securityEvent.TLSALPN != "h3" {
				t.Fatalf("security event tls_alpn = %q, want %q", securityEvent.TLSALPN, "h3")
			}
			if securityEvent.TLSSNI != tt.host {
				t.Fatalf("security event tls_sni = %q, want %q", securityEvent.TLSSNI, tt.host)
			}
			if securityEvent.TLSJA3Hash != accessLog.TLSJA3Hash || securityEvent.TLSJA4 != accessLog.TLSJA4 || securityEvent.TLSCipherSuites != accessLog.TLSCipherSuites {
				t.Fatalf("security event TLS metadata mismatch: %+v vs %+v", securityEvent, accessLog)
			}

			fingerprint := appProc.waitForFingerprintSummary(t, url.Values{
				"tls_version":       []string{"TLS13"},
				"tls_sni":           []string{tt.host},
				"tls_alpn":          []string{"h3"},
				"tls_ja4":           []string{accessLog.TLSJA4},
				"tls_cipher_suites": []string{"AES_256_GCM_SHA384"},
			})
			if fingerprint.TLSJA3Hash != accessLog.TLSJA3Hash {
				t.Fatalf("fingerprint tls_ja3_hash = %q, want %q", fingerprint.TLSJA3Hash, accessLog.TLSJA3Hash)
			}
			if fingerprint.TLSVersion != "TLS13" {
				t.Fatalf("fingerprint tls_version = %q, want %q", fingerprint.TLSVersion, "TLS13")
			}
			if fingerprint.TLSALPN != "h3" {
				t.Fatalf("fingerprint tls_alpn = %q, want %q", fingerprint.TLSALPN, "h3")
			}
			if fingerprint.TLSSNI != tt.host {
				t.Fatalf("fingerprint tls_sni = %q, want %q", fingerprint.TLSSNI, tt.host)
			}
			if !strings.Contains(fingerprint.TLSCipherSuites, "TLS_AES_128_GCM_SHA256") || !strings.Contains(fingerprint.TLSCipherSuites, "TLS_AES_256_GCM_SHA384") {
				t.Fatalf("fingerprint tls_cipher_suites = %q, want inbound QUIC TLS1.3 suites", fingerprint.TLSCipherSuites)
			}

			trace := appProc.waitForRequestTrace(t, requestID)
			if trace.RequestID != requestID {
				t.Fatalf("request trace request_id = %q, want %q", trace.RequestID, requestID)
			}
			if len(trace.AccessLogs) == 0 {
				t.Fatal("request trace access_logs is empty")
			}
			if len(trace.SecurityEvents) == 0 {
				t.Fatal("request trace security_events is empty")
			}

			var traceAccessLog *store.AccessLog
			for i := range trace.AccessLogs {
				if trace.AccessLogs[i].ID == accessLog.ID {
					traceAccessLog = &trace.AccessLogs[i]
					break
				}
			}
			if traceAccessLog == nil {
				t.Fatalf("request trace missing access log id %d", accessLog.ID)
			}
			if traceAccessLog.HTTPProtocol != "h3" {
				t.Fatalf("request trace access log http_protocol = %q, want %q", traceAccessLog.HTTPProtocol, "h3")
			}
			if traceAccessLog.TLSVersion != accessLog.TLSVersion || traceAccessLog.TLSALPN != accessLog.TLSALPN || traceAccessLog.TLSSNI != accessLog.TLSSNI || traceAccessLog.TLSJA3Hash != accessLog.TLSJA3Hash || traceAccessLog.TLSJA4 != accessLog.TLSJA4 || traceAccessLog.TLSCipherSuites != accessLog.TLSCipherSuites {
				t.Fatalf("request trace access log TLS metadata mismatch: %+v vs %+v", *traceAccessLog, accessLog)
			}

			var traceSecurityEvent *store.SecurityEvent
			for i := range trace.SecurityEvents {
				if trace.SecurityEvents[i].ID == securityEvent.ID {
					traceSecurityEvent = &trace.SecurityEvents[i]
					break
				}
			}
			if traceSecurityEvent == nil {
				t.Fatalf("request trace missing security event id %d", securityEvent.ID)
			}
			if traceSecurityEvent.TLSVersion != securityEvent.TLSVersion || traceSecurityEvent.TLSALPN != securityEvent.TLSALPN || traceSecurityEvent.TLSSNI != securityEvent.TLSSNI || traceSecurityEvent.TLSJA3Hash != securityEvent.TLSJA3Hash || traceSecurityEvent.TLSJA4 != securityEvent.TLSJA4 || traceSecurityEvent.TLSCipherSuites != securityEvent.TLSCipherSuites {
				t.Fatalf("request trace security event TLS metadata mismatch: %+v vs %+v", *traceSecurityEvent, securityEvent)
			}
		})
	}
}

func TestRunHotReloadsHTTP3LoopbackTLSDefaultsForInheritedSitesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http3 loopback tls defaults hot reload upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "http3-loopback-tls-defaults-reload.example.test"
	const requestPath = "/http3-loopback-tls-defaults-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS12",
			CipherSuites:             "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			DefaultALPN:              "h2,h3,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SessionTicketsEnabled:    true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "http3-loopback-tls-defaults-observe",
			Description: "records HTTP/3 loopback TLS default hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-http3-loopback-tls-defaults",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_alpn:h3",
			Action:   store.ActionObserve,
			Priority: 1,
			Enabled:  true,
		}
		if err := db.Create(&rule).Error; err != nil {
			return fmt.Errorf("create rule %q: %w", rule.Name, err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	respBefore, bodyBefore := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 loopback response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "http3 loopback tls defaults hot reload upstream:"+requestPath {
		t.Fatalf("initial HTTP/3 loopback response body = %q, want %q", bodyBefore, "http3 loopback tls defaults hot reload upstream:"+requestPath)
	}
	if respBefore.ProtoMajor != 3 {
		t.Fatalf("initial HTTP/3 loopback proto major = %d, want 3", respBefore.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respBefore, "initial HTTP/3 loopback")
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial HTTP/3 loopback TLS defaults",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyBefore)),
	})

	var updateResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"min_version":"TLS10","max_version":"TLS10","cipher_suites":"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA","default_alpn":"h3,http/1.1"}`), &updateResp)
	if updateResp.MinVersion != "TLS10" {
		t.Fatalf("update response min_version = %q, want %q", updateResp.MinVersion, "TLS10")
	}
	if updateResp.MaxVersion != "TLS10" {
		t.Fatalf("update response max_version = %q, want %q", updateResp.MaxVersion, "TLS10")
	}
	if updateResp.CipherSuites != "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" {
		t.Fatalf("update response cipher_suites = %q, want %q", updateResp.CipherSuites, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
	}

	respAfter, bodyAfter := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded HTTP/3 loopback response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "http3 loopback tls defaults hot reload upstream:"+requestPath {
		t.Fatalf("reloaded HTTP/3 loopback response body = %q, want %q", bodyAfter, "http3 loopback tls defaults hot reload upstream:"+requestPath)
	}
	if respAfter.ProtoMajor != 3 {
		t.Fatalf("reloaded HTTP/3 loopback proto major = %d, want 3", respAfter.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respAfter, "reloaded HTTP/3 loopback")
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded HTTP/3 loopback TLS defaults",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDAfter,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyAfter)),
	})
	appProc.requireHTTPSFailure(t, tcpBind, siteHost, requestPath, tls.VersionTLS12, tls.VersionTLS12)
}

func TestRunHotReloadsSiteTLSOverridesWithHTTP3LoopbackInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "site tls override http3 loopback upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "site-tls-override-http3.example.test"
	const requestPath = "/site-tls-override-http3-check"

	var siteID uint
	var certID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS13",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,h3,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SessionTicketsEnabled:    true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		certPEM, keyPEM, err := acme.GenerateSelfSignedPEM(siteHost, []string{siteHost}, nil, time.Hour)
		if err != nil {
			return fmt.Errorf("generate site certificate: %w", err)
		}
		cert := store.Certificate{
			Name:    "site tls override http3",
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}
		if err := db.Create(&cert).Error; err != nil {
			return fmt.Errorf("create site certificate: %w", err)
		}

		policy := store.Policy{
			Name:        "site-tls-override-http3-loopback-observe",
			Description: "records site TLS override HTTP/2 and HTTP/3 loopback requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-site-override-initial-tls13",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-site-override-http3",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
			{
				Name:     "observe-site-override-reloaded-tls12",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				Action:   store.ActionObserve,
				Priority: 3,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			CertID:       &cert.ID,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		certID = cert.ID
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSState(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13, 2, "h2", tls.VersionTLS13)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "site tls override http3 loopback upstream:"+requestPath {
		t.Fatalf("initial HTTPS response body = %q, want %q", bodyBefore, "site tls override http3 loopback upstream:"+requestPath)
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial site TLS override HTTPS",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyBefore)),
	})
	respH3Before, bodyH3Before := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if respH3Before.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 response status = %d, want %d, body=%s\n%s", respH3Before.StatusCode, http.StatusOK, bodyH3Before, appProc.output.String())
	}
	if bodyH3Before != "site tls override http3 loopback upstream:"+requestPath {
		t.Fatalf("initial HTTP/3 response body = %q, want %q", bodyH3Before, "site tls override http3 loopback upstream:"+requestPath)
	}
	if respH3Before.ProtoMajor != 3 {
		t.Fatalf("initial HTTP/3 proto major = %d, want 3", respH3Before.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respH3Before, "initial site TLS override HTTP/3")
	requestIDH3Before := strings.TrimSpace(respH3Before.Header.Get("X-Request-ID"))
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial site TLS override HTTP/3",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDH3Before,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyH3Before)),
	})

	var updateResp store.Site
	appProc.postJSON(
		t,
		fmt.Sprintf("/api/v1/sites/%d/update", siteID),
		[]byte(fmt.Sprintf(`{"cert_id":%d,"min_tls_version":"TLS12","max_tls_version":"TLS12","cipher_suites":"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","alpn":"h2,h3,http/1.1"}`, certID)),
		&updateResp,
	)
	if updateResp.MinTLSVersion != "TLS12" {
		t.Fatalf("updated site min_tls_version = %q, want TLS12", updateResp.MinTLSVersion)
	}
	if updateResp.MaxTLSVersion != "TLS12" {
		t.Fatalf("updated site max_tls_version = %q, want TLS12", updateResp.MaxTLSVersion)
	}
	if updateResp.CipherSuites != "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" {
		t.Fatalf("updated site cipher_suites = %q, want TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", updateResp.CipherSuites)
	}
	if updateResp.ALPN != "h2,h3,http/1.1" {
		t.Fatalf("updated site alpn = %q, want h2,h3,http/1.1", updateResp.ALPN)
	}

	respAfter, bodyAfter := appProc.waitHTTPSStateWithCipherSuites(t, tcpBind, siteHost, requestPath, tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}, 2, "h2", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "site tls override http3 loopback upstream:"+requestPath {
		t.Fatalf("reloaded HTTPS response body = %q, want %q", bodyAfter, "site tls override http3 loopback upstream:"+requestPath)
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:           "reloaded site TLS override HTTPS",
		siteID:          siteID,
		requestPath:     requestPath,
		requestID:       requestIDAfter,
		siteHost:        siteHost,
		statusCode:      http.StatusOK,
		httpProtocol:    "h2",
		tlsVersion:      "TLS12",
		tlsALPN:         "h2",
		ja4Prefix:       't',
		responseSize:    int64(len(bodyAfter)),
		tlsCipherSuites: []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
	})
	appProc.requireHTTPSFailure(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13)

	respH3After, bodyH3After := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if respH3After.StatusCode != http.StatusOK {
		t.Fatalf("reloaded HTTP/3 response status = %d, want %d, body=%s\n%s", respH3After.StatusCode, http.StatusOK, bodyH3After, appProc.output.String())
	}
	if respH3After.ProtoMajor != 3 {
		t.Fatalf("reloaded HTTP/3 proto major = %d, want 3", respH3After.ProtoMajor)
	}
	if bodyH3After != "site tls override http3 loopback upstream:"+requestPath {
		t.Fatalf("reloaded HTTP/3 response body = %q, want %q", bodyH3After, "site tls override http3 loopback upstream:"+requestPath)
	}
	requireAppProcessHTTP3TLSState(t, respH3After, "reloaded site TLS override HTTP/3")
	requestIDH3After := strings.TrimSpace(respH3After.Header.Get("X-Request-ID"))
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded site TLS override HTTP/3",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDH3After,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyH3After)),
	})
}

func TestRunHotReloadsTLSDefaultMinVersionForNewConnectionsInSeparateProcess(t *testing.T) {
	const initialTLS12CipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tls default min version hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls-default-min-reload.example.test"
	const requestPath = "/tls-default-min-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "tls-default-min-reload-observe",
			Description: "records TLS default minimum version hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-tls12-default-min-reload",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS12",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-tls13-default-min-reload",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_version:TLS13",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
			{
				Name:     "observe-tls12-default-min-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + initialTLS12CipherName,
				Action:   store.ActionObserve,
				Priority: 3,
				Enabled:  true,
			},
			{
				Name:     "observe-tls13-default-min-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 4,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:          siteHost,
			UpstreamURLs:  upstream.URL,
			Bind:          tcpBind,
			Network:       "tcp",
			Enabled:       true,
			TLSEnabled:    true,
			MaxTLSVersion: "TLS13",
			ALPN:          "h2,http/1.1",
			PolicyID:      &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSStateWithCipherSuites(t, tcpBind, siteHost, requestPath, tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, 2, "h2", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial TLS12 HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "tls default min version hot reload upstream" {
		t.Fatalf("initial TLS12 HTTPS response body = %q, want %q", bodyBefore, "tls default min version hot reload upstream")
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial TLS12 HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "initial TLS12 default min reload",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestIDBefore,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h2",
		tlsVersion:       "TLS12",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(bodyBefore)),
		tlsCipherSuites:  []string{initialTLS12CipherName},
	})

	var updateResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"min_version":"TLS13"}`), &updateResp)
	if updateResp.MinVersion != "TLS13" {
		t.Fatalf("update response min_version = %q, want %q", updateResp.MinVersion, "TLS13")
	}
	if updateResp.MaxVersion != "TLS13" {
		t.Fatalf("update response max_version = %q, want %q", updateResp.MaxVersion, "TLS13")
	}
	if updateResp.DefaultALPN != "h2,http/1.1" {
		t.Fatalf("update response default_alpn = %q, want %q", updateResp.DefaultALPN, "h2,http/1.1")
	}

	respAfter, bodyAfter := appProc.waitHTTPSState(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13, 2, "h2", tls.VersionTLS13)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded TLS13 HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "tls default min version hot reload upstream" {
		t.Fatalf("reloaded TLS13 HTTPS response body = %q, want %q", bodyAfter, "tls default min version hot reload upstream")
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("reloaded TLS13 HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "reloaded TLS13 default min reload",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestIDAfter,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "h2",
		tlsVersion:       "TLS13",
		tlsALPN:          "h2",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(bodyAfter)),
	})

	appProc.requireHTTPSFailure(t, tcpBind, siteHost, requestPath, tls.VersionTLS12, tls.VersionTLS12)
}

func TestRunHotReloadsTLSDefaultMaxVersionForInheritedSitesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tls default max version hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls-default-max-reload.example.test"
	const requestPath = "/tls-default-max-reload-check"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		site := store.Site{
			Host:          siteHost,
			UpstreamURLs:  upstream.URL,
			Bind:          tcpBind,
			Network:       "tcp",
			Enabled:       true,
			TLSEnabled:    true,
			MinTLSVersion: "TLS12",
			MaxTLSVersion: "",
			ALPN:          "h2,http/1.1",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}

		var stored store.Site
		if err := db.First(&stored, site.ID).Error; err != nil {
			return fmt.Errorf("load stored site: %w", err)
		}
		if stored.MaxTLSVersion != "" {
			return fmt.Errorf("stored site max_tls_version = %q, want empty", stored.MaxTLSVersion)
		}
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSState(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13, 2, "h2", tls.VersionTLS13)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial TLS13 HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "tls default max version hot reload upstream" {
		t.Fatalf("initial TLS13 HTTPS response body = %q, want %q", bodyBefore, "tls default max version hot reload upstream")
	}

	var updateResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"max_version":"TLS12"}`), &updateResp)
	if updateResp.MaxVersion != "TLS12" {
		t.Fatalf("update response max_version = %q, want %q", updateResp.MaxVersion, "TLS12")
	}
	if updateResp.MinVersion != "TLS12" {
		t.Fatalf("update response min_version = %q, want %q", updateResp.MinVersion, "TLS12")
	}

	respAfter, bodyAfter := appProc.waitHTTPSState(t, tcpBind, siteHost, requestPath, tls.VersionTLS12, tls.VersionTLS12, 2, "h2", tls.VersionTLS12)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded TLS12 HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "tls default max version hot reload upstream" {
		t.Fatalf("reloaded TLS12 HTTPS response body = %q, want %q", bodyAfter, "tls default max version hot reload upstream")
	}

	appProc.requireHTTPSFailure(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13)
}

func TestRunHotReloadsTLSDefaultCipherSuitesForInheritedSitesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tls default cipher suites hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls-default-cipher-reload.example.test"
	const requestPath = "/tls-default-cipher-reload-check"
	const initialCipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	const reloadedCipherName = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS12",
			CipherSuites:             initialCipherName,
			DefaultALPN:              "http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SessionTicketsEnabled:    true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "tls-default-cipher-reload-observe",
			Description: "records TLS default cipher suite hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-initial-default-cipher-suite",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + initialCipherName,
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-reloaded-default-cipher-suite",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:" + reloadedCipherName,
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSStateWithCipherSuites(t, tcpBind, siteHost, requestPath, tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, 1, "http/1.1", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial cipher HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "tls default cipher suites hot reload upstream" {
		t.Fatalf("initial cipher HTTPS response body = %q, want %q", bodyBefore, "tls default cipher suites hot reload upstream")
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial cipher HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "initial TLS12 default cipher suite",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestIDBefore,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "http/1.1",
		tlsVersion:       "TLS12",
		tlsALPN:          "http/1.1",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(bodyBefore)),
		tlsCipherSuites:  []string{initialCipherName},
	})

	var updateResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"cipher_suites":"`+reloadedCipherName+`"}`), &updateResp)
	if updateResp.CipherSuites != reloadedCipherName {
		t.Fatalf("update response cipher_suites = %q, want %q", updateResp.CipherSuites, reloadedCipherName)
	}

	respAfter, bodyAfter := appProc.waitHTTPSStateWithCipherSuites(t, tcpBind, siteHost, requestPath, tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}, 1, "http/1.1", tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded cipher HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "tls default cipher suites hot reload upstream" {
		t.Fatalf("reloaded cipher HTTPS response body = %q, want %q", bodyAfter, "tls default cipher suites hot reload upstream")
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("reloaded cipher HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:            "reloaded TLS12 default cipher suite",
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestIDAfter,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		httpProtocol:     "http/1.1",
		tlsVersion:       "TLS12",
		tlsALPN:          "http/1.1",
		ja4Prefix:        't',
		upstreamProtocol: "HTTP/1.1",
		responseSize:     int64(len(bodyAfter)),
		tlsCipherSuites:  []string{reloadedCipherName},
	})

	appProc.requireHTTPSCipherSuiteFailure(t, tcpBind, siteHost, requestPath, tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256})
}

func TestRunHotReloadsTLSDefaultCurvePreferencesForInheritedSitesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tls default curve preferences hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls-default-curve-reload.example.test"
	const requestPath = "/tls-default-curve-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS13",
			MaxVersion:               "TLS13",
			DefaultALPN:              "http/1.1",
			CurvePreferences:         "CurveP256",
			PreferServerCipherSuites: true,
			SessionTicketsEnabled:    true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "tls-default-curve-reload-observe",
			Description: "records TLS default curve preference hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-initial-default-curve-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-reloaded-default-curve-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSStateWithTLSExpectations(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13, nil, []tls.CurveID{tls.CurveP256}, 1, "http/1.1", tls.VersionTLS13, 0, tls.CurveP256)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial curve HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "tls default curve preferences hot reload upstream" {
		t.Fatalf("initial curve HTTPS response body = %q, want %q", bodyBefore, "tls default curve preferences hot reload upstream")
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial curve HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial TLS default curve preference",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "http/1.1",
		tlsVersion:   "TLS13",
		tlsALPN:      "http/1.1",
		ja4Prefix:    't',
		responseSize: int64(len(bodyBefore)),
		tlsCurves:    []string{strconv.Itoa(int(tls.CurveP256))},
	})

	var updateResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"curve_preferences":"CurveP384"}`), &updateResp)
	if updateResp.CurvePreferences != "CurveP384" {
		t.Fatalf("update response curve_preferences = %q, want %q", updateResp.CurvePreferences, "CurveP384")
	}

	respAfter, bodyAfter := appProc.waitHTTPSStateWithTLSExpectations(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13, nil, []tls.CurveID{tls.CurveP384}, 1, "http/1.1", tls.VersionTLS13, 0, tls.CurveP384)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded curve HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "tls default curve preferences hot reload upstream" {
		t.Fatalf("reloaded curve HTTPS response body = %q, want %q", bodyAfter, "tls default curve preferences hot reload upstream")
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("reloaded curve HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded TLS default curve preference",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDAfter,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "http/1.1",
		tlsVersion:   "TLS13",
		tlsALPN:      "http/1.1",
		ja4Prefix:    't',
		responseSize: int64(len(bodyAfter)),
		tlsCurves:    []string{strconv.Itoa(int(tls.CurveP384))},
	})

	appProc.requireHTTPSCurveFailure(t, tcpBind, siteHost, requestPath, tls.VersionTLS13, tls.VersionTLS13, []tls.CurveID{tls.CurveP256})
}

func TestRunHotReloadsTLSDefaultSessionTicketsForInheritedSitesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tls default session tickets hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls-default-session-tickets-reload.example.test"
	const requestPath = "/tls-default-session-tickets-reload-check"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS13",
			MaxVersion:               "TLS13",
			DefaultALPN:              "http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SessionTicketsEnabled:    true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSSessionResumptionState(t, tcpBind, siteHost, requestPath, true)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial session ticket HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "tls default session tickets hot reload upstream" {
		t.Fatalf("initial session ticket HTTPS response body = %q, want %q", bodyBefore, "tls default session tickets hot reload upstream")
	}

	var disableResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"session_tickets_enabled":false}`), &disableResp)
	if disableResp.SessionTicketsEnabled {
		t.Fatalf("disable response session_tickets_enabled = true, want false")
	}

	respDisabled, bodyDisabled := appProc.waitHTTPSSessionResumptionState(t, tcpBind, siteHost, requestPath, false)
	if respDisabled.StatusCode != http.StatusOK {
		t.Fatalf("disabled session ticket HTTPS response status = %d, want %d, body=%s\n%s", respDisabled.StatusCode, http.StatusOK, bodyDisabled, appProc.output.String())
	}
	if bodyDisabled != "tls default session tickets hot reload upstream" {
		t.Fatalf("disabled session ticket HTTPS response body = %q, want %q", bodyDisabled, "tls default session tickets hot reload upstream")
	}

	var enableResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"session_tickets_enabled":true}`), &enableResp)
	if !enableResp.SessionTicketsEnabled {
		t.Fatalf("enable response session_tickets_enabled = false, want true")
	}

	respAfter, bodyAfter := appProc.waitHTTPSSessionResumptionState(t, tcpBind, siteHost, requestPath, true)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("re-enabled session ticket HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "tls default session tickets hot reload upstream" {
		t.Fatalf("re-enabled session ticket HTTPS response body = %q, want %q", bodyAfter, "tls default session tickets hot reload upstream")
	}
}

func TestRunHotReloadsHTTP3TLSDefaultSessionTicketsForInheritedSitesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http3 session tickets hot reload upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "http3-session-tickets-reload.example.test"
	const requestPath = "/http3-session-tickets-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,h3,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SessionTicketsEnabled:    true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "http3-session-tickets-reload-observe",
			Description: "records HTTP/3 session ticket hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-http3-session-ticket-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-http3-session-ticket-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTP3SessionResumptionState(t, udpBind, siteHost, requestPath, true)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 session ticket response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "http3 session tickets hot reload upstream:"+requestPath {
		t.Fatalf("initial HTTP/3 session ticket response body = %q, want %q", bodyBefore, "http3 session tickets hot reload upstream:"+requestPath)
	}
	if respBefore.ProtoMajor != 3 {
		t.Fatalf("initial HTTP/3 session ticket proto major = %d, want 3", respBefore.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respBefore, "initial HTTP/3 session ticket")
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial HTTP/3 session ticket response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:                       "initial HTTP/3 session tickets",
		siteID:                      siteID,
		requestPath:                 requestPath,
		requestID:                   requestIDBefore,
		siteHost:                    siteHost,
		statusCode:                  http.StatusOK,
		httpProtocol:                "h3",
		tlsVersion:                  "TLS13",
		tlsALPN:                     "h3",
		ja4Prefix:                   'q',
		responseSize:                int64(len(bodyBefore)),
		expectMissingTLSClientHello: true,
	})

	var disableResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"session_tickets_enabled":false}`), &disableResp)
	if disableResp.SessionTicketsEnabled {
		t.Fatalf("disable response session_tickets_enabled = true, want false")
	}

	respDisabled, bodyDisabled := appProc.waitHTTP3SessionResumptionState(t, udpBind, siteHost, requestPath, false)
	if respDisabled.StatusCode != http.StatusOK {
		t.Fatalf("disabled HTTP/3 session ticket response status = %d, want %d, body=%s\n%s", respDisabled.StatusCode, http.StatusOK, bodyDisabled, appProc.output.String())
	}
	if bodyDisabled != "http3 session tickets hot reload upstream:"+requestPath {
		t.Fatalf("disabled HTTP/3 session ticket response body = %q, want %q", bodyDisabled, "http3 session tickets hot reload upstream:"+requestPath)
	}
	if respDisabled.ProtoMajor != 3 {
		t.Fatalf("disabled HTTP/3 session ticket proto major = %d, want 3", respDisabled.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respDisabled, "disabled HTTP/3 session ticket")
	requestIDDisabled := strings.TrimSpace(respDisabled.Header.Get("X-Request-ID"))
	if requestIDDisabled == "" {
		t.Fatal("disabled HTTP/3 session ticket response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "disabled HTTP/3 session tickets",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDDisabled,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsVersion:   "TLS13",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyDisabled)),
	})

	var enableResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"session_tickets_enabled":true}`), &enableResp)
	if !enableResp.SessionTicketsEnabled {
		t.Fatalf("enable response session_tickets_enabled = false, want true")
	}

	respAfter, bodyAfter := appProc.waitHTTP3SessionResumptionState(t, udpBind, siteHost, requestPath, true)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("re-enabled HTTP/3 session ticket response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "http3 session tickets hot reload upstream:"+requestPath {
		t.Fatalf("re-enabled HTTP/3 session ticket response body = %q, want %q", bodyAfter, "http3 session tickets hot reload upstream:"+requestPath)
	}
	if respAfter.ProtoMajor != 3 {
		t.Fatalf("re-enabled HTTP/3 session ticket proto major = %d, want 3", respAfter.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respAfter, "re-enabled HTTP/3 session ticket")
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("re-enabled HTTP/3 session ticket response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:                       "re-enabled HTTP/3 session tickets",
		siteID:                      siteID,
		requestPath:                 requestPath,
		requestID:                   requestIDAfter,
		siteHost:                    siteHost,
		statusCode:                  http.StatusOK,
		httpProtocol:                "h3",
		tlsVersion:                  "TLS13",
		tlsALPN:                     "h3",
		ja4Prefix:                   'q',
		responseSize:                int64(len(bodyAfter)),
		expectMissingTLSClientHello: true,
	})
}

func TestRunHotReloadsHTTP3TLSDefaultCurvePreferencesForInheritedSitesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http3 curve preferences hot reload upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "http3-curve-reload.example.test"
	const requestPath = "/http3-curve-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
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
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,h3,http/1.1",
			CurvePreferences:         "CurveP256",
			PreferServerCipherSuites: true,
			SessionTicketsEnabled:    true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "http3-curve-reload-observe",
			Description: "records HTTP/3 TLS curve preference hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-http3-curve-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-http3-curve-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTP3StateWithCurvePreferences(t, udpBind, siteHost, requestPath, []tls.CurveID{tls.CurveP256}, tls.CurveP256)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTP/3 curve response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "http3 curve preferences hot reload upstream:"+requestPath {
		t.Fatalf("initial HTTP/3 curve response body = %q, want %q", bodyBefore, "http3 curve preferences hot reload upstream:"+requestPath)
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial HTTP/3 curve response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial HTTP/3 TLS default curve preference",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsVersion:   "TLS13",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyBefore)),
		tlsCurves:    []string{strconv.Itoa(int(tls.CurveP256))},
	})

	var updateResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"curve_preferences":"CurveP384"}`), &updateResp)
	if updateResp.CurvePreferences != "CurveP384" {
		t.Fatalf("update response curve_preferences = %q, want %q", updateResp.CurvePreferences, "CurveP384")
	}

	respAfter, bodyAfter := appProc.waitHTTP3StateWithCurvePreferences(t, udpBind, siteHost, requestPath, []tls.CurveID{tls.CurveP384}, tls.CurveP384)
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded HTTP/3 curve response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "http3 curve preferences hot reload upstream:"+requestPath {
		t.Fatalf("reloaded HTTP/3 curve response body = %q, want %q", bodyAfter, "http3 curve preferences hot reload upstream:"+requestPath)
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("reloaded HTTP/3 curve response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded HTTP/3 TLS default curve preference",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDAfter,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsVersion:   "TLS13",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyAfter)),
		tlsCurves:    []string{strconv.Itoa(int(tls.CurveP384))},
	})

	failurePath := requestPath + "/unsupported-curve"
	siteObservabilityBeforeFailure := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBeforeFailure := appProc.globalObservabilityTotals(t)
	fingerprintBeforeFailure := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h3"},
	})
	appProc.requireHTTP3CurveFailure(t, udpBind, siteHost, failurePath, []tls.CurveID{tls.CurveP256})
	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBeforeFailure, "HTTP/3 unsupported curve handshake failure")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBeforeFailure, "HTTP/3 unsupported curve handshake failure")
	appProc.requireNoGlobalObservability(t, siteHost, failurePath, "HTTP/3 unsupported curve handshake failure")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h3"},
	}, fingerprintBeforeFailure, "HTTP/3 unsupported curve handshake failure")
}

func TestRunHotReloadsNetworkDefaultALPNForNewHTTPSConnectionsInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "network default alpn hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "network-default-alpn-reload.example.test"
	const requestPath = "/network-default-alpn-reload-check"

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
			Name:        "network-default-alpn-reload-observe",
			Description: "records network default ALPN hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-network-default-alpn-h2",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h2",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-network-default-alpn-http11",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:http/1.1",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
			{
				Name:     "observe-network-default-alpn-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 3,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "network default alpn hot reload upstream" {
		t.Fatalf("initial HTTPS response body = %q, want %q", bodyBefore, "network default alpn hot reload upstream")
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial network default ALPN h2",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyBefore)),
	})

	var disableH2Resp adminsystem.NetworkConfig
	appProc.postJSON(t, "/api/v1/network-config", []byte(`{"default_alpn":"http/1.1"}`), &disableH2Resp)
	if disableH2Resp.DefaultALPN != "http/1.1" {
		t.Fatalf("disable h2 response default_alpn = %q, want %q", disableH2Resp.DefaultALPN, "http/1.1")
	}
	if !disableH2Resp.HTTP2Enabled {
		t.Fatal("disable h2 response http2_enabled = false, want true")
	}

	respDisabled, bodyDisabled := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 1, "http/1.1")
	if respDisabled.StatusCode != http.StatusOK {
		t.Fatalf("disabled h2 HTTPS response status = %d, want %d, body=%s\n%s", respDisabled.StatusCode, http.StatusOK, bodyDisabled, appProc.output.String())
	}
	if bodyDisabled != "network default alpn hot reload upstream" {
		t.Fatalf("disabled h2 HTTPS response body = %q, want %q", bodyDisabled, "network default alpn hot reload upstream")
	}
	requestIDDisabled := strings.TrimSpace(respDisabled.Header.Get("X-Request-ID"))
	if requestIDDisabled == "" {
		t.Fatal("disabled h2 HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "disabled network default ALPN http/1.1",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDDisabled,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "http/1.1",
		tlsVersion:   "TLS13",
		tlsALPN:      "http/1.1",
		ja4Prefix:    't',
		responseSize: int64(len(bodyDisabled)),
	})

	var enableH2Resp adminsystem.NetworkConfig
	appProc.postJSON(t, "/api/v1/network-config", []byte(`{"default_alpn":"h2,http/1.1"}`), &enableH2Resp)
	if enableH2Resp.DefaultALPN != "h2,http/1.1" {
		t.Fatalf("enable h2 response default_alpn = %q, want %q", enableH2Resp.DefaultALPN, "h2,http/1.1")
	}
	if !enableH2Resp.HTTP2Enabled {
		t.Fatal("enable h2 response http2_enabled = false, want true")
	}

	respAfter, bodyAfter := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("re-enabled h2 HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "network default alpn hot reload upstream" {
		t.Fatalf("re-enabled h2 HTTPS response body = %q, want %q", bodyAfter, "network default alpn hot reload upstream")
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("re-enabled h2 HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "re-enabled network default ALPN h2",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDAfter,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyAfter)),
	})
}

func TestRunHotReloadsTLSDefaultALPNForInheritedSitesInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tls default alpn hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "tls-default-alpn-reload.example.test"
	const requestPath = "/tls-default-alpn-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   false,
			DefaultALPN:    "http/1.1",
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

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:               "TLS12",
			MaxVersion:               "TLS13",
			DefaultALPN:              "h2,http/1.1",
			CurvePreferences:         "X25519,CurveP256,CurveP384",
			PreferServerCipherSuites: true,
			SelfSignedOnIP:           true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "tls-default-alpn-reload-observe",
			Description: "records TLS default ALPN hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-initial-default-alpn-h2",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h2",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-initial-default-alpn-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
			{
				Name:     "observe-reloaded-default-alpn-http11",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:http/1.1",
				Action:   store.ActionObserve,
				Priority: 3,
				Enabled:  true,
			},
			{
				Name:     "observe-reloaded-default-alpn-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 4,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	respBefore, bodyBefore := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "tls default alpn hot reload upstream" {
		t.Fatalf("initial HTTPS response body = %q, want %q", bodyBefore, "tls default alpn hot reload upstream")
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial TLS default ALPN h2",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyBefore)),
	})

	var updateResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"default_alpn":"http/1.1"}`), &updateResp)
	if updateResp.DefaultALPN != "http/1.1" {
		t.Fatalf("update response default_alpn = %q, want %q", updateResp.DefaultALPN, "http/1.1")
	}

	respAfter, bodyAfter := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 1, "http/1.1")
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "tls default alpn hot reload upstream" {
		t.Fatalf("reloaded HTTPS response body = %q, want %q", bodyAfter, "tls default alpn hot reload upstream")
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("reloaded HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded TLS default ALPN http/1.1",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDAfter,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "http/1.1",
		tlsVersion:   "TLS13",
		tlsALPN:      "http/1.1",
		ja4Prefix:    't',
		responseSize: int64(len(bodyAfter)),
	})
}

func TestRunHotReloadsTLSDefaultALPNControlsInheritedHTTP3InSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tls default alpn http3 upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "tls-default-alpn-http3.example.test"
	const requestPath = "/tls-default-alpn-http3-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "http/1.1",
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
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		policy := store.Policy{
			Name:        "tls-default-alpn-http3-control-observe",
			Description: "records TLS default ALPN HTTP/3 control hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-tls-default-alpn-http3-h2",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h2",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-tls-default-alpn-http3-h3",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h3",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
			{
				Name:     "observe-tls-default-alpn-http3-http11",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:http/1.1",
				Action:   store.ActionObserve,
				Priority: 3,
				Enabled:  true,
			},
			{
				Name:     "observe-tls-default-alpn-http3-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 4,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
			PolicyID:     &policy.ID,
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		siteID = site.ID
		return nil
	})

	wantAltSvc := fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind))
	respBefore, bodyBefore := appProc.waitHTTPSProtocolAltSvc(t, tcpBind, siteHost, requestPath, 2, "h2", wantAltSvc)
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial HTTPS response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "tls default alpn http3 upstream:"+requestPath {
		t.Fatalf("initial HTTPS response body = %q, want %q", bodyBefore, "tls default alpn http3 upstream:"+requestPath)
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial TLS default ALPN HTTP/3 control HTTPS",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyBefore)),
	})

	respH3, bodyH3 := appProc.doHTTP3Request(t, udpBind, siteHost, requestPath)
	if respH3.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 response status = %d, want %d, body=%s\n%s", respH3.StatusCode, http.StatusOK, bodyH3, appProc.output.String())
	}
	if bodyH3 != "tls default alpn http3 upstream:"+requestPath {
		t.Fatalf("HTTP/3 response body = %q, want %q", bodyH3, "tls default alpn http3 upstream:"+requestPath)
	}
	if respH3.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 proto major = %d, want 3", respH3.ProtoMajor)
	}
	requireAppProcessHTTP3TLSState(t, respH3, "initial TLS default ALPN HTTP/3 control HTTP/3")
	requestIDH3 := strings.TrimSpace(respH3.Header.Get("X-Request-ID"))
	if requestIDH3 == "" {
		t.Fatal("HTTP/3 response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial TLS default ALPN HTTP/3 control HTTP/3",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDH3,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h3",
		tlsVersion:   "TLS13",
		tlsALPN:      "h3",
		ja4Prefix:    'q',
		responseSize: int64(len(bodyH3)),
	})

	var updateResp adminsystem.TLSDefaultConfig
	appProc.postJSON(t, "/api/v1/tls-config", []byte(`{"default_alpn":"http/1.1"}`), &updateResp)
	if updateResp.DefaultALPN != "http/1.1" {
		t.Fatalf("update response default_alpn = %q, want %q", updateResp.DefaultALPN, "http/1.1")
	}

	respAfter, bodyAfter := appProc.waitHTTPSProtocolAltSvc(t, tcpBind, siteHost, requestPath, 1, "http/1.1", "")
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded HTTPS response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "tls default alpn http3 upstream:"+requestPath {
		t.Fatalf("reloaded HTTPS response body = %q, want %q", bodyAfter, "tls default alpn http3 upstream:"+requestPath)
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("reloaded HTTPS response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded TLS default ALPN HTTP/3 control HTTPS",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDAfter,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "http/1.1",
		tlsVersion:   "TLS13",
		tlsALPN:      "http/1.1",
		ja4Prefix:    't',
		responseSize: int64(len(bodyAfter)),
	})
	unavailableHost := "tls-default-alpn-http3-disabled-unavailable.example.test"
	unavailablePath := requestPath + "/disabled-h3-alpn"
	siteObservabilityBeforeUnavailable := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBeforeUnavailable := appProc.globalObservabilityTotals(t)
	appProc.requireHTTP3Unavailable(t, udpBind, unavailableHost, unavailablePath)
	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBeforeUnavailable, "TLS default ALPN removed HTTP/3")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBeforeUnavailable, "TLS default ALPN removed HTTP/3")
	appProc.requireNoGlobalObservability(t, unavailableHost, unavailablePath, "TLS default ALPN removed HTTP/3")
	appProc.requireNoFingerprintSummary(t, url.Values{
		"tls_sni":  []string{unavailableHost},
		"tls_alpn": []string{"h3"},
	}, "TLS default ALPN removed HTTP/3")
	appProc.requireNoSiteObservability(t, siteID, unavailablePath, "TLS default ALPN removed HTTP/3")
}

func TestRunHotReloadsHTTP2ConfigForNewConnectionsInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http2 hot reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "http2-reload.example.test"
	const requestPath = "/http2-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		policy := store.Policy{
			Name:        "http2-config-reload-observe",
			Description: "records HTTP/2 config hot reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rule := store.Rule{
			Name:     "observe-http2-config-reload-cipher",
			PolicyID: policy.ID,
			Phase:    store.PhaseCustom,
			Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
			Action:   store.ActionObserve,
			Priority: 1,
			Enabled:  true,
		}
		if err := db.Create(&rule).Error; err != nil {
			return fmt.Errorf("create rule %q: %w", rule.Name, err)
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

	connBefore, frBefore, settingsBefore := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	if got := settingsBefore[http2.SettingMaxConcurrentStreams]; got != 100 {
		t.Fatalf("initial SETTINGS_MAX_CONCURRENT_STREAMS = %d, want 100", got)
	}
	initialHeaderListSize, ok := settingsBefore[http2.SettingMaxHeaderListSize]
	if !ok {
		t.Fatal("initial server settings missing SETTINGS_MAX_HEADER_LIST_SIZE")
	}
	if initialHeaderListSize != uint32((1<<20)+(100*32)) {
		t.Fatalf("initial SETTINGS_MAX_HEADER_LIST_SIZE = %d, want %d", initialHeaderListSize, uint32((1<<20)+(100*32)))
	}

	writeRawHTTP2HeadersWithDuplicateCookieFieldsProcess(
		t,
		frBefore,
		1,
		siteHost,
		requestPath,
		12,
	)
	respHeadersRawBefore, streamEndedRawBefore := readRawHTTP2ResponseHeadersProcess(t, connBefore, frBefore, 1, "200")
	if streamEndedRawBefore {
		t.Fatal("initial raw HTTP/2 response ended with headers before body")
	}
	if !readRawHTTP2ResponseDataContainsProcess(t, connBefore, frBefore, 1, "http2 hot reload upstream") {
		t.Fatal("initial raw HTTP/2 response body did not contain upstream marker")
	}
	requestIDRawBefore := strings.TrimSpace(respHeadersRawBefore.Get("X-Request-ID"))
	if requestIDRawBefore == "" {
		t.Fatal("initial raw HTTP/2 response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial raw HTTP/2 config reload",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDRawBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len("http2 hot reload upstream")),
	})
	_ = connBefore.Close()

	respBefore, bodyBefore := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respBefore.StatusCode != http.StatusOK {
		t.Fatalf("initial observed HTTP/2 response status = %d, want %d, body=%s\n%s", respBefore.StatusCode, http.StatusOK, bodyBefore, appProc.output.String())
	}
	if bodyBefore != "http2 hot reload upstream" {
		t.Fatalf("initial observed HTTP/2 response body = %q, want %q", bodyBefore, "http2 hot reload upstream")
	}
	requestIDBefore := strings.TrimSpace(respBefore.Header.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial observed HTTP/2 response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial HTTP/2 config reload",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyBefore)),
	})

	var updateResp struct {
		ReadTimeoutSeconds           int    `json:"read_timeout_seconds"`
		DisableKeepalive             bool   `json:"disable_keepalive"`
		PermitProhibitedCipherSuites bool   `json:"permit_prohibited_cipher_suites"`
		MaxConcurrentStreams         uint32 `json:"max_concurrent_streams"`
		MaxReadFrameSize             uint32 `json:"max_read_frame_size"`
		IdleTimeoutSeconds           int    `json:"idle_timeout_seconds"`
		MaxUploadBufferPerConnection int32  `json:"max_upload_buffer_per_connection"`
		MaxUploadBufferPerStream     int32  `json:"max_upload_buffer_per_stream"`
		MaxHeaderBytes               int    `json:"max_header_bytes"`
		MaxHeaderFields              int    `json:"max_header_fields"`
	}
	appProc.postJSON(
		t,
		"/api/v1/http2-config",
		[]byte(`{"max_concurrent_streams":7,"max_header_bytes":2048,"max_header_fields":15}`),
		&updateResp,
	)
	if updateResp.MaxConcurrentStreams != 7 {
		t.Fatalf("update response max_concurrent_streams = %d, want 7", updateResp.MaxConcurrentStreams)
	}
	if updateResp.MaxHeaderBytes != 2048 {
		t.Fatalf("update response max_header_bytes = %d, want 2048", updateResp.MaxHeaderBytes)
	}
	if updateResp.MaxHeaderFields != 15 {
		t.Fatalf("update response max_header_fields = %d, want 15", updateResp.MaxHeaderFields)
	}

	appProc.waitHTTP2ServerSettings(t, tcpBind, func(settings map[http2.SettingID]uint32) bool {
		return settings[http2.SettingMaxConcurrentStreams] == 7 &&
			settings[http2.SettingMaxHeaderListSize] == uint32(2048+(15*32)) &&
			settings[http2.SettingMaxFrameSize] == 64<<10
	})

	connAfter, frAfter, settingsAfter := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	defer connAfter.Close()

	if got := settingsAfter[http2.SettingMaxConcurrentStreams]; got != 7 {
		t.Fatalf("reloaded SETTINGS_MAX_CONCURRENT_STREAMS = %d, want 7", got)
	}
	if got := settingsAfter[http2.SettingMaxHeaderListSize]; got != uint32(2048+(15*32)) {
		t.Fatalf("reloaded SETTINGS_MAX_HEADER_LIST_SIZE = %d, want %d", got, uint32(2048+(5*32)))
	}

	respAfter, bodyAfter := appProc.waitHTTPSProtocol(t, tcpBind, siteHost, requestPath, 2, "h2")
	if respAfter.StatusCode != http.StatusOK {
		t.Fatalf("reloaded observed HTTP/2 response status = %d, want %d, body=%s\n%s", respAfter.StatusCode, http.StatusOK, bodyAfter, appProc.output.String())
	}
	if bodyAfter != "http2 hot reload upstream" {
		t.Fatalf("reloaded observed HTTP/2 response body = %q, want %q", bodyAfter, "http2 hot reload upstream")
	}
	requestIDAfter := strings.TrimSpace(respAfter.Header.Get("X-Request-ID"))
	if requestIDAfter == "" {
		t.Fatal("reloaded observed HTTP/2 response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "reloaded HTTP/2 config reload",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDAfter,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len(bodyAfter)),
	})

	siteObservabilityBeforeRejection := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBeforeRejection := appProc.globalObservabilityTotals(t)
	fingerprintBeforeRejection := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})
	rejectedPathAfterReload := requestPath + "/too-many-headers-after-reload"
	writeRawHTTP2HeadersWithDuplicateCookieFieldsProcess(
		t,
		frAfter,
		1,
		siteHost,
		rejectedPathAfterReload,
		20,
	)
	readRawHTTP2ResponseStatusProcess(t, connAfter, frAfter, 1, "431")
	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBeforeRejection, "reloaded raw HTTP/2 header field rejection")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBeforeRejection, "reloaded raw HTTP/2 header field rejection")
	appProc.requireNoSiteObservability(t, siteID, rejectedPathAfterReload, "reloaded raw HTTP/2 header field rejection")
	appProc.requireNoGlobalObservability(t, siteHost, rejectedPathAfterReload, "reloaded raw HTTP/2 header field rejection")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBeforeRejection, "reloaded raw HTTP/2 header field rejection")
}

func TestRunHotReloadsHTTP2ConfigWithoutBlockingOnExistingConnectionsInSeparateProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "http2 stale connection reload upstream")
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)

	const siteHost = "http2-stale-connection-reload.example.test"
	const requestPath = "/http2-stale-connection-reload-check"

	var siteID uint
	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		policy := store.Policy{
			Name:        "http2-stale-connection-reload-observe",
			Description: "records HTTP/2 stale connection reload requests for observability verification",
		}
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		rules := []store.Rule{
			{
				Name:     "observe-http2-stale-connection-alpn",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_alpn:h2",
				Action:   store.ActionObserve,
				Priority: 1,
				Enabled:  true,
			},
			{
				Name:     "observe-http2-stale-connection-cipher",
				PolicyID: policy.ID,
				Phase:    store.PhaseCustom,
				Pattern:  "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
				Action:   store.ActionObserve,
				Priority: 2,
				Enabled:  true,
			},
		}
		for i := range rules {
			if err := db.Create(&rules[i]).Error; err != nil {
				return fmt.Errorf("create rule %q: %w", rules[i].Name, err)
			}
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

	connBefore, frBefore, settingsBefore := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = connBefore.Close()
	})
	if got := settingsBefore[http2.SettingMaxConcurrentStreams]; got != 100 {
		t.Fatalf("initial SETTINGS_MAX_CONCURRENT_STREAMS = %d, want 100", got)
	}
	if got := settingsBefore[http2.SettingMaxHeaderListSize]; got != uint32((1<<20)+(100*32)) {
		t.Fatalf("initial SETTINGS_MAX_HEADER_LIST_SIZE = %d, want %d", got, uint32((1<<20)+(100*32)))
	}

	writeRawHTTP2HeadersWithDuplicateCookieFieldsProcess(
		t,
		frBefore,
		1,
		siteHost,
		requestPath,
		12,
	)
	respHeadersBefore, streamEndedBefore := readRawHTTP2ResponseHeadersProcess(t, connBefore, frBefore, 1, "200")
	if streamEndedBefore {
		t.Fatal("initial raw HTTP/2 response ended with headers before body")
	}
	if !readRawHTTP2ResponseDataContainsProcess(t, connBefore, frBefore, 1, "http2 stale connection reload upstream") {
		t.Fatal("initial raw HTTP/2 response body did not contain upstream marker")
	}
	requestIDBefore := strings.TrimSpace(respHeadersBefore.Get("X-Request-ID"))
	if requestIDBefore == "" {
		t.Fatal("initial raw HTTP/2 response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "initial HTTP/2 stale connection reload",
		siteID:       siteID,
		requestPath:  requestPath,
		requestID:    requestIDBefore,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len("http2 stale connection reload upstream")),
	})

	var updateResp struct {
		ReadTimeoutSeconds           int    `json:"read_timeout_seconds"`
		DisableKeepalive             bool   `json:"disable_keepalive"`
		PermitProhibitedCipherSuites bool   `json:"permit_prohibited_cipher_suites"`
		MaxConcurrentStreams         uint32 `json:"max_concurrent_streams"`
		MaxReadFrameSize             uint32 `json:"max_read_frame_size"`
		IdleTimeoutSeconds           int    `json:"idle_timeout_seconds"`
		MaxUploadBufferPerConnection int32  `json:"max_upload_buffer_per_connection"`
		MaxUploadBufferPerStream     int32  `json:"max_upload_buffer_per_stream"`
		MaxHeaderBytes               int    `json:"max_header_bytes"`
		MaxHeaderFields              int    `json:"max_header_fields"`
	}
	reloadStarted := time.Now()
	appProc.postJSON(
		t,
		"/api/v1/http2-config",
		[]byte(`{"max_concurrent_streams":7,"max_header_bytes":2048,"max_header_fields":15}`),
		&updateResp,
	)
	if elapsed := time.Since(reloadStarted); elapsed > 2*time.Second {
		t.Fatalf("HTTP/2 config reload took %s with an existing h2 connection, want less than 2s", elapsed)
	}
	if updateResp.MaxConcurrentStreams != 7 {
		t.Fatalf("update response max_concurrent_streams = %d, want 7", updateResp.MaxConcurrentStreams)
	}
	if updateResp.MaxHeaderBytes != 2048 {
		t.Fatalf("update response max_header_bytes = %d, want 2048", updateResp.MaxHeaderBytes)
	}
	if updateResp.MaxHeaderFields != 15 {
		t.Fatalf("update response max_header_fields = %d, want 15", updateResp.MaxHeaderFields)
	}

	appProc.waitHTTP2ServerSettings(t, tcpBind, func(settings map[http2.SettingID]uint32) bool {
		return settings[http2.SettingMaxConcurrentStreams] == 7 &&
			settings[http2.SettingMaxHeaderListSize] == uint32(2048+(15*32)) &&
			settings[http2.SettingMaxFrameSize] == 64<<10
	})

	stalePathAfterReload := requestPath + "/existing-after-reload"
	writeRawHTTP2HeadersWithDuplicateCookieFieldsProcess(
		t,
		frBefore,
		3,
		siteHost,
		stalePathAfterReload,
		1,
	)
	respHeadersStaleAfter, streamEndedStaleAfter := readRawHTTP2ResponseHeadersProcess(t, connBefore, frBefore, 3, "200")
	if streamEndedStaleAfter {
		t.Fatal("stale raw HTTP/2 response ended with headers before body")
	}
	if !readRawHTTP2ResponseDataContainsProcess(t, connBefore, frBefore, 3, "http2 stale connection reload upstream") {
		t.Fatal("stale raw HTTP/2 response body did not contain upstream marker")
	}
	requestIDStaleAfter := strings.TrimSpace(respHeadersStaleAfter.Get("X-Request-ID"))
	if requestIDStaleAfter == "" {
		t.Fatal("stale raw HTTP/2 response missing X-Request-ID header")
	}
	requireAppProcessObservedRequest(t, appProc, appProcessObservedRequestExpectation{
		label:        "stale raw HTTP/2 connection after reload",
		siteID:       siteID,
		requestPath:  stalePathAfterReload,
		requestID:    requestIDStaleAfter,
		siteHost:     siteHost,
		statusCode:   http.StatusOK,
		httpProtocol: "h2",
		tlsVersion:   "TLS13",
		tlsALPN:      "h2",
		ja4Prefix:    't',
		responseSize: int64(len("http2 stale connection reload upstream")),
	})

	connAfter, frAfter, settingsAfter := appProc.newRawHTTP2ClientConnWithServerSettingsForHost(t, tcpBind, siteHost)
	t.Cleanup(func() {
		_ = connAfter.Close()
	})
	if got := settingsAfter[http2.SettingMaxConcurrentStreams]; got != 7 {
		t.Fatalf("reloaded SETTINGS_MAX_CONCURRENT_STREAMS = %d, want 7", got)
	}
	if got := settingsAfter[http2.SettingMaxHeaderListSize]; got != uint32(2048+(15*32)) {
		t.Fatalf("reloaded SETTINGS_MAX_HEADER_LIST_SIZE = %d, want %d", got, uint32(2048+(15*32)))
	}
	siteObservabilityBeforeRejection := appProc.siteObservabilityTotals(t, siteID)
	globalObservabilityBeforeRejection := appProc.globalObservabilityTotals(t)
	fingerprintBeforeRejection := appProc.fingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	})
	rejectedPathAfterReload := requestPath + "/too-many-headers-after-reload"
	writeRawHTTP2HeadersWithDuplicateCookieFieldsProcess(
		t,
		frAfter,
		1,
		siteHost,
		rejectedPathAfterReload,
		20,
	)
	readRawHTTP2ResponseStatusProcess(t, connAfter, frAfter, 1, "431")
	appProc.requireSiteObservabilityTotals(t, siteID, siteObservabilityBeforeRejection, "reloaded raw HTTP/2 stale test header field rejection")
	appProc.requireGlobalObservabilityTotals(t, globalObservabilityBeforeRejection, "reloaded raw HTTP/2 stale test header field rejection")
	appProc.requireNoSiteObservability(t, siteID, rejectedPathAfterReload, "reloaded raw HTTP/2 stale test header field rejection")
	appProc.requireNoGlobalObservability(t, siteHost, rejectedPathAfterReload, "reloaded raw HTTP/2 stale test header field rejection")
	appProc.requireFingerprintSummaryTotals(t, url.Values{
		"tls_sni":  []string{siteHost},
		"tls_alpn": []string{"h2"},
	}, fingerprintBeforeRejection, "reloaded raw HTTP/2 stale test header field rejection")
}

type appProcessHarness struct {
	adminURL string
	apiToken string
	cancel   context.CancelFunc
	cmd      *exec.Cmd
	output   lockedBuffer
	waitCh   chan error
	exited   bool
	exitErr  error
}

func startAppProcessHarness(t *testing.T) *appProcessHarness {
	return startAppProcessHarnessWithSetup(t, nil)
}

func startAppProcessHarnessWithSetup(t *testing.T, setup func(*gorm.DB) error) *appProcessHarness {
	return startAppProcessHarnessWithSetupAndEnv(t, setup, nil)
}

func startAppProcessHarnessWithSetupAndEnv(t *testing.T, setup func(*gorm.DB) error, extraEnv []string) *appProcessHarness {
	t.Helper()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "waf.db")
	logDBPath := filepath.Join(tempDir, "waf_logs.db")
	adminBind := reserveAppProcessBind(t)
	apiToken := seedAppProcessConfigDB(t, dbPath, adminBind, setup)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppProcessHelper$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		appProcessHelperEnv+"=1",
		"MY_OPENWAF_DB_DRIVER=sqlite",
		"MY_OPENWAF_DSN="+dbPath,
		"MY_OPENWAF_LOG_DSN="+logDBPath,
		"MY_OPENWAF_DATA="+tempDir,
		"MY_OPENWAF_ADMIN_BIND="+adminBind,
		"MY_OPENWAF_REDIS_ADDR=",
		"MY_OPENWAF_REDIS_PASSWORD=",
		"MY_OPENWAF_REDIS_DB=0",
	)
	cmd.Env = append(cmd.Env, extraEnv...)

	h := &appProcessHarness{
		adminURL: "http://" + adminBind,
		apiToken: apiToken,
		cancel:   cancel,
		cmd:      cmd,
		waitCh:   make(chan error, 1),
	}
	cmd.Stdout = &h.output
	cmd.Stderr = &h.output

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start app helper process: %v", err)
	}

	go func() {
		h.waitCh <- cmd.Wait()
	}()

	t.Cleanup(func() {
		h.stop(t)
	})

	h.waitForReady(t)
	return h
}

func reserveAppProcessBind(t *testing.T) string {
	t.Helper()

	for attempt := 0; attempt < 128; attempt++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve app process bind: %v", err)
		}
		bind := ln.Addr().String()
		if err := ln.Close(); err != nil {
			t.Fatalf("release app process bind: %v", err)
		}
		if reserveAppProcessBindOnce("tcp", bind) {
			return bind
		}
	}

	t.Fatal("reserve app process bind: exhausted unique bind attempts")
	return ""
}

func reserveAppProcessUDPBind(t *testing.T) string {
	t.Helper()

	for attempt := 0; attempt < 128; attempt++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve app process udp bind: %v", err)
		}
		bind := pc.LocalAddr().String()
		if err := pc.Close(); err != nil {
			t.Fatalf("release app process udp bind: %v", err)
		}
		if reserveAppProcessBindOnce("udp", bind) {
			return bind
		}
	}

	t.Fatal("reserve app process udp bind: exhausted unique bind attempts")
	return ""
}

func reserveAppProcessBindOnce(network, bind string) bool {
	key := network + "://" + bind
	appProcessReservedBinds.Lock()
	defer appProcessReservedBinds.Unlock()
	if _, ok := appProcessReservedBinds.seen[key]; ok {
		return false
	}
	appProcessReservedBinds.seen[key] = struct{}{}
	return true
}

func startAppProcessHTTP3UpstreamServer(t *testing.T, handler http.Handler) (*http3.Server, string) {
	t.Helper()

	cert, err := acme.GenerateSelfSigned("127.0.0.1:0")
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp for http3 upstream: %v", err)
	}

	server := &http3.Server{
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h3"},
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(pc)
	}()

	t.Cleanup(func() {
		closeAppProcessHTTP3UpstreamServer(t, server)
		select {
		case serveErr := <-errCh:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !strings.Contains(serveErr.Error(), "closed network connection") {
				t.Fatalf("http3 upstream serve returned error: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("http3 upstream server did not stop in time")
		}
	})

	return server, "h3://" + pc.LocalAddr().String()
}

func closeAppProcessHTTP3UpstreamServer(t *testing.T, server *http3.Server) {
	t.Helper()
	if server == nil {
		return
	}
	if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("close http3 upstream server: %v", err)
	}
}

func seedAppProcessConfigDB(t *testing.T, dbPath string, adminBind string, setup func(*gorm.DB) error) string {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open process config db: %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("migrate process config db: %v", err)
	}
	token, _, err := store.SeedDefaults(db, adminBind, slog.Default())
	if err != nil {
		t.Fatalf("seed process config db: %v", err)
	}
	if token == "" {
		t.Fatal("seed process config db returned empty api token")
	}
	if setup != nil {
		if err := setup(db); err != nil {
			t.Fatalf("setup process config db: %v", err)
		}
	}
	sqlDB, err := db.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
	return token
}

func (h *appProcessHarness) pollExit() (bool, error) {
	if h.exited {
		return true, h.exitErr
	}
	select {
	case err := <-h.waitCh:
		h.exited = true
		h.exitErr = err
		return true, err
	default:
		return false, nil
	}
}

func (h *appProcessHarness) waitForReady(t *testing.T) {
	t.Helper()

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited early: %v\n%s", err, h.output.String())
		}

		req, err := http.NewRequest(http.MethodGet, h.adminURL+"/api/v1/health", nil)
		if err != nil {
			t.Fatalf("build health request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("app helper process did not become ready in time\n%s", h.output.String())
}

func (h *appProcessHarness) stop(t *testing.T) {
	t.Helper()

	if exited, _ := h.pollExit(); exited {
		return
	}
	h.cancel()

	select {
	case err := <-h.waitCh:
		h.exited = true
		h.exitErr = err
	case <-time.After(5 * time.Second):
		if h.cmd != nil && h.cmd.Process != nil {
			_ = h.cmd.Process.Kill()
		}
		err := <-h.waitCh
		h.exited = true
		h.exitErr = err
	}
}

func (h *appProcessHarness) getJSON(t *testing.T, path string, out any) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, h.adminURL+path, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+h.apiToken)
	h.doJSON(t, req, out)
}

func (h *appProcessHarness) postJSON(t *testing.T, path string, body []byte, out any) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, h.adminURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build POST %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+h.apiToken)
	req.Header.Set("Content-Type", "application/json")
	h.doJSON(t, req, out)
}

func (h *appProcessHarness) doJSON(t *testing.T, req *http.Request, out any) {
	t.Helper()

	if exited, err := h.pollExit(); exited {
		t.Fatalf("app helper process exited before %s %s: %v\n%s", req.Method, req.URL.Path, err, h.output.String())
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", req.Method, req.URL.Path, err, h.output.String())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", req.Method, req.URL.Path, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s status = %d, want 200, body=%s\n%s", req.Method, req.URL.Path, resp.StatusCode, string(body), h.output.String())
	}
	if out == nil {
		return
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("decode %s %s response: %v, body=%s", req.Method, req.URL.Path, err, string(body))
	}
}

func parseAppProcessCertificatePEM(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(strings.TrimSpace(certPEM)))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("certificate PEM did not contain a CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate PEM: %v", err)
	}
	return cert
}

func requireAppProcessPeerCertificateRaw(t *testing.T, resp *http.Response, wantRaw []byte, label string) {
	t.Helper()

	if resp.TLS == nil {
		t.Fatalf("%s TLS state is nil", label)
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("%s peer certificates are empty", label)
	}
	if !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, wantRaw) {
		t.Fatalf("%s peer certificate raw bytes did not match expected certificate", label)
	}
}

func requireAppProcessHTTP3TLSState(t *testing.T, resp *http.Response, label string) {
	t.Helper()

	if resp.TLS == nil {
		t.Fatalf("%s TLS state is nil", label)
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("%s TLS version = %#x, want TLS 1.3", label, resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("%s TLS ALPN = %q, want %q", label, resp.TLS.NegotiatedProtocol, "h3")
	}
}

func requireAppProcessOCSPResponse(t *testing.T, resp *http.Response, want []byte, label string) {
	t.Helper()

	if resp.TLS == nil {
		t.Fatalf("%s TLS state is nil", label)
	}
	if !bytes.Equal(resp.TLS.OCSPResponse, want) {
		t.Fatalf("%s OCSP response = %x, want %x", label, resp.TLS.OCSPResponse, want)
	}
}

func requireAppProcessNoOCSPResponse(t *testing.T, resp *http.Response, label string) {
	t.Helper()

	if resp.TLS == nil {
		t.Fatalf("%s TLS state is nil", label)
	}
	if len(resp.TLS.OCSPResponse) != 0 {
		t.Fatalf("%s OCSP response = %x, want empty", label, resp.TLS.OCSPResponse)
	}
}

func (h *appProcessHarness) waitRuntimeRedisState(t *testing.T, wantEnabled bool, wantAddr string, wantDB int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var runtimeResp adminsystem.RuntimeConfigResponse
		h.getJSON(t, "/api/v1/runtime-config", &runtimeResp)
		if runtimeResp.RedisEnabled == wantEnabled && runtimeResp.RedisAddr == wantAddr && runtimeResp.RedisDB == wantDB {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("runtime redis state did not converge to enabled=%v addr=%q db=%d\n%s", wantEnabled, wantAddr, wantDB, h.output.String())
}

func (h *appProcessHarness) waitRuntimeResponseCompressionState(t *testing.T, wantEnabled bool, wantGzipEnabled bool, wantMinBytes int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var runtimeResp adminsystem.RuntimeConfigResponse
		h.getJSON(t, "/api/v1/runtime-config", &runtimeResp)
		if runtimeResp.ResponseCompressionEnabled == wantEnabled &&
			runtimeResp.ResponseCompressionGzipEnabled == wantGzipEnabled &&
			runtimeResp.ResponseCompressionMinBytes == wantMinBytes {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf(
		"runtime response compression state did not converge to enabled=%v gzip_enabled=%v min_bytes=%d\n%s",
		wantEnabled,
		wantGzipEnabled,
		wantMinBytes,
		h.output.String(),
	)
}

func (h *appProcessHarness) waitForRequestTrace(t *testing.T, requestID string) struct {
	RequestID      string                `json:"request_id"`
	AccessLogs     []store.AccessLog     `json:"access_logs"`
	SecurityEvents []store.SecurityEvent `json:"security_events"`
} {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var trace struct {
			RequestID      string                `json:"request_id"`
			AccessLogs     []store.AccessLog     `json:"access_logs"`
			SecurityEvents []store.SecurityEvent `json:"security_events"`
		}
		h.getJSON(t, "/api/v1/request/"+url.PathEscape(requestID), &trace)
		if len(trace.AccessLogs) > 0 || len(trace.SecurityEvents) > 0 {
			return trace
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("request trace did not appear for request_id=%q\n%s", requestID, h.output.String())
	return struct {
		RequestID      string                `json:"request_id"`
		AccessLogs     []store.AccessLog     `json:"access_logs"`
		SecurityEvents []store.SecurityEvent `json:"security_events"`
	}{}
}

func waitForAppMockRedisCommand(t *testing.T, srv *appMockRedisServer, prefix string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if appMockRedisHasCommand(srv.Commands(), prefix) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("mock redis did not observe command prefix %q, commands=%#v", prefix, srv.Commands())
}

func countAppMockRedisCommandsWithPrefix(commands []string, prefix string) int {
	prefix = strings.ToUpper(prefix)
	count := 0
	for _, command := range commands {
		if strings.Contains(strings.ToUpper(command), prefix) {
			count++
		}
	}
	return count
}

func (h *appProcessHarness) doHTTP3Request(t *testing.T, udpBind string, host string, path string) (*http.Response, string) {
	t.Helper()

	return h.doHTTP3RequestWithServerName(t, udpBind, host, host, path)
}

func (h *appProcessHarness) doHTTP3RequestWithServerName(t *testing.T, udpBind string, serverName string, host string, path string) (*http.Response, string) {
	t.Helper()

	targetAddr := udpBind
	targetURL := "https://" + serverName + ":" + extractPort(udpBind) + path
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, targetAddr, tlsCfg, cfg)
		},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		_ = transport.Close()
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP/3 request: %v\n%s", err, h.output.String())
		}

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTP/3 request: %v", err)
		}
		req.Host = host

		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read HTTP/3 response body: %v", readErr)
			}
			return resp, string(body)
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP/3 endpoint did not become ready in time for server_name=%q host=%q\n%s", serverName, host, h.output.String())
	return nil, ""
}

func (h *appProcessHarness) waitHTTP3Response(t *testing.T, udpBind string, host string, path string, ready func(*http.Response, string) bool) (*http.Response, string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP/3 response wait: %v\n%s", err, h.output.String())
		}

		resp, body := h.doHTTP3Request(t, udpBind, host, path)
		if ready == nil || ready(resp, body) {
			return resp, body
		}
		lastObserved = fmt.Sprintf("status=%d proto_major=%d body=%s", resp.StatusCode, resp.ProtoMajor, body)
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP/3 response did not converge, last=%s\n%s", lastObserved, h.output.String())
	return nil, ""
}

func (h *appProcessHarness) waitHTTP3SessionResumptionState(t *testing.T, udpBind string, host string, path string, wantResume bool) (*http.Response, string) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(udpBind) + path
	cache := tls.NewLRUClientSessionCache(8)
	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP/3 session resumption request: %v\n%s", err, h.output.String())
		}

		var lastResp *http.Response
		var lastBody string
		observed := make([]bool, 0, 3)
		for i := 0; i < 3; i++ {
			resp, body, err := h.doHTTP3RequestWithSessionCache(t, udpBind, targetURL, host, cache)
			if err != nil {
				lastObserved = err.Error()
				break
			}
			lastResp = resp
			lastBody = body
			didResume := resp.TLS != nil && resp.TLS.DidResume
			observed = append(observed, didResume)
			if resp.StatusCode != http.StatusOK {
				break
			}
			if wantResume && didResume {
				return resp, body
			}
		}
		if !wantResume && len(observed) == 3 && !observed[1] && !observed[2] && lastResp != nil && lastResp.StatusCode == http.StatusOK {
			return lastResp, lastBody
		}
		if len(observed) > 0 {
			status := 0
			tlsVersion := uint16(0)
			if lastResp != nil {
				status = lastResp.StatusCode
				if lastResp.TLS != nil {
					tlsVersion = lastResp.TLS.Version
				}
			}
			lastObserved = fmt.Sprintf("status=%d proto_major=%d tls_version=%#x did_resume=%v body=%s", status, 3, tlsVersion, observed, lastBody)
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP/3 session resumption state did not converge to did_resume=%v, last=%s\n%s", wantResume, lastObserved, h.output.String())
	return nil, ""
}

func (h *appProcessHarness) doHTTP3RequestWithSessionCache(t *testing.T, udpBind string, targetURL string, host string, cache tls.ClientSessionCache) (*http.Response, string, error) {
	t.Helper()

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h3"},
			ClientSessionCache: cache,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	defer func() {
		_ = transport.Close()
	}()

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 session resumption request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read HTTP/3 session resumption response body: %v", readErr)
	}
	return resp, string(body), nil
}

func (h *appProcessHarness) waitHTTP3StateWithCurvePreferences(t *testing.T, udpBind string, host string, path string, curvePreferences []tls.CurveID, wantCurveID tls.CurveID) (*http.Response, string) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(udpBind) + path
	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP/3 curve request: %v\n%s", err, h.output.String())
		}

		resp, body, err := h.doHTTP3RequestWithCurvePreferences(t, udpBind, targetURL, host, curvePreferences)
		if err != nil {
			lastObserved = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		negotiatedProtocol := ""
		negotiatedVersion := uint16(0)
		negotiatedCurveID := tls.CurveID(0)
		if resp.TLS != nil {
			negotiatedProtocol = resp.TLS.NegotiatedProtocol
			negotiatedVersion = resp.TLS.Version
			negotiatedCurveID = resp.TLS.CurveID
		}
		lastObserved = fmt.Sprintf("status=%d proto_major=%d alpn=%q tls_version=%#x curve_id=%#x body=%s", resp.StatusCode, resp.ProtoMajor, negotiatedProtocol, negotiatedVersion, negotiatedCurveID, body)
		if resp.StatusCode == http.StatusOK && resp.ProtoMajor == 3 && negotiatedProtocol == "h3" && negotiatedVersion == tls.VersionTLS13 && negotiatedCurveID == wantCurveID {
			return resp, body
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP/3 curve state did not converge to curve_id=%#x, last=%s\n%s", wantCurveID, lastObserved, h.output.String())
	return nil, ""
}

func (h *appProcessHarness) doHTTP3RequestWithCurvePreferences(t *testing.T, udpBind string, targetURL string, host string, curvePreferences []tls.CurveID) (*http.Response, string, error) {
	t.Helper()

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h3"},
			CurvePreferences:   curvePreferences,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
		},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	defer func() {
		_ = transport.Close()
	}()

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTP/3 curve request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read HTTP/3 curve response body: %v", readErr)
	}
	return resp, string(body), nil
}

func (h *appProcessHarness) requireHTTP3CurveFailure(t *testing.T, udpBind string, host string, path string, curvePreferences []tls.CurveID) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(udpBind) + path
	resp, body, err := h.doHTTP3RequestWithCurvePreferences(t, udpBind, targetURL, host, curvePreferences)
	if err != nil {
		return
	}

	negotiatedVersion := uint16(0)
	negotiatedProtocol := ""
	negotiatedCurveID := tls.CurveID(0)
	if resp.TLS != nil {
		negotiatedVersion = resp.TLS.Version
		negotiatedProtocol = resp.TLS.NegotiatedProtocol
		negotiatedCurveID = resp.TLS.CurveID
	}
	t.Fatalf("expected HTTP/3 request with client curve preferences %v to fail, got status=%d proto_major=%d tls_version=%#x curve_id=%#x alpn=%q body=%s\n%s", curvePreferences, resp.StatusCode, resp.ProtoMajor, negotiatedVersion, negotiatedCurveID, negotiatedProtocol, body, h.output.String())
}

func (h *appProcessHarness) requireHTTP3ALPNHandshakeFailure(t *testing.T, udpBind string, host string, nextProtos []string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, udpBind, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         host,
		NextProtos:         nextProtos,
	}, nil)
	if err != nil {
		return
	}
	defer func() {
		_ = conn.CloseWithError(0, "")
	}()

	state := conn.ConnectionState().TLS
	t.Fatalf("expected HTTP/3 request with client ALPN %v to fail, got tls_version=%#x alpn=%q\n%s", nextProtos, state.Version, state.NegotiatedProtocol, h.output.String())
}

func (h *appProcessHarness) closeIdleHTTP3Connection(t *testing.T, udpBind string, serverName string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, udpBind, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		NextProtos:         []string{"h3"},
	}, nil)
	if err != nil {
		t.Fatalf("dial idle HTTP/3 connection: %v\n%s", err, h.output.String())
	}
	state := conn.ConnectionState().TLS
	if state.Version != tls.VersionTLS13 {
		_ = conn.CloseWithError(0, "")
		t.Fatalf("idle HTTP/3 TLS version = %#x, want TLS 1.3", state.Version)
	}
	if state.NegotiatedProtocol != "h3" {
		_ = conn.CloseWithError(0, "")
		t.Fatalf("idle HTTP/3 ALPN = %q, want %q", state.NegotiatedProtocol, "h3")
	}
	if err := conn.CloseWithError(0, ""); err != nil {
		t.Fatalf("close idle HTTP/3 connection: %v", err)
	}
}

func (h *appProcessHarness) requireHTTP3Unavailable(t *testing.T, udpBind string, host string, path string) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(udpBind) + path
	deadline := time.Now().Add(3 * time.Second)
	successes := 0
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP/3 unavailable check: %v\n%s", err, h.output.String())
		}

		transport := &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			},
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return quic.DialAddr(ctx, udpBind, tlsCfg, cfg)
			},
		}
		client := &http.Client{
			Timeout:   700 * time.Millisecond,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			_ = transport.Close()
			t.Fatalf("build HTTP/3 unavailable request: %v", err)
		}
		req.Host = host

		resp, err := client.Do(req)
		if err != nil {
			_ = transport.Close()
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		_ = transport.Close()
		successes++
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP/3 endpoint %s still responded after expected removal, successes=%d\n%s", udpBind, successes, h.output.String())
}

func (h *appProcessHarness) waitHTTPSProtocol(t *testing.T, bind string, host string, path string, wantProtoMajor int, wantALPN string) (*http.Response, string) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTPS request: %v\n%s", err, h.output.String())
		}

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTPS request: %v", err)
		}
		req.Host = host

		resp, err := client.Do(req)
		if err != nil {
			lastObserved = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read HTTPS response body: %v", readErr)
		}
		transport.CloseIdleConnections()

		negotiatedProtocol := ""
		if resp.TLS != nil {
			negotiatedProtocol = resp.TLS.NegotiatedProtocol
		}
		lastObserved = fmt.Sprintf("status=%d proto_major=%d alpn=%q body=%s", resp.StatusCode, resp.ProtoMajor, negotiatedProtocol, string(body))
		if resp.ProtoMajor == wantProtoMajor && negotiatedProtocol == wantALPN {
			return resp, string(body)
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTPS protocol did not converge to proto_major=%d alpn=%q, last=%s\n%s", wantProtoMajor, wantALPN, lastObserved, h.output.String())
	return nil, ""
}

func (h *appProcessHarness) waitHTTPSProtocolAltSvc(t *testing.T, bind string, host string, path string, wantProtoMajor int, wantALPN string, wantAltSvc string) (*http.Response, string) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTPS Alt-Svc request: %v\n%s", err, h.output.String())
		}

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTPS Alt-Svc request: %v", err)
		}
		req.Host = host

		resp, err := client.Do(req)
		if err != nil {
			lastObserved = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read HTTPS Alt-Svc response body: %v", readErr)
		}
		transport.CloseIdleConnections()

		body := string(bodyBytes)
		gotAltSvc := resp.Header.Get("Alt-Svc")
		negotiatedProtocol := ""
		if resp.TLS != nil {
			negotiatedProtocol = resp.TLS.NegotiatedProtocol
		}
		lastObserved = fmt.Sprintf("status=%d proto_major=%d alpn=%q alt_svc=%q body=%s", resp.StatusCode, resp.ProtoMajor, negotiatedProtocol, gotAltSvc, body)
		if resp.ProtoMajor == wantProtoMajor && negotiatedProtocol == wantALPN && gotAltSvc == wantAltSvc {
			return resp, body
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTPS protocol and Alt-Svc did not converge to proto_major=%d alpn=%q alt_svc=%q, last=%s\n%s", wantProtoMajor, wantALPN, wantAltSvc, lastObserved, h.output.String())
	return nil, ""
}

func (h *appProcessHarness) waitHTTPSState(t *testing.T, bind string, host string, path string, clientMinVersion uint16, clientMaxVersion uint16, wantProtoMajor int, wantALPN string, wantTLSVersion uint16) (*http.Response, string) {
	t.Helper()

	return h.waitHTTPSStateWithTLSExpectations(t, bind, host, path, clientMinVersion, clientMaxVersion, nil, nil, wantProtoMajor, wantALPN, wantTLSVersion, 0, 0)
}

func (h *appProcessHarness) waitHTTPSStateWithCipherSuites(t *testing.T, bind string, host string, path string, clientMinVersion uint16, clientMaxVersion uint16, cipherSuites []uint16, wantProtoMajor int, wantALPN string, wantTLSVersion uint16, wantCipherSuite uint16) (*http.Response, string) {
	t.Helper()

	return h.waitHTTPSStateWithTLSExpectations(t, bind, host, path, clientMinVersion, clientMaxVersion, cipherSuites, nil, wantProtoMajor, wantALPN, wantTLSVersion, wantCipherSuite, 0)
}

func (h *appProcessHarness) waitHTTPSStateWithTLSExpectations(t *testing.T, bind string, host string, path string, clientMinVersion uint16, clientMaxVersion uint16, cipherSuites []uint16, curvePreferences []tls.CurveID, wantProtoMajor int, wantALPN string, wantTLSVersion uint16, wantCipherSuite uint16, wantCurveID tls.CurveID) (*http.Response, string) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         clientMinVersion,
			MaxVersion:         clientMaxVersion,
			NextProtos:         []string{"h2", "http/1.1"},
			CipherSuites:       cipherSuites,
			CurvePreferences:   curvePreferences,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTPS state request: %v\n%s", err, h.output.String())
		}

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTPS state request: %v", err)
		}
		req.Host = host

		resp, err := client.Do(req)
		if err != nil {
			lastObserved = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read HTTPS state response body: %v", readErr)
		}
		transport.CloseIdleConnections()

		negotiatedProtocol := ""
		negotiatedVersion := uint16(0)
		negotiatedCipherSuite := uint16(0)
		negotiatedCurveID := tls.CurveID(0)
		if resp.TLS != nil {
			negotiatedProtocol = resp.TLS.NegotiatedProtocol
			negotiatedVersion = resp.TLS.Version
			negotiatedCipherSuite = resp.TLS.CipherSuite
			negotiatedCurveID = resp.TLS.CurveID
		}
		lastObserved = fmt.Sprintf("status=%d proto_major=%d alpn=%q tls_version=%#x cipher_suite=%#x curve_id=%#x body=%s", resp.StatusCode, resp.ProtoMajor, negotiatedProtocol, negotiatedVersion, negotiatedCipherSuite, negotiatedCurveID, string(body))
		cipherSuiteOK := wantCipherSuite == 0 || negotiatedCipherSuite == wantCipherSuite
		curveIDOK := wantCurveID == 0 || negotiatedCurveID == wantCurveID
		if resp.ProtoMajor == wantProtoMajor && negotiatedProtocol == wantALPN && negotiatedVersion == wantTLSVersion && cipherSuiteOK && curveIDOK {
			return resp, string(body)
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTPS state did not converge to proto_major=%d alpn=%q tls_version=%#x cipher_suite=%#x curve_id=%#x, last=%s\n%s", wantProtoMajor, wantALPN, wantTLSVersion, wantCipherSuite, wantCurveID, lastObserved, h.output.String())
	return nil, ""
}

func (h *appProcessHarness) waitHTTPSSessionResumptionState(t *testing.T, bind string, host string, path string, wantResume bool) (*http.Response, string) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	cache := tls.NewLRUClientSessionCache(8)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"http/1.1"},
			ClientSessionCache: cache,
		},
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTPS session resumption request: %v\n%s", err, h.output.String())
		}

		var lastResp *http.Response
		var lastBody string
		observed := make([]bool, 0, 3)
		for i := 0; i < 3; i++ {
			resp, body, err := h.doHTTPSRequestWithClient(t, client, targetURL, host)
			transport.CloseIdleConnections()
			if err != nil {
				lastObserved = err.Error()
				break
			}
			lastResp = resp
			lastBody = body
			didResume := resp.TLS != nil && resp.TLS.DidResume
			observed = append(observed, didResume)
			if resp.StatusCode != http.StatusOK {
				break
			}
			if wantResume && didResume {
				return resp, body
			}
		}
		if !wantResume && len(observed) == 3 && !observed[1] && !observed[2] && lastResp != nil && lastResp.StatusCode == http.StatusOK {
			return lastResp, lastBody
		}
		if len(observed) > 0 {
			status := 0
			tlsVersion := uint16(0)
			if lastResp != nil {
				status = lastResp.StatusCode
				if lastResp.TLS != nil {
					tlsVersion = lastResp.TLS.Version
				}
			}
			lastObserved = fmt.Sprintf("status=%d tls_version=%#x did_resume=%v body=%s", status, tlsVersion, observed, lastBody)
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTPS session resumption state did not converge to did_resume=%v, last=%s\n%s", wantResume, lastObserved, h.output.String())
	return nil, ""
}

func (h *appProcessHarness) doHTTPSRequestWithClient(t *testing.T, client *http.Client, targetURL string, host string) (*http.Response, string, error) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTPS client request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read HTTPS client response body: %v", readErr)
	}
	return resp, string(body), nil
}

func (h *appProcessHarness) requireHTTPSFailure(t *testing.T, bind string, host string, path string, clientMinVersion uint16, clientMaxVersion uint16) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         clientMinVersion,
			MaxVersion:         clientMaxVersion,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTPS failure request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err == nil {
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read unexpected HTTPS success body: %v", readErr)
		}
		t.Fatalf("expected HTTPS request with client TLS range [%#x,%#x] to fail, got status=%d proto_major=%d tls_version=%#x alpn=%q body=%s\n%s", clientMinVersion, clientMaxVersion, resp.StatusCode, resp.ProtoMajor, resp.TLS.Version, resp.TLS.NegotiatedProtocol, string(body), h.output.String())
	}
}

func (h *appProcessHarness) requireHTTPSCipherSuiteFailure(t *testing.T, bind string, host string, path string, clientMinVersion uint16, clientMaxVersion uint16, cipherSuites []uint16) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         clientMinVersion,
			MaxVersion:         clientMaxVersion,
			NextProtos:         []string{"h2", "http/1.1"},
			CipherSuites:       cipherSuites,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTPS cipher suite failure request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err == nil {
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read unexpected HTTPS cipher suite success body: %v", readErr)
		}
		t.Fatalf("expected HTTPS request with client cipher suites %v to fail, got status=%d proto_major=%d tls_version=%#x cipher_suite=%#x alpn=%q body=%s\n%s", cipherSuites, resp.StatusCode, resp.ProtoMajor, resp.TLS.Version, resp.TLS.CipherSuite, resp.TLS.NegotiatedProtocol, string(body), h.output.String())
	}
}

func (h *appProcessHarness) requireHTTPSCurveFailure(t *testing.T, bind string, host string, path string, clientMinVersion uint16, clientMaxVersion uint16, curvePreferences []tls.CurveID) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         clientMinVersion,
			MaxVersion:         clientMaxVersion,
			NextProtos:         []string{"h2", "http/1.1"},
			CurvePreferences:   curvePreferences,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("build HTTPS curve failure request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err == nil {
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read unexpected HTTPS curve success body: %v", readErr)
		}
		t.Fatalf("expected HTTPS request with client curve preferences %v to fail, got status=%d proto_major=%d tls_version=%#x curve_id=%#x alpn=%q body=%s\n%s", curvePreferences, resp.StatusCode, resp.ProtoMajor, resp.TLS.Version, resp.TLS.CurveID, resp.TLS.NegotiatedProtocol, string(body), h.output.String())
	}
}

func (h *appProcessHarness) doHTTPRequest(t *testing.T, bind string, host string, path string) (*http.Response, string) {
	t.Helper()

	targetURL := "http://" + bind + path
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP request: %v\n%s", err, h.output.String())
		}

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTP request: %v", err)
		}
		req.Host = host

		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read HTTP response body: %v", readErr)
			}
			return resp, string(body)
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP endpoint did not become ready in time\n%s", h.output.String())
	return nil, ""
}

func (h *appProcessHarness) waitHTTPResponseEncoding(t *testing.T, bind string, host string, path string, headers http.Header, wantEncoding string) (*http.Response, []byte) {
	t.Helper()

	return h.waitHTTPResponse(t, bind, host, path, headers, func(resp *http.Response, body []byte) bool {
		return resp.StatusCode == http.StatusOK && strings.TrimSpace(resp.Header.Get("Content-Encoding")) == wantEncoding
	})
}

func (h *appProcessHarness) waitHTTPSResponseEncoding(t *testing.T, bind string, host string, path string, headers http.Header, wantProtoMajor int, wantALPN string, wantEncoding string) (*http.Response, []byte) {
	t.Helper()

	targetURL := "https://" + host + ":" + extractPort(bind) + path
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, bind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
	})

	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTPS response wait: %v\n%s", err, h.output.String())
		}

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTPS response wait request: %v", err)
		}
		req.Host = host
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			lastObserved = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read HTTPS response wait body: %v", readErr)
		}
		transport.CloseIdleConnections()

		negotiatedProtocol := ""
		negotiatedVersion := uint16(0)
		if resp.TLS != nil {
			negotiatedProtocol = resp.TLS.NegotiatedProtocol
			negotiatedVersion = resp.TLS.Version
		}
		lastObserved = fmt.Sprintf(
			"status=%d proto_major=%d alpn=%q tls_version=%#x content_encoding=%q content_type=%q body_len=%d",
			resp.StatusCode,
			resp.ProtoMajor,
			negotiatedProtocol,
			negotiatedVersion,
			resp.Header.Get("Content-Encoding"),
			resp.Header.Get("Content-Type"),
			len(body),
		)
		if resp.StatusCode == http.StatusOK &&
			resp.ProtoMajor == wantProtoMajor &&
			negotiatedProtocol == wantALPN &&
			strings.TrimSpace(resp.Header.Get("Content-Encoding")) == wantEncoding {
			return resp, body
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTPS response did not converge, last=%s\n%s", lastObserved, h.output.String())
	return nil, nil
}

func (h *appProcessHarness) waitHTTPResponse(t *testing.T, bind string, host string, path string, headers http.Header, ready func(*http.Response, []byte) bool) (*http.Response, []byte) {
	t.Helper()

	targetURL := "http://" + bind + path
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	lastObserved := "no successful response observed"
	for time.Now().Before(deadline) {
		if exited, err := h.pollExit(); exited {
			t.Fatalf("app helper process exited before HTTP response wait: %v\n%s", err, h.output.String())
		}

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build HTTP response wait request: %v", err)
		}
		req.Host = host
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			lastObserved = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read HTTP response wait body: %v", readErr)
		}

		lastObserved = fmt.Sprintf(
			"status=%d content_encoding=%q content_type=%q body_len=%d",
			resp.StatusCode,
			resp.Header.Get("Content-Encoding"),
			resp.Header.Get("Content-Type"),
			len(body),
		)
		if ready == nil || ready(resp, body) {
			return resp, body
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP response did not converge, last=%s\n%s", lastObserved, h.output.String())
	return nil, nil
}

func requireDecodedHTTPResponseBody(t *testing.T, contentEncoding string, body []byte, want string) {
	t.Helper()

	got := decodeHTTPResponseBody(t, contentEncoding, body)
	if got != want {
		t.Fatalf("decoded HTTP response body mismatch: got_len=%d want_len=%d", len(got), len(want))
	}
}

func decodeHTTPResponseBody(t *testing.T, contentEncoding string, body []byte) string {
	t.Helper()

	switch strings.TrimSpace(contentEncoding) {
	case "":
		return string(body)
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("create gzip reader: %v", err)
		}
		defer reader.Close()

		decoded, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read gzip body: %v", err)
		}
		return string(decoded)
	case "br":
		decoded, err := io.ReadAll(brotli.NewReader(bytes.NewReader(body)))
		if err != nil {
			t.Fatalf("read brotli body: %v", err)
		}
		return string(decoded)
	default:
		t.Fatalf("unsupported content encoding in test: %q", contentEncoding)
		return ""
	}
}

func mustGzipAppProcessBytes(t *testing.T, body []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("create gzip writer: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		_ = writer.Close()
		t.Fatalf("write gzip body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func mustBrotliAppProcessBytes(t *testing.T, body []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := brotli.NewWriterLevel(&buf, 4)
	if _, err := writer.Write(body); err != nil {
		_ = writer.Close()
		t.Fatalf("write brotli body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close brotli writer: %v", err)
	}
	return buf.Bytes()
}

func mustEncodeAppProcessBytes(t *testing.T, body []byte, encodings ...string) []byte {
	t.Helper()

	encoded := body
	for _, encoding := range encodings {
		switch encoding {
		case "", "identity":
		case "gzip", "x-gzip":
			encoded = mustGzipAppProcessBytes(t, encoded)
		case "br":
			encoded = mustBrotliAppProcessBytes(t, encoded)
		default:
			t.Fatalf("unsupported encoding for app process test helper: %s", encoding)
		}
	}
	return encoded
}

func (h *appProcessHarness) waitForSiteAccessLog(t *testing.T, siteID uint, path string, params url.Values) store.AccessLog {
	t.Helper()

	type accessLogListResponse struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}

	queryPath := appProcSiteListPath(siteID, "access-logs", path, params)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var resp accessLogListResponse
		h.getJSON(t, queryPath, &resp)
		if len(resp.Items) > 0 {
			return resp.Items[0]
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("site access log did not appear for site_id=%d path=%q\n%s", siteID, path, h.output.String())
	return store.AccessLog{}
}

func (h *appProcessHarness) waitForSiteSecurityEvent(t *testing.T, siteID uint, path string, params url.Values) store.SecurityEvent {
	t.Helper()

	type securityEventListResponse struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}

	queryPath := appProcSiteListPath(siteID, "security-events", path, params)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var resp securityEventListResponse
		h.getJSON(t, queryPath, &resp)
		if len(resp.Items) > 0 {
			return resp.Items[0]
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("site security event did not appear for site_id=%d path=%q\n%s", siteID, path, h.output.String())
	return store.SecurityEvent{}
}

func (h *appProcessHarness) requireNoSiteObservability(t *testing.T, siteID uint, path string, label string) {
	t.Helper()

	type accessLogListResponse struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	type securityEventListResponse struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}

	accessLogQueryPath := appProcSiteListPath(siteID, "access-logs", path, nil)
	securityEventQueryPath := appProcSiteListPath(siteID, "security-events", path, nil)
	deadline := time.Now().Add(2 * time.Second)
	for {
		var accessResp accessLogListResponse
		h.getJSON(t, accessLogQueryPath, &accessResp)
		if accessResp.Total > 0 || len(accessResp.Items) > 0 {
			t.Fatalf("%s unexpectedly wrote access log for site_id=%d path=%q: total=%d items=%+v", label, siteID, path, accessResp.Total, accessResp.Items)
		}

		var securityResp securityEventListResponse
		h.getJSON(t, securityEventQueryPath, &securityResp)
		if securityResp.Total > 0 || len(securityResp.Items) > 0 {
			t.Fatalf("%s unexpectedly wrote security event for site_id=%d path=%q: total=%d items=%+v", label, siteID, path, securityResp.Total, securityResp.Items)
		}

		if time.Now().After(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *appProcessHarness) requireNoGlobalObservability(t *testing.T, host string, path string, label string) {
	t.Helper()

	type accessLogListResponse struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	type securityEventListResponse struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}

	query := url.Values{}
	query.Set("page", "1")
	query.Set("page_size", "20")
	query.Set("host", host)
	query.Set("path", path)

	accessLogQueryPath := "/api/v1/access-logs?" + query.Encode()
	securityEventQueryPath := "/api/v1/security-events?" + query.Encode()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var accessResp accessLogListResponse
		h.getJSON(t, accessLogQueryPath, &accessResp)
		if accessResp.Total > 0 || len(accessResp.Items) > 0 {
			t.Fatalf("%s unexpectedly wrote global access log for host=%q path=%q: total=%d items=%+v", label, host, path, accessResp.Total, accessResp.Items)
		}

		var securityResp securityEventListResponse
		h.getJSON(t, securityEventQueryPath, &securityResp)
		if securityResp.Total > 0 || len(securityResp.Items) > 0 {
			t.Fatalf("%s unexpectedly wrote global security event for host=%q path=%q: total=%d items=%+v", label, host, path, securityResp.Total, securityResp.Items)
		}

		if time.Now().After(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *appProcessHarness) requireNoFingerprintSummary(t *testing.T, params url.Values, label string) {
	t.Helper()

	type fingerprintListResponse struct {
		Items []repository.FingerprintSummary `json:"items"`
		Total int64                           `json:"total"`
		Page  int                             `json:"page"`
	}

	query := url.Values{}
	query.Set("page", "1")
	query.Set("page_size", "20")
	for key, values := range params {
		for _, value := range values {
			query.Add(key, value)
		}
	}

	queryPath := "/api/v1/fingerprints?" + query.Encode()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var resp fingerprintListResponse
		h.getJSON(t, queryPath, &resp)
		if resp.Total > 0 || len(resp.Items) > 0 {
			t.Fatalf("%s unexpectedly wrote fingerprint summary for query=%q: total=%d items=%+v", label, query.Encode(), resp.Total, resp.Items)
		}

		if time.Now().After(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type appProcessSiteObservabilityTotals struct {
	accessLogs     int64
	securityEvents int64
}

type appProcessGlobalObservabilityTotals struct {
	accessLogs     int64
	securityEvents int64
}

type appProcessFingerprintSummaryTotals struct {
	groups int64
	count  int64
}

func (h *appProcessHarness) globalObservabilityTotals(t *testing.T) appProcessGlobalObservabilityTotals {
	t.Helper()

	type accessLogListResponse struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	type securityEventListResponse struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}

	query := url.Values{}
	query.Set("page", "1")
	query.Set("page_size", "1")

	var accessResp accessLogListResponse
	h.getJSON(t, "/api/v1/access-logs?"+query.Encode(), &accessResp)
	var securityResp securityEventListResponse
	h.getJSON(t, "/api/v1/security-events?"+query.Encode(), &securityResp)

	return appProcessGlobalObservabilityTotals{
		accessLogs:     accessResp.Total,
		securityEvents: securityResp.Total,
	}
}

func (h *appProcessHarness) requireGlobalObservabilityTotals(t *testing.T, want appProcessGlobalObservabilityTotals, label string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		got := h.globalObservabilityTotals(t)
		if got.accessLogs != want.accessLogs || got.securityEvents != want.securityEvents {
			t.Fatalf("%s unexpectedly changed global observability totals: got=%+v want=%+v", label, got, want)
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *appProcessHarness) siteObservabilityTotals(t *testing.T, siteID uint) appProcessSiteObservabilityTotals {
	t.Helper()

	type accessLogListResponse struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	type securityEventListResponse struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}

	query := url.Values{}
	query.Set("page", "1")
	query.Set("page_size", "1")

	var accessResp accessLogListResponse
	h.getJSON(t, fmt.Sprintf("/api/v1/sites/%d/access-logs?%s", siteID, query.Encode()), &accessResp)
	var securityResp securityEventListResponse
	h.getJSON(t, fmt.Sprintf("/api/v1/sites/%d/security-events?%s", siteID, query.Encode()), &securityResp)

	return appProcessSiteObservabilityTotals{
		accessLogs:     accessResp.Total,
		securityEvents: securityResp.Total,
	}
}

func (h *appProcessHarness) requireSiteObservabilityTotals(t *testing.T, siteID uint, want appProcessSiteObservabilityTotals, label string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		got := h.siteObservabilityTotals(t, siteID)
		if got.accessLogs != want.accessLogs || got.securityEvents != want.securityEvents {
			t.Fatalf("%s unexpectedly changed site observability totals for site_id=%d: got=%+v want=%+v", label, siteID, got, want)
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *appProcessHarness) fingerprintSummaryTotals(t *testing.T, params url.Values) appProcessFingerprintSummaryTotals {
	t.Helper()

	type fingerprintListResponse struct {
		Items []repository.FingerprintSummary `json:"items"`
		Total int64                           `json:"total"`
		Page  int                             `json:"page"`
	}

	query := url.Values{}
	query.Set("page", "1")
	query.Set("page_size", "200")
	for key, values := range params {
		for _, value := range values {
			query.Add(key, value)
		}
	}

	var resp fingerprintListResponse
	h.getJSON(t, "/api/v1/fingerprints?"+query.Encode(), &resp)
	if resp.Total > int64(len(resp.Items)) {
		t.Fatalf("fingerprint summary query=%q returned %d items for total=%d", query.Encode(), len(resp.Items), resp.Total)
	}

	var count int64
	for _, item := range resp.Items {
		count += item.Count
	}
	return appProcessFingerprintSummaryTotals{
		groups: resp.Total,
		count:  count,
	}
}

func (h *appProcessHarness) requireFingerprintSummaryTotals(t *testing.T, params url.Values, want appProcessFingerprintSummaryTotals, label string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		got := h.fingerprintSummaryTotals(t, params)
		if got != want {
			t.Fatalf("%s unexpectedly changed fingerprint summary totals: got=%+v want=%+v", label, got, want)
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *appProcessHarness) waitForFingerprintSummary(t *testing.T, params url.Values) repository.FingerprintSummary {
	t.Helper()

	type fingerprintListResponse struct {
		Items []repository.FingerprintSummary `json:"items"`
		Total int64                           `json:"total"`
		Page  int                             `json:"page"`
	}

	query := url.Values{}
	query.Set("page", "1")
	query.Set("page_size", "20")
	for key, values := range params {
		for _, value := range values {
			query.Add(key, value)
		}
	}

	queryPath := "/api/v1/fingerprints?" + query.Encode()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var resp fingerprintListResponse
		h.getJSON(t, queryPath, &resp)
		if len(resp.Items) > 0 {
			return resp.Items[0]
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("fingerprint summary did not appear for query=%q\n%s", query.Encode(), h.output.String())
	return repository.FingerprintSummary{}
}

func (h *appProcessHarness) requireFingerprintSummaryForAccessLog(t *testing.T, accessLog store.AccessLog, label string) repository.FingerprintSummary {
	t.Helper()

	if accessLog.TLSJA3Hash == "" || accessLog.TLSJA4 == "" {
		t.Fatalf("%s access log missing fingerprint metadata: %+v", label, accessLog)
	}

	query := url.Values{
		"tls_ja3_hash": []string{accessLog.TLSJA3Hash},
		"tls_ja4":      []string{accessLog.TLSJA4},
		"tls_version":  []string{accessLog.TLSVersion},
		"tls_alpn":     []string{accessLog.TLSALPN},
		"tls_sni":      []string{accessLog.TLSSNI},
	}
	if accessLog.TLSCipherSuites != "" {
		query.Set("tls_cipher_suites", accessLog.TLSCipherSuites)
	}
	if accessLog.TLSExtensions != "" {
		query.Set("tls_extensions", accessLog.TLSExtensions)
	}
	if accessLog.TLSCurves != "" {
		query.Set("tls_curves", accessLog.TLSCurves)
	}
	if accessLog.TLSPointFormats != "" {
		query.Set("tls_point_formats", accessLog.TLSPointFormats)
	}

	fingerprint := h.waitForFingerprintSummary(t, query)
	if fingerprint.TLSJA3Hash != accessLog.TLSJA3Hash {
		t.Fatalf("%s fingerprint tls_ja3_hash = %q, want %q", label, fingerprint.TLSJA3Hash, accessLog.TLSJA3Hash)
	}
	if fingerprint.TLSJA4 != accessLog.TLSJA4 {
		t.Fatalf("%s fingerprint tls_ja4 = %q, want %q", label, fingerprint.TLSJA4, accessLog.TLSJA4)
	}
	if fingerprint.TLSVersion != accessLog.TLSVersion {
		t.Fatalf("%s fingerprint tls_version = %q, want %q", label, fingerprint.TLSVersion, accessLog.TLSVersion)
	}
	if fingerprint.TLSALPN != accessLog.TLSALPN {
		t.Fatalf("%s fingerprint tls_alpn = %q, want %q", label, fingerprint.TLSALPN, accessLog.TLSALPN)
	}
	if fingerprint.TLSSNI != accessLog.TLSSNI {
		t.Fatalf("%s fingerprint tls_sni = %q, want %q", label, fingerprint.TLSSNI, accessLog.TLSSNI)
	}
	if fingerprint.TLSCipherSuites != accessLog.TLSCipherSuites {
		t.Fatalf("%s fingerprint tls_cipher_suites = %q, want %q", label, fingerprint.TLSCipherSuites, accessLog.TLSCipherSuites)
	}
	if fingerprint.TLSExtensions != accessLog.TLSExtensions {
		t.Fatalf("%s fingerprint tls_extensions = %q, want %q", label, fingerprint.TLSExtensions, accessLog.TLSExtensions)
	}
	if fingerprint.TLSCurves != accessLog.TLSCurves {
		t.Fatalf("%s fingerprint tls_curves = %q, want %q", label, fingerprint.TLSCurves, accessLog.TLSCurves)
	}
	if fingerprint.TLSPointFormats != accessLog.TLSPointFormats {
		t.Fatalf("%s fingerprint tls_point_formats = %q, want %q", label, fingerprint.TLSPointFormats, accessLog.TLSPointFormats)
	}
	if fingerprint.Count < 1 {
		t.Fatalf("%s fingerprint count = %d, want >= 1", label, fingerprint.Count)
	}
	return fingerprint
}

func appProcSiteListPath(siteID uint, resource string, path string, params url.Values) string {
	query := url.Values{}
	query.Set("page", "1")
	query.Set("page_size", "20")
	query.Set("path", path)
	for key, values := range params {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	return fmt.Sprintf("/api/v1/sites/%d/%s?%s", siteID, resource, query.Encode())
}

func requireAppProcessResponseTrailerObservability(t *testing.T, h *appProcessHarness, label string, siteID uint, requestPath string, requestID string, siteHost string, wantHTTPProtocol string, wantTLSALPN string, wantJA4Prefix byte) store.AccessLog {
	t.Helper()

	return requireAppProcessObservedRequest(t, h, appProcessObservedRequestExpectation{
		label:            label,
		siteID:           siteID,
		requestPath:      requestPath,
		requestID:        requestID,
		siteHost:         siteHost,
		statusCode:       http.StatusOK,
		cacheState:       "bypass",
		httpProtocol:     wantHTTPProtocol,
		tlsALPN:          wantTLSALPN,
		ja4Prefix:        wantJA4Prefix,
		upstreamProtocol: "HTTP/1.1",
		responseSize:     0,
	})
}

type appProcessObservedRequestExpectation struct {
	label                       string
	siteID                      uint
	requestPath                 string
	requestID                   string
	siteHost                    string
	tlsSNI                      string
	statusCode                  int
	cacheState                  string
	httpProtocol                string
	tlsVersion                  string
	tlsALPN                     string
	ja4Prefix                   byte
	queryString                 string
	upstreamProtocol            string
	responseSize                int64
	tlsCipherSuites             []string
	tlsCurves                   []string
	allowEmptyUpstreamProtocol  bool
	allowMissingTLSClientHello  bool
	expectMissingTLSClientHello bool
}

type appProcessAccessLogTraceExpectation struct {
	label                       string
	requestID                   string
	siteHost                    string
	tlsSNI                      string
	statusCode                  int
	wafAction                   string
	securityEventAction         string
	httpProtocol                string
	upstreamProtocol            string
	tlsVersion                  string
	tlsALPN                     string
	ja4Prefix                   byte
	tlsCipherSuites             []string
	expectMissingTLSClientHello bool
}

func requireAppProcessAccessLogTrace(t *testing.T, h *appProcessHarness, accessLog store.AccessLog, expect appProcessAccessLogTraceExpectation) {
	t.Helper()

	if expect.wafAction == "" {
		expect.wafAction = "none"
	}
	if expect.tlsVersion == "" {
		expect.tlsVersion = "TLS13"
	}
	if len(expect.tlsCipherSuites) == 0 {
		expect.tlsCipherSuites = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}
	}
	if expect.tlsSNI == "" {
		expect.tlsSNI = expect.siteHost
	}

	if accessLog.RequestID != expect.requestID {
		t.Fatalf("%s access log request_id = %q, want %q", expect.label, accessLog.RequestID, expect.requestID)
	}
	if accessLog.StatusCode != expect.statusCode {
		t.Fatalf("%s access log status_code = %d, want %d", expect.label, accessLog.StatusCode, expect.statusCode)
	}
	if accessLog.WAFAction != expect.wafAction {
		t.Fatalf("%s access log waf_action = %q, want %q", expect.label, accessLog.WAFAction, expect.wafAction)
	}
	if accessLog.HTTPProtocol != expect.httpProtocol {
		t.Fatalf("%s access log http_protocol = %q, want %q", expect.label, accessLog.HTTPProtocol, expect.httpProtocol)
	}
	if accessLog.UpstreamHTTPProtocol != expect.upstreamProtocol {
		t.Fatalf("%s access log upstream_http_protocol = %q, want %q", expect.label, accessLog.UpstreamHTTPProtocol, expect.upstreamProtocol)
	}
	if accessLog.TLSVersion != expect.tlsVersion {
		t.Fatalf("%s access log tls_version = %q, want %q", expect.label, accessLog.TLSVersion, expect.tlsVersion)
	}
	if accessLog.TLSALPN != expect.tlsALPN {
		t.Fatalf("%s access log tls_alpn = %q, want %q", expect.label, accessLog.TLSALPN, expect.tlsALPN)
	}
	if accessLog.TLSSNI != expect.tlsSNI {
		t.Fatalf("%s access log tls_sni = %q, want %q", expect.label, accessLog.TLSSNI, expect.tlsSNI)
	}
	if expect.expectMissingTLSClientHello {
		if accessLog.TLSJA3 != "" || accessLog.TLSJA3Hash != "" || accessLog.TLSJA4 != "" || accessLog.TLSCipherSuites != "" || accessLog.TLSExtensions != "" || accessLog.TLSCurves != "" || accessLog.TLSPointFormats != "" {
			t.Fatalf("%s access log contains unexpected ClientHello fingerprint metadata: %+v", expect.label, accessLog)
		}
	} else {
		if accessLog.TLSJA3Hash == "" {
			t.Fatalf("%s access log tls_ja3_hash is empty: %+v", expect.label, accessLog)
		}
		if accessLog.TLSJA4 == "" || accessLog.TLSJA4[0] != expect.ja4Prefix {
			t.Fatalf("%s access log tls_ja4 = %q, want prefix %q", expect.label, accessLog.TLSJA4, string(expect.ja4Prefix))
		}
		for _, suite := range expect.tlsCipherSuites {
			if !strings.Contains(accessLog.TLSCipherSuites, suite) {
				t.Fatalf("%s access log tls_cipher_suites = %q, want to contain %q", expect.label, accessLog.TLSCipherSuites, suite)
			}
		}
	}

	trace := h.waitForRequestTrace(t, expect.requestID)
	if trace.RequestID != expect.requestID {
		t.Fatalf("%s request trace request_id = %q, want %q", expect.label, trace.RequestID, expect.requestID)
	}
	if len(trace.AccessLogs) == 0 {
		t.Fatalf("%s request trace access_logs is empty", expect.label)
	}

	var traceAccessLog *store.AccessLog
	for i := range trace.AccessLogs {
		if trace.AccessLogs[i].ID == accessLog.ID {
			traceAccessLog = &trace.AccessLogs[i]
			break
		}
	}
	if traceAccessLog == nil {
		t.Fatalf("%s request trace missing access log id %d", expect.label, accessLog.ID)
	}
	if traceAccessLog.RequestID != accessLog.RequestID || traceAccessLog.StatusCode != accessLog.StatusCode || traceAccessLog.WAFAction != accessLog.WAFAction {
		t.Fatalf("%s request trace access log status mismatch: %+v vs %+v", expect.label, *traceAccessLog, accessLog)
	}
	if traceAccessLog.HTTPProtocol != accessLog.HTTPProtocol || traceAccessLog.CacheState != accessLog.CacheState || traceAccessLog.UpstreamHTTPProtocol != accessLog.UpstreamHTTPProtocol || traceAccessLog.QueryString != accessLog.QueryString || traceAccessLog.ResponseSize != accessLog.ResponseSize {
		t.Fatalf("%s request trace access log transport mismatch: %+v vs %+v", expect.label, *traceAccessLog, accessLog)
	}
	if traceAccessLog.TLSVersion != accessLog.TLSVersion || traceAccessLog.TLSALPN != accessLog.TLSALPN || traceAccessLog.TLSSNI != accessLog.TLSSNI || traceAccessLog.TLSJA3 != accessLog.TLSJA3 || traceAccessLog.TLSJA3Hash != accessLog.TLSJA3Hash || traceAccessLog.TLSJA4 != accessLog.TLSJA4 || traceAccessLog.TLSCipherSuites != accessLog.TLSCipherSuites || traceAccessLog.TLSExtensions != accessLog.TLSExtensions || traceAccessLog.TLSCurves != accessLog.TLSCurves || traceAccessLog.TLSPointFormats != accessLog.TLSPointFormats {
		t.Fatalf("%s request trace access log TLS metadata mismatch: %+v vs %+v", expect.label, *traceAccessLog, accessLog)
	}

	if expect.securityEventAction == "" {
		return
	}
	if len(trace.SecurityEvents) == 0 {
		t.Fatalf("%s request trace security_events is empty", expect.label)
	}
	var traceSecurityEvent *store.SecurityEvent
	for i := range trace.SecurityEvents {
		if trace.SecurityEvents[i].RequestID == expect.requestID && trace.SecurityEvents[i].Action == expect.securityEventAction {
			traceSecurityEvent = &trace.SecurityEvents[i]
			break
		}
	}
	if traceSecurityEvent == nil {
		t.Fatalf("%s request trace missing %s security event for request_id=%q", expect.label, expect.securityEventAction, expect.requestID)
	}
	if traceSecurityEvent.TLSVersion != accessLog.TLSVersion || traceSecurityEvent.TLSALPN != accessLog.TLSALPN || traceSecurityEvent.TLSSNI != accessLog.TLSSNI || traceSecurityEvent.TLSJA3 != accessLog.TLSJA3 || traceSecurityEvent.TLSJA3Hash != accessLog.TLSJA3Hash || traceSecurityEvent.TLSJA4 != accessLog.TLSJA4 || traceSecurityEvent.TLSCipherSuites != accessLog.TLSCipherSuites || traceSecurityEvent.TLSExtensions != accessLog.TLSExtensions || traceSecurityEvent.TLSCurves != accessLog.TLSCurves || traceSecurityEvent.TLSPointFormats != accessLog.TLSPointFormats {
		t.Fatalf("%s request trace security event TLS metadata mismatch: %+v vs %+v", expect.label, *traceSecurityEvent, accessLog)
	}
}

func requireAppProcessObservedRequest(t *testing.T, h *appProcessHarness, expect appProcessObservedRequestExpectation) store.AccessLog {
	t.Helper()

	if expect.cacheState == "" {
		expect.cacheState = "bypass"
	}
	if expect.upstreamProtocol == "" && !expect.allowEmptyUpstreamProtocol {
		expect.upstreamProtocol = "HTTP/1.1"
	}
	if expect.tlsVersion == "" {
		expect.tlsVersion = "TLS13"
	}
	if len(expect.tlsCipherSuites) == 0 {
		expect.tlsCipherSuites = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}
	}
	if expect.tlsSNI == "" {
		expect.tlsSNI = expect.siteHost
	}

	accessLog := h.waitForSiteAccessLog(t, expect.siteID, expect.requestPath, url.Values{
		"request_id": []string{expect.requestID},
	})
	if accessLog.RequestID != expect.requestID {
		t.Fatalf("%s access log request_id = %q, want %q", expect.label, accessLog.RequestID, expect.requestID)
	}
	if accessLog.StatusCode != expect.statusCode {
		t.Fatalf("%s access log status_code = %d, want %d", expect.label, accessLog.StatusCode, expect.statusCode)
	}
	if accessLog.WAFAction != string(store.ActionObserve) {
		t.Fatalf("%s access log waf_action = %q, want %q", expect.label, accessLog.WAFAction, store.ActionObserve)
	}
	if accessLog.CacheState != expect.cacheState {
		t.Fatalf("%s access log cache_state = %q, want %q", expect.label, accessLog.CacheState, expect.cacheState)
	}
	if accessLog.HTTPProtocol != expect.httpProtocol {
		t.Fatalf("%s access log http_protocol = %q, want %q", expect.label, accessLog.HTTPProtocol, expect.httpProtocol)
	}
	if accessLog.UpstreamHTTPProtocol != expect.upstreamProtocol {
		t.Fatalf("%s access log upstream_http_protocol = %q, want %q", expect.label, accessLog.UpstreamHTTPProtocol, expect.upstreamProtocol)
	}
	if accessLog.QueryString != expect.queryString {
		t.Fatalf("%s access log query_string = %q, want %q", expect.label, accessLog.QueryString, expect.queryString)
	}
	if accessLog.ResponseSize != expect.responseSize {
		t.Fatalf("%s access log response_size = %d, want %d", expect.label, accessLog.ResponseSize, expect.responseSize)
	}
	if accessLog.TLSVersion != expect.tlsVersion {
		t.Fatalf("%s access log tls_version = %q, want %q", expect.label, accessLog.TLSVersion, expect.tlsVersion)
	}
	if accessLog.TLSALPN != expect.tlsALPN {
		t.Fatalf("%s access log tls_alpn = %q, want %q", expect.label, accessLog.TLSALPN, expect.tlsALPN)
	}
	if accessLog.TLSSNI != expect.tlsSNI {
		t.Fatalf("%s access log tls_sni = %q, want %q", expect.label, accessLog.TLSSNI, expect.tlsSNI)
	}
	if expect.expectMissingTLSClientHello {
		if accessLog.TLSJA3 != "" || accessLog.TLSJA3Hash != "" || accessLog.TLSJA4 != "" || accessLog.TLSCipherSuites != "" || accessLog.TLSExtensions != "" || accessLog.TLSCurves != "" || accessLog.TLSPointFormats != "" {
			t.Fatalf("%s access log contains unexpected ClientHello fingerprint metadata: %+v", expect.label, accessLog)
		}
	} else {
		if accessLog.TLSJA3Hash == "" && !expect.allowMissingTLSClientHello {
			t.Fatalf("%s access log tls_ja3_hash is empty: %+v", expect.label, accessLog)
		}
		if accessLog.TLSJA4 == "" && !expect.allowMissingTLSClientHello {
			t.Fatalf("%s access log tls_ja4 = %q, want prefix %q", expect.label, accessLog.TLSJA4, string(expect.ja4Prefix))
		}
		if accessLog.TLSJA4 != "" && accessLog.TLSJA4[0] != expect.ja4Prefix {
			t.Fatalf("%s access log tls_ja4 = %q, want prefix %q", expect.label, accessLog.TLSJA4, string(expect.ja4Prefix))
		}
		if accessLog.TLSCipherSuites != "" || !expect.allowMissingTLSClientHello {
			for _, suite := range expect.tlsCipherSuites {
				if !strings.Contains(accessLog.TLSCipherSuites, suite) {
					t.Fatalf("%s access log tls_cipher_suites = %q, want to contain %q", expect.label, accessLog.TLSCipherSuites, suite)
				}
			}
		}
		for _, curve := range expect.tlsCurves {
			if !strings.Contains(accessLog.TLSCurves, curve) {
				t.Fatalf("%s access log tls_curves = %q, want to contain %q", expect.label, accessLog.TLSCurves, curve)
			}
		}
	}

	trace := h.waitForRequestTrace(t, expect.requestID)
	if trace.RequestID != expect.requestID {
		t.Fatalf("%s request trace request_id = %q, want %q", expect.label, trace.RequestID, expect.requestID)
	}
	if len(trace.AccessLogs) == 0 {
		t.Fatalf("%s request trace access_logs is empty", expect.label)
	}
	if len(trace.SecurityEvents) == 0 {
		t.Fatalf("%s request trace security_events is empty", expect.label)
	}

	var traceAccessLog *store.AccessLog
	for i := range trace.AccessLogs {
		if trace.AccessLogs[i].ID == accessLog.ID {
			traceAccessLog = &trace.AccessLogs[i]
			break
		}
	}
	if traceAccessLog == nil {
		t.Fatalf("%s request trace missing access log id %d", expect.label, accessLog.ID)
	}
	if traceAccessLog.HTTPProtocol != accessLog.HTTPProtocol || traceAccessLog.CacheState != accessLog.CacheState || traceAccessLog.UpstreamHTTPProtocol != accessLog.UpstreamHTTPProtocol || traceAccessLog.QueryString != accessLog.QueryString || traceAccessLog.ResponseSize != accessLog.ResponseSize {
		t.Fatalf("%s request trace access log transport mismatch: %+v vs %+v", expect.label, *traceAccessLog, accessLog)
	}
	if traceAccessLog.TLSVersion != accessLog.TLSVersion || traceAccessLog.TLSALPN != accessLog.TLSALPN || traceAccessLog.TLSSNI != accessLog.TLSSNI || traceAccessLog.TLSJA3 != accessLog.TLSJA3 || traceAccessLog.TLSJA3Hash != accessLog.TLSJA3Hash || traceAccessLog.TLSJA4 != accessLog.TLSJA4 || traceAccessLog.TLSCipherSuites != accessLog.TLSCipherSuites || traceAccessLog.TLSExtensions != accessLog.TLSExtensions || traceAccessLog.TLSCurves != accessLog.TLSCurves || traceAccessLog.TLSPointFormats != accessLog.TLSPointFormats {
		t.Fatalf("%s request trace access log TLS metadata mismatch: %+v vs %+v", expect.label, *traceAccessLog, accessLog)
	}

	var traceSecurityEvent *store.SecurityEvent
	for i := range trace.SecurityEvents {
		if trace.SecurityEvents[i].RequestID == expect.requestID && trace.SecurityEvents[i].Action == string(store.ActionObserve) {
			traceSecurityEvent = &trace.SecurityEvents[i]
			break
		}
	}
	if traceSecurityEvent == nil {
		t.Fatalf("%s request trace missing observe security event for request_id=%q", expect.label, expect.requestID)
	}
	if traceSecurityEvent.TLSVersion != accessLog.TLSVersion || traceSecurityEvent.TLSALPN != accessLog.TLSALPN || traceSecurityEvent.TLSSNI != accessLog.TLSSNI || traceSecurityEvent.TLSJA3 != accessLog.TLSJA3 || traceSecurityEvent.TLSJA3Hash != accessLog.TLSJA3Hash || traceSecurityEvent.TLSJA4 != accessLog.TLSJA4 || traceSecurityEvent.TLSCipherSuites != accessLog.TLSCipherSuites || traceSecurityEvent.TLSExtensions != accessLog.TLSExtensions || traceSecurityEvent.TLSCurves != accessLog.TLSCurves || traceSecurityEvent.TLSPointFormats != accessLog.TLSPointFormats {
		t.Fatalf("%s request trace security event TLS metadata mismatch: %+v vs %+v", expect.label, *traceSecurityEvent, accessLog)
	}
	return accessLog
}

func (h *appProcessHarness) newRawHTTP2ClientConnWithServerSettings(t *testing.T, bind string) (*tls.Conn, *http2.Framer, map[http2.SettingID]uint32) {
	t.Helper()

	return h.newRawHTTP2ClientConnWithServerSettingsForHost(t, bind, "")
}

func (h *appProcessHarness) newRawHTTP2ClientConnWithServerSettingsForHost(t *testing.T, bind string, serverName string) (*tls.Conn, *http2.Framer, map[http2.SettingID]uint32) {
	t.Helper()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2"},
	}
	if strings.TrimSpace(serverName) != "" {
		tlsConfig.ServerName = serverName
	}

	conn, err := tls.Dial("tcp", bind, tlsConfig)
	if err != nil {
		t.Fatalf("tls dial raw h2: %v\n%s", err, h.output.String())
	}
	if state := conn.ConnectionState(); state.NegotiatedProtocol != "h2" {
		_ = conn.Close()
		t.Fatalf("negotiated protocol = %q, want %q\n%s", state.NegotiatedProtocol, "h2", h.output.String())
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		_ = conn.Close()
		t.Fatalf("write client preface: %v\n%s", err, h.output.String())
	}

	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		_ = conn.Close()
		t.Fatalf("WriteSettings() error = %v\n%s", err, h.output.String())
	}
	settings := waitForRawHTTP2ServerSettingsProcess(t, conn, fr, h.output.String())
	return conn, fr, settings
}

func (h *appProcessHarness) waitHTTP2ServerSettings(t *testing.T, bind string, ready func(map[http2.SettingID]uint32) bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, _, settings := h.newRawHTTP2ClientConnWithServerSettings(t, bind)
		_ = conn.Close()
		if ready(settings) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP/2 server settings did not converge after reload\n%s", h.output.String())
}

func waitForRawHTTP2ServerSettingsProcess(t *testing.T, conn *tls.Conn, fr *http2.Framer, processOutput string) map[http2.SettingID]uint32 {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read server settings frame: %v\n%s", err, processOutput)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}
		if settings, ok := frame.(*http2.SettingsFrame); ok && !settings.IsAck() {
			got := make(map[http2.SettingID]uint32)
			if err := settings.ForeachSetting(func(s http2.Setting) error {
				got[s.ID] = s.Val
				return nil
			}); err != nil {
				t.Fatalf("ForeachSetting() error = %v", err)
			}
			if err := fr.WriteSettingsAck(); err != nil {
				t.Fatalf("WriteSettingsAck() error = %v", err)
			}
			return got
		}
		if _, ok := frame.(*http2.GoAwayFrame); ok {
			t.Fatalf("server sent GOAWAY before request sequence started\n%s", processOutput)
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not receive server settings frame in time\n%s", processOutput)
		}
	}
}

func encodeRawHTTP2RequestHeadersWithFieldsProcess(t *testing.T, authority string, path string, fields []hpack.HeaderField) []byte {
	t.Helper()

	allFields := make([]hpack.HeaderField, 0, 4+len(fields))
	allFields = append(allFields,
		hpack.HeaderField{Name: ":method", Value: http.MethodGet},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: authority},
		hpack.HeaderField{Name: ":path", Value: path},
	)
	allFields = append(allFields, fields...)
	return encodeRawHTTP2HeaderBlockProcess(t, allFields)
}

func encodeRawHTTP2HeaderBlockProcess(t *testing.T, fields []hpack.HeaderField) []byte {
	t.Helper()

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatalf("encode raw h2 header %q: %v", field.Name, err)
		}
	}
	return block.Bytes()
}

func writeRawHTTP2HeadersWithDuplicateCookieFieldsProcess(t *testing.T, fr *http2.Framer, streamID uint32, authority string, path string, duplicateCookies int) {
	t.Helper()

	fields := make([]hpack.HeaderField, 0, duplicateCookies)
	for i := 0; i < duplicateCookies; i++ {
		fields = append(fields, hpack.HeaderField{Name: "cookie", Value: fmt.Sprintf("crumb%d=value%d", i, i)})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithFieldsProcess(t, authority, path, fields),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,path=%q,duplicateCookies=%d) error = %v", streamID, path, duplicateCookies, err)
	}
}

func readRawHTTP2ResponseHeadersProcess(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32, wantStatus string) (http.Header, bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response headers frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 response header sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.MetaHeadersFrame:
			if typed.StreamID != streamID {
				continue
			}
			if got := typed.PseudoValue("status"); got != wantStatus {
				t.Fatalf("raw h2 response status = %q, want %q", got, wantStatus)
			}
			headers := make(http.Header)
			for _, field := range typed.Fields {
				if field.IsPseudo() {
					continue
				}
				headers.Add(field.Name, field.Value)
			}
			return headers, typed.StreamEnded()
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe response headers for stream %d", streamID)
		}
	}
}

func readRawHTTP2ResponseHeadersStatusProcess(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32, wantStatus string) bool {
	t.Helper()

	_, streamEnded := readRawHTTP2ResponseHeadersProcess(t, conn, fr, streamID, wantStatus)
	return streamEnded
}

func readRawHTTP2StreamProtocolErrorProcess(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 protocol error frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.RSTStreamFrame:
			if typed.StreamID != streamID {
				continue
			}
			if typed.ErrCode != http2.ErrCodeProtocol {
				t.Fatalf("raw h2 stream protocol error code = %v, want %v", typed.ErrCode, http2.ErrCodeProtocol)
			}
			return
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY for stream-level raw h2 protocol error: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.MetaHeadersFrame:
			if typed.StreamID == streamID {
				t.Fatalf("raw h2 malformed stream received response status %q, want RST_STREAM PROTOCOL_ERROR", typed.PseudoValue("status"))
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe RST_STREAM PROTOCOL_ERROR for stream %d", streamID)
		}
	}
}

func readRawHTTP2ConnectionProtocolErrorProcess(t *testing.T, conn *tls.Conn, label string) {
	t.Helper()

	readRawHTTP2ConnectionErrorProcess(t, conn, label, http2.ErrCodeProtocol)
}

func readRawHTTP2ConnectionErrorProcess(t *testing.T, conn *tls.Conn, label string, wantErrCode http2.ErrCode) {
	t.Helper()

	fr := http2.NewFramer(conn, conn)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "use of closed network connection") {
				if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
					t.Fatalf("clear read deadline: %v", clearErr)
				}
				return
			}
			t.Fatalf("%s read returned unexpected error: %v", label, err)
		}

		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			t.Fatalf("clear read deadline: %v", clearErr)
		}
		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			if typed.ErrCode != wantErrCode {
				t.Fatalf("%s GOAWAY err_code = %v, want %v", label, typed.ErrCode, wantErrCode)
			}
			return
		case *http2.SettingsFrame, *http2.WindowUpdateFrame:
			continue
		default:
			t.Fatalf("%s received unexpected frame type %T before connection close", label, frame)
		}

		if time.Now().After(deadline) {
			t.Fatalf("%s did not return GOAWAY or close in time", label)
		}
	}
}

func readRawHTTP2GoAwayAndNoResponseForStreamProcess(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32, wantLastStreamID uint32, label string) {
	t.Helper()

	sawGoAway := false
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Now().Before(deadline) {
					continue
				}
				if sawGoAway {
					if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
						t.Fatalf("clear read deadline: %v", clearErr)
					}
					return
				}
			}
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "use of closed network connection") {
				if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
					t.Fatalf("clear read deadline: %v", clearErr)
				}
				if !sawGoAway {
					t.Fatalf("%s connection closed before GOAWAY", label)
				}
				return
			}
			t.Fatalf("%s read returned unexpected error: %v", label, err)
		}

		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			t.Fatalf("clear read deadline: %v", clearErr)
		}
		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			if typed.ErrCode != http2.ErrCodeNo {
				t.Fatalf("%s GOAWAY err_code = %v, want %v", label, typed.ErrCode, http2.ErrCodeNo)
			}
			if typed.LastStreamID != wantLastStreamID {
				t.Fatalf("%s GOAWAY last_stream_id = %d, want %d", label, typed.LastStreamID, wantLastStreamID)
			}
			sawGoAway = true
		case *http2.MetaHeadersFrame:
			if typed.StreamID == streamID {
				t.Fatalf("%s received response status %q for ignored stream %d", label, typed.PseudoValue("status"), streamID)
			}
		case *http2.DataFrame:
			if typed.StreamID == streamID {
				t.Fatalf("%s received DATA for ignored stream %d", label, streamID)
			}
		case *http2.RSTStreamFrame:
			if typed.StreamID == streamID {
				t.Fatalf("%s received RST_STREAM err_code=%v for ignored stream %d", label, typed.ErrCode, streamID)
			}
		case *http2.SettingsFrame, *http2.WindowUpdateFrame:
			continue
		default:
			t.Fatalf("%s received unexpected frame type %T", label, frame)
		}

		if time.Now().After(deadline) {
			if !sawGoAway {
				t.Fatalf("%s did not observe GOAWAY in time", label)
			}
			return
		}
	}
}

func readRawHTTP2ResponseDataContainsProcess(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32, wantSubstring string) bool {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response data frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 response data sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.DataFrame:
			if typed.StreamID != streamID {
				continue
			}
			if strings.Contains(string(typed.Data()), wantSubstring) {
				return true
			}
		}

		if time.Now().After(deadline) {
			return false
		}
	}
}

func readRawHTTP2ResponseStatusProcess(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32, wantStatus string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.MetaHeadersFrame:
			if typed.StreamID != streamID {
				continue
			}
			if got := typed.PseudoValue("status"); got != wantStatus {
				t.Fatalf("raw h2 response status = %q, want %q", got, wantStatus)
			}
			if typed.StreamEnded() {
				return
			}
		case *http2.DataFrame:
			if typed.StreamID == streamID && typed.StreamEnded() {
				return
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe response completion for stream %d", streamID)
		}
	}
}
