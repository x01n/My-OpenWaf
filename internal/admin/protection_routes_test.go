package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/admin/protect"
	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/admin/system"
	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type adminRouteTestServer struct {
	addr               string
	repos              *repository.Repos
	snapshot           *snapshot.Holder
	apiToken           string
	reloadHits         atomic.Int32
	redisReloadHits    atomic.Int32
	runtimeStateMu     sync.RWMutex
	runtimeCfg         core.Config
	runtimeRedisEnable bool
	reloadRedis        func() error
}

func newAdminRouteTestServer(t *testing.T) *adminRouteTestServer {
	return newAdminRouteTestServerWithRuntimeConfig(t, core.Config{})
}

func newAdminRouteTestServerWithRuntimeConfig(t *testing.T, runtimeCfg core.Config) *adminRouteTestServer {
	return newAdminRouteTestServerWithRuntimeState(t, runtimeCfg, strings.TrimSpace(runtimeCfg.RedisAddr) != "")
}

func newAdminRouteTestServerWithRuntimeState(t *testing.T, runtimeCfg core.Config, runtimeRedisEnabled bool) *adminRouteTestServer {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}

	repos := repository.New(db)
	token, _, err := repos.AdminAPIKey.Create("route-test")
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	snapshotHolder := &snapshot.Holder{}

	testSrv := &adminRouteTestServer{
		repos:              repos,
		snapshot:           snapshotHolder,
		apiToken:           token,
		runtimeCfg:         runtimeCfg,
		runtimeRedisEnable: runtimeRedisEnabled,
	}
	realtime := system.NewRealtimeHub(nil, nil, nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen admin route test server: %v", err)
	}

	secret := []byte("route-test-secret")
	srv := server.Default(server.WithListener(ln))
	RegisterRoutes(srv, &Dependencies{
		Repos: repos,
		Reload: func() error {
			testSrv.reloadHits.Add(1)
			return nil
		},
		ReloadRedis: func() error {
			testSrv.redisReloadHits.Add(1)
			testSrv.runtimeStateMu.RLock()
			reloadRedis := testSrv.reloadRedis
			testSrv.runtimeStateMu.RUnlock()
			if reloadRedis != nil {
				return reloadRedis()
			}
			return nil
		},
		RuntimeState: func() (core.Config, bool) {
			testSrv.runtimeStateMu.RLock()
			defer testSrv.runtimeStateMu.RUnlock()
			return testSrv.runtimeCfg, testSrv.runtimeRedisEnable
		},
		Snapshot:   snapshotHolder,
		JWTSecret:  secret,
		DB:         db,
		LogDB:      db,
		TokenMgr:   auth.NewTokenManager(secret, db),
		SessionMgr: auth.NewSessionManager(db),
		BruteForce: auth.NewBruteForceDetector(5, time.Minute),
		Realtime:   realtime,
	})

	go srv.Spin()
	deadline := time.Now().Add(time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatalf("admin route test server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})

	testSrv.addr = ln.Addr().String()
	return testSrv
}

func (s *adminRouteTestServer) setRuntimeState(cfg core.Config, redisEnabled bool) {
	s.runtimeStateMu.Lock()
	s.runtimeCfg = cfg
	s.runtimeRedisEnable = redisEnabled
	s.runtimeStateMu.Unlock()
}

func (s *adminRouteTestServer) runtimeState() (core.Config, bool) {
	s.runtimeStateMu.RLock()
	defer s.runtimeStateMu.RUnlock()
	return s.runtimeCfg, s.runtimeRedisEnable
}

func (s *adminRouteTestServer) setReloadRedis(fn func() error) {
	s.runtimeStateMu.Lock()
	s.reloadRedis = fn
	s.runtimeStateMu.Unlock()
}

func (s *adminRouteTestServer) postJSON(t *testing.T, path string, body []byte) *protocol.Response {
	t.Helper()

	c, err := client.NewClient(client.WithDialer(standard.NewDialer()))
	if err != nil {
		t.Fatalf("create admin route client: %v", err)
	}

	req, resp := protocol.AcquireRequest(), protocol.AcquireResponse()
	t.Cleanup(func() {
		protocol.ReleaseRequest(req)
		protocol.ReleaseResponse(resp)
	})

	req.SetMethod("POST")
	req.SetRequestURI("http://" + s.addr + path)
	req.Header.Set("Authorization", "Bearer "+s.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)

	if err := c.Do(context.Background(), req, resp); err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (s *adminRouteTestServer) getJSON(t *testing.T, path string) *protocol.Response {
	t.Helper()

	c, err := client.NewClient(client.WithDialer(standard.NewDialer()))
	if err != nil {
		t.Fatalf("create admin route client: %v", err)
	}

	req, resp := protocol.AcquireRequest(), protocol.AcquireResponse()
	t.Cleanup(func() {
		protocol.ReleaseRequest(req)
		protocol.ReleaseResponse(resp)
	})

	req.SetMethod("GET")
	req.SetRequestURI("http://" + s.addr + path)
	req.Header.Set("Authorization", "Bearer "+s.apiToken)

	if err := c.Do(context.Background(), req, resp); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func (s *adminRouteTestServer) getJSONWithHeaders(t *testing.T, path string, headers map[string]string) *protocol.Response {
	t.Helper()

	c, err := client.NewClient(client.WithDialer(standard.NewDialer()))
	if err != nil {
		t.Fatalf("create admin route client: %v", err)
	}

	req, resp := protocol.AcquireRequest(), protocol.AcquireResponse()
	t.Cleanup(func() {
		protocol.ReleaseRequest(req)
		protocol.ReleaseResponse(resp)
	})

	req.SetMethod("GET")
	req.SetRequestURI("http://" + s.addr + path)
	req.Header.Set("Authorization", "Bearer "+s.apiToken)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if err := c.Do(context.Background(), req, resp); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

type adminRouteTestRedisServer struct {
	ln       net.Listener
	mu       sync.Mutex
	commands []string
}

func startAdminRouteTestRedisServer(t *testing.T) *adminRouteTestRedisServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen admin route mock redis: %v", err)
	}

	srv := &adminRouteTestRedisServer{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handle(conn)
		}
	}()
	return srv
}

func (s *adminRouteTestRedisServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *adminRouteTestRedisServer) Close() {
	_ = s.ln.Close()
}

func (s *adminRouteTestRedisServer) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]string, len(s.commands))
	copy(out, s.commands)
	return out
}

func (s *adminRouteTestRedisServer) record(args []string) {
	parts := make([]string, len(args))
	for i := range args {
		parts[i] = strings.ToUpper(args[i])
	}

	s.mu.Lock()
	s.commands = append(s.commands, strings.Join(parts, " "))
	s.mu.Unlock()
}

func (s *adminRouteTestRedisServer) handle(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		args, err := readAdminRouteRESPArgs(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}

		s.record(args)

		switch strings.ToUpper(args[0]) {
		case "HELLO":
			_, _ = conn.Write([]byte("-ERR unknown command 'hello'\r\n"))
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}

func readAdminRouteRESPArgs(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}

	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected RESP array, got %q", line)
	}

	count, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}

		header = strings.TrimRight(header, "\r\n")
		if !strings.HasPrefix(header, "$") {
			return nil, fmt.Errorf("expected bulk string, got %q", header)
		}

		length, err := strconv.Atoi(header[1:])
		if err != nil {
			return nil, err
		}

		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		if _, err := r.Discard(2); err != nil {
			return nil, err
		}

		args = append(args, string(buf))
	}

	return args, nil
}

func adminRouteHasRedisCommandPrefix(commands []string, prefix string) bool {
	for _, command := range commands {
		if strings.Contains(command, prefix) {
			return true
		}
	}
	return false
}

func TestProtectionSettingsPostRouteUpdatesProtectionAndReloads(t *testing.T) {
	srv := newAdminRouteTestServer(t)

	cfg := store.DefaultProtectionConfig()
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"captcha","condition":"all","captcha_type":"math"}]`
	cfg.CaptchaEnabled = true
	cfg.ShieldEnabled = true
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 120
	cfg.SetEscalationSteps([]store.EscalationStepDef{{Threshold: 3, Action: "challenge"}})
	if err := shared.SaveProtectionConfig(srv.repos.SystemSettings, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	resp := srv.postJSON(t, "/api/v1/protection-settings", []byte(`{"builtin_owasp_on_hit":"observe"}`))
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	loaded := shared.LoadProtectionConfig(srv.repos.SystemSettings)
	if loaded.OWASPAction != "observe" {
		t.Fatalf("POST route did not update builtin_owasp_on_hit: %#v", loaded)
	}
	if !loaded.ChainEnabled || loaded.ChainSteps != cfg.ChainSteps || !loaded.CaptchaEnabled || !loaded.ShieldEnabled || !loaded.EscalationEnabled || loaded.EscalationWindowSecs != 120 {
		t.Fatalf("POST route should preserve challenge fields: %#v", loaded)
	}
	steps := loaded.GetEscalationSteps()
	if len(steps) != 1 || steps[0].Threshold != 3 || steps[0].Action != "challenge" {
		t.Fatalf("POST route should preserve escalation steps: %#v", steps)
	}
	if srv.reloadHits.Load() != 1 {
		t.Fatalf("POST /api/v1/protection-settings reload count = %d, want 1", srv.reloadHits.Load())
	}
}

func TestBotSettingsUpdatePostRoutePreservesSharedFieldsWhenPatchOmitsThem(t *testing.T) {
	srv := newAdminRouteTestServer(t)

	cfg := store.DefaultProtectionConfig()
	cfg.BotDetectionEnabled = true
	if err := shared.SaveProtectionConfig(srv.repos.SystemSettings, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := srv.repos.SystemSettings.Set("drop_policy", `{"enabled":true,"bot_score_threshold":92,"cve_auto_drop_critical":true,"cve_auto_drop_high":true}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	resp := srv.postJSON(t, "/api/v1/bot-settings/update", []byte(`{"high_risk_countries":["CN","RU"]}`))
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	protection := shared.LoadProtectionConfig(srv.repos.SystemSettings)
	if !protection.BotDetectionEnabled {
		t.Fatalf("bot list-only POST route should not sync default enabled=false into protection: %#v", protection)
	}

	val, err := srv.repos.SystemSettings.Get("drop_policy")
	if err != nil {
		t.Fatalf("load drop policy: %v", err)
	}
	var dropPolicy struct {
		BotScoreThreshold int `json:"bot_score_threshold"`
	}
	if err := json.Unmarshal([]byte(val), &dropPolicy); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if dropPolicy.BotScoreThreshold != 92 {
		t.Fatalf("bot list-only POST route should not sync default threshold=60 into drop policy, got %d", dropPolicy.BotScoreThreshold)
	}
	if srv.reloadHits.Load() != 1 {
		t.Fatalf("POST /api/v1/bot-settings/update reload count = %d, want 1", srv.reloadHits.Load())
	}
}

func TestBotStatsGetRouteReturnsAggregated24hStats(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.BotScoreLog{
		{TotalScore: 90, IsHighRisk: true, Action: "block", CreatedAt: now.Add(-time.Hour)},
		{TotalScore: 30, IsHighRisk: false, Action: "allow", CreatedAt: now.Add(-2 * time.Hour)},
		{TotalScore: 100, IsHighRisk: true, Action: "drop", CreatedAt: now.Add(-25 * time.Hour)},
	}
	if err := srv.repos.BotScore.BatchCreate(items); err != nil {
		t.Fatalf("seed bot score logs: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/bot-stats")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Total24h    int64   `json:"total_24h"`
		Blocked24h  int64   `json:"blocked_24h"`
		HighRisk24h int64   `json:"high_risk_24h"`
		AvgScore24h float64 `json:"avg_score_24h"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode bot stats: %v", err)
	}
	if got.Total24h != 2 || got.Blocked24h != 1 || got.HighRisk24h != 1 || got.AvgScore24h != 60 {
		t.Fatalf("unexpected bot stats response: %#v", got)
	}
}

func TestBotScoresGetRouteFiltersByTLSSNI(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.BotScoreLog{
		{Host: "one.example", Path: "/one", TLSSNI: "login.example.com", TotalScore: 90, CreatedAt: now},
		{Host: "two.example", Path: "/two", TLSSNI: "api.example.com", TotalScore: 60, CreatedAt: now},
	}
	if err := srv.repos.BotScore.BatchCreate(items); err != nil {
		t.Fatalf("seed bot score logs: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/bot-scores?tls_sni=login.example")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.BotScoreLog `json:"items"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode bot score response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 {
		t.Fatalf("expected one filtered bot score, got %#v", got)
	}
	if got.Items[0].TLSSNI != "login.example.com" {
		t.Fatalf("unexpected tls_sni in response: %#v", got.Items[0])
	}
}

func TestSecurityEventsGetRouteFiltersByTLSFields(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.SecurityEvent{
		{
			Host:            "one.example",
			Path:            "/one",
			Action:          "intercept",
			TLSVersion:      "TLS13",
			TLSSNI:          "checkout.example.com",
			TLSALPN:         "h2",
			TLSJA3Hash:      "ja3-route",
			TLSJA4:          "ja4-route",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			HeaderOrder:     "Host,User-Agent,Accept",
			CreatedAt:       now,
		},
		{
			Host:            "two.example",
			Path:            "/two",
			Action:          "intercept",
			TLSVersion:      "TLS12",
			TLSSNI:          "api.example.com",
			TLSALPN:         "http/1.1",
			TLSJA3Hash:      "ja3-other",
			TLSJA4:          "ja4-other",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
			HeaderOrder:     "Host,Accept,User-Agent",
			CreatedAt:       now,
		},
	}
	if err := srv.repos.SecurityEvent.BatchCreate(items); err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/security-events?tls_version=TLS%201.3&tls_sni=checkout&tls_alpn=h2&tls_ja3_hash=ja3-route&tls_ja4=ja4-route&tls_cipher_suites=AES_256_GCM_SHA384&tls_extensions=16%2C43&tls_curves=29%2C23&tls_point_formats=0&header_order=User-Agent%2CAccept")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode security event response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 {
		t.Fatalf("expected one filtered security event, got %#v", got)
	}
	if got.Items[0].TLSSNI != "checkout.example.com" || got.Items[0].TLSJA3Hash != "ja3-route" || got.Items[0].TLSJA4 != "ja4-route" || got.Items[0].TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" || got.Items[0].TLSExtensions != "0,16,43" || got.Items[0].TLSCurves != "29,23" || got.Items[0].TLSPointFormats != "0" {
		t.Fatalf("unexpected TLS fields in response: %#v", got.Items[0])
	}
}

func TestAccessLogsGetRouteFiltersByTLSFields(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.AccessLog{
		{
			RequestID:       "access-tls-route-match",
			Host:            "one.example",
			Path:            "/one",
			Method:          "GET",
			StatusCode:      403,
			TLSVersion:      "TLS13",
			TLSSNI:          "checkout.example.com",
			TLSALPN:         "h2",
			TLSJA3Hash:      "ja3-route",
			TLSJA4:          "ja4-route",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			CreatedAt:       now,
		},
		{
			RequestID:       "access-tls-route-other",
			Host:            "two.example",
			Path:            "/two",
			Method:          "GET",
			StatusCode:      200,
			TLSVersion:      "TLS12",
			TLSSNI:          "api.example.com",
			TLSALPN:         "http/1.1",
			TLSJA3Hash:      "ja3-other",
			TLSJA4:          "ja4-other",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
			CreatedAt:       now,
		},
	}
	if err := srv.repos.AccessLog.BatchCreate(items); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/access-logs?tls_version=1.3&tls_sni=checkout&tls_alpn=h2&tls_ja3_hash=ja3-route&tls_ja4=ja4-route&tls_cipher_suites=AES_256_GCM_SHA384&tls_extensions=16%2C43&tls_curves=29%2C23&tls_point_formats=0")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode access log response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 {
		t.Fatalf("expected one filtered access log, got %#v", got)
	}
	if got.Items[0].RequestID != "access-tls-route-match" || got.Items[0].TLSSNI != "checkout.example.com" || got.Items[0].TLSJA3Hash != "ja3-route" || got.Items[0].TLSJA4 != "ja4-route" || got.Items[0].TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" || got.Items[0].TLSExtensions != "0,16,43" || got.Items[0].TLSCurves != "29,23" || got.Items[0].TLSPointFormats != "0" {
		t.Fatalf("unexpected access log TLS fields in response: %#v", got.Items[0])
	}
}

func TestAccessLogsGetRouteFiltersByStaleCacheState(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.AccessLog{
		{
			RequestID:  "access-cache-stale-match",
			Host:       "cache.example",
			Path:       "/stale",
			Method:     "GET",
			StatusCode: http.StatusOK,
			CacheState: "stale",
			CreatedAt:  now,
		},
		{
			RequestID:  "access-cache-hit-other",
			Host:       "cache.example",
			Path:       "/hit",
			Method:     "GET",
			StatusCode: http.StatusOK,
			CacheState: "hit",
			CreatedAt:  now,
		},
	}
	if err := srv.repos.AccessLog.BatchCreate(items); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/access-logs?cache_state=stale")
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode access log response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 {
		t.Fatalf("expected one stale cache-state access log, got %#v", got)
	}
	if got.Items[0].RequestID != "access-cache-stale-match" || got.Items[0].CacheState != "stale" {
		t.Fatalf("unexpected stale cache-state access log: %#v", got.Items[0])
	}
}

func TestFingerprintsGetRouteFiltersAcrossAllPages(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.AccessLog{
		{
			RequestID:       "fp-newest",
			Host:            "newest.example",
			Path:            "/newest",
			Method:          "GET",
			StatusCode:      200,
			TLSVersion:      "TLS13",
			TLSSNI:          "newest.example",
			TLSALPN:         "h2",
			TLSJA3Hash:      "ja3-newest",
			TLSJA4:          "ja4-newest",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			CreatedAt:       now,
		},
		{
			RequestID:       "fp-middle",
			Host:            "middle.example",
			Path:            "/middle",
			Method:          "GET",
			StatusCode:      200,
			TLSVersion:      "TLS12",
			TLSSNI:          "middle.example",
			TLSALPN:         "http/1.1",
			TLSJA3Hash:      "ja3-middle",
			TLSJA4:          "ja4-middle",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
			CreatedAt:       now.Add(-time.Minute),
		},
		{
			RequestID:       "fp-target",
			Host:            "target.example",
			Path:            "/target",
			Method:          "GET",
			StatusCode:      200,
			TLSVersion:      "TLS13",
			TLSSNI:          "target.example",
			TLSALPN:         "h3",
			TLSJA3Hash:      "ja3-target",
			TLSJA4:          "ja4-target",
			TLSCipherSuites: "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			CreatedAt:       now.Add(-2 * time.Minute),
		},
	}
	if err := srv.repos.AccessLog.BatchCreate(items); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/fingerprints?page=1&page_size=1&tls_ja4=ja4-target&tls_cipher_suites=CHACHA20&tls_extensions=16%2C43&tls_curves=29%2C23&tls_point_formats=0")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []repository.FingerprintSummary `json:"items"`
		Total int64                           `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode fingerprint response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 {
		t.Fatalf("expected one filtered fingerprint group, got %#v", got)
	}
	if got.Items[0].TLSJA3Hash != "ja3-target" || got.Items[0].TLSJA4 != "ja4-target" || got.Items[0].TLSSNI != "target.example" || got.Items[0].TLSCipherSuites != "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256" || got.Items[0].TLSExtensions != "0,16,43" || got.Items[0].TLSCurves != "29,23" || got.Items[0].TLSPointFormats != "0" {
		t.Fatalf("unexpected fingerprint item: %#v", got.Items[0])
	}
}

func TestSecurityEventsGetRouteFiltersByQueryString(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.SecurityEvent{
		{
			SiteID:      7,
			RequestID:   "security-query-match",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			Action:      "intercept",
			CreatedAt:   now,
		},
		{
			SiteID:      8,
			RequestID:   "security-query-other",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fdocs&token=basic",
			Action:      "intercept",
			CreatedAt:   now,
		},
	}
	if err := srv.repos.SecurityEvent.BatchCreate(items); err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/security-events?query_string=token%3Dvip")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode security event response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 || got.Items[0].RequestID != "security-query-match" {
		t.Fatalf("expected one query_string-filtered security event, got %#v", got)
	}
}

func TestSecurityEventsGetRouteFiltersBySiteID(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.SecurityEvent{
		{
			SiteID:      7,
			RequestID:   "security-site-match",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			Action:      "intercept",
			CreatedAt:   now,
		},
		{
			SiteID:      8,
			RequestID:   "security-site-other",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			Action:      "intercept",
			CreatedAt:   now,
		},
	}
	if err := srv.repos.SecurityEvent.BatchCreate(items); err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/security-events?site_id=7&query_string=token%3Dvip")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode security event response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 || got.Items[0].RequestID != "security-site-match" {
		t.Fatalf("expected one site-filtered security event, got %#v", got)
	}
}

func TestSecurityEventsGetRouteFiltersByUnifiedQuery(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.SecurityEvent{
		{
			RequestID:   "security-unified-match",
			ClientIP:    "10.3.0.1",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			RuleIDStr:   "custom:orders:001",
			TLSJA4:      "ja4-unified",
			Action:      "intercept",
			CreatedAt:   now,
		},
		{
			RequestID:   "security-unified-other",
			ClientIP:    "10.3.0.2",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fdocs&token=basic",
			RuleIDStr:   "custom:profile:001",
			TLSJA4:      "ja4-other",
			Action:      "intercept",
			CreatedAt:   now,
		},
	}
	if err := srv.repos.SecurityEvent.BatchCreate(items); err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/security-events?q=custom%3Aorders%3A001")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode security event response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 || got.Items[0].RequestID != "security-unified-match" {
		t.Fatalf("expected one unified-query-filtered security event, got %#v", got)
	}
}

func TestAccessLogsGetRouteFiltersByQueryString(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.AccessLog{
		{
			RequestID:   "access-query-match",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			Method:      "GET",
			StatusCode:  200,
			CreatedAt:   now,
		},
		{
			RequestID:   "access-query-other",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fdocs&token=basic",
			Method:      "GET",
			StatusCode:  200,
			CreatedAt:   now,
		},
	}
	if err := srv.repos.AccessLog.BatchCreate(items); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/access-logs?query_string=token%3Dvip")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode access log response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 || got.Items[0].RequestID != "access-query-match" {
		t.Fatalf("expected one query_string-filtered access log, got %#v", got)
	}
}

func TestAccessLogsGetRouteFiltersByUnifiedQuery(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.AccessLog{
		{
			RequestID:   "access-unified-match",
			ClientIP:    "10.2.0.1",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			TLSJA4:      "ja4-unified",
			Method:      "GET",
			StatusCode:  200,
			CreatedAt:   now,
		},
		{
			RequestID:   "access-unified-other",
			ClientIP:    "10.2.0.2",
			Host:        "one.example",
			Path:        "/login",
			QueryString: "redirect=%2Fdocs&token=basic",
			TLSJA4:      "ja4-other",
			Method:      "GET",
			StatusCode:  200,
			CreatedAt:   now,
		},
	}
	if err := srv.repos.AccessLog.BatchCreate(items); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/access-logs?q=ja4-unified")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
	}
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode access log response: %v", err)
	}
	if got.Total != 1 || len(got.Items) != 1 || got.Items[0].RequestID != "access-unified-match" {
		t.Fatalf("expected one unified-query-filtered access log, got %#v", got)
	}
}

func TestDropPolicyUpdatePostRoutePreservesSharedFieldsWhenPatchOmitsThem(t *testing.T) {
	srv := newAdminRouteTestServer(t)

	cfg := store.DefaultProtectionConfig()
	cfg.CVEAutoDropCritical = false
	cfg.CVEAutoDropHigh = false
	if err := shared.SaveProtectionConfig(srv.repos.SystemSettings, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := srv.repos.SystemSettings.Set("bot_settings", `{"enabled":true,"score_threshold":91}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	resp := srv.postJSON(t, "/api/v1/drop-policy/update", []byte(`{"enabled":false}`))
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	protection := shared.LoadProtectionConfig(srv.repos.SystemSettings)
	if protection.CVEAutoDropCritical || protection.CVEAutoDropHigh {
		t.Fatalf("enabled-only POST route should not sync default CVE flags into protection: %#v", protection)
	}

	val, err := srv.repos.SystemSettings.Get("bot_settings")
	if err != nil {
		t.Fatalf("load bot settings: %v", err)
	}
	var bot shared.BotSettingsResponse
	if err := json.Unmarshal([]byte(val), &bot); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if bot.ScoreThreshold != 91 {
		t.Fatalf("enabled-only POST route should not sync default bot threshold, got %d", bot.ScoreThreshold)
	}

	val, err = srv.repos.SystemSettings.Get("drop_policy")
	if err != nil {
		t.Fatalf("load drop policy: %v", err)
	}
	var dropPolicy protect.DropPolicyResponse
	if err := json.Unmarshal([]byte(val), &dropPolicy); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if dropPolicy.Enabled || dropPolicy.BotScoreThreshold != 91 || dropPolicy.CVEAutoDropCritical || dropPolicy.CVEAutoDropHigh {
		t.Fatalf("drop policy POST route should save enabled change over derived shared fields, got %#v", dropPolicy)
	}
	if srv.reloadHits.Load() != 1 {
		t.Fatalf("POST /api/v1/drop-policy/update reload count = %d, want 1", srv.reloadHits.Load())
	}
}

func TestRuntimeConfigGetRouteReturnsInjectedRuntimeConfig(t *testing.T) {
	srv := newAdminRouteTestServerWithRuntimeConfig(t, core.Config{
		DBDriver:  "sqlite",
		DataDir:   "./data",
		RedisAddr: "127.0.0.1:6379",
		RedisDB:   7,
		AdminBind: ":9443",
		CVE: core.CVEConfig{
			Enabled:      true,
			FeedEnabled:  true,
			FeedInterval: "6h",
		},
		Drop: core.DropConfig{
			Enabled: true,
		},
	})
	sn := &snapshot.Snapshot{
		Revision:                       1,
		HSTSEnabled:                    true,
		XSSProtectionEnabled:           true,
		ExpectCTEnabled:                true,
		ExpectCTValue:                  "max-age=86400, enforce",
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: false,
		ResponseCompressionMinBytes:    2048,
	}
	srv.snapshot.Store(sn)

	resp := srv.getJSON(t, "/api/v1/runtime-config")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got system.RuntimeConfigResponse
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode runtime config response: %v", err)
	}
	if got.Source != "runtime" {
		t.Fatalf("runtime config source = %q, want %q", got.Source, "runtime")
	}
	if !got.RedisEnabled || got.RedisAddr != "127.0.0.1:6379" || got.RedisDB != 7 {
		t.Fatalf("runtime config should reflect injected runtime redis config, got %#v", got)
	}
	if !got.HSTSEnabled {
		t.Fatalf("runtime config should reflect snapshot hsts setting, got %#v", got)
	}
	if !got.XSSProtectionEnabled {
		t.Fatalf("runtime config should reflect snapshot xss protection setting, got %#v", got)
	}
	if !got.ExpectCTEnabled || got.ExpectCTValue != "max-age=86400, enforce" {
		t.Fatalf("runtime config should reflect snapshot expect-ct setting, got %#v", got)
	}
	if !got.ResponseCompressionEnabled || got.ResponseCompressionGzipEnabled || got.ResponseCompressionMinBytes != 2048 {
		t.Fatalf("runtime config should reflect snapshot response compression setting, got %#v", got)
	}
	if got.RestartRequired {
		t.Fatalf("runtime config restart_required = %v, want false", got.RestartRequired)
	}
}

func TestRuntimeConfigGetRouteReflectsRuntimeRedisDisabledState(t *testing.T) {
	srv := newAdminRouteTestServerWithRuntimeState(t, core.Config{
		DBDriver:  "sqlite",
		DataDir:   "./data",
		RedisAddr: "127.0.0.1:6379",
		RedisDB:   7,
		AdminBind: ":9443",
	}, false)

	resp := srv.getJSON(t, "/api/v1/runtime-config")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got system.RuntimeConfigResponse
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode runtime config response: %v", err)
	}
	if got.RedisEnabled {
		t.Fatalf("runtime config redis_enabled = %v, want false", got.RedisEnabled)
	}
	if got.RedisAddr != "127.0.0.1:6379" || got.RedisDB != 7 {
		t.Fatalf("runtime config should retain configured redis target for inspection, got %#v", got)
	}
}

func TestRuntimeConfigGetRouteReflectsStoredDropPolicyEnabledState(t *testing.T) {
	srv := newAdminRouteTestServerWithRuntimeConfig(t, core.Config{
		DBDriver:  "sqlite",
		DataDir:   "./data",
		AdminBind: ":9443",
		Drop: core.DropConfig{
			Enabled: true,
		},
	})
	if err := srv.repos.SystemSettings.Set("drop_policy", `{"enabled":false,"bot_score_threshold":91}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/runtime-config")
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	var got system.RuntimeConfigResponse
	if err := json.Unmarshal(resp.Body(), &got); err != nil {
		t.Fatalf("decode runtime config response: %v", err)
	}
	if got.DropEnabled {
		t.Fatalf("runtime config drop_enabled = %v, want false", got.DropEnabled)
	}
}

func TestRedisConfigPostRouteHotReloadsRuntimeStateWithoutRestart(t *testing.T) {
	redisSrv := startAdminRouteTestRedisServer(t)
	t.Cleanup(redisSrv.Close)

	srv := newAdminRouteTestServerWithRuntimeState(t, core.Config{}, false)
	srv.setReloadRedis(func() error {
		srv.setRuntimeState(core.Config{
			RedisAddr:     redisSrv.Addr(),
			RedisPassword: "route-secret",
			RedisDB:       9,
		}, true)
		return nil
	})

	resp := srv.postJSON(t, "/api/v1/redis-config", []byte(fmt.Sprintf(`{"enabled":true,"addr":%q,"password":"route-secret","db":9}`, redisSrv.Addr())))
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	if srv.redisReloadHits.Load() != 1 {
		t.Fatalf("redis reload hits = %d, want 1", srv.redisReloadHits.Load())
	}

	deadline := time.Now().Add(time.Second)
	for {
		if adminRouteHasRedisCommandPrefix(redisSrv.Commands(), "PING") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected redis probe commands, got %#v", redisSrv.Commands())
		}
		time.Sleep(10 * time.Millisecond)
	}

	var gotRedis system.RedisConfigResponse
	if err := json.Unmarshal(resp.Body(), &gotRedis); err != nil {
		t.Fatalf("decode redis config response: %v", err)
	}
	if !gotRedis.Enabled || gotRedis.Addr != redisSrv.Addr() || gotRedis.DB != 9 {
		t.Fatalf("redis config response = %#v, want enabled addr/db applied", gotRedis)
	}
	if !gotRedis.PasswordSet {
		t.Fatalf("redis config response should keep password_set=true, got %#v", gotRedis)
	}
	if gotRedis.RestartRequired {
		t.Fatalf("redis config response restart_required = %v, want false", gotRedis.RestartRequired)
	}

	stored := system.LoadRedisConfig(srv.repos.SystemSettings)
	if !stored.Enabled || stored.Addr != redisSrv.Addr() || stored.Password != "route-secret" || stored.DB != 9 {
		t.Fatalf("stored redis config = %#v, want enabled runtime target", stored)
	}

	runtimeResp := srv.getJSON(t, "/api/v1/runtime-config")
	if runtimeResp.StatusCode() != 200 {
		t.Fatalf("unexpected runtime status %d: %s", runtimeResp.StatusCode(), bytes.TrimSpace(runtimeResp.Body()))
	}

	var gotRuntime system.RuntimeConfigResponse
	if err := json.Unmarshal(runtimeResp.Body(), &gotRuntime); err != nil {
		t.Fatalf("decode runtime config response: %v", err)
	}
	if !gotRuntime.RedisEnabled || gotRuntime.RedisAddr != redisSrv.Addr() || gotRuntime.RedisDB != 9 {
		t.Fatalf("runtime config should reflect hot reloaded redis state, got %#v", gotRuntime)
	}
	if gotRuntime.RestartRequired {
		t.Fatalf("runtime config restart_required = %v, want false", gotRuntime.RestartRequired)
	}
}

func TestRedisConfigPostRouteHotReloadCanDisableRuntimeState(t *testing.T) {
	redisSrv := startAdminRouteTestRedisServer(t)
	t.Cleanup(redisSrv.Close)

	srv := newAdminRouteTestServerWithRuntimeState(t, core.Config{
		RedisAddr:     redisSrv.Addr(),
		RedisPassword: "route-secret",
		RedisDB:       9,
	}, true)
	if err := srv.repos.SystemSettings.Set(store.SettingKeyRedisConfig, fmt.Sprintf(`{"enabled":true,"addr":"%s","password":"route-secret","db":9}`, redisSrv.Addr())); err != nil {
		t.Fatalf("seed redis config: %v", err)
	}
	srv.setReloadRedis(func() error {
		cfg, _ := srv.runtimeState()
		cfg.RedisAddr = ""
		cfg.RedisPassword = ""
		cfg.RedisDB = 0
		srv.setRuntimeState(cfg, false)
		return nil
	})

	resp := srv.postJSON(t, "/api/v1/redis-config", []byte(`{"enabled":false}`))
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}

	if srv.redisReloadHits.Load() != 1 {
		t.Fatalf("redis reload hits = %d, want 1", srv.redisReloadHits.Load())
	}

	var gotRedis system.RedisConfigResponse
	if err := json.Unmarshal(resp.Body(), &gotRedis); err != nil {
		t.Fatalf("decode redis config response: %v", err)
	}
	if gotRedis.Enabled {
		t.Fatalf("redis config response enabled = %v, want false", gotRedis.Enabled)
	}
	if gotRedis.RestartRequired {
		t.Fatalf("redis config response restart_required = %v, want false", gotRedis.RestartRequired)
	}

	stored := system.LoadRedisConfig(srv.repos.SystemSettings)
	if stored.Enabled {
		t.Fatalf("stored redis config enabled = %v, want false", stored.Enabled)
	}
	if stored.Addr != redisSrv.Addr() || stored.Password != "route-secret" || stored.DB != 9 {
		t.Fatalf("stored redis config should preserve disabled target for later reuse, got %#v", stored)
	}

	runtimeResp := srv.getJSON(t, "/api/v1/runtime-config")
	if runtimeResp.StatusCode() != 200 {
		t.Fatalf("unexpected runtime status %d: %s", runtimeResp.StatusCode(), bytes.TrimSpace(runtimeResp.Body()))
	}

	var gotRuntime system.RuntimeConfigResponse
	if err := json.Unmarshal(runtimeResp.Body(), &gotRuntime); err != nil {
		t.Fatalf("decode runtime config response: %v", err)
	}
	if gotRuntime.RedisEnabled {
		t.Fatalf("runtime config redis_enabled = %v, want false", gotRuntime.RedisEnabled)
	}
	if gotRuntime.RedisAddr != "" || gotRuntime.RedisDB != 0 {
		t.Fatalf("runtime config should clear active redis target after disable, got %#v", gotRuntime)
	}
}

func TestSecurityHeadersWriteHSTSForForwardedHTTPSWhenEnabled(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	srv.snapshot.Store(&snapshot.Snapshot{
		Revision:              1,
		HSTSEnabled:           true,
		XSSProtectionEnabled:  true,
		HPKPEnabled:           true,
		HPKPValue:             `pin-sha256="abc"; max-age=86400`,
		HPKPReportOnlyEnabled: true,
		HPKPReportOnlyValue:   `pin-sha256="abc"; max-age=86400; report-uri="https://report.example/hpkp"`,
	})

	resp := srv.getJSONWithHeaders(t, "/api/v1/runtime-config", map[string]string{
		"X-Forwarded-Proto": "https",
	})
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
	}
	if got := string(resp.Header.Peek(adminHSTSHeaderName)); got != adminHSTSHeaderValue {
		t.Fatalf("Strict-Transport-Security = %q, want %q", got, adminHSTSHeaderValue)
	}
	if got := string(resp.Header.Peek(adminXSSHeaderName)); got != adminXSSHeaderValue {
		t.Fatalf("X-XSS-Protection = %q, want %q", got, adminXSSHeaderValue)
	}
	if got := string(resp.Header.Peek(adminHPKPHeaderName)); got != `pin-sha256="abc"; max-age=86400` {
		t.Fatalf("Public-Key-Pins = %q, want configured value", got)
	}
	if got := string(resp.Header.Peek(adminHPKPReportOnlyHeaderName)); got != `pin-sha256="abc"; max-age=86400; report-uri="https://report.example/hpkp"` {
		t.Fatalf("Public-Key-Pins-Report-Only = %q, want configured value", got)
	}
	if got := string(resp.Header.Peek("X-Content-Type-Options")); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
}

func TestSecurityHeadersSkipHSTSForPlainHTTPAndDisabledSnapshot(t *testing.T) {
	t.Run("plain_http", func(t *testing.T) {
		srv := newAdminRouteTestServer(t)
		srv.snapshot.Store(&snapshot.Snapshot{
			Revision:             1,
			HSTSEnabled:          true,
			XSSProtectionEnabled: true,
			HPKPEnabled:          true,
			HPKPValue:            `pin-sha256="abc"; max-age=86400`,
		})

		resp := srv.getJSON(t, "/api/v1/runtime-config")
		if resp.StatusCode() != 200 {
			t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
		}
		if got := string(resp.Header.Peek(adminHSTSHeaderName)); got != "" {
			t.Fatalf("Strict-Transport-Security should be empty for plain HTTP, got %q", got)
		}
		if got := string(resp.Header.Peek(adminXSSHeaderName)); got != adminXSSHeaderValue {
			t.Fatalf("X-XSS-Protection = %q, want %q", got, adminXSSHeaderValue)
		}
		if got := string(resp.Header.Peek(adminHPKPHeaderName)); got != "" {
			t.Fatalf("Public-Key-Pins should be empty for plain HTTP, got %q", got)
		}
		if got := string(resp.Header.Peek(adminHPKPReportOnlyHeaderName)); got != "" {
			t.Fatalf("Public-Key-Pins-Report-Only should be empty for plain HTTP, got %q", got)
		}
	})

	t.Run("disabled_snapshot", func(t *testing.T) {
		srv := newAdminRouteTestServer(t)
		srv.snapshot.Store(&snapshot.Snapshot{
			Revision:              1,
			HSTSEnabled:           false,
			XSSProtectionEnabled:  false,
			HPKPEnabled:           false,
			HPKPReportOnlyEnabled: false,
		})

		resp := srv.getJSONWithHeaders(t, "/api/v1/runtime-config", map[string]string{
			"X-Forwarded-Proto": "https",
		})
		if resp.StatusCode() != 200 {
			t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
		}
		if got := string(resp.Header.Peek(adminHSTSHeaderName)); got != "" {
			t.Fatalf("Strict-Transport-Security should be empty when snapshot disables HSTS, got %q", got)
		}
		if got := string(resp.Header.Peek(adminXSSHeaderName)); got != "" {
			t.Fatalf("X-XSS-Protection should be empty when snapshot disables XSS protection, got %q", got)
		}
		if got := string(resp.Header.Peek(adminHPKPHeaderName)); got != "" {
			t.Fatalf("Public-Key-Pins should be empty when snapshot disables HPKP, got %q", got)
		}
		if got := string(resp.Header.Peek(adminHPKPReportOnlyHeaderName)); got != "" {
			t.Fatalf("Public-Key-Pins-Report-Only should be empty when snapshot disables HPKP report only, got %q", got)
		}
	})
}
