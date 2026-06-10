package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/admin/protect"
	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/admin/system"
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
	addr       string
	repos      *repository.Repos
	apiToken   string
	reloadHits atomic.Int32
}

func newAdminRouteTestServer(t *testing.T) *adminRouteTestServer {
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

	testSrv := &adminRouteTestServer{
		repos:    repos,
		apiToken: token,
	}
	realtime := system.NewRealtimeHub(nil, nil, nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen admin route test server: %v", err)
	}

	secret := []byte("route-test-secret")
	srv := server.Default(server.WithListener(ln))
	RegisterRoutes(srv, &Dependencies{
		Repos:      repos,
		Reload:     func() error { testSrv.reloadHits.Add(1); return nil },
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
			Host:        "one.example",
			Path:        "/one",
			Action:      "intercept",
			TLSVersion:  "TLS13",
			TLSSNI:      "checkout.example.com",
			TLSALPN:     "h2",
			TLSJA3Hash:  "ja3-route",
			TLSJA4:      "ja4-route",
			HeaderOrder: "Host,User-Agent,Accept",
			CreatedAt:   now,
		},
		{
			Host:        "two.example",
			Path:        "/two",
			Action:      "intercept",
			TLSVersion:  "TLS12",
			TLSSNI:      "api.example.com",
			TLSALPN:     "http/1.1",
			TLSJA3Hash:  "ja3-other",
			TLSJA4:      "ja4-other",
			HeaderOrder: "Host,Accept,User-Agent",
			CreatedAt:   now,
		},
	}
	if err := srv.repos.SecurityEvent.BatchCreate(items); err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/security-events?tls_version=TLS13&tls_sni=checkout&tls_alpn=h2&tls_ja3_hash=ja3-route&tls_ja4=ja4-route&header_order=User-Agent%2CAccept")
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
	if got.Items[0].TLSSNI != "checkout.example.com" || got.Items[0].TLSJA3Hash != "ja3-route" || got.Items[0].TLSJA4 != "ja4-route" {
		t.Fatalf("unexpected TLS fields in response: %#v", got.Items[0])
	}
}

func TestAccessLogsGetRouteFiltersByTLSFields(t *testing.T) {
	srv := newAdminRouteTestServer(t)
	now := time.Now()
	items := []store.AccessLog{
		{
			RequestID:  "access-tls-route-match",
			Host:       "one.example",
			Path:       "/one",
			Method:     "GET",
			StatusCode: 403,
			TLSVersion: "TLS13",
			TLSSNI:     "checkout.example.com",
			TLSALPN:    "h2",
			TLSJA3Hash: "ja3-route",
			TLSJA4:     "ja4-route",
			CreatedAt:  now,
		},
		{
			RequestID:  "access-tls-route-other",
			Host:       "two.example",
			Path:       "/two",
			Method:     "GET",
			StatusCode: 200,
			TLSVersion: "TLS12",
			TLSSNI:     "api.example.com",
			TLSALPN:    "http/1.1",
			TLSJA3Hash: "ja3-other",
			TLSJA4:     "ja4-other",
			CreatedAt:  now,
		},
	}
	if err := srv.repos.AccessLog.BatchCreate(items); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	resp := srv.getJSON(t, "/api/v1/access-logs?tls_version=TLS13&tls_sni=checkout&tls_alpn=h2&tls_ja3_hash=ja3-route&tls_ja4=ja4-route")
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
	if got.Items[0].RequestID != "access-tls-route-match" || got.Items[0].TLSSNI != "checkout.example.com" || got.Items[0].TLSJA3Hash != "ja3-route" || got.Items[0].TLSJA4 != "ja4-route" {
		t.Fatalf("unexpected access log TLS fields in response: %#v", got.Items[0])
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
