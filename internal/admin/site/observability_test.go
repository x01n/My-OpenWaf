package site

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	adminevent "My-OpenWaf/internal/admin/event"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func newSiteObservabilityReposForTest(t *testing.T) (*repository.SiteRepo, *repository.DropEventRepo, *repository.SecurityEventRepo, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.DropEvent{}, &store.SecurityEvent{}); err != nil {
		t.Fatalf("migrate observability tables: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewDropEventRepo(db), repository.NewSecurityEventRepo(db), db
}

func invokeSiteGetHandler(t *testing.T, handler app.HandlerFunc, siteID uint, path string, query url.Values) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("GET")
	uri := path
	if encoded := query.Encode(); encoded != "" {
		uri += "?" + encoded
	}
	req.SetRequestURI(uri)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: strconv.FormatUint(uint64(siteID), 10)}}
	handler(context.Background(), ctx)
	return ctx
}

func TestListSiteDropEventsFiltersByTimeRange(t *testing.T) {
	siteRepo, dropRepo, _, db := newSiteObservabilityReposForTest(t)
	siteItem := &store.Site{
		Host:         "drop-time.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	base := time.Date(2026, 6, 8, 10, 0, 0, 0, time.UTC)
	events := []store.DropEvent{
		{SiteID: siteItem.ID, ClientIP: "203.0.113.10", Source: "bot", CreatedAt: base.Add(-time.Hour), Path: "/old"},
		{SiteID: siteItem.ID, ClientIP: "203.0.113.10", Source: "bot", CreatedAt: base.Add(30 * time.Minute), Path: "/inside"},
		{SiteID: siteItem.ID, ClientIP: "203.0.113.10", Source: "bot", CreatedAt: base.Add(3 * time.Hour), Path: "/new"},
		{SiteID: siteItem.ID + 100, ClientIP: "203.0.113.10", Source: "bot", CreatedAt: base.Add(30 * time.Minute), Path: "/other-site"},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatalf("seed drop events: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		ListSiteDropEvents(siteRepo, dropRepo),
		siteItem.ID,
		"/api/v1/sites/1/drop-events",
		url.Values{
			"page":       {"1"},
			"page_size":  {"20"},
			"client_ip":  {"203.0.113.10"},
			"source":     {"bot"},
			"start_time": {base.Format(time.RFC3339)},
			"end_time":   {base.Add(2 * time.Hour).Format(time.RFC3339)},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.DropEvent `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected one in-range event, got total=%d items=%#v", resp.Total, resp.Items)
	}
	if resp.Items[0].Path != "/inside" {
		t.Fatalf("unexpected event path %q", resp.Items[0].Path)
	}
}

func TestListSiteSecurityEventsFiltersByTimeRange(t *testing.T) {
	siteRepo, _, securityRepo, db := newSiteObservabilityReposForTest(t)
	siteItem := &store.Site{
		Host:         "security-time.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	base := time.Date(2026, 6, 8, 10, 0, 0, 0, time.UTC)
	events := []store.SecurityEvent{
		{SiteID: siteItem.ID, RequestID: "old", ClientIP: "198.51.100.10", Host: siteItem.Host, Path: "/old", Action: "intercept", Phase: "custom", Category: "sqli", CreatedAt: base.Add(-time.Hour)},
		{SiteID: siteItem.ID, RequestID: "inside", ClientIP: "198.51.100.10", Host: siteItem.Host, Path: "/inside", Action: "intercept", Phase: "custom", Category: "sqli", CreatedAt: base.Add(30 * time.Minute)},
		{SiteID: siteItem.ID, RequestID: "new", ClientIP: "198.51.100.10", Host: siteItem.Host, Path: "/new", Action: "intercept", Phase: "custom", Category: "sqli", CreatedAt: base.Add(3 * time.Hour)},
		{SiteID: siteItem.ID + 100, RequestID: "other-site", ClientIP: "198.51.100.10", Host: siteItem.Host, Path: "/other-site", Action: "intercept", Phase: "custom", Category: "sqli", CreatedAt: base.Add(30 * time.Minute)},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		adminevent.ListSiteSecurityEvents(siteRepo, securityRepo),
		siteItem.ID,
		"/api/v1/sites/1/security-events",
		url.Values{
			"page":      {"1"},
			"page_size": {"20"},
			"client_ip": {"198.51.100.10"},
			"action":    {"intercept"},
			"phase":     {"custom"},
			"category":  {"sqli"},
			"since":     {base.Format(time.RFC3339)},
			"until":     {base.Add(2 * time.Hour).Format(time.RFC3339)},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected one in-range event, got total=%d items=%#v", resp.Total, resp.Items)
	}
	if resp.Items[0].RequestID != "inside" {
		t.Fatalf("unexpected event request_id %q", resp.Items[0].RequestID)
	}
}

func TestListSiteSecurityEventsKeepsAlternateConfiguredHosts(t *testing.T) {
	siteRepo, _, securityRepo, db := newSiteObservabilityReposForTest(t)
	siteItem := &store.Site{
		Host:         "app.multi-security.example,api.multi-security.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8443",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	events := []store.SecurityEvent{
		{
			SiteID:    siteItem.ID,
			RequestID: "multi-host-security-event",
			ClientIP:  "198.51.100.11",
			Host:      "api.multi-security.example",
			Path:      "/api/orders",
			Action:    "intercept",
			Phase:     "custom",
			Category:  "sqli",
		},
		{
			SiteID:    siteItem.ID + 1,
			RequestID: "other-site-event",
			ClientIP:  "198.51.100.11",
			Host:      "api.multi-security.example",
			Path:      "/api/orders",
			Action:    "intercept",
			Phase:     "custom",
			Category:  "sqli",
		},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		adminevent.ListSiteSecurityEvents(siteRepo, securityRepo),
		siteItem.ID,
		"/api/v1/sites/1/security-events",
		url.Values{
			"page":      {"1"},
			"page_size": {"20"},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected one site-scoped event from alternate configured host, got total=%d items=%#v", resp.Total, resp.Items)
	}
	if resp.Items[0].RequestID != "multi-host-security-event" || resp.Items[0].Host != "api.multi-security.example" {
		t.Fatalf("unexpected event item %#v", resp.Items[0])
	}
}

func TestListSiteSecurityEventsFiltersByTLSFields(t *testing.T) {
	siteRepo, _, securityRepo, db := newSiteObservabilityReposForTest(t)
	siteItem := &store.Site{
		Host:         "security-tls.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8443",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	events := []store.SecurityEvent{
		{
			SiteID:          siteItem.ID,
			RequestID:       "tls-match",
			ClientIP:        "198.51.100.20",
			Host:            siteItem.Host,
			Path:            "/match",
			Action:          "intercept",
			Phase:           "owasp_default",
			Category:        "sqli",
			TLSVersion:      "TLS13",
			TLSSNI:          "checkout.security-tls.example",
			TLSALPN:         "h2",
			TLSJA3Hash:      "ja3-security-event",
			TLSJA4:          "ja4-security-event",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			HeaderOrder:     "Host,User-Agent,Accept",
		},
		{
			SiteID:          siteItem.ID,
			RequestID:       "tls-other",
			ClientIP:        "198.51.100.20",
			Host:            siteItem.Host,
			Path:            "/other",
			Action:          "intercept",
			Phase:           "owasp_default",
			Category:        "sqli",
			TLSVersion:      "TLS12",
			TLSSNI:          "api.security-tls.example",
			TLSALPN:         "http/1.1",
			TLSJA3Hash:      "ja3-other",
			TLSJA4:          "ja4-other",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
			HeaderOrder:     "Host,Accept,User-Agent",
		},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		adminevent.ListSiteSecurityEvents(siteRepo, securityRepo),
		siteItem.ID,
		"/api/v1/sites/1/security-events",
		url.Values{
			"page":              {"1"},
			"page_size":         {"20"},
			"tls_version":       {"TLSv1.3"},
			"tls_sni":           {"checkout"},
			"tls_alpn":          {"h2"},
			"tls_ja3_hash":      {"ja3-security-event"},
			"tls_ja4":           {"ja4-security-event"},
			"tls_cipher_suites": {"AES_256_GCM_SHA384"},
			"tls_extensions":    {"16,43"},
			"tls_curves":        {"29,23"},
			"tls_point_formats": {"0"},
			"header_order":      {"User-Agent,Accept"},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected one TLS-filtered event, got total=%d items=%#v", resp.Total, resp.Items)
	}
	if resp.Items[0].RequestID != "tls-match" || resp.Items[0].TLSExtensions != "0,16,43" || resp.Items[0].TLSCurves != "29,23" || resp.Items[0].TLSPointFormats != "0" {
		t.Fatalf("unexpected event item %#v", resp.Items[0])
	}
}

func TestListSiteAccessLogsFiltersByTLSFields(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.AccessLog{}); err != nil {
		t.Fatalf("migrate access log tables: %v", err)
	}
	siteRepo := repository.NewSiteRepo(db)
	accessRepo := repository.NewAccessLogRepo(db)
	siteItem := &store.Site{
		Host:         "access-tls.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8443",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	logs := []store.AccessLog{
		{
			SiteID:          siteItem.ID,
			RequestID:       "tls-access-match",
			ClientIP:        "198.51.100.30",
			Host:            siteItem.Host,
			Path:            "/match",
			Method:          "GET",
			StatusCode:      403,
			TLSVersion:      "TLS13",
			TLSSNI:          "checkout.access-tls.example",
			TLSALPN:         "h2",
			TLSJA3Hash:      "ja3-site-access",
			TLSJA4:          "ja4-site-access",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
		},
		{
			SiteID:          siteItem.ID,
			RequestID:       "tls-access-other",
			ClientIP:        "198.51.100.30",
			Host:            siteItem.Host,
			Path:            "/other",
			Method:          "GET",
			StatusCode:      200,
			TLSVersion:      "TLS12",
			TLSSNI:          "api.access-tls.example",
			TLSALPN:         "http/1.1",
			TLSJA3Hash:      "ja3-other",
			TLSJA4:          "ja4-other",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
		},
	}
	if err := accessRepo.BatchCreate(logs); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		ListSiteAccessLogs(siteRepo, accessRepo),
		siteItem.ID,
		"/api/v1/sites/1/access-logs",
		url.Values{
			"page":              {"1"},
			"page_size":         {"20"},
			"tls_version":       {"0x0304"},
			"tls_sni":           {"checkout"},
			"tls_alpn":          {"h2"},
			"tls_ja3_hash":      {"ja3-site-access"},
			"tls_ja4":           {"ja4-site-access"},
			"tls_cipher_suites": {"AES_256_GCM_SHA384"},
			"tls_extensions":    {"16,43"},
			"tls_curves":        {"29,23"},
			"tls_point_formats": {"0"},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected one TLS-filtered access log, got total=%d items=%#v", resp.Total, resp.Items)
	}
	if resp.Items[0].RequestID != "tls-access-match" || resp.Items[0].TLSExtensions != "0,16,43" || resp.Items[0].TLSCurves != "29,23" || resp.Items[0].TLSPointFormats != "0" {
		t.Fatalf("unexpected access log item %#v", resp.Items[0])
	}
}

func TestListSiteAccessLogsFiltersByStaleCacheState(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.AccessLog{}); err != nil {
		t.Fatalf("migrate access log tables: %v", err)
	}
	siteRepo := repository.NewSiteRepo(db)
	accessRepo := repository.NewAccessLogRepo(db)
	siteItem := &store.Site{
		Host:         "access-cache-state.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8443",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	logs := []store.AccessLog{
		{
			SiteID:     siteItem.ID,
			RequestID:  "site-access-cache-stale-match",
			Host:       siteItem.Host,
			Path:       "/stale",
			Method:     "GET",
			StatusCode: 200,
			CacheState: "stale",
		},
		{
			SiteID:     siteItem.ID,
			RequestID:  "site-access-cache-hit-other",
			Host:       siteItem.Host,
			Path:       "/hit",
			Method:     "GET",
			StatusCode: 200,
			CacheState: "hit",
		},
		{
			SiteID:     siteItem.ID + 1,
			RequestID:  "other-site-cache-stale",
			Host:       "other.example",
			Path:       "/stale",
			Method:     "GET",
			StatusCode: 200,
			CacheState: "stale",
		},
	}
	if err := accessRepo.BatchCreate(logs); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		ListSiteAccessLogs(siteRepo, accessRepo),
		siteItem.ID,
		"/api/v1/sites/1/access-logs",
		url.Values{
			"page":        {"1"},
			"page_size":   {"20"},
			"cache_state": {"stale"},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected one stale cache-state access log, got total=%d items=%#v", resp.Total, resp.Items)
	}
	if resp.Items[0].RequestID != "site-access-cache-stale-match" || resp.Items[0].CacheState != "stale" || resp.Items[0].SiteID != siteItem.ID {
		t.Fatalf("unexpected stale cache-state site access log: %#v", resp.Items[0])
	}
}

func TestSiteAccessLogStatsIncludesCacheStates(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.AccessLog{}); err != nil {
		t.Fatalf("migrate access log tables: %v", err)
	}
	siteRepo := repository.NewSiteRepo(db)
	accessRepo := repository.NewAccessLogRepo(db)
	siteItem := &store.Site{
		Host:         "access-stats-cache-state.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8443",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	now := time.Now()
	logs := []store.AccessLog{
		{SiteID: siteItem.ID, RequestID: "stats-hit", Method: "GET", StatusCode: 200, CacheState: "hit", CreatedAt: now},
		{SiteID: siteItem.ID, RequestID: "stats-miss", Method: "GET", StatusCode: 200, CacheState: "miss", CreatedAt: now},
		{SiteID: siteItem.ID, RequestID: "stats-bypass", Method: "GET", StatusCode: 206, CacheState: "bypass", CreatedAt: now},
		{SiteID: siteItem.ID, RequestID: "stats-stale", Method: "GET", StatusCode: 200, CacheState: "stale", CreatedAt: now},
		{SiteID: siteItem.ID, RequestID: "stats-observe", Method: "GET", StatusCode: 200, WAFAction: "observe", CacheState: "hit", CreatedAt: now},
		{SiteID: siteItem.ID, RequestID: "stats-intercept", Method: "GET", StatusCode: 403, WAFAction: "intercept", CacheState: "bypass", CreatedAt: now},
		{SiteID: siteItem.ID + 1, RequestID: "other-stale", Method: "GET", StatusCode: 200, CacheState: "stale", CreatedAt: now},
	}
	if err := accessRepo.BatchCreate(logs); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		SiteAccessLogStats(siteRepo, accessRepo),
		siteItem.ID,
		"/api/v1/sites/1/access-logs/stats",
		url.Values{"hours": {"24"}},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp repository.SiteAccessLogStats
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Requests != 6 || resp.Intercepts != 1 || resp.Observes != 1 {
		t.Fatalf("unexpected request/action stats: %#v", resp)
	}
	if resp.CacheHits != 2 || resp.CacheMisses != 1 || resp.CacheBypasses != 2 || resp.CacheStales != 1 {
		t.Fatalf("unexpected cache state stats: %#v", resp)
	}
}

func TestListSiteSecurityEventsFiltersByQueryString(t *testing.T) {
	siteRepo, _, securityRepo, db := newSiteObservabilityReposForTest(t)
	siteItem := &store.Site{
		Host:         "security-query.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	events := []store.SecurityEvent{
		{
			SiteID:      siteItem.ID,
			RequestID:   "site-security-query-match",
			ClientIP:    "198.51.100.40",
			Host:        siteItem.Host,
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			Action:      "intercept",
			Phase:       "custom",
			Category:    "sqli",
		},
		{
			SiteID:      siteItem.ID,
			RequestID:   "site-security-query-other",
			ClientIP:    "198.51.100.40",
			Host:        siteItem.Host,
			Path:        "/login",
			QueryString: "redirect=%2Fdocs&token=basic",
			Action:      "intercept",
			Phase:       "custom",
			Category:    "sqli",
		},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		adminevent.ListSiteSecurityEvents(siteRepo, securityRepo),
		siteItem.ID,
		"/api/v1/sites/1/security-events",
		url.Values{
			"page":         {"1"},
			"page_size":    {"20"},
			"query_string": {"token=vip"},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].RequestID != "site-security-query-match" {
		t.Fatalf("expected one query_string-filtered security event, got total=%d items=%#v", resp.Total, resp.Items)
	}
}

func TestListSiteAccessLogsFiltersByQueryString(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.AccessLog{}); err != nil {
		t.Fatalf("migrate access log tables: %v", err)
	}
	siteRepo := repository.NewSiteRepo(db)
	accessRepo := repository.NewAccessLogRepo(db)
	siteItem := &store.Site{
		Host:         "access-query.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	logs := []store.AccessLog{
		{
			SiteID:      siteItem.ID,
			RequestID:   "site-access-query-match",
			ClientIP:    "198.51.100.50",
			Host:        siteItem.Host,
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			Method:      "GET",
			StatusCode:  200,
		},
		{
			SiteID:      siteItem.ID,
			RequestID:   "site-access-query-other",
			ClientIP:    "198.51.100.50",
			Host:        siteItem.Host,
			Path:        "/login",
			QueryString: "redirect=%2Fdocs&token=basic",
			Method:      "GET",
			StatusCode:  200,
		},
	}
	if err := accessRepo.BatchCreate(logs); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		ListSiteAccessLogs(siteRepo, accessRepo),
		siteItem.ID,
		"/api/v1/sites/1/access-logs",
		url.Values{
			"page":         {"1"},
			"page_size":    {"20"},
			"query_string": {"token=vip"},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].RequestID != "site-access-query-match" {
		t.Fatalf("expected one query_string-filtered access log, got total=%d items=%#v", resp.Total, resp.Items)
	}
}

func TestListSiteAccessLogsFiltersByUnifiedQuery(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.AccessLog{}); err != nil {
		t.Fatalf("migrate access log tables: %v", err)
	}
	siteRepo := repository.NewSiteRepo(db)
	accessRepo := repository.NewAccessLogRepo(db)
	siteItem := &store.Site{
		Host:         "site-access-q.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	logs := []store.AccessLog{
		{
			SiteID:      siteItem.ID,
			RequestID:   "site-access-q-match",
			ClientIP:    "198.51.100.60",
			Host:        siteItem.Host,
			Path:        "/console",
			QueryString: "token=vip",
			Method:      "GET",
			StatusCode:  200,
			TLSSNI:      "console.site-access-q.example",
			TLSJA3Hash:  "ja3-site-access-q",
			TLSJA4:      "ja4-site-access-q",
		},
		{
			SiteID:      siteItem.ID,
			RequestID:   "site-access-q-other",
			ClientIP:    "198.51.100.61",
			Host:        siteItem.Host,
			Path:        "/docs",
			QueryString: "token=basic",
			Method:      "GET",
			StatusCode:  200,
			TLSSNI:      "docs.site-access-q.example",
			TLSJA3Hash:  "ja3-site-access-other",
			TLSJA4:      "ja4-site-access-other",
		},
	}
	if err := accessRepo.BatchCreate(logs); err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		ListSiteAccessLogs(siteRepo, accessRepo),
		siteItem.ID,
		"/api/v1/sites/1/access-logs",
		url.Values{
			"page":      {"1"},
			"page_size": {"20"},
			"q":         {"ja3-site-access-q"},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.AccessLog `json:"items"`
		Total int64             `json:"total"`
		Page  int               `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].RequestID != "site-access-q-match" {
		t.Fatalf("expected one unified-query access log, got total=%d items=%#v", resp.Total, resp.Items)
	}
}

func TestListSiteSecurityEventsFiltersByUnifiedQuery(t *testing.T) {
	siteRepo, _, securityRepo, db := newSiteObservabilityReposForTest(t)
	siteItem := &store.Site{
		Host:         "site-security-q.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(siteItem); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	events := []store.SecurityEvent{
		{
			SiteID:      siteItem.ID,
			RequestID:   "site-security-q-match",
			ClientIP:    "198.51.100.70",
			Host:        siteItem.Host,
			Path:        "/login",
			QueryString: "token=vip",
			Action:      "intercept",
			Phase:       "custom",
			Category:    "sqli",
			RuleIDStr:   "RULE-900001",
			TLSSNI:      "login.site-security-q.example",
			TLSJA3Hash:  "ja3-site-security-q",
			TLSJA4:      "ja4-site-security-q",
			HeaderOrder: "Host,User-Agent,Accept",
		},
		{
			SiteID:      siteItem.ID,
			RequestID:   "site-security-q-other",
			ClientIP:    "198.51.100.71",
			Host:        siteItem.Host,
			Path:        "/docs",
			QueryString: "token=basic",
			Action:      "intercept",
			Phase:       "custom",
			Category:    "sqli",
			RuleIDStr:   "RULE-100001",
			TLSSNI:      "docs.site-security-q.example",
			TLSJA3Hash:  "ja3-site-security-other",
			TLSJA4:      "ja4-site-security-other",
			HeaderOrder: "Host,Accept,User-Agent",
		},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatalf("seed security events: %v", err)
	}

	ctx := invokeSiteGetHandler(
		t,
		adminevent.ListSiteSecurityEvents(siteRepo, securityRepo),
		siteItem.ID,
		"/api/v1/sites/1/security-events",
		url.Values{
			"page":      {"1"},
			"page_size": {"20"},
			"q":         {"RULE-900001"},
		},
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Items []store.SecurityEvent `json:"items"`
		Total int64                 `json:"total"`
		Page  int                   `json:"page"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].RequestID != "site-security-q-match" {
		t.Fatalf("expected one unified-query security event, got total=%d items=%#v", resp.Total, resp.Items)
	}
}
