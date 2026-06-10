package repository

import (
	"testing"
	"time"

	"My-OpenWaf/internal/store"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}, &store.SecurityEvent{}, &store.BotScoreLog{}, &store.Rule{}, &store.Site{}, &store.SiteListener{}); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	return db
}

func TestAccessLogRepoListStatusGroup(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	items := []store.AccessLog{
		{SiteID: 1, Host: "example.com", Path: "/ok", Method: "GET", StatusCode: 200},
		{SiteID: 1, Host: "example.com", Path: "/missing", Method: "GET", StatusCode: 404},
		{SiteID: 1, Host: "example.com", Path: "/bad", Method: "GET", StatusCode: 502},
		{SiteID: 1, Host: "api.example.com", Path: "/api/missing", Method: "GET", StatusCode: 404},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	got, total, err := repo.List(0, 20, AccessLogFilter{StatusGroup: "4xx", Host: "example.com", Path: "missing"})
	if err != nil {
		t.Fatalf("list logs: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("4xx host/path filter returned total=%d items=%v", total, got)
	}
	if accessLogCountCacheKey(AccessLogFilter{Host: "example.com"}) == accessLogCountCacheKey(AccessLogFilter{Host: "api.example.com"}) {
		t.Fatal("host filters must not share count cache keys")
	}
	if accessLogCountCacheKey(AccessLogFilter{Path: "/a"}) == accessLogCountCacheKey(AccessLogFilter{Path: "/b"}) {
		t.Fatal("path filters must not share count cache keys")
	}
}

func TestAccessLogRepoListTLSFilters(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	items := []store.AccessLog{
		{
			SiteID:     1,
			Host:       "example.com",
			Path:       "/checkout",
			Method:     "GET",
			StatusCode: 403,
			TLSVersion: "TLS13",
			TLSSNI:     "checkout.example.com",
			TLSALPN:    "h2",
			TLSJA3Hash: "ja3-checkout",
			TLSJA4:     "ja4-checkout",
		},
		{
			SiteID:     1,
			Host:       "example.com",
			Path:       "/api",
			Method:     "GET",
			StatusCode: 200,
			TLSVersion: "TLS12",
			TLSSNI:     "api.example.com",
			TLSALPN:    "http/1.1",
			TLSJA3Hash: "ja3-api",
			TLSJA4:     "ja4-api",
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	got, total, err := repo.List(0, 20, AccessLogFilter{
		TLSVersion: "TLS13",
		TLSSNI:     "checkout",
		TLSALPN:    "h2",
		TLSJA3Hash: "ja3-checkout",
		TLSJA4:     "ja4-checkout",
	})
	if err != nil {
		t.Fatalf("list logs: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].TLSSNI != "checkout.example.com" {
		t.Fatalf("TLS filters returned total=%d items=%#v", total, got)
	}
	if accessLogCountCacheKey(AccessLogFilter{TLSSNI: "checkout"}) == accessLogCountCacheKey(AccessLogFilter{TLSSNI: "api"}) {
		t.Fatal("tls_sni filters must not share access log count cache keys")
	}
	if accessLogCountCacheKey(AccessLogFilter{TLSJA3Hash: "ja3-checkout"}) == accessLogCountCacheKey(AccessLogFilter{TLSJA3Hash: "ja3-api"}) {
		t.Fatal("tls_ja3_hash filters must not share access log count cache keys")
	}
	if accessLogCountCacheKey(AccessLogFilter{TLSJA4: "ja4-checkout"}) == accessLogCountCacheKey(AccessLogFilter{TLSJA4: "ja4-api"}) {
		t.Fatal("tls_ja4 filters must not share access log count cache keys")
	}
}

func TestAccessLogRepoListFingerprintsSQLite(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	now := time.Now()
	items := []store.AccessLog{
		{SiteID: 1, Host: "example.com", TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", CreatedAt: now.Add(-time.Minute)},
		{SiteID: 1, Host: "example.com", TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", CreatedAt: now},
		{SiteID: 1, Host: "example.com", TLSJA3Hash: "bbb", TLSJA4: "ja4-b", TLSVersion: "TLS12", TLSALPN: "http/1.1", TLSSNI: "example.com", CreatedAt: now},
		{SiteID: 1, Host: "example.com", CreatedAt: now},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}
	if err := db.Create(&store.BotScoreLog{TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", TotalScore: 80, IsHighRisk: true, CreatedAt: now}).Error; err != nil {
		t.Fatalf("create matching bot score log: %v", err)
	}
	if err := db.Create(&store.BotScoreLog{TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "other.example.com", TotalScore: 20, IsHighRisk: true, CreatedAt: now}).Error; err != nil {
		t.Fatalf("create other sni bot score log: %v", err)
	}

	got, total, err := repo.ListFingerprints(0, 20)
	if err != nil {
		t.Fatalf("list fingerprints: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("expected two fingerprint groups, total=%d items=%v", total, got)
	}
	if got[0].Count != 2 || got[0].TLSJA3Hash != "aaa" {
		t.Fatalf("expected newest aggregate first, got %#v", got[0])
	}
	if got[0].HighRiskCount != 1 || got[0].AvgBotScore != 80 {
		t.Fatalf("expected bot score aggregation to stay scoped by tls_sni, got %#v", got[0])
	}
}

func TestSecurityEventRepoListHostAndPathFilters(t *testing.T) {
	db := newTestDB(t)
	repo := NewSecurityEventRepo(db)
	items := []store.SecurityEvent{
		{SiteID: 1, Host: "example.com", Path: "/admin", Action: "intercept", Category: "sqli"},
		{SiteID: 1, Host: "api.example.com", Path: "/v1/admin", Action: "intercept", Category: "xss"},
		{SiteID: 1, Host: "other.test", Path: "/admin", Action: "intercept", Category: "sqli"},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create security events: %v", err)
	}

	got, total, err := repo.List(0, 20, SecurityEventFilter{Host: "example.com", Path: "admin"})
	if err != nil {
		t.Fatalf("list security events: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("host/path filter returned total=%d items=%v", total, got)
	}
	if secEventCountCacheKey(SecurityEventFilter{Host: "example.com"}) == secEventCountCacheKey(SecurityEventFilter{Host: "api.example.com"}) {
		t.Fatal("host filters must not share security event count cache keys")
	}
	if secEventCountCacheKey(SecurityEventFilter{Path: "/a"}) == secEventCountCacheKey(SecurityEventFilter{Path: "/b"}) {
		t.Fatal("path filters must not share security event count cache keys")
	}
}

func TestSecurityEventRepoListTLSFilters(t *testing.T) {
	db := newTestDB(t)
	repo := NewSecurityEventRepo(db)
	items := []store.SecurityEvent{
		{
			SiteID:      1,
			Host:        "example.com",
			Path:        "/blocked",
			Action:      "intercept",
			TLSVersion:  "TLS13",
			TLSSNI:      "checkout.example.com",
			TLSALPN:     "h2",
			TLSJA3Hash:  "ja3-checkout",
			TLSJA4:      "ja4-checkout",
			HeaderOrder: "Host,User-Agent,Accept",
		},
		{
			SiteID:      1,
			Host:        "example.com",
			Path:        "/blocked",
			Action:      "intercept",
			TLSVersion:  "TLS12",
			TLSSNI:      "api.example.com",
			TLSALPN:     "http/1.1",
			TLSJA3Hash:  "ja3-api",
			TLSJA4:      "ja4-api",
			HeaderOrder: "Host,Accept,User-Agent",
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create security events: %v", err)
	}

	got, total, err := repo.List(0, 20, SecurityEventFilter{
		TLSVersion:  "TLS13",
		TLSSNI:      "checkout",
		TLSALPN:     "h2",
		TLSJA3Hash:  "ja3-checkout",
		TLSJA4:      "ja4-checkout",
		HeaderOrder: "User-Agent,Accept",
	})
	if err != nil {
		t.Fatalf("list security events: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].TLSSNI != "checkout.example.com" {
		t.Fatalf("TLS filters returned total=%d items=%#v", total, got)
	}
	if secEventCountCacheKey(SecurityEventFilter{TLSSNI: "checkout"}) == secEventCountCacheKey(SecurityEventFilter{TLSSNI: "api"}) {
		t.Fatal("tls_sni filters must not share security event count cache keys")
	}
	if secEventCountCacheKey(SecurityEventFilter{TLSJA3Hash: "ja3-checkout"}) == secEventCountCacheKey(SecurityEventFilter{TLSJA3Hash: "ja3-api"}) {
		t.Fatal("tls_ja3_hash filters must not share security event count cache keys")
	}
	if secEventCountCacheKey(SecurityEventFilter{TLSJA4: "ja4-checkout"}) == secEventCountCacheKey(SecurityEventFilter{TLSJA4: "ja4-api"}) {
		t.Fatal("tls_ja4 filters must not share security event count cache keys")
	}
}

func TestRuleRepoBatchCreateRollsBackOnError(t *testing.T) {
	db := newTestDB(t)
	repo := NewRuleRepo(db)
	err := repo.BatchCreate([]store.Rule{
		{ID: 7, Name: "ok", PolicyID: 1, Phase: store.PhaseACL, Pattern: "block_path:/admin", Action: store.ActionIntercept},
		{ID: 7, Name: "duplicate", PolicyID: 1, Phase: store.PhaseACL, Pattern: "block_path:/admin", Action: store.ActionIntercept},
	})
	if err == nil {
		t.Fatal("expected batch create error")
	}

	items, total, err := repo.List(0, 20)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("batch create should rollback all rules, total=%d items=%v", total, items)
	}
}

func TestRuleRepoListFilteredPolicyAndQuery(t *testing.T) {
	db := newTestDB(t)
	repo := NewRuleRepo(db)
	items := []store.Rule{
		{Name: "admin block", PolicyID: 1, Phase: store.PhaseACL, Pattern: "block_path:/admin", Action: store.ActionIntercept, Priority: 20},
		{Name: "api observe", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "block_path:/api", Action: store.ActionObserve, Priority: 30},
		{Name: "admin other policy", PolicyID: 2, Phase: store.PhaseACL, Pattern: "block_path:/admin", Action: store.ActionIntercept, Priority: 10},
	}
	for i := range items {
		if err := repo.Create(&items[i]); err != nil {
			t.Fatalf("create rule: %v", err)
		}
	}

	policyID := uint(1)
	got, total, err := repo.ListFiltered(0, 20, RuleFilter{PolicyID: &policyID, Query: "admin"})
	if err != nil {
		t.Fatalf("list filtered rules: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].PolicyID != policyID || got[0].Name != "admin block" {
		t.Fatalf("unexpected filtered rules total=%d items=%+v", total, got)
	}
}

func TestSiteListenerRepoDeleteBySite(t *testing.T) {
	db := newTestDB(t)
	repo := NewSiteListenerRepo(db)
	items := []store.SiteListener{
		{SiteID: 1, Bind: ":80", Network: "tcp", Enabled: true},
		{SiteID: 1, Bind: ":443", Network: "tcp", Enabled: true},
		{SiteID: 2, Bind: ":8080", Network: "tcp", Enabled: true},
	}
	for i := range items {
		if err := repo.Create(&items[i]); err != nil {
			t.Fatalf("create listener: %v", err)
		}
	}

	if err := repo.DeleteBySite(1); err != nil {
		t.Fatalf("delete listeners by site: %v", err)
	}
	deleted, err := repo.ListBySite(1)
	if err != nil {
		t.Fatalf("list deleted site listeners: %v", err)
	}
	kept, err := repo.ListBySite(2)
	if err != nil {
		t.Fatalf("list kept site listeners: %v", err)
	}
	if len(deleted) != 0 || len(kept) != 1 || kept[0].Bind != ":8080" {
		t.Fatalf("unexpected listeners after DeleteBySite, deleted=%v kept=%v", deleted, kept)
	}
}

func TestSiteRepoCountByCertID(t *testing.T) {
	db := newTestDB(t)
	repo := NewSiteRepo(db)
	certID := uint(7)
	otherCertID := uint(8)
	sites := []store.Site{
		{Host: "a.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":443", Network: "tcp", Enabled: true, CertID: &certID},
		{Host: "b.example", UpstreamURLs: "http://127.0.0.1:8081", Bind: ":8443", Network: "tcp", Enabled: true, CertID: &certID},
		{Host: "c.example", UpstreamURLs: "http://127.0.0.1:8082", Bind: ":9443", Network: "tcp", Enabled: true, CertID: &otherCertID},
	}
	for i := range sites {
		if err := repo.Create(&sites[i]); err != nil {
			t.Fatalf("create site: %v", err)
		}
	}

	count, err := repo.CountByCertID(certID)
	if err != nil {
		t.Fatalf("count sites by cert: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 site refs, got %d", count)
	}
}

func TestSiteRepoCountByPolicyID(t *testing.T) {
	db := newTestDB(t)
	repo := NewSiteRepo(db)
	policyID := uint(3)
	otherPolicyID := uint(4)
	sites := []store.Site{
		{Host: "a.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":80", Network: "tcp", Enabled: true, PolicyID: &policyID},
		{Host: "b.example", UpstreamURLs: "http://127.0.0.1:8081", Bind: ":81", Network: "tcp", Enabled: true, PolicyID: &policyID},
		{Host: "c.example", UpstreamURLs: "http://127.0.0.1:8082", Bind: ":82", Network: "tcp", Enabled: true, PolicyID: &otherPolicyID},
	}
	for i := range sites {
		if err := repo.Create(&sites[i]); err != nil {
			t.Fatalf("create site: %v", err)
		}
	}

	count, err := repo.CountByPolicyID(policyID)
	if err != nil {
		t.Fatalf("count sites by policy: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 policy refs, got %d", count)
	}
}

func TestSiteListenerRepoCountByCertID(t *testing.T) {
	db := newTestDB(t)
	repo := NewSiteListenerRepo(db)
	certID := uint(7)
	otherCertID := uint(8)
	items := []store.SiteListener{
		{SiteID: 1, Bind: ":443", Network: "tcp", Enabled: true, CertID: &certID},
		{SiteID: 2, Bind: ":8443", Network: "tcp", Enabled: true, CertID: &certID},
		{SiteID: 3, Bind: ":9443", Network: "tcp", Enabled: true, CertID: &otherCertID},
	}
	for i := range items {
		if err := repo.Create(&items[i]); err != nil {
			t.Fatalf("create listener: %v", err)
		}
	}

	count, err := repo.CountByCertID(certID)
	if err != nil {
		t.Fatalf("count listeners by cert: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 listener refs, got %d", count)
	}
}

func TestSiteRepoDeleteWithListenersDeletesAtomically(t *testing.T) {
	db := newTestDB(t)
	siteRepo := NewSiteRepo(db)
	listenerRepo := NewSiteListenerRepo(db)
	site := store.Site{Host: "example.com", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":80", Network: "tcp", Enabled: true}
	if err := siteRepo.Create(&site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	if err := listenerRepo.Create(&store.SiteListener{SiteID: site.ID, Bind: ":80", Network: "tcp", Enabled: true}); err != nil {
		t.Fatalf("create listener: %v", err)
	}

	if err := siteRepo.DeleteWithListeners(site.ID); err != nil {
		t.Fatalf("delete site with listeners: %v", err)
	}
	if _, err := siteRepo.Get(site.ID); err == nil {
		t.Fatal("site should be deleted")
	}
	listeners, err := listenerRepo.ListBySite(site.ID)
	if err != nil {
		t.Fatalf("list listeners after site delete: %v", err)
	}
	if len(listeners) != 0 {
		t.Fatalf("listeners should be deleted with site, got %v", listeners)
	}
}

func TestSiteListenerRepoCreateWithLegacyPromotion(t *testing.T) {
	db := newTestDB(t)
	repo := NewSiteListenerRepo(db)
	legacy := &store.SiteListener{SiteID: 1, Bind: ":80", Network: "tcp", Enabled: true, Note: "migrated from legacy bind"}
	item := &store.SiteListener{SiteID: 1, Bind: ":443", Network: "tcp", Enabled: true}

	if err := repo.CreateWithLegacyPromotion(item, legacy); err != nil {
		t.Fatalf("create with legacy promotion: %v", err)
	}
	listeners, err := repo.ListBySite(1)
	if err != nil {
		t.Fatalf("list listeners: %v", err)
	}
	if len(listeners) != 2 || listeners[0].Bind != ":443" || listeners[1].Bind != ":80" {
		t.Fatalf("expected promoted legacy and new listener, got %v", listeners)
	}
}
