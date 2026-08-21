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

func TestAccessLogCountCacheKeyPreservesNanosecondRangeAndInstant(t *testing.T) {
	instant := time.Date(2026, time.August, 16, 12, 30, 45, 123456789, time.UTC)
	nextNanosecond := instant.Add(time.Nanosecond)

	sinceKey := accessLogCountCacheKey(AccessLogFilter{Since: &instant})
	if sinceKey == accessLogCountCacheKey(AccessLogFilter{Since: &nextNanosecond}) {
		t.Fatal("same-second filters with different Since nanoseconds must not share count cache keys")
	}

	untilKey := accessLogCountCacheKey(AccessLogFilter{Until: &instant})
	if untilKey == accessLogCountCacheKey(AccessLogFilter{Until: &nextNanosecond}) {
		t.Fatal("same-second filters with different Until nanoseconds must not share count cache keys")
	}

	inUTCPlusEight := instant.In(time.FixedZone("UTC+8", 8*60*60))
	if sinceKey != accessLogCountCacheKey(AccessLogFilter{Since: &inUTCPlusEight}) {
		t.Fatal("identical Since instants in different time zones must share count cache keys")
	}
	if untilKey != accessLogCountCacheKey(AccessLogFilter{Until: &inUTCPlusEight}) {
		t.Fatal("identical Until instants in different time zones must share count cache keys")
	}

	timestamp := instant.UTC().Format(time.RFC3339Nano)
	if accessLogCountCacheKey(AccessLogFilter{Host: "x:si" + timestamp}) == accessLogCountCacheKey(AccessLogFilter{Host: "x", Since: &instant}) {
		t.Fatal("host values must not collide with time filter fields")
	}
	if accessLogCountCacheKey(AccessLogFilter{Host: "x:p/foo"}) == accessLogCountCacheKey(AccessLogFilter{Host: "x", Path: "/foo"}) {
		t.Fatal("length-delimited fields must not collide with adjacent fields")
	}
}

func TestAccessLogRepoStatsBySiteIncludesCacheStates(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	now := time.Now()
	items := []store.AccessLog{
		{SiteID: 1, Host: "example.com", Path: "/hit", Method: "GET", StatusCode: 200, CacheState: "hit", CreatedAt: now},
		{SiteID: 1, Host: "example.com", Path: "/miss", Method: "GET", StatusCode: 200, CacheState: "miss", CreatedAt: now},
		{SiteID: 1, Host: "example.com", Path: "/bypass", Method: "GET", StatusCode: 206, CacheState: "bypass", CreatedAt: now},
		{SiteID: 1, Host: "example.com", Path: "/stale", Method: "GET", StatusCode: 200, CacheState: "stale", CreatedAt: now},
		{SiteID: 1, Host: "example.com", Path: "/observe", Method: "GET", StatusCode: 200, WAFAction: "observe", CacheState: "hit", CreatedAt: now},
		{SiteID: 1, Host: "example.com", Path: "/block", Method: "GET", StatusCode: 403, WAFAction: "intercept", CacheState: "bypass", CreatedAt: now},
		{SiteID: 2, Host: "other.example", Path: "/stale", Method: "GET", StatusCode: 200, CacheState: "stale", CreatedAt: now},
		{SiteID: 1, Host: "example.com", Path: "/old-stale", Method: "GET", StatusCode: 200, CacheState: "stale", CreatedAt: now.Add(-48 * time.Hour)},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	stats, err := repo.StatsBySite(1, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("stats by site: %v", err)
	}
	if stats.Requests != 6 || stats.Intercepts != 1 || stats.Observes != 1 {
		t.Fatalf("unexpected request/action stats: %#v", stats)
	}
	if stats.CacheHits != 2 || stats.CacheMisses != 1 || stats.CacheBypasses != 2 || stats.CacheStales != 1 {
		t.Fatalf("unexpected cache state stats: %#v", stats)
	}
}

// TestAccessLogRepoVisitorKindStatsDistinctRequestIDCounts 验证人工/机器访问聚合：
// human = 窗口内 AccessLog 中无 BotScoreLog 关联的 request_id；bot = 窗口内
// BotScoreLog 唯一 request_id。同 request_id 多条 AccessLog 只算一次；空
// request_id 不计入；外站/超窗请求不计入；BotScoreLog 在 LogDB 共享同一 SQLite，
// BotScoreLog.request_id 关联到 AccessLog.request_id 上时必须可见。
func TestAccessLogRepoVisitorKindStatsDistinctRequestIDCounts(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	now := time.Now()
	since := now.Add(-time.Hour)

	// 窗口内：3 条 human（无 BotScoreLog）、2 条 bot（有 BotScoreLog）。
	// 同 request_id="req-bot-1" 在 AccessLog 中出现两次，但 bot 计数只看 BotScoreLog 唯一性。
	// 故意加 request_id="" 的 AccessLog 应不计入 human。
	logs := []store.AccessLog{
		{SiteID: 1, RequestID: "req-human-1", Host: "example.com", Path: "/a", Method: "GET", StatusCode: 200, CreatedAt: now},
		{SiteID: 1, RequestID: "req-human-2", Host: "example.com", Path: "/b", Method: "GET", StatusCode: 200, CreatedAt: now},
		{SiteID: 1, RequestID: "req-human-3", Host: "example.com", Path: "/c", Method: "GET", StatusCode: 200, CreatedAt: now},
		// bot-1 出现两次（同一 request 多次记录日志）
		{SiteID: 1, RequestID: "req-bot-1", Host: "example.com", Path: "/x", Method: "GET", StatusCode: 200, CreatedAt: now},
		{SiteID: 1, RequestID: "req-bot-1", Host: "example.com", Path: "/x", Method: "GET", StatusCode: 200, CreatedAt: now},
		{SiteID: 1, RequestID: "req-bot-2", Host: "example.com", Path: "/y", Method: "GET", StatusCode: 200, CreatedAt: now},
		// 空 request_id——必须不计入
		{SiteID: 1, RequestID: "", Host: "example.com", Path: "/z", Method: "GET", StatusCode: 200, CreatedAt: now},
		// 外站
		{SiteID: 2, RequestID: "req-other-site-human", Host: "other.example", Path: "/q", Method: "GET", StatusCode: 200, CreatedAt: now},
		// 超窗：48 小时前——必须不计入
		{SiteID: 1, RequestID: "req-old-bot", Host: "example.com", Path: "/old", Method: "GET", StatusCode: 200, CreatedAt: now.Add(-48 * time.Hour)},
		// 口径二：终止类 waf_action 且无 BotScoreLog 关联——必须落入 UnclassifiedIntercept
		// 而不是 human（模拟 OWASP/CVE/ACL 短路拦截，未进入 BotDetection）
		{SiteID: 1, RequestID: "req-owasp-block", Host: "example.com", Path: "/sqli", Method: "GET", StatusCode: 403, WAFAction: "intercept", CreatedAt: now},
		{SiteID: 1, RequestID: "req-acl-drop", Host: "example.com", Path: "/bad", Method: "GET", StatusCode: 0, WAFAction: "drop", CreatedAt: now},
		// 边界：既有 BotScoreLog 关联又是终止类 action——优先级须归 bot，不得双计
		{SiteID: 1, RequestID: "req-bot-terminal", Host: "example.com", Path: "/w", Method: "GET", StatusCode: 403, WAFAction: "intercept", CreatedAt: now},
		// 其他非安全类：既不计入 human 也不计入拦截，仅体现在 TotalVisits 差额
		{SiteID: 1, RequestID: "req-maintenance", Host: "example.com", Path: "/m", Method: "GET", StatusCode: 503, WAFAction: "maintenance", CreatedAt: now},
		// 质询通过：真实浏览器解出质询，须归 human
		{SiteID: 1, RequestID: "req-challenge-passed", Host: "example.com", Path: "/cp", Method: "GET", StatusCode: 302, WAFAction: "challenge_passed", CreatedAt: now},
	}
	if err := repo.BatchCreate(logs); err != nil {
		t.Fatalf("batch create access logs: %v", err)
	}

	// BotScoreLog：bot-1、bot-2 关联；req-old-bot 在窗口外；空 request_id 不计入
	bot := []store.BotScoreLog{
		{SiteID: 1, RequestID: "req-bot-1", Host: "example.com", Path: "/x", UserAgent: "ua", TotalScore: 90, IsHighRisk: true, Action: "drop", CreatedAt: now},
		{SiteID: 1, RequestID: "req-bot-2", Host: "example.com", Path: "/y", UserAgent: "ua", TotalScore: 70, IsHighRisk: true, Action: "challenge", CreatedAt: now},
		// 窗口外——必须不计入
		{SiteID: 1, RequestID: "req-old-bot", Host: "example.com", Path: "/old", UserAgent: "ua", TotalScore: 80, IsHighRisk: true, Action: "drop", CreatedAt: now.Add(-48 * time.Hour)},
		// 空 request_id——必须不计入（防御性）
		{SiteID: 1, RequestID: "", Host: "example.com", Path: "/z", UserAgent: "ua", TotalScore: 90, IsHighRisk: true, Action: "drop", CreatedAt: now},
		// 边界：与终止类 waf_action 的 AccessLog 同 request_id，锁死 bot 优先级
		{SiteID: 1, RequestID: "req-bot-terminal", Host: "example.com", Path: "/w", UserAgent: "ua", TotalScore: 85, IsHighRisk: true, Action: "block", CreatedAt: now},
	}
	for i := range bot {
		if err := db.Create(&bot[i]).Error; err != nil {
			t.Fatalf("create bot score %d: %v", i, err)
		}
	}

	// 站点 1（口径二）：
	// human=4：req-human-1/2/3（waf_action 未设置，落 human 枚举）+ req-challenge-passed
	// bot=3：req-bot-1、req-bot-2、req-bot-terminal（唯一性去重）
	// 未判定拦截=2：req-owasp-block、req-acl-drop（终止类且无 bot 关联）
	// total=10；三类之和 9，差额 1 = req-maintenance（其他非安全类）
	site1, err := repo.VisitorKindStats(1, since)
	if err != nil {
		t.Fatalf("visitor kind stats site=1: %v", err)
	}
	if site1.HumanVisits != 4 {
		t.Fatalf("site1 human visits = %d, want 4 (raw=%+v)", site1.HumanVisits, site1)
	}
	if site1.BotVisits != 3 {
		t.Fatalf("site1 bot visits = %d, want 3 (raw=%+v)", site1.BotVisits, site1)
	}
	if site1.UnclassifiedIntercept != 2 {
		t.Fatalf("site1 unclassified intercept = %d, want 2 (raw=%+v)", site1.UnclassifiedIntercept, site1)
	}
	if site1.TotalVisits != 10 {
		t.Fatalf("site1 total visits = %d, want 10 (raw=%+v)", site1.TotalVisits, site1)
	}
	// 锁死优先级：req-bot-terminal 既有 BotScoreLog 又是 waf_action="intercept"，
	// 必须只计入 bot，不得同时计入未判定拦截（否则 3+2 会变成 3+3）。
	if site1.BotVisits+site1.UnclassifiedIntercept != 5 {
		t.Fatalf("bot+intercept = %d, want 5 (no double counting) (raw=%+v)", site1.BotVisits+site1.UnclassifiedIntercept, site1)
	}
	// 其他非安全类残差：maintenance 不得落入任何一类。
	if got := site1.TotalVisits - (site1.HumanVisits + site1.BotVisits + site1.UnclassifiedIntercept); got != 1 {
		t.Fatalf("site1 residual (other non-security) = %d, want 1 (raw=%+v)", got, site1)
	}

	// 全局：human=5（站点 1 的 4 + 站点 2 的 1）、bot=3、未判定拦截=2、total=11
	global, err := repo.VisitorKindStatsGlobal(since)
	if err != nil {
		t.Fatalf("visitor kind stats global: %v", err)
	}
	if global.HumanVisits != 5 {
		t.Fatalf("global human visits = %d, want 5 (raw=%+v)", global.HumanVisits, global)
	}
	if global.BotVisits != 3 {
		t.Fatalf("global bot visits = %d, want 3 (raw=%+v)", global.BotVisits, global)
	}
	if global.UnclassifiedIntercept != 2 {
		t.Fatalf("global unclassified intercept = %d, want 2 (raw=%+v)", global.UnclassifiedIntercept, global)
	}
	if global.TotalVisits != 11 {
		t.Fatalf("global total visits = %d, want 11 (raw=%+v)", global.TotalVisits, global)
	}

	// 站点 2：human=1（无 BotScoreLog）、bot=0、未判定拦截=0、total=1
	site2, err := repo.VisitorKindStats(2, since)
	if err != nil {
		t.Fatalf("visitor kind stats site=2: %v", err)
	}
	if site2.HumanVisits != 1 || site2.BotVisits != 0 {
		t.Fatalf("site2 stats = %+v, want human=1 bot=0", site2)
	}
	if site2.UnclassifiedIntercept != 0 || site2.TotalVisits != 1 {
		t.Fatalf("site2 stats = %+v, want intercept=0 total=1", site2)
	}
}

// TestAccessLogRepoVisitorKindStatsNoBotScoreTable 验证 BotScoreLog 表缺失时回退为全 human：
// 与 ListFingerprints 中的 hasBotScoreTable 回退一致（internal/store/repository/access_log.go:210,254）。
func TestAccessLogRepoVisitorKindStatsNoBotScoreTable(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := NewAccessLogRepo(db)
	now := time.Now()
	items := []store.AccessLog{
		{SiteID: 1, RequestID: "rid-1", Host: "x", Path: "/", Method: "GET", StatusCode: 200, CreatedAt: now},
		{SiteID: 1, RequestID: "rid-2", Host: "x", Path: "/", Method: "GET", StatusCode: 200, CreatedAt: now},
		// 缺表时 bot 恒为 0，但终止类 waf_action 仍须落入未判定拦截而非 human——
		// 这是口径二对「新部署全部误报为人工」的缓解点。
		{SiteID: 1, RequestID: "rid-blocked", Host: "x", Path: "/sqli", Method: "GET", StatusCode: 403, WAFAction: "intercept", CreatedAt: now},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create: %v", err)
	}

	stats, err := repo.VisitorKindStatsGlobal(now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.HumanVisits != 2 || stats.BotVisits != 0 {
		t.Fatalf("without bot_score_log table, want human=2 bot=0, got %+v", stats)
	}
	if stats.UnclassifiedIntercept != 1 {
		t.Fatalf("without bot_score_log table, want unclassified intercept=1, got %+v", stats)
	}
	if stats.TotalVisits != 3 {
		t.Fatalf("without bot_score_log table, want total=3, got %+v", stats)
	}
}

func TestAccessLogRepoListTLSFilters(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	items := []store.AccessLog{
		{
			SiteID:          1,
			Host:            "example.com",
			Path:            "/checkout",
			Method:          "GET",
			StatusCode:      403,
			TLSVersion:      "TLS13",
			TLSSNI:          "checkout.example.com",
			TLSALPN:         "h2",
			TLSJA3Hash:      "ja3-checkout",
			TLSJA4:          "ja4-checkout",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
		},
		{
			SiteID:          1,
			Host:            "example.com",
			Path:            "/api",
			Method:          "GET",
			StatusCode:      200,
			TLSVersion:      "TLS12",
			TLSSNI:          "api.example.com",
			TLSALPN:         "http/1.1",
			TLSJA3Hash:      "ja3-api",
			TLSJA4:          "ja4-api",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	got, total, err := repo.List(0, 20, AccessLogFilter{
		TLSVersion:      "1.3",
		TLSSNI:          "checkout",
		TLSALPN:         "h2",
		TLSJA3Hash:      "ja3-checkout",
		TLSJA4:          "ja4-checkout",
		TLSCipherSuites: "AES_256_GCM_SHA384",
		TLSExtensions:   "16,43",
		TLSCurves:       "29,23",
		TLSPointFormats: "0",
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
	if accessLogCountCacheKey(AccessLogFilter{TLSCipherSuites: "AES_256_GCM_SHA384"}) == accessLogCountCacheKey(AccessLogFilter{TLSCipherSuites: "AES_128_GCM_SHA256"}) {
		t.Fatal("tls_cipher_suites filters must not share access log count cache keys")
	}
	if accessLogCountCacheKey(AccessLogFilter{TLSExtensions: "16,43"}) == accessLogCountCacheKey(AccessLogFilter{TLSExtensions: "11,35"}) {
		t.Fatal("tls_extensions filters must not share access log count cache keys")
	}
	if accessLogCountCacheKey(AccessLogFilter{TLSCurves: "29,23"}) == accessLogCountCacheKey(AccessLogFilter{TLSCurves: "24,25"}) {
		t.Fatal("tls_curves filters must not share access log count cache keys")
	}
	if accessLogCountCacheKey(AccessLogFilter{TLSPointFormats: "0"}) == accessLogCountCacheKey(AccessLogFilter{TLSPointFormats: "1"}) {
		t.Fatal("tls_point_formats filters must not share access log count cache keys")
	}
	if accessLogCountCacheKey(AccessLogFilter{TLSVersion: "TLS13"}) != accessLogCountCacheKey(AccessLogFilter{TLSVersion: "1.3"}) {
		t.Fatal("tls_version aliases should share access log count cache keys")
	}
}

func TestAccessLogRepoListQueryStringFilter(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	items := []store.AccessLog{
		{
			SiteID:      1,
			RequestID:   "query-match",
			Host:        "example.com",
			Path:        "/search",
			QueryString: "user=alice&token=vip",
			Method:      "GET",
			StatusCode:  200,
		},
		{
			SiteID:      1,
			RequestID:   "query-other",
			Host:        "example.com",
			Path:        "/search",
			QueryString: "user=bob&token=basic",
			Method:      "GET",
			StatusCode:  200,
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	got, total, err := repo.List(0, 20, AccessLogFilter{QueryString: "token=vip"})
	if err != nil {
		t.Fatalf("list logs: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "query-match" {
		t.Fatalf("query_string filter returned total=%d items=%#v", total, got)
	}
	if accessLogCountCacheKey(AccessLogFilter{QueryString: "token=vip"}) == accessLogCountCacheKey(AccessLogFilter{QueryString: "token=basic"}) {
		t.Fatal("query_string filters must not share access log count cache keys")
	}
}

func TestAccessLogRepoListQueryMatchesAcrossFields(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	items := []store.AccessLog{
		{
			SiteID:          1,
			RequestID:       "req-alpha",
			ClientIP:        "10.0.0.1",
			Host:            "example.com",
			Path:            "/orders/view",
			QueryString:     "trace_id=abc123",
			TLSSNI:          "orders.example.com",
			TLSJA3Hash:      "ja3-orders",
			TLSJA4:          "ja4-orders",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			Method:          "GET",
			StatusCode:      200,
		},
		{
			SiteID:          1,
			RequestID:       "req-beta",
			ClientIP:        "10.0.0.2",
			Host:            "example.com",
			Path:            "/profile",
			QueryString:     "view=summary",
			TLSSNI:          "profile.example.com",
			TLSJA3Hash:      "ja3-profile",
			TLSJA4:          "ja4-profile",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
			Method:          "GET",
			StatusCode:      200,
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	got, total, err := repo.List(0, 20, AccessLogFilter{Query: "abc123"})
	if err != nil {
		t.Fatalf("list logs by query_string search: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "req-alpha" {
		t.Fatalf("query search by query_string returned total=%d items=%#v", total, got)
	}

	got, total, err = repo.List(0, 20, AccessLogFilter{Query: "ja4-profile"})
	if err != nil {
		t.Fatalf("list logs by tls_ja4 search: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "req-beta" {
		t.Fatalf("query search by tls_ja4 returned total=%d items=%#v", total, got)
	}

	got, total, err = repo.List(0, 20, AccessLogFilter{Query: "AES_256_GCM_SHA384"})
	if err != nil {
		t.Fatalf("list logs by tls_cipher_suites query: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "req-alpha" {
		t.Fatalf("query search by tls_cipher_suites returned total=%d items=%#v", total, got)
	}

	got, total, err = repo.List(0, 20, AccessLogFilter{Query: "16,43"})
	if err != nil {
		t.Fatalf("list logs by tls_extensions query: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "req-alpha" {
		t.Fatalf("query search by tls_extensions returned total=%d items=%#v", total, got)
	}

	if accessLogCountCacheKey(AccessLogFilter{Query: "abc123"}) == accessLogCountCacheKey(AccessLogFilter{Query: "ja4-profile"}) {
		t.Fatal("query filters must not share access log count cache keys")
	}
}

func TestAccessLogRepoListNormalizesLegacyHTTPProtocolFromTLSALPN(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	items := []store.AccessLog{
		{
			SiteID:       1,
			RequestID:    "legacy-h2",
			Host:         "example.com",
			Path:         "/h2",
			Method:       "GET",
			StatusCode:   200,
			HTTPProtocol: "https",
			TLSALPN:      "h2",
		},
		{
			SiteID:       1,
			RequestID:    "legacy-h1",
			Host:         "example.com",
			Path:         "/h1",
			Method:       "GET",
			StatusCode:   200,
			HTTPProtocol: "https",
			TLSALPN:      "",
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	got, total, err := repo.List(0, 20, AccessLogFilter{})
	if err != nil {
		t.Fatalf("list logs: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("unexpected total=%d items=%#v", total, got)
	}
	if got[0].RequestID != "legacy-h1" || got[0].HTTPProtocol != "http/1.1" {
		t.Fatalf("expected latest legacy https row to normalize to http/1.1, got %#v", got[0])
	}
	if got[1].RequestID != "legacy-h2" || got[1].HTTPProtocol != "h2" {
		t.Fatalf("expected TLS ALPN to normalize legacy https row to h2, got %#v", got[1])
	}
}

func TestAccessLogRepoListNormalizesHTTPVersionStrings(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	items := []store.AccessLog{
		{
			SiteID:       1,
			RequestID:    "http-2",
			Host:         "example.com",
			Path:         "/h2",
			Method:       "GET",
			StatusCode:   200,
			HTTPProtocol: "HTTP/2.0",
		},
		{
			SiteID:       1,
			RequestID:    "http-3",
			Host:         "example.com",
			Path:         "/h3",
			Method:       "GET",
			StatusCode:   200,
			HTTPProtocol: "HTTP/3.0",
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	got, total, err := repo.List(0, 20, AccessLogFilter{})
	if err != nil {
		t.Fatalf("list logs: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("unexpected total=%d items=%#v", total, got)
	}
	if got[0].RequestID != "http-3" || got[0].HTTPProtocol != "h3" {
		t.Fatalf("expected HTTP/3.0 to normalize to h3, got %#v", got[0])
	}
	if got[1].RequestID != "http-2" || got[1].HTTPProtocol != "h2" {
		t.Fatalf("expected HTTP/2.0 to normalize to h2, got %#v", got[1])
	}
}

func TestAccessLogRepoListFingerprintsSQLite(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	now := time.Now()
	items := []store.AccessLog{
		{SiteID: 1, RequestID: "req-a-old", Host: "example.com", TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384", TLSExtensions: "0,16,43", TLSCurves: "29,23", TLSPointFormats: "0", CreatedAt: now.Add(-time.Minute)},
		{SiteID: 1, RequestID: "req-a-new", Host: "example.com", TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384", TLSExtensions: "0,16,43", TLSCurves: "29,23", TLSPointFormats: "0", CreatedAt: now},
		{SiteID: 1, RequestID: "req-b", Host: "example.com", TLSJA3Hash: "bbb", TLSJA4: "ja4-b", TLSVersion: "TLS12", TLSALPN: "http/1.1", TLSSNI: "example.com", TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", TLSExtensions: "0,11,35", TLSCurves: "24,25", TLSPointFormats: "1", CreatedAt: now},
		{SiteID: 1, Host: "example.com", CreatedAt: now},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}
	if err := db.Create(&store.BotScoreLog{RequestID: "req-a-new", TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "example.com", TotalScore: 80, IsHighRisk: true, CreatedAt: now}).Error; err != nil {
		t.Fatalf("create matching bot score log: %v", err)
	}
	if err := db.Create(&store.BotScoreLog{RequestID: "req-other-sni", TLSJA3Hash: "aaa", TLSJA4: "ja4-a", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "other.example.com", TotalScore: 20, IsHighRisk: true, CreatedAt: now}).Error; err != nil {
		t.Fatalf("create other sni bot score log: %v", err)
	}

	got, total, err := repo.ListFingerprints(0, 20, FingerprintFilter{})
	if err != nil {
		t.Fatalf("list fingerprints: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("expected two fingerprint groups, total=%d items=%v", total, got)
	}
	if got[0].Count != 2 || got[0].TLSJA3Hash != "aaa" {
		t.Fatalf("expected newest aggregate first, got %#v", got[0])
	}
	if got[0].TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Fatalf("expected tls_cipher_suites in fingerprint aggregate, got %#v", got[0])
	}
	if got[0].TLSExtensions != "0,16,43" || got[0].TLSCurves != "29,23" || got[0].TLSPointFormats != "0" {
		t.Fatalf("expected TLS shape metadata in fingerprint aggregate, got %#v", got[0])
	}
	if got[0].HighRiskCount != 1 || got[0].AvgBotScore != 80 {
		t.Fatalf("expected bot score aggregation to stay scoped by grouped request ids, got %#v", got[0])
	}
}

func TestAccessLogRepoListFingerprintsAppliesFiltersBeforePagination(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	now := time.Now()
	items := []store.AccessLog{
		{SiteID: 1, RequestID: "fp-newest", Host: "example.com", TLSJA3Hash: "ja3-newest", TLSJA4: "ja4-newest", TLSVersion: "TLS13", TLSALPN: "h2", TLSSNI: "latest.example.com", TLSCipherSuites: "TLS_AES_128_GCM_SHA256", CreatedAt: now},
		{SiteID: 1, RequestID: "fp-middle", Host: "example.com", TLSJA3Hash: "ja3-middle", TLSJA4: "ja4-middle", TLSVersion: "TLS12", TLSALPN: "http/1.1", TLSSNI: "middle.example.com", TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", TLSExtensions: "0,11,35", TLSCurves: "24,25", TLSPointFormats: "1", CreatedAt: now.Add(-time.Minute)},
		{SiteID: 1, RequestID: "fp-target", Host: "example.com", TLSJA3Hash: "ja3-target", TLSJA4: "ja4-target", TLSVersion: "TLS13", TLSALPN: "h3", TLSSNI: "target.example.com", TLSCipherSuites: "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256", TLSExtensions: "0,16,43", TLSCurves: "29,23", TLSPointFormats: "0", CreatedAt: now.Add(-2 * time.Minute)},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}

	got, total, err := repo.ListFingerprints(0, 1, FingerprintFilter{
		TLSJA4: "ja4-target",
	})
	if err != nil {
		t.Fatalf("list fingerprints by ja4: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("expected one filtered fingerprint group, total=%d items=%#v", total, got)
	}
	if got[0].TLSJA3Hash != "ja3-target" || got[0].TLSSNI != "target.example.com" {
		t.Fatalf("unexpected filtered fingerprint group: %#v", got[0])
	}

	got, total, err = repo.ListFingerprints(0, 20, FingerprintFilter{
		TLSSNI:          "target",
		TLSVersion:      "1.3",
		TLSALPN:         "h3",
		TLSCipherSuites: "CHACHA20",
		TLSExtensions:   "16,43",
		TLSCurves:       "29,23",
		TLSPointFormats: "0",
	})
	if err != nil {
		t.Fatalf("list fingerprints by combined filters: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("expected one combined-filter fingerprint group, total=%d items=%#v", total, got)
	}
	if got[0].TLSJA4 != "ja4-target" || got[0].TLSCipherSuites != "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256" {
		t.Fatalf("unexpected combined-filter fingerprint group: %#v", got[0])
	}
	if got[0].TLSExtensions != "0,16,43" || got[0].TLSCurves != "29,23" || got[0].TLSPointFormats != "0" {
		t.Fatalf("unexpected TLS shape metadata in filtered fingerprint group: %#v", got[0])
	}
}

func TestAccessLogRepoListFingerprintsSeparatesBotScoresByTLSCipherSuites(t *testing.T) {
	db := newTestDB(t)
	repo := NewAccessLogRepo(db)
	now := time.Now()
	items := []store.AccessLog{
		{
			SiteID:          1,
			RequestID:       "req-suites-a",
			Host:            "example.com",
			TLSJA3Hash:      "ja3-shared",
			TLSJA4:          "ja4-shared",
			TLSVersion:      "TLS13",
			TLSALPN:         "h3",
			TLSSNI:          "shared.example.com",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			CreatedAt:       now,
		},
		{
			SiteID:          1,
			RequestID:       "req-suites-b",
			Host:            "example.com",
			TLSJA3Hash:      "ja3-shared",
			TLSJA4:          "ja4-shared",
			TLSVersion:      "TLS13",
			TLSALPN:         "h3",
			TLSSNI:          "shared.example.com",
			TLSCipherSuites: "TLS_CHACHA20_POLY1305_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
			CreatedAt:       now.Add(-time.Minute),
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create logs: %v", err)
	}
	if err := db.Create(&store.BotScoreLog{
		RequestID:  "req-suites-a",
		TLSJA3Hash: "ja3-shared",
		TLSJA4:     "ja4-shared",
		TLSVersion: "TLS13",
		TLSALPN:    "h3",
		TLSSNI:     "shared.example.com",
		TotalScore: 90,
		IsHighRisk: true,
		CreatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("create bot score a: %v", err)
	}
	if err := db.Create(&store.BotScoreLog{
		RequestID:  "req-suites-b",
		TLSJA3Hash: "ja3-shared",
		TLSJA4:     "ja4-shared",
		TLSVersion: "TLS13",
		TLSALPN:    "h3",
		TLSSNI:     "shared.example.com",
		TotalScore: 10,
		IsHighRisk: false,
		CreatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("create bot score b: %v", err)
	}

	got, total, err := repo.ListFingerprints(0, 20, FingerprintFilter{
		TLSJA3Hash:      "ja3-shared",
		TLSCipherSuites: "CHACHA20",
		TLSExtensions:   "11,35",
		TLSCurves:       "24,25",
		TLSPointFormats: "1",
	})
	if err != nil {
		t.Fatalf("list fingerprints by tls_cipher_suites: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("expected one filtered fingerprint group, total=%d items=%#v", total, got)
	}
	if got[0].TLSCipherSuites != "TLS_CHACHA20_POLY1305_SHA256" {
		t.Fatalf("unexpected tls_cipher_suites in fingerprint group: %#v", got[0])
	}
	if got[0].TLSExtensions != "0,11,35" || got[0].TLSCurves != "24,25" || got[0].TLSPointFormats != "1" {
		t.Fatalf("unexpected TLS shape metadata in fingerprint group: %#v", got[0])
	}
	if got[0].HighRiskCount != 0 || got[0].AvgBotScore != 10 {
		t.Fatalf("bot scores should stay scoped to request ids within the tls_cipher_suites group, got %#v", got[0])
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
			SiteID:          1,
			Host:            "example.com",
			Path:            "/blocked",
			Action:          "intercept",
			TLSVersion:      "TLS13",
			TLSSNI:          "checkout.example.com",
			TLSALPN:         "h2",
			TLSJA3Hash:      "ja3-checkout",
			TLSJA4:          "ja4-checkout",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			HeaderOrder:     "Host,User-Agent,Accept",
		},
		{
			SiteID:          1,
			Host:            "example.com",
			Path:            "/blocked",
			Action:          "intercept",
			TLSVersion:      "TLS12",
			TLSSNI:          "api.example.com",
			TLSALPN:         "http/1.1",
			TLSJA3Hash:      "ja3-api",
			TLSJA4:          "ja4-api",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
			HeaderOrder:     "Host,Accept,User-Agent",
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create security events: %v", err)
	}

	got, total, err := repo.List(0, 20, SecurityEventFilter{
		TLSVersion:      "TLS 1.3",
		TLSSNI:          "checkout",
		TLSALPN:         "h2",
		TLSJA3Hash:      "ja3-checkout",
		TLSJA4:          "ja4-checkout",
		TLSCipherSuites: "AES_256_GCM_SHA384",
		TLSExtensions:   "16,43",
		TLSCurves:       "29,23",
		TLSPointFormats: "0",
		HeaderOrder:     "User-Agent,Accept",
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
	if secEventCountCacheKey(SecurityEventFilter{TLSCipherSuites: "AES_256_GCM_SHA384"}) == secEventCountCacheKey(SecurityEventFilter{TLSCipherSuites: "AES_128_GCM_SHA256"}) {
		t.Fatal("tls_cipher_suites filters must not share security event count cache keys")
	}
	if secEventCountCacheKey(SecurityEventFilter{TLSExtensions: "16,43"}) == secEventCountCacheKey(SecurityEventFilter{TLSExtensions: "11,35"}) {
		t.Fatal("tls_extensions filters must not share security event count cache keys")
	}
	if secEventCountCacheKey(SecurityEventFilter{TLSCurves: "29,23"}) == secEventCountCacheKey(SecurityEventFilter{TLSCurves: "24,25"}) {
		t.Fatal("tls_curves filters must not share security event count cache keys")
	}
	if secEventCountCacheKey(SecurityEventFilter{TLSPointFormats: "0"}) == secEventCountCacheKey(SecurityEventFilter{TLSPointFormats: "1"}) {
		t.Fatal("tls_point_formats filters must not share security event count cache keys")
	}
	if secEventCountCacheKey(SecurityEventFilter{TLSVersion: "TLS13"}) != secEventCountCacheKey(SecurityEventFilter{TLSVersion: "0x0304"}) {
		t.Fatal("tls_version aliases should share security event count cache keys")
	}
}

func TestSecurityEventRepoListQueryStringFilter(t *testing.T) {
	db := newTestDB(t)
	repo := NewSecurityEventRepo(db)
	items := []store.SecurityEvent{
		{
			SiteID:      1,
			RequestID:   "query-event-match",
			Host:        "example.com",
			Path:        "/login",
			QueryString: "redirect=%2Fconsole&token=vip",
			Action:      "intercept",
			Category:    "sqli",
		},
		{
			SiteID:      1,
			RequestID:   "query-event-other",
			Host:        "example.com",
			Path:        "/login",
			QueryString: "redirect=%2Fdocs&token=basic",
			Action:      "intercept",
			Category:    "sqli",
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create security events: %v", err)
	}

	got, total, err := repo.List(0, 20, SecurityEventFilter{QueryString: "token=vip"})
	if err != nil {
		t.Fatalf("list security events: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "query-event-match" {
		t.Fatalf("query_string filter returned total=%d items=%#v", total, got)
	}
	if secEventCountCacheKey(SecurityEventFilter{QueryString: "token=vip"}) == secEventCountCacheKey(SecurityEventFilter{QueryString: "token=basic"}) {
		t.Fatal("query_string filters must not share security event count cache keys")
	}
}

func TestSecurityEventRepoListQueryMatchesAcrossFields(t *testing.T) {
	db := newTestDB(t)
	repo := NewSecurityEventRepo(db)
	items := []store.SecurityEvent{
		{
			SiteID:          1,
			RequestID:       "evt-alpha",
			ClientIP:        "10.1.0.1",
			Host:            "example.com",
			Path:            "/blocked",
			QueryString:     "trace_id=abc123",
			RuleIDStr:       "custom:orders:001",
			TLSSNI:          "orders.example.com",
			TLSJA3Hash:      "ja3-orders",
			TLSJA4:          "ja4-orders",
			TLSCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			TLSExtensions:   "0,16,43",
			TLSCurves:       "29,23",
			TLSPointFormats: "0",
			HeaderOrder:     "Host,User-Agent,Accept",
			Action:          "intercept",
		},
		{
			SiteID:          1,
			RequestID:       "evt-beta",
			ClientIP:        "10.1.0.2",
			Host:            "example.com",
			Path:            "/observe",
			QueryString:     "view=summary",
			RuleIDStr:       "custom:profile:001",
			TLSSNI:          "profile.example.com",
			TLSJA3Hash:      "ja3-profile",
			TLSJA4:          "ja4-profile",
			TLSCipherSuites: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			TLSExtensions:   "0,11,35",
			TLSCurves:       "24,25",
			TLSPointFormats: "1",
			HeaderOrder:     "Host,Accept,User-Agent",
			Action:          "observe",
		},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("create security events: %v", err)
	}

	got, total, err := repo.List(0, 20, SecurityEventFilter{Query: "custom:orders:001"})
	if err != nil {
		t.Fatalf("list security events by rule_id_str query: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "evt-alpha" {
		t.Fatalf("query search by rule_id_str returned total=%d items=%#v", total, got)
	}

	got, total, err = repo.List(0, 20, SecurityEventFilter{Query: "ja4-profile"})
	if err != nil {
		t.Fatalf("list security events by tls_ja4 query: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "evt-beta" {
		t.Fatalf("query search by tls_ja4 returned total=%d items=%#v", total, got)
	}

	got, total, err = repo.List(0, 20, SecurityEventFilter{Query: "AES_256_GCM_SHA384"})
	if err != nil {
		t.Fatalf("list security events by tls_cipher_suites query: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "evt-alpha" {
		t.Fatalf("query search by tls_cipher_suites returned total=%d items=%#v", total, got)
	}

	got, total, err = repo.List(0, 20, SecurityEventFilter{Query: "16,43"})
	if err != nil {
		t.Fatalf("list security events by tls_extensions query: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].RequestID != "evt-alpha" {
		t.Fatalf("query search by tls_extensions returned total=%d items=%#v", total, got)
	}

	if secEventCountCacheKey(SecurityEventFilter{Query: "custom:orders:001"}) == secEventCountCacheKey(SecurityEventFilter{Query: "ja4-profile"}) {
		t.Fatal("query filters must not share security event count cache keys")
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

func TestRuleRepoListByPolicyUsesExecutionOrder(t *testing.T) {
	db := newTestDB(t)
	repo := NewRuleRepo(db)
	items := []store.Rule{
		{Name: "custom first priority", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "block_path:/custom-a", Action: store.ActionObserve, Priority: 1},
		{Name: "acl later priority", PolicyID: 1, Phase: store.PhaseACL, Pattern: "block_path:/acl", Action: store.ActionIntercept, Priority: 20},
		{Name: "signature middle", PolicyID: 1, Phase: store.PhaseSignature, Pattern: "block_path:/sig", Action: store.ActionIntercept, Priority: 5},
		{Name: "custom second priority", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "block_path:/custom-b", Action: store.ActionObserve, Priority: 10},
	}
	for i := range items {
		if err := repo.Create(&items[i]); err != nil {
			t.Fatalf("create rule: %v", err)
		}
	}

	got, err := repo.ListByPolicy(1)
	if err != nil {
		t.Fatalf("list by policy: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(got))
	}
	gotNames := []string{got[0].Name, got[1].Name, got[2].Name, got[3].Name}
	wantNames := []string{
		"acl later priority",
		"signature middle",
		"custom first priority",
		"custom second priority",
	}
	for i := range wantNames {
		if gotNames[i] != wantNames[i] {
			t.Fatalf("rule order = %#v, want %#v", gotNames, wantNames)
		}
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
