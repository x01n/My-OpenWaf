package system

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func newDashboardLogDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	return db
}

func newDashboardConfigDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}, &store.ConfigRevision{}); err != nil {
		t.Fatalf("migrate config db: %v", err)
	}
	return db
}

func TestBuildDashboardResponseContainsExpectedFields(t *testing.T) {
	s := dataplane.Summary{
		QPS1s:       12,
		QPS5s:       8,
		ReqTotal:    1000,
		Status2xx:   900,
		Status4xx:   50,
		Status5xx:   10,
		WAFBlocks:   40,
		WAFObserves: 20,
		BuiltinHits: 5,
		UptimeSec:   3600,
		UniqueIPs:   200,
		AttackIPs:   3,
	}
	ds := dashboardDBStats{
		UniqueVisitors24h: 12,
		HumanVisits24h:    7,
		BotVisits24h:      4,

		UnclassifiedIntercept24h:           3,
		VisitKindTotal24h:                  15,
		VisitorFusionHTTPSReleasedTotal24h: 9,
		VisitorFusionHuman24h:              4,
		VisitorFusionBot24h:                2,
		VisitorFusionUnknown24h:            3,
		BotTotal24h:                        30,
		BotBlocked24h:                      10,
		BotHighRisk24h:                     5,
		CVETotal24h:                        2,
		CVEByType:                          []cveCatStat{{Category: "sqli", Count: 2}},
		DropTotal24h:                       7,
		DropBySource:                       map[string]int64{"bot": 4, "rule": 3},
	}

	resp := buildDashboardResponse(s, 42, ds)

	requiredKeys := []string{
		"qps_1s", "qps_5s", "requests_total",
		"status_2xx", "errors_upstream_4xx", "errors_upstream_5xx",
		"waf_blocks", "waf_observes", "builtin_hits",
		"uptime_sec", "unique_ips", "attack_ips", "unique_visitors_24h", "revision",
		"human_visits_24h", "bot_visits_24h",
		"unclassified_intercept_24h", "visit_kind_total_24h",
		"visitor_fusion_https_released_total_24h", "visitor_fusion_human_24h", "visitor_fusion_bot_24h", "visitor_fusion_unknown_24h",
		"bot_total_24h", "bot_blocked_24h", "bot_high_risk_24h",
		"cve_total_24h", "cve_by_type_24h",
		"drop_total_24h", "drop_by_source_24h",
	}
	for _, k := range requiredKeys {
		if _, ok := resp[k]; !ok {
			t.Errorf("buildDashboardResponse missing key %q", k)
		}
	}

	if got, ok := resp["revision"].(uint64); !ok || got != 42 {
		t.Errorf("revision = %v, want 42", resp["revision"])
	}
	if got, ok := resp["qps_1s"].(float64); !ok || int(got) != 12 {
		t.Errorf("qps_1s = %v, want 12", resp["qps_1s"])
	}
	if got, ok := resp["visitor_fusion_https_released_total_24h"].(int64); !ok || got != 9 {
		t.Errorf("visitor_fusion_https_released_total_24h = %v, want 9", resp["visitor_fusion_https_released_total_24h"])
	}
	if got, ok := resp["bot_total_24h"].(int64); !ok || got != 30 {
		t.Errorf("bot_total_24h = %v, want 30", resp["bot_total_24h"])
	}
	if got, ok := resp["human_visits_24h"].(int64); !ok || got != 7 {
		t.Errorf("human_visits_24h = %v, want 7", resp["human_visits_24h"])
	}
	if got, ok := resp["bot_visits_24h"].(int64); !ok || got != 4 {
		t.Errorf("bot_visits_24h = %v, want 4", resp["bot_visits_24h"])
	}
	if got, ok := resp["unclassified_intercept_24h"].(int64); !ok || got != 3 {
		t.Errorf("unclassified_intercept_24h = %v, want 3", resp["unclassified_intercept_24h"])
	}
	if got, ok := resp["visit_kind_total_24h"].(int64); !ok || got != 15 {
		t.Errorf("visit_kind_total_24h = %v, want 15", resp["visit_kind_total_24h"])
	}
	// 三类之和 7+4+3=14，总数 15，差额 1 为其他非安全类动作——口径二的预期语义。
	if resp["human_visits_24h"].(int64)+resp["bot_visits_24h"].(int64)+resp["unclassified_intercept_24h"].(int64) >= resp["visit_kind_total_24h"].(int64)+1 {
		t.Errorf("three kinds must not exceed total: %v", resp)
	}
}

func TestBuildDashboardSnapshotWithEmptyLogDB(t *testing.T) {
	configDB := newDashboardConfigDBForTest(t)
	logDB := newDashboardLogDBForTest(t)

	deps := &DashboardDeps{
		Metrics:  dataplane.NewMetrics(),
		ConfigDB: configDB,
		LogDB:    logDB,
		Cache:    nil,
	}

	result := BuildDashboardSnapshot(deps)
	if result == nil {
		t.Fatal("BuildDashboardSnapshot returned nil")
	}

	for _, key := range []string{"unique_visitors_24h", "visitor_fusion_https_released_total_24h", "visitor_fusion_human_24h", "visitor_fusion_bot_24h", "visitor_fusion_unknown_24h", "bot_total_24h", "bot_blocked_24h", "cve_total_24h", "drop_total_24h"} {
		v, ok := result[key]
		if !ok {
			t.Errorf("missing key %q", key)
			continue
		}
		if v.(int64) != 0 {
			t.Errorf("%s = %v, want 0 for empty log DB", key, v)
		}
	}
}

// TestBuildDashboardSnapshotCountsDistinctClientIPs 验证独立访客按近 24h AccessLog client_ip 去重。
func TestBuildDashboardSnapshotCountsDistinctClientIPs(t *testing.T) {
	configDB := newDashboardConfigDBForTest(t)
	logDB := newDashboardLogDBForTest(t)
	now := time.Now()

	items := []store.AccessLog{
		{ClientIP: "1.1.1.1", CreatedAt: now},
		{ClientIP: "1.1.1.1", CreatedAt: now.Add(-time.Hour)},
		{ClientIP: "2.2.2.2", CreatedAt: now.Add(-2 * time.Hour)},
		{ClientIP: "3.3.3.3", CreatedAt: now.Add(-48 * time.Hour)},
	}
	if err := logDB.Create(&items).Error; err != nil {
		t.Fatalf("seed access logs: %v", err)
	}

	deps := &DashboardDeps{
		Metrics:    dataplane.NewMetrics(),
		ConfigDB:   configDB,
		LogDB:      logDB,
		Cache:      nil,
		AccessRepo: repository.NewAccessLogRepo(logDB),
	}

	result := BuildDashboardSnapshot(deps)
	got, ok := result["unique_visitors_24h"].(int64)
	if !ok {
		t.Fatalf("unique_visitors_24h missing or wrong type: %#v", result["unique_visitors_24h"])
	}
	if got != 2 {
		t.Fatalf("unique_visitors_24h = %d, want 2", got)
	}
}

func TestBuildDashboardSnapshotCountsVisitorFusionWindow(t *testing.T) {
	configDB := newDashboardConfigDBForTest(t)
	logDB := newDashboardLogDBForTest(t)
	now := time.Now()
	items := []store.AccessLog{
		{CreatedAt: now, VisitorFusionClass: "human", VisitorFusionEvidenceSufficient: true},
		{CreatedAt: now, VisitorFusionClass: "bot", VisitorFusionEvidenceSufficient: true},
		{CreatedAt: now, VisitorFusionClass: "unknown", VisitorFusionEvidenceSufficient: true},
		{CreatedAt: now, VisitorFusionClass: "human", VisitorFusionEvidenceSufficient: false},
		{CreatedAt: now.Add(-25 * time.Hour), VisitorFusionClass: "human", VisitorFusionEvidenceSufficient: true},
	}
	if err := logDB.Create(&items).Error; err != nil {
		t.Fatalf("seed visitor fusion access logs: %v", err)
	}

	result := BuildDashboardSnapshot(&DashboardDeps{
		Metrics:  dataplane.NewMetrics(),
		ConfigDB: configDB,
		LogDB:    logDB,
		Cache:    nil,
	})
	want := map[string]int64{
		"visitor_fusion_https_released_total_24h": 3,
		"visitor_fusion_human_24h":                1,
		"visitor_fusion_bot_24h":                  1,
		"visitor_fusion_unknown_24h":              1,
	}
	for key, expected := range want {
		got, ok := result[key].(int64)
		if !ok || got != expected {
			t.Errorf("%s = %#v, want %d", key, result[key], expected)
		}
	}
}

// TestBuildDashboardSnapshotIncludesVisitorKindStats 验证 BuildDashboardSnapshot
// 注入 AccessRepo 后能在返回结构中输出 human_visits_24h / bot_visits_24h 字段。
func TestBuildDashboardSnapshotIncludesVisitorKindStats(t *testing.T) {
	repoDB := newDashboardLogDBForTest(t)
	// LogDB 已包含 BotScoreLog 迁移（newDashboardLogDBForTest 调用 store.AutoMigrateLogs）。
	// 但 bot_score_logs 表需要单独建，因为其表结构由 setupBotScoreLogTable 之类 helper 提供。
	if !repoDB.Migrator().HasTable(&store.BotScoreLog{}) {
		t.Fatalf("BotScoreLog table missing after AutoMigrateLogs")
	}
	now := time.Now()
	accessItems := []store.AccessLog{
		{ClientIP: "10.0.0.1", RequestID: "r-human-1", SiteID: 1, CreatedAt: now},
		{ClientIP: "10.0.0.2", RequestID: "r-human-2", SiteID: 1, CreatedAt: now.Add(-time.Minute)},
		{ClientIP: "10.0.0.3", RequestID: "r-human-3", SiteID: 1, CreatedAt: now.Add(-2 * time.Minute)},
		{ClientIP: "10.0.0.4", RequestID: "r-bot-1", SiteID: 1, CreatedAt: now.Add(-3 * time.Minute)},
		{ClientIP: "10.0.0.5", RequestID: "r-bot-2", SiteID: 1, CreatedAt: now.Add(-4 * time.Minute)},
		// 口径二：终止类 waf_action 且无 BotScoreLog 关联，须落入 unclassified_intercept_24h
		{ClientIP: "10.0.0.6", RequestID: "r-owasp-block", SiteID: 1, WAFAction: "intercept", CreatedAt: now.Add(-5 * time.Minute)},
	}
	if err := repoDB.Create(&accessItems).Error; err != nil {
		t.Fatalf("seed access logs: %v", err)
	}
	botItems := []store.BotScoreLog{
		{RequestID: "r-bot-1", SiteID: 1, CreatedAt: now.Add(-3 * time.Minute)},
		{RequestID: "r-bot-2", SiteID: 1, CreatedAt: now.Add(-4 * time.Minute)},
	}
	if err := repoDB.Create(&botItems).Error; err != nil {
		t.Fatalf("seed bot logs: %v", err)
	}

	deps := &DashboardDeps{
		Metrics:    dataplane.NewMetrics(),
		ConfigDB:   newDashboardConfigDBForTest(t),
		LogDB:      repoDB,
		Cache:      nil,
		AccessRepo: repository.NewAccessLogRepo(repoDB),
	}

	result := BuildDashboardSnapshot(deps)
	human, ok := result["human_visits_24h"].(int64)
	if !ok {
		t.Fatalf("human_visits_24h missing or wrong type: %#v", result["human_visits_24h"])
	}
	if human != 3 {
		t.Fatalf("human_visits_24h = %d, want 3", human)
	}
	bot, ok := result["bot_visits_24h"].(int64)
	if !ok {
		t.Fatalf("bot_visits_24h missing or wrong type: %#v", result["bot_visits_24h"])
	}
	if bot != 2 {
		t.Fatalf("bot_visits_24h = %d, want 2", bot)
	}
	// 口径二：r-owasp-block 为终止类 action 且无 bot 关联，须单独成类而非计入 human。
	intercepted, ok := result["unclassified_intercept_24h"].(int64)
	if !ok {
		t.Fatalf("unclassified_intercept_24h missing or wrong type: %#v", result["unclassified_intercept_24h"])
	}
	if intercepted != 1 {
		t.Fatalf("unclassified_intercept_24h = %d, want 1", intercepted)
	}
	total, ok := result["visit_kind_total_24h"].(int64)
	if !ok {
		t.Fatalf("visit_kind_total_24h missing or wrong type: %#v", result["visit_kind_total_24h"])
	}
	if total != 6 {
		t.Fatalf("visit_kind_total_24h = %d, want 6", total)
	}
	// 本组 fixture 无「其他非安全类」动作，故三类之和恰等于总数。
	if human+bot+intercepted != total {
		t.Fatalf("human+bot+intercepted = %d, want %d", human+bot+intercepted, total)
	}
}
