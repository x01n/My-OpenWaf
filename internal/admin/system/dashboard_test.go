package system

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/store"
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
		BotTotal24h:       30,
		BotBlocked24h:     10,
		BotHighRisk24h:    5,
		CVETotal24h:       2,
		CVEByType:         []cveCatStat{{Category: "sqli", Count: 2}},
		DropTotal24h:      7,
		DropBySource:      map[string]int64{"bot": 4, "rule": 3},
	}

	resp := buildDashboardResponse(s, 42, ds)

	requiredKeys := []string{
		"qps_1s", "qps_5s", "requests_total",
		"status_2xx", "errors_upstream_4xx", "errors_upstream_5xx",
		"waf_blocks", "waf_observes", "builtin_hits",
		"uptime_sec", "unique_ips", "attack_ips", "unique_visitors_24h", "revision",
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
	if got, ok := resp["bot_total_24h"].(int64); !ok || got != 30 {
		t.Errorf("bot_total_24h = %v, want 30", resp["bot_total_24h"])
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

	for _, key := range []string{"unique_visitors_24h", "bot_total_24h", "bot_blocked_24h", "cve_total_24h", "drop_total_24h"} {
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
		Metrics:  dataplane.NewMetrics(),
		ConfigDB: configDB,
		LogDB:    logDB,
		Cache:    nil,
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
