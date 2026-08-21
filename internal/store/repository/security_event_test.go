package repository

import (
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newSecurityEventRepoForTest(t *testing.T) *SecurityEventRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SecurityEvent{}); err != nil {
		t.Fatalf("migrate security event: %v", err)
	}
	return NewSecurityEventRepo(db)
}

func TestTopCountriesAggregatesByGeoCountry(t *testing.T) {
	repo := newSecurityEventRepoForTest(t)
	now := time.Now()
	events := []store.SecurityEvent{
		{GeoCountry: "CN", CreatedAt: now.Add(-time.Hour)},
		{GeoCountry: "CN", CreatedAt: now.Add(-2 * time.Hour)},
		{GeoCountry: "CN", CreatedAt: now.Add(-3 * time.Hour)},
		{GeoCountry: "US", CreatedAt: now.Add(-time.Hour)},
		{GeoCountry: "US", CreatedAt: now.Add(-2 * time.Hour)},
		{GeoCountry: "JP", CreatedAt: now.Add(-time.Hour)},
		{GeoCountry: "", CreatedAt: now.Add(-time.Hour)},        // 无地理信息应被排除
		{GeoCountry: "RU", CreatedAt: now.Add(-48 * time.Hour)}, // 超出时间窗应被排除
	}
	for i := range events {
		if err := repo.db.Create(&events[i]).Error; err != nil {
			t.Fatalf("create event: %v", err)
		}
	}

	since := now.Add(-24 * time.Hour)
	stats, err := repo.TopCountries(since, 10)
	if err != nil {
		t.Fatalf("TopCountries: %v", err)
	}

	// 应有 3 个国家（CN/US/JP），排除空 geo 和超窗的 RU。
	if len(stats) != 3 {
		t.Fatalf("countries = %d, want 3", len(stats))
	}
	// 按 count 降序：CN(3) > US(2) > JP(1)。
	if stats[0].Country != "CN" || stats[0].Count != 3 {
		t.Errorf("top country = %s(%d), want CN(3)", stats[0].Country, stats[0].Count)
	}
	if stats[1].Country != "US" || stats[1].Count != 2 {
		t.Errorf("2nd country = %s(%d), want US(2)", stats[1].Country, stats[1].Count)
	}
	if stats[2].Country != "JP" || stats[2].Count != 1 {
		t.Errorf("3rd country = %s(%d), want JP(1)", stats[2].Country, stats[2].Count)
	}
}

func TestTopCountriesRespectsLimit(t *testing.T) {
	repo := newSecurityEventRepoForTest(t)
	now := time.Now()
	countries := []string{"CN", "US", "JP", "DE", "FR"}
	for i, c := range countries {
		// 让计数递减以固定排序：CN 最多。
		for j := 0; j <= len(countries)-i; j++ {
			e := store.SecurityEvent{GeoCountry: c, CreatedAt: now.Add(-time.Hour)}
			if err := repo.db.Create(&e).Error; err != nil {
				t.Fatalf("create: %v", err)
			}
		}
	}

	stats, err := repo.TopCountries(now.Add(-24*time.Hour), 3)
	if err != nil {
		t.Fatalf("TopCountries: %v", err)
	}
	if len(stats) != 3 {
		t.Fatalf("countries = %d, want 3 (limit)", len(stats))
	}
}

// ---------- ListRequests（请求级聚合）测试 ----------

// seedSecurityEvents 批量写入事件，便于聚合用例构造数据。
func seedSecurityEvents(t *testing.T, repo *SecurityEventRepo, events []store.SecurityEvent) {
	t.Helper()
	for i := range events {
		if err := repo.db.Create(&events[i]).Error; err != nil {
			t.Fatalf("create event: %v", err)
		}
	}
}

func TestListRequestsFiltersBeforeGrouping(t *testing.T) {
	repo := newSecurityEventRepoForTest(t)
	now := time.Now()
	seedSecurityEvents(t, repo, []store.SecurityEvent{
		// req-a：既有 intercept 又有 observe，intercept 过滤后仍应计入。
		{RequestID: "req-a", Action: "intercept", CreatedAt: now.Add(-3 * time.Minute)},
		{RequestID: "req-a", Action: "observe", CreatedAt: now.Add(-2 * time.Minute)},
		// req-b：仅 intercept。
		{RequestID: "req-b", Action: "intercept", CreatedAt: now.Add(-time.Minute)},
		// req-c：仅 observe，intercept 过滤后整个请求都不应出现。
		{RequestID: "req-c", Action: "observe", CreatedAt: now},
	})

	items, total, err := repo.ListRequests(0, 20, SecurityEventFilter{Action: "intercept"})
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2 (req-a/req-b)", total)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	for _, it := range items {
		if it.RequestID == "req-c" {
			t.Errorf("req-c should be filtered out by action=intercept")
		}
		// req-a 的两条事件里只有 1 条是 intercept，先过滤再分组时计数应为 1。
		if it.RequestID == "req-a" && it.EventCount != 1 {
			t.Errorf("req-a event_count = %d, want 1 (filter applied before grouping)", it.EventCount)
		}
	}
}

func TestListRequestsExcludesEmptyRequestID(t *testing.T) {
	repo := newSecurityEventRepoForTest(t)
	now := time.Now()
	seedSecurityEvents(t, repo, []store.SecurityEvent{
		{RequestID: "req-a", Action: "intercept", CreatedAt: now.Add(-time.Minute)},
		{RequestID: "", Action: "intercept", CreatedAt: now},
		{RequestID: "", Action: "observe", CreatedAt: now},
	})

	items, total, err := repo.ListRequests(0, 20, SecurityEventFilter{})
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if total != 1 {
		t.Fatalf("total = %d, want 1 (empty request_id excluded)", total)
	}
	if len(items) != 1 || items[0].RequestID != "req-a" {
		t.Fatalf("items = %+v, want only req-a", items)
	}
}

func TestListRequestsPaginationKeepsFullTotal(t *testing.T) {
	repo := newSecurityEventRepoForTest(t)
	now := time.Now()
	seedSecurityEvents(t, repo, []store.SecurityEvent{
		{RequestID: "req-a", Action: "intercept", CreatedAt: now.Add(-3 * time.Minute)},
		{RequestID: "req-b", Action: "intercept", CreatedAt: now.Add(-2 * time.Minute)},
		{RequestID: "req-b", Action: "observe", CreatedAt: now.Add(-time.Minute)},
		{RequestID: "req-c", Action: "observe", CreatedAt: now},
	})

	items, total, err := repo.ListRequests(0, 1, SecurityEventFilter{})
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1 (limit)", len(items))
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3 (distinct request_id, not affected by limit)", total)
	}
}

func TestListRequestsOrdersByLastSeenDesc(t *testing.T) {
	repo := newSecurityEventRepoForTest(t)
	now := time.Now().Truncate(time.Second)
	// request_id 字典序（req-a < req-b < req-c）与时间序（req-a 最新）刻意相反，
	// 只有真正按 last_seen 排序才会返回 req-a/req-b/req-c。
	seedSecurityEvents(t, repo, []store.SecurityEvent{
		{RequestID: "req-c", Action: "intercept", CreatedAt: now.Add(-30 * time.Minute)},
		{RequestID: "req-b", Action: "intercept", CreatedAt: now.Add(-20 * time.Minute)},
		{RequestID: "req-a", Action: "intercept", CreatedAt: now.Add(-10 * time.Minute)},
		// req-c 的另一条事件更早，不影响其 last_seen。
		{RequestID: "req-c", Action: "observe", CreatedAt: now.Add(-40 * time.Minute)},
	})

	items, _, err := repo.ListRequests(0, 20, SecurityEventFilter{})
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	want := []string{"req-a", "req-b", "req-c"}
	if len(items) != len(want) {
		t.Fatalf("items = %d, want %d", len(items), len(want))
	}
	for i, id := range want {
		if items[i].RequestID != id {
			t.Errorf("items[%d].request_id = %s, want %s (last_seen DESC)", i, items[i].RequestID, id)
		}
	}
}

func TestListRequestsSecondaryOrderByRequestIDDesc(t *testing.T) {
	repo := newSecurityEventRepoForTest(t)
	same := time.Now().Truncate(time.Second)
	seedSecurityEvents(t, repo, []store.SecurityEvent{
		{RequestID: "req-a", Action: "intercept", CreatedAt: same},
		{RequestID: "req-b", Action: "intercept", CreatedAt: same},
	})

	items, _, err := repo.ListRequests(0, 20, SecurityEventFilter{})
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	// last_seen 相同时次级排序为 request_id DESC。
	if items[0].RequestID != "req-b" || items[1].RequestID != "req-a" {
		t.Errorf("order = [%s %s], want [req-b req-a] (request_id DESC on tie)", items[0].RequestID, items[1].RequestID)
	}
}

func TestListRequestsLastSeenIsMaxCreatedAt(t *testing.T) {
	repo := newSecurityEventRepoForTest(t)
	newest := time.Now().Truncate(time.Second)
	seedSecurityEvents(t, repo, []store.SecurityEvent{
		{RequestID: "req-a", Action: "intercept", CreatedAt: newest.Add(-10 * time.Minute)},
		{RequestID: "req-a", Action: "observe", CreatedAt: newest},
		{RequestID: "req-a", Action: "observe", CreatedAt: newest.Add(-5 * time.Minute)},
	})

	items, _, err := repo.ListRequests(0, 20, SecurityEventFilter{})
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if items[0].EventCount != 3 {
		t.Errorf("event_count = %d, want 3", items[0].EventCount)
	}
	if !items[0].LastSeen.Equal(newest) {
		t.Errorf("last_seen = %s, want %s (MAX(created_at))", items[0].LastSeen, newest)
	}
}
