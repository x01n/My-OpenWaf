package threatintel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestParseEntriesValidatesAndDedups(t *testing.T) {
	sid := uint(7)
	feed := &store.ThreatIntelFeed{ID: 3, Name: "恶意源", Kind: "blacklist", Action: "drop", SiteID: &sid}
	body := []byte(`
# 注释行
1.1.1.1
2.2.2.0/24

   3.3.3.3
1.1.1.1
not-an-ip
999.999.999.999
4.4.4.4 # 行内注释
2001:db8::/32
`)
	entries := parseEntries(body, feed)

	// 合法且去重后应为: 1.1.1.1, 2.2.2.0/24, 3.3.3.3, 4.4.4.4, 2001:db8::/32
	if len(entries) != 5 {
		values := make([]string, len(entries))
		for i, e := range entries {
			values[i] = e.Value
		}
		t.Fatalf("期望 5 条合法条目, 实得 %d: %v", len(entries), values)
	}

	for _, e := range entries {
		if e.Kind != store.IPListBlack {
			t.Errorf("条目 %s Kind 应继承 blacklist, 实得 %s", e.Value, e.Kind)
		}
		if e.Action != "drop" {
			t.Errorf("条目 %s Action 应继承 drop, 实得 %s", e.Value, e.Action)
		}
		if e.SiteID == nil || *e.SiteID != 7 {
			t.Errorf("条目 %s SiteID 应继承 7", e.Value)
		}
		if e.FeedID == nil || *e.FeedID != 3 {
			t.Errorf("条目 %s FeedID 应为 3", e.Value)
		}
		if !e.Enabled {
			t.Errorf("条目 %s 应默认启用", e.Value)
		}
		if e.Note != "来自订阅: 恶意源" {
			t.Errorf("条目 %s Note 不符: %s", e.Value, e.Note)
		}
	}
}

func TestParseEntriesEmpty(t *testing.T) {
	feed := &store.ThreatIntelFeed{ID: 1, Name: "空", Kind: "whitelist", Action: "intercept"}
	if got := parseEntries([]byte("# 全是注释\n\n   \n"), feed); len(got) != 0 {
		t.Fatalf("期望 0 条, 实得 %d", len(got))
	}
}

func TestIsValidIPOrCIDR(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":       true,
		"10.0.0.0/8":    true,
		"::1":           true,
		"2001:db8::/32": true,
		"1.2.3.4/33":    false,
		"1.2.3.256":     false,
		"foo":           false,
		"":              false,
	}
	for in, want := range cases {
		if got := isValidIPOrCIDR(in); got != want {
			t.Errorf("isValidIPOrCIDR(%q)=%v, 期望 %v", in, got, want)
		}
	}
}

func newManagerForTest(t *testing.T) (*Manager, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.ThreatIntelFeed{}, &store.IPListEntry{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	reloaded := 0
	m := NewManager(db, nil, func() error { reloaded++; return nil })
	return m, db
}

func TestSyncFeedReplacesEntriesAndRecordsStatus(t *testing.T) {
	m, db := newManagerForTest(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("5.5.5.5\n6.6.6.0/24\nbad-line\n"))
	}))
	defer srv.Close()

	feed := &store.ThreatIntelFeed{Name: "t", URL: srv.URL, Kind: "blacklist", Action: "intercept", Enabled: true, SyncInterval: 3600}
	if err := db.Create(feed).Error; err != nil {
		t.Fatalf("create feed: %v", err)
	}

	if err := m.SyncFeed(feed.ID); err != nil {
		t.Fatalf("sync: %v", err)
	}

	var count int64
	db.Model(&store.IPListEntry{}).Where("feed_id = ?", feed.ID).Count(&count)
	if count != 2 {
		t.Fatalf("期望写入 2 条条目, 实得 %d", count)
	}

	var updated store.ThreatIntelFeed
	if err := db.First(&updated, feed.ID).Error; err != nil {
		t.Fatalf("reload feed: %v", err)
	}
	if updated.LastSyncAt == nil {
		t.Errorf("LastSyncAt 应被设置")
	}
	if updated.LastError != "" {
		t.Errorf("成功同步 LastError 应为空, 实得 %s", updated.LastError)
	}
	if updated.EntryCount != 2 {
		t.Errorf("EntryCount 应为 2, 实得 %d", updated.EntryCount)
	}
}

func TestSyncFeedHTTPErrorRecordsLastError(t *testing.T) {
	m, db := newManagerForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	feed := &store.ThreatIntelFeed{Name: "t", URL: srv.URL, Kind: "blacklist", Action: "intercept", Enabled: true}
	if err := db.Create(feed).Error; err != nil {
		t.Fatalf("create feed: %v", err)
	}

	if err := m.SyncFeed(feed.ID); err == nil {
		t.Fatalf("期望同步返回错误")
	}

	var updated store.ThreatIntelFeed
	db.First(&updated, feed.ID)
	if updated.LastError == "" {
		t.Errorf("失败同步应记录 LastError")
	}
}

func TestIsDue(t *testing.T) {
	m := &Manager{}
	now := time.Now()
	// 从未同步过 -> 到期
	if !m.isDue(store.ThreatIntelFeed{SyncInterval: 60}, now) {
		t.Errorf("未同步过的 feed 应到期")
	}
	recent := now.Add(-30 * time.Second)
	if m.isDue(store.ThreatIntelFeed{SyncInterval: 60, LastSyncAt: &recent}, now) {
		t.Errorf("30 秒前同步、间隔 60 秒的 feed 不应到期")
	}
	old := now.Add(-120 * time.Second)
	if !m.isDue(store.ThreatIntelFeed{SyncInterval: 60, LastSyncAt: &old}, now) {
		t.Errorf("120 秒前同步、间隔 60 秒的 feed 应到期")
	}
}
