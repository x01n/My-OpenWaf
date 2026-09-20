package repository

import (
	"testing"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newThreatIntelRepoForTest(t *testing.T) *ThreatIntelRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.ThreatIntelFeed{}, &store.IPListEntry{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewThreatIntelRepo(db)
}

func TestThreatIntelRepoCRUDAndListEnabled(t *testing.T) {
	repo := newThreatIntelRepoForTest(t)

	f1 := &store.ThreatIntelFeed{Name: "feed-a", URL: "http://x/a.txt", Kind: "blacklist", Action: "intercept", Enabled: true}
	f2 := &store.ThreatIntelFeed{Name: "feed-b", URL: "http://x/b.txt", Kind: "whitelist", Action: "drop", Enabled: true}
	if err := repo.Create(f1); err != nil {
		t.Fatalf("create f1: %v", err)
	}
	if err := repo.Create(f2); err != nil {
		t.Fatalf("create f2: %v", err)
	}

	all, err := repo.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("期望 2 条订阅源, 实得 %d", len(all))
	}

	enabled, err := repo.ListEnabled()
	if err != nil {
		t.Fatalf("list enabled: %v", err)
	}
	if len(enabled) != 2 {
		t.Fatalf("期望 2 条启用, 实得 %d", len(enabled))
	}

	// 通过 Update(Save 全量保存)将 f2 停用，验证 ListEnabled 收敛。
	got2, err := repo.Get(f2.ID)
	if err != nil {
		t.Fatalf("get f2: %v", err)
	}
	got2.Enabled = false
	if err := repo.Update(got2); err != nil {
		t.Fatalf("update f2: %v", err)
	}
	enabled, _ = repo.ListEnabled()
	if len(enabled) != 1 || enabled[0].Name != "feed-a" {
		t.Fatalf("停用 f2 后期望仅 feed-a 启用, 实得 %+v", enabled)
	}

	got, err := repo.Get(f1.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got.Enabled = false
	if err := repo.Update(got); err != nil {
		t.Fatalf("update: %v", err)
	}
	enabled, _ = repo.ListEnabled()
	if len(enabled) != 0 {
		t.Fatalf("停用后期望 0 条启用, 实得 %d", len(enabled))
	}
}

func TestThreatIntelRepoReplaceFeedEntries(t *testing.T) {
	repo := newThreatIntelRepoForTest(t)
	feed := &store.ThreatIntelFeed{Name: "feed", URL: "http://x", Kind: "blacklist", Action: "intercept", Enabled: true}
	if err := repo.Create(feed); err != nil {
		t.Fatalf("create feed: %v", err)
	}
	fid := feed.ID

	// 手动条目（FeedID 为 nil），不应被替换逻辑清除。
	manual := store.IPListEntry{Kind: store.IPListBlack, Value: "9.9.9.9", Enabled: true, Action: "intercept"}
	if err := repo.db.Create(&manual).Error; err != nil {
		t.Fatalf("create manual entry: %v", err)
	}

	first := []store.IPListEntry{
		{Kind: store.IPListBlack, Value: "1.1.1.1", Enabled: true, Action: "intercept", FeedID: &fid},
		{Kind: store.IPListBlack, Value: "2.2.2.0/24", Enabled: true, Action: "intercept", FeedID: &fid},
	}
	if err := repo.ReplaceFeedEntries(fid, first); err != nil {
		t.Fatalf("replace first: %v", err)
	}
	if n := repo.CountFeedEntries(fid); n != 2 {
		t.Fatalf("首次替换后期望 2 条, 实得 %d", n)
	}

	// 第二次替换应清除旧的 feed 条目并写入新的。
	second := []store.IPListEntry{
		{Kind: store.IPListBlack, Value: "3.3.3.3", Enabled: true, Action: "intercept", FeedID: &fid},
	}
	if err := repo.ReplaceFeedEntries(fid, second); err != nil {
		t.Fatalf("replace second: %v", err)
	}
	if n := repo.CountFeedEntries(fid); n != 1 {
		t.Fatalf("二次替换后期望 1 条, 实得 %d", n)
	}

	// 手动条目应仍然存在。
	var manualCount int64
	repo.db.Model(&store.IPListEntry{}).Where("feed_id IS NULL").Count(&manualCount)
	if manualCount != 1 {
		t.Fatalf("手动条目应保留 1 条, 实得 %d", manualCount)
	}
}

func TestThreatIntelRepoDeleteCascadesEntries(t *testing.T) {
	repo := newThreatIntelRepoForTest(t)
	feed := &store.ThreatIntelFeed{Name: "feed", URL: "http://x", Kind: "blacklist", Action: "intercept", Enabled: true}
	if err := repo.Create(feed); err != nil {
		t.Fatalf("create feed: %v", err)
	}
	fid := feed.ID
	entries := []store.IPListEntry{
		{Kind: store.IPListBlack, Value: "1.1.1.1", Enabled: true, Action: "intercept", FeedID: &fid},
		{Kind: store.IPListBlack, Value: "2.2.2.2", Enabled: true, Action: "intercept", FeedID: &fid},
	}
	if err := repo.ReplaceFeedEntries(fid, entries); err != nil {
		t.Fatalf("seed entries: %v", err)
	}

	if err := repo.Delete(fid); err != nil {
		t.Fatalf("delete feed: %v", err)
	}
	if _, err := repo.Get(fid); err == nil {
		t.Fatalf("删除后订阅源仍存在")
	}
	if n := repo.CountFeedEntries(fid); n != 0 {
		t.Fatalf("删除后期望 0 条派生条目, 实得 %d", n)
	}
}
