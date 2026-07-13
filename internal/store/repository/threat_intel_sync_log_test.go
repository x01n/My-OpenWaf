package repository

import (
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newTISyncLogRepoForTest(t *testing.T) *ThreatIntelSyncLogRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.ThreatIntelSyncLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewThreatIntelSyncLogRepo(db)
}

func TestThreatIntelSyncLogCreateAndList(t *testing.T) {
	repo := newTISyncLogRepoForTest(t)
	now := time.Now()

	// 追加 3 条：2 成功 1 失败，混合 feedID 与 trigger。
	entries := []*store.ThreatIntelSyncLog{
		{FeedID: 1, FeedName: "A", StartedAt: now.Add(-3 * time.Minute), FinishedAt: now.Add(-3 * time.Minute).Add(500 * time.Millisecond), DurationMs: 500, Success: true, EntriesAdded: 120, Trigger: "auto"},
		{FeedID: 1, FeedName: "A", StartedAt: now.Add(-2 * time.Minute), FinishedAt: now.Add(-2 * time.Minute).Add(300 * time.Millisecond), DurationMs: 300, Success: false, Trigger: "manual", Error: "拉取失败: connection refused"},
		{FeedID: 2, FeedName: "B", StartedAt: now.Add(-1 * time.Minute), FinishedAt: now.Add(-1 * time.Minute).Add(700 * time.Millisecond), DurationMs: 700, Success: true, EntriesAdded: 50, Trigger: "auto"},
	}
	for _, e := range entries {
		if err := repo.Create(e); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	// 全部（3 条），按 created_at DESC 排序。
	items, total, err := repo.List(0, 10, 0, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("count = %d/%d, want 3/3", total, len(items))
	}

	// 只取 FeedID=1 的：2 条。
	_, cnt, _ := repo.List(0, 10, 1, "")
	if cnt != 2 {
		t.Errorf("feed=1 count = %d, want 2", cnt)
	}

	// status=success：2 条。
	_, cnt, _ = repo.List(0, 10, 0, "success")
	if cnt != 2 {
		t.Errorf("success count = %d, want 2", cnt)
	}

	// status=failed：1 条。
	_, cnt, _ = repo.List(0, 10, 0, "failed")
	if cnt != 1 {
		t.Errorf("failed count = %d, want 1", cnt)
	}

	// feedID=1 且 status=failed：1 条。
	_, cnt, _ = repo.List(0, 10, 1, "failed")
	if cnt != 1 {
		t.Errorf("feed=1 failed count = %d, want 1", cnt)
	}
}

func TestThreatIntelSyncLogDeleteOlderThan(t *testing.T) {
	repo := newTISyncLogRepoForTest(t)
	now := time.Now()

	// 一条 10 天前，一条今天。
	old := &store.ThreatIntelSyncLog{FeedID: 1, StartedAt: now.Add(-10 * 24 * time.Hour), Success: true}
	recent := &store.ThreatIntelSyncLog{FeedID: 1, StartedAt: now, Success: true}
	if err := repo.Create(old); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(recent); err != nil {
		t.Fatal(err)
	}
	// 手动回填 CreatedAt（GORM 会自动填当前时间，无法直接测保留策略）。
	if err := repo.db.Model(old).Update("created_at", now.Add(-10*24*time.Hour)).Error; err != nil {
		t.Fatal(err)
	}

	deleted, err := repo.DeleteOlderThan(now.Add(-7 * 24 * time.Hour))
	if err != nil {
		t.Fatalf("delete older: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
	_, total, _ := repo.List(0, 10, 0, "")
	if total != 1 {
		t.Errorf("remaining = %d, want 1", total)
	}
}
