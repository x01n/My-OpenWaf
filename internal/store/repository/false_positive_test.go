package repository

import (
	"testing"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newFalsePositiveRepoForTest(t *testing.T) *FalsePositiveRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.FalsePositiveReport{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewFalsePositiveRepo(db)
}

func TestFalsePositiveCreateListGetUpdate(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)

	rec := &store.FalsePositiveReport{
		SecurityEventID: 42,
		RequestID:       "req-abc",
		RuleIDStr:       "owasp:sqli:1001",
		Category:        "owasp",
		ClientIP:        "1.2.3.4",
		Host:            "example.com",
		Path:            "/api/login",
		SubmittedBy:     "admin",
		Note:            "误报 - 是合法登录尝试",
		Status:          "pending",
	}
	if err := repo.Create(rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	if rec.ID == 0 {
		t.Fatal("id not set after create")
	}

	// List 无过滤应返回该记录。
	items, total, err := repo.List(0, 10, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("list count = %d/%d, want 1/1", total, len(items))
	}
	if items[0].Note != rec.Note {
		t.Errorf("note = %q, want %q", items[0].Note, rec.Note)
	}

	// Get by id。
	got, err := repo.Get(rec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RuleIDStr != rec.RuleIDStr {
		t.Errorf("rule = %q, want %q", got.RuleIDStr, rec.RuleIDStr)
	}

	// UpdateStatus。
	if err := repo.UpdateStatus(rec.ID, "confirmed"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = repo.Get(rec.ID)
	if got.Status != "confirmed" {
		t.Errorf("status = %q, want confirmed", got.Status)
	}

	// List 按 status 过滤。
	_, cnt, _ := repo.List(0, 10, "pending")
	if cnt != 0 {
		t.Errorf("pending count = %d, want 0 after status change", cnt)
	}
	_, cnt, _ = repo.List(0, 10, "confirmed")
	if cnt != 1 {
		t.Errorf("confirmed count = %d, want 1", cnt)
	}

	// Delete。
	if err := repo.Delete(rec.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, cnt, _ = repo.List(0, 10, "")
	if cnt != 0 {
		t.Errorf("count after delete = %d, want 0", cnt)
	}
}
