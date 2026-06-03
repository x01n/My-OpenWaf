package repository

import (
	"testing"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestRecordedResourceRepoUpsertIncrementsHitCount(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resource: %v", err)
	}

	repo := NewRecordedResourceRepo(db)
	first := &store.RecordedResource{
		SiteID:         1,
		Method:         "GET",
		Host:           "example.com",
		Path:           "/login",
		StatusCode:     200,
		MatchedRuleIDs: "1",
		PrimaryRuleID:  1,
		HitCount:       1,
	}
	if err := repo.Upsert(first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	second := &store.RecordedResource{
		SiteID:         1,
		Method:         "GET",
		Host:           "example.com",
		Path:           "/login",
		StatusCode:     403,
		MatchedRuleIDs: "2",
		PrimaryRuleID:  2,
		HitCount:       1,
	}
	if err := repo.Upsert(second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	var got store.RecordedResource
	if err := db.Where("site_id = ? AND method = ? AND host = ? AND path = ?", 1, "GET", "example.com", "/login").First(&got).Error; err != nil {
		t.Fatalf("load recorded resource: %v", err)
	}
	if got.HitCount != 2 || got.StatusCode != 403 || got.PrimaryRuleID != 2 || got.MatchedRuleIDs != "2" {
		t.Fatalf("upsert did not refresh aggregate row: %#v", got)
	}
}
