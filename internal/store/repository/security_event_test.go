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
		{GeoCountry: "", CreatedAt: now.Add(-time.Hour)},   // 无地理信息应被排除
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
