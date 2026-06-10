package repository

import (
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newBotScoreRepoForTest(t *testing.T) *BotScoreRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.BotScoreLog{}); err != nil {
		t.Fatalf("migrate bot score log: %v", err)
	}
	return NewBotScoreRepo(db)
}

func TestBotScoreRepoStats24hAggregatesAverageAndCounts(t *testing.T) {
	repo := newBotScoreRepoForTest(t)
	now := time.Now()
	items := []store.BotScoreLog{
		{TotalScore: 90, IsHighRisk: true, Action: "block", CreatedAt: now.Add(-time.Hour)},
		{TotalScore: 60, IsHighRisk: false, Action: "drop", CreatedAt: now.Add(-2 * time.Hour)},
		{TotalScore: 30, IsHighRisk: false, Action: "allow", CreatedAt: now.Add(-3 * time.Hour)},
		{TotalScore: 100, IsHighRisk: true, Action: "block", CreatedAt: now.Add(-25 * time.Hour)},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("seed bot score logs: %v", err)
	}

	stats, err := repo.Stats24h()
	if err != nil {
		t.Fatalf("load bot score stats: %v", err)
	}
	if stats.Total24h != 3 || stats.Blocked24h != 2 || stats.HighRisk24h != 1 {
		t.Fatalf("unexpected stats counts: %#v", stats)
	}
	if stats.AvgScore24h != 60 {
		t.Fatalf("expected avg_score_24h 60, got %v", stats.AvgScore24h)
	}
}

func TestBotScoreRepoListFiltersByTLSSNI(t *testing.T) {
	repo := newBotScoreRepoForTest(t)
	now := time.Now()
	items := []store.BotScoreLog{
		{ClientIP: "203.0.113.10", Host: "one.example", TLSSNI: "login.example.com", TotalScore: 90, CreatedAt: now},
		{ClientIP: "203.0.113.11", Host: "two.example", TLSSNI: "api.example.com", TotalScore: 60, CreatedAt: now},
		{ClientIP: "203.0.113.12", Host: "three.example", TLSSNI: "login.other.test", TotalScore: 40, CreatedAt: now},
	}
	if err := repo.BatchCreate(items); err != nil {
		t.Fatalf("seed bot score logs: %v", err)
	}

	got, total, err := repo.List(0, 20, BotScoreFilter{TLSSNI: "login.example"})
	if err != nil {
		t.Fatalf("list bot score logs: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("expected one tls_sni match, total=%d items=%#v", total, got)
	}
	if got[0].TLSSNI != "login.example.com" {
		t.Fatalf("unexpected tls_sni match: %#v", got[0])
	}
}
