package repository

import (
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type BotScoreRepo struct{ db *gorm.DB }

func NewBotScoreRepo(db *gorm.DB) *BotScoreRepo {
	return &BotScoreRepo{db: db}
}

// BotScoreFilter holds query filters for listing bot score logs.
type BotScoreFilter struct {
	ClientIP  string
	MinScore  *int
	MaxScore  *int
	StartTime *time.Time
	EndTime   *time.Time
}

func (r *BotScoreRepo) Create(item *store.BotScoreLog) error {
	return r.db.Create(item).Error
}

func (r *BotScoreRepo) List(offset, limit int, f BotScoreFilter) ([]store.BotScoreLog, int64, error) {
	q := r.db.Model(&store.BotScoreLog{})
	q = applyBotScoreFilters(q, f)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var items []store.BotScoreLog
	if err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// BotScoreStats holds aggregated bot detection statistics.
type BotScoreStats struct {
	Total24h    int64 `json:"total_24h"`
	Blocked24h  int64 `json:"blocked_24h"`
	HighRisk24h int64 `json:"high_risk_24h"`
}

func (r *BotScoreRepo) Stats24h() (*BotScoreStats, error) {
	since := time.Now().Add(-24 * time.Hour)
	var stats BotScoreStats

	r.db.Model(&store.BotScoreLog{}).Where("created_at >= ?", since).Count(&stats.Total24h)
	r.db.Model(&store.BotScoreLog{}).Where("created_at >= ? AND action IN ('block','drop')", since).Count(&stats.Blocked24h)
	r.db.Model(&store.BotScoreLog{}).Where("created_at >= ? AND is_high_risk = ?", since, true).Count(&stats.HighRisk24h)

	return &stats, nil
}

func applyBotScoreFilters(q *gorm.DB, f BotScoreFilter) *gorm.DB {
	if f.ClientIP != "" {
		q = q.Where("client_ip = ?", f.ClientIP)
	}
	if f.MinScore != nil {
		q = q.Where("total_score >= ?", *f.MinScore)
	}
	if f.MaxScore != nil {
		q = q.Where("total_score <= ?", *f.MaxScore)
	}
	if f.StartTime != nil {
		q = q.Where("created_at >= ?", *f.StartTime)
	}
	if f.EndTime != nil {
		q = q.Where("created_at <= ?", *f.EndTime)
	}
	return q
}

// ─── Fingerprint Repo ───────────────────────────────────────────────

type FingerprintRepo struct{ db *gorm.DB }

func NewFingerprintRepo(db *gorm.DB) *FingerprintRepo {
	return &FingerprintRepo{db: db}
}

// FingerprintStats holds aggregated fingerprint statistics.
type FingerprintStats struct {
	TopJA3      []FingerprintEntry `json:"top_ja3"`
	BrowserDist []BrowserDist      `json:"browser_distribution"`
	TotalCount  int64              `json:"total_count"`
}

type FingerprintEntry struct {
	JA3Hash     string `json:"ja3_hash"`
	Count       int64  `json:"count"`
	IsKnownGood bool   `json:"is_known_good"`
}

type BrowserDist struct {
	Browser string `json:"browser"`
	Count   int64  `json:"count"`
}

func (r *FingerprintRepo) GetStats() (*FingerprintStats, error) {
	var totalCount int64
	r.db.Model(&store.FingerprintRecord{}).Count(&totalCount)

	var topJA3 []FingerprintEntry
	r.db.Model(&store.FingerprintRecord{}).
		Select("ja3_hash, count, is_known_good").
		Order("count DESC").
		Limit(10).
		Scan(&topJA3)

	var browserDist []BrowserDist
	r.db.Model(&store.FingerprintRecord{}).
		Select("browser, SUM(count) as count").
		Where("browser != ''").
		Group("browser").
		Order("count DESC").
		Scan(&browserDist)

	return &FingerprintStats{
		TopJA3:      topJA3,
		BrowserDist: browserDist,
		TotalCount:  totalCount,
	}, nil
}
