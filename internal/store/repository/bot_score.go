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
	Host      string
	Path      string
	UserAgent string
	RequestID string
	JA3Hash   string
	JA4       string
	TLSSNI    string
	HighRisk  *bool
	MinScore  *int
	MaxScore  *int
	StartTime *time.Time
	EndTime   *time.Time
}

func (r *BotScoreRepo) Create(item *store.BotScoreLog) error {
	return r.db.Create(item).Error
}

// BatchCreate inserts multiple bot score logs in a single transaction.
func (r *BotScoreRepo) BatchCreate(items []store.BotScoreLog) error {
	if len(items) == 0 {
		return nil
	}
	return r.db.CreateInBatches(items, 100).Error
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
	Total24h    int64   `json:"total_24h"`
	Blocked24h  int64   `json:"blocked_24h"`
	HighRisk24h int64   `json:"high_risk_24h"`
	AvgScore24h float64 `json:"avg_score_24h"`
}

func (r *BotScoreRepo) Stats24h() (*BotScoreStats, error) {
	since := time.Now().Add(-24 * time.Hour)

	var result struct {
		Total    int64   `gorm:"column:total"`
		Blocked  int64   `gorm:"column:blocked"`
		HighRisk int64   `gorm:"column:high_risk"`
		AvgScore float64 `gorm:"column:avg_score"`
	}
	err := r.db.Model(&store.BotScoreLog{}).
		Select("COUNT(*) as total, "+
			"SUM(CASE WHEN action IN ('block','drop') THEN 1 ELSE 0 END) as blocked, "+
			"SUM(CASE WHEN is_high_risk = 1 THEN 1 ELSE 0 END) as high_risk, "+
			"COALESCE(AVG(total_score), 0) as avg_score").
		Where("created_at >= ?", since).
		Scan(&result).Error
	if err != nil {
		return nil, err
	}

	return &BotScoreStats{
		Total24h:    result.Total,
		Blocked24h:  result.Blocked,
		HighRisk24h: result.HighRisk,
		AvgScore24h: result.AvgScore,
	}, nil
}

func applyBotScoreFilters(q *gorm.DB, f BotScoreFilter) *gorm.DB {
	if f.ClientIP != "" {
		q = q.Where("client_ip = ?", f.ClientIP)
	}
	if f.Host != "" {
		q = q.Where("host LIKE ?", "%"+f.Host+"%")
	}
	if f.Path != "" {
		q = q.Where("path LIKE ?", "%"+f.Path+"%")
	}
	if f.UserAgent != "" {
		q = q.Where("user_agent LIKE ?", "%"+f.UserAgent+"%")
	}
	if f.RequestID != "" {
		q = q.Where("request_id = ?", f.RequestID)
	}
	if f.JA3Hash != "" {
		q = q.Where("tls_ja3_hash = ?", f.JA3Hash)
	}
	if f.JA4 != "" {
		q = q.Where("tls_ja4 = ?", f.JA4)
	}
	if f.TLSSNI != "" {
		q = q.Where("tls_sni LIKE ?", "%"+f.TLSSNI+"%")
	}
	if f.HighRisk != nil {
		q = q.Where("is_high_risk = ?", *f.HighRisk)
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
