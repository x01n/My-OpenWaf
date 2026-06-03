package repository

import (
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ApplicationRouteRuleRepo struct{ db *gorm.DB }

func NewApplicationRouteRuleRepo(db *gorm.DB) *ApplicationRouteRuleRepo {
	return &ApplicationRouteRuleRepo{db: db}
}

func (r *ApplicationRouteRuleRepo) ListBySite(siteID uint) ([]store.ApplicationRouteRule, error) {
	var list []store.ApplicationRouteRule
	return list, r.db.Where("site_id = ?", siteID).Order("priority DESC, id ASC").Find(&list).Error
}

func (r *ApplicationRouteRuleRepo) ListBySitePaged(siteID uint, offset, limit int) ([]store.ApplicationRouteRule, int64, error) {
	var list []store.ApplicationRouteRule
	var total int64
	q := r.db.Model(&store.ApplicationRouteRule{}).Where("site_id = ?", siteID)
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Order("priority DESC, id ASC").Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func (r *ApplicationRouteRuleRepo) Get(id uint) (*store.ApplicationRouteRule, error) {
	var item store.ApplicationRouteRule
	if err := r.db.First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *ApplicationRouteRuleRepo) Create(item *store.ApplicationRouteRule) error {
	enabled := item.Enabled
	if err := r.db.Create(item).Error; err != nil {
		return err
	}
	if !enabled {
		if err := r.db.Model(item).UpdateColumn("enabled", false).Error; err != nil {
			return err
		}
		item.Enabled = false
	}
	return nil
}

func (r *ApplicationRouteRuleRepo) Update(item *store.ApplicationRouteRule) error {
	return r.db.Save(item).Error
}

func (r *ApplicationRouteRuleRepo) Delete(id uint) error {
	return r.db.Delete(&store.ApplicationRouteRule{}, id).Error
}

// RecordedResourceRepo persists aggregated resource rows when application-route rules match.
type RecordedResourceRepo struct{ db *gorm.DB }

func NewRecordedResourceRepo(db *gorm.DB) *RecordedResourceRepo {
	return &RecordedResourceRepo{db: db}
}

func (r *RecordedResourceRepo) ListBySite(siteID uint, offset, limit int) ([]store.RecordedResource, int64, error) {
	var list []store.RecordedResource
	var total int64
	q := r.db.Model(&store.RecordedResource{}).Where("site_id = ?", siteID)
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Order("last_seen DESC, id DESC").Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func (r *RecordedResourceRepo) ClearSite(siteID uint) error {
	return r.db.Where("site_id = ?", siteID).Delete(&store.RecordedResource{}).Error
}

// Upsert increments hit_count and refreshes metadata when the same resource key appears again.
func (r *RecordedResourceRepo) Upsert(rec *store.RecordedResource) error {
	if rec == nil {
		return nil
	}
	now := time.Now().UTC()
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	rec.LastSeen = now
	if rec.HitCount <= 0 {
		rec.HitCount = 1
	}

	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "site_id"},
			{Name: "method"},
			{Name: "host"},
			{Name: "path"},
		},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"last_seen":             rec.LastSeen,
			"hit_count":             gorm.Expr("hit_count + ?", rec.HitCount),
			"status_code":           rec.StatusCode,
			"content_type":          rec.ContentType,
			"client_ip":             rec.ClientIP,
			"ja3_hash":              rec.JA3Hash,
			"user_agent":            rec.UserAgent,
			"matched_rule_ids":      rec.MatchedRuleIDs,
			"primary_rule_id":       rec.PrimaryRuleID,
			"request_headers_json":  rec.RequestHeadersJSON,
			"response_headers_json": rec.ResponseHeadersJSON,
			"request_body_snippet":  rec.RequestBodySnippet,
			"response_body_snippet": rec.ResponseBodySnippet,
		}),
	}).Create(rec).Error
}
