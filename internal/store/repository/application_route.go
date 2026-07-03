package repository

import (
	"strconv"
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

// RecordedResourceRepo persists aggregated site resource rows and their historical rule metadata.
type RecordedResourceRepo struct{ db *gorm.DB }

func NewRecordedResourceRepo(db *gorm.DB) *RecordedResourceRepo {
	return &RecordedResourceRepo{db: db}
}

type RecordedResourceFilter struct {
	Query       string
	Method      string
	Host        string
	Path        string
	QueryString string
	ClientIP    string
	StatusCode  int
	TLSVersion  string
	TLSSNI      string
	TLSALPN     string
	JA3Hash     string
	JA4         string
	UserAgent   string
	RuleID      uint
}

func (r *RecordedResourceRepo) ListBySite(siteID uint, offset, limit int, f RecordedResourceFilter) ([]store.RecordedResource, int64, error) {
	f = normalizeRecordedResourceFilter(f)
	var list []store.RecordedResource
	var total int64
	q := r.db.Model(&store.RecordedResource{}).Where("site_id = ?", siteID)
	q = applyRecordedResourceFilters(q, f)
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
			{Name: "query_string"},
		},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"last_seen":    rec.LastSeen,
			"hit_count":    gorm.Expr("hit_count + ?", rec.HitCount),
			"status_code":  rec.StatusCode,
			"content_type": rec.ContentType,
			"client_ip":    rec.ClientIP,
			"tls_version":  rec.TLSVersion,
			"tls_sni":      rec.TLSSNI,
			"tls_alpn":     rec.TLSALPN,
			"ja3_hash":     rec.JA3Hash,
			"ja4":          rec.JA4,
			"user_agent":   rec.UserAgent,
			"matched_rule_ids": gorm.Expr(
				"CASE WHEN ? <> '' THEN ? WHEN COALESCE(matched_rule_ids, '') <> '' THEN matched_rule_ids ELSE '' END",
				rec.MatchedRuleIDs,
				rec.MatchedRuleIDs,
			),
			"primary_rule_id": gorm.Expr(
				"CASE WHEN ? > 0 THEN ? WHEN COALESCE(primary_rule_id, 0) > 0 THEN primary_rule_id ELSE 0 END",
				rec.PrimaryRuleID,
				rec.PrimaryRuleID,
			),
			"request_headers_json":  rec.RequestHeadersJSON,
			"response_headers_json": rec.ResponseHeadersJSON,
			"request_body_snippet":  rec.RequestBodySnippet,
			"response_body_snippet": rec.ResponseBodySnippet,
		}),
	}).Create(rec).Error
}

func applyRecordedResourceFilters(q *gorm.DB, f RecordedResourceFilter) *gorm.DB {
	if f.Query != "" {
		like := "%" + f.Query + "%"
		args := []any{
			like,
			like,
			like,
			like,
			like,
			like,
			like,
			like,
			like,
			like,
			like,
			like,
			like,
		}
		expr := `(method LIKE ? OR host LIKE ? OR path LIKE ? OR query_string LIKE ? OR client_ip LIKE ? OR content_type LIKE ? OR tls_version LIKE ? OR tls_sni LIKE ? OR tls_alpn LIKE ? OR ja3_hash LIKE ? OR ja4 LIKE ? OR user_agent LIKE ? OR matched_rule_ids LIKE ?`
		if numeric, err := strconv.Atoi(f.Query); err == nil && numeric > 0 {
			expr += ` OR status_code = ? OR primary_rule_id = ?`
			args = append(args, numeric, numeric)
		}
		expr += `)`
		q = q.Where(expr, args...)
	}
	if f.Method != "" {
		q = q.Where("method = ?", f.Method)
	}
	if f.Host != "" {
		q = q.Where("host LIKE ?", "%"+f.Host+"%")
	}
	if f.Path != "" {
		q = q.Where("path LIKE ?", "%"+f.Path+"%")
	}
	if f.QueryString != "" {
		q = q.Where("query_string LIKE ?", "%"+f.QueryString+"%")
	}
	if f.ClientIP != "" {
		q = q.Where("client_ip = ?", f.ClientIP)
	}
	if f.StatusCode > 0 {
		q = q.Where("status_code = ?", f.StatusCode)
	}
	if f.TLSVersion != "" {
		q = q.Where("tls_version = ?", f.TLSVersion)
	}
	if f.TLSSNI != "" {
		q = q.Where("tls_sni LIKE ?", "%"+f.TLSSNI+"%")
	}
	if f.TLSALPN != "" {
		q = q.Where("tls_alpn LIKE ?", "%"+f.TLSALPN+"%")
	}
	if f.JA3Hash != "" {
		q = q.Where("ja3_hash = ?", f.JA3Hash)
	}
	if f.JA4 != "" {
		q = q.Where("ja4 = ?", f.JA4)
	}
	if f.UserAgent != "" {
		q = q.Where("user_agent LIKE ?", "%"+f.UserAgent+"%")
	}
	if f.RuleID > 0 {
		ruleID := strconv.FormatUint(uint64(f.RuleID), 10)
		q = q.Where(
			`primary_rule_id = ? OR matched_rule_ids = ? OR matched_rule_ids LIKE ? OR matched_rule_ids LIKE ? OR matched_rule_ids LIKE ?`,
			f.RuleID,
			ruleID,
			ruleID+",%",
			"%,"+ruleID+",%",
			"%,"+ruleID,
		)
	}
	return q
}
