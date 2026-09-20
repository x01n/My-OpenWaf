package detect

import (
	"errors"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

func loadOWASPViews(db *gorm.DB, policyID uint, c *app.RequestContext) ([]owaspRuleView, error) {
	category := strings.TrimSpace(string(c.Query("category")))
	query := strings.TrimSpace(string(c.Query("q")))
	if len(query) > maxRuleSearchQueryBytes {
		return nil, errors.New("q exceeds 256 bytes")
	}
	snapshot, err := getOWASPReadSnapshot(db, policyID)
	if err != nil {
		return nil, err
	}
	if category == "" && query == "" {
		return snapshot.views, nil
	}
	likePattern := "%" + query + "%"
	var nativeMatches map[string]struct{}
	if query != "" && !usesSQLiteOWASPInMemoryLike(db) {
		matchingIDs, matchErr := loadNativeOWASPMatchingRuleIDs(db, category, likePattern)
		if matchErr != nil {
			return nil, matchErr
		}
		nativeMatches = make(map[string]struct{}, len(matchingIDs))
		for i := range matchingIDs {
			nativeMatches[matchingIDs[i]] = struct{}{}
		}
	}
	views := make([]owaspRuleView, 0, len(snapshot.views))
	for i := range snapshot.views {
		view := snapshot.views[i]
		if category != "" && view.Category != category {
			continue
		}
		if query != "" {
			if nativeMatches != nil {
				if _, ok := nativeMatches[view.ID]; !ok {
					continue
				}
			} else if !sqliteASCIILike(likePattern, view.ID) &&
				!sqliteASCIILike(likePattern, view.Name) &&
				!sqliteASCIILike(likePattern, view.Description) {
				continue
			}
		}
		views = append(views, view)
	}
	return views, nil
}

func usesSQLiteOWASPInMemoryLike(db *gorm.DB) bool {
	return strings.EqualFold(db.Dialector.Name(), "sqlite")
}

/**
 * loadNativeOWASPMatchingRuleIDs 让非 SQLite 数据库使用自身的 LIKE 与排序规则，
 * 仅返回命中规则 ID，避免在应用层猜测 MySQL 或 PostgreSQL 的 collation。
 */
func loadNativeOWASPMatchingRuleIDs(db *gorm.DB, category, likePattern string) ([]string, error) {
	query := db.Model(&store.OWASPRuleCatalog{}).
		Where("active = ?", true).
		Where("rule_id LIKE ? OR name LIKE ? OR description LIKE ?", likePattern, likePattern, likePattern)
	if category != "" {
		query = query.Where("category = ?", category)
	}
	var ruleIDs []string
	if err := query.Pluck("rule_id", &ruleIDs).Error; err != nil {
		return nil, err
	}
	return ruleIDs, nil
}

func paginateOWASPViews(c *app.RequestContext, views []owaspRuleView) []owaspRuleView {
	page, _ := strconv.Atoi(string(c.Query("page")))
	pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 500 {
		pageSize = 100
	}
	start := (page - 1) * pageSize
	if start >= len(views) {
		return []owaspRuleView{}
	}
	end := start + pageSize
	if end > len(views) {
		end = len(views)
	}
	return views[start:end]
}

/**
 * sqliteASCIILike 实现当前 SQLite LIKE 的 `%`、`_` 与 ASCII 大小写折叠语义。
 */
func sqliteASCIILike(pattern, value string) bool {
	patternRunes := []rune(pattern)
	valueRunes := []rune(value)
	previous := make([]bool, len(valueRunes)+1)
	current := make([]bool, len(valueRunes)+1)
	previous[0] = true
	for _, patternRune := range patternRunes {
		clear(current)
		switch patternRune {
		case '%':
			current[0] = previous[0]
			for i := 1; i <= len(valueRunes); i++ {
				current[i] = previous[i] || current[i-1]
			}
		case '_':
			for i := 1; i <= len(valueRunes); i++ {
				current[i] = previous[i-1]
			}
		default:
			for i := 1; i <= len(valueRunes); i++ {
				current[i] = previous[i-1] && equalSQLiteLikeRune(patternRune, valueRunes[i-1])
			}
		}
		previous, current = current, previous
	}
	return previous[len(valueRunes)]
}

func equalSQLiteLikeRune(left, right rune) bool {
	if left >= 'A' && left <= 'Z' {
		left += 'a' - 'A'
	}
	if right >= 'A' && right <= 'Z' {
		right += 'a' - 'A'
	}
	return left == right
}

type owaspRuleStats struct {
	Total         int            `json:"total"`
	EnabledCount  int            `json:"enabled_count"`
	DisabledCount int            `json:"disabled_count"`
	ByCategory    map[string]int `json:"by_category"`
	PolicyID      uint           `json:"policy_id"`
}

func buildOWASPRuleStats(policyID uint, views []owaspRuleView) owaspRuleStats {
	stats := owaspRuleStats{
		Total:      len(views),
		ByCategory: make(map[string]int),
		PolicyID:   policyID,
	}
	for i := range views {
		stats.ByCategory[views[i].Category]++
		if views[i].Enabled {
			stats.EnabledCount++
		}
	}
	stats.DisabledCount = stats.Total - stats.EnabledCount
	return stats
}
