package store

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAutoMigrateCreatesOWASPListIndexesAndAvoidsTemporarySort(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&OWASPRuleCatalog{}); err != nil {
		t.Fatalf("migrate OWASP catalog: %v", err)
	}
	items := []OWASPRuleCatalog{
		{RuleID: "owasp:a:002", Category: "a", Name: "a2", Active: true},
		{RuleID: "owasp:a:001", Category: "a", Name: "a1", Active: true},
		{RuleID: "owasp:b:001", Category: "b", Name: "b1", Active: true},
	}
	if err := db.Create(&items).Error; err != nil {
		t.Fatalf("seed OWASP catalog: %v", err)
	}

	tests := []struct {
		name        string
		indexName   string
		wantColumns []string
		query       string
		args        []any
	}{
		{
			name:        "active ordered list",
			indexName:   "idx_owasp_active_rule_id",
			wantColumns: []string{"active", "rule_id"},
			query:       "EXPLAIN QUERY PLAN SELECT * FROM owasp_rule_catalogs WHERE active = ? ORDER BY rule_id ASC LIMIT 500",
			args:        []any{true},
		},
		{
			name:        "active category ordered list",
			indexName:   "idx_owasp_active_category_rule_id",
			wantColumns: []string{"active", "category", "rule_id"},
			query:       "EXPLAIN QUERY PLAN SELECT * FROM owasp_rule_catalogs WHERE active = ? AND category = ? ORDER BY rule_id ASC LIMIT 500",
			args:        []any{true, "a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var columns []struct {
				Seqno int
				Name  string
			}
			if err := db.Raw("PRAGMA index_info(" + tt.indexName + ")").Scan(&columns).Error; err != nil {
				t.Fatalf("read index %s: %v", tt.indexName, err)
			}
			if len(columns) != len(tt.wantColumns) {
				t.Fatalf("index %s columns=%v want=%v", tt.indexName, columns, tt.wantColumns)
			}
			for i := range tt.wantColumns {
				if columns[i].Name != tt.wantColumns[i] {
					t.Fatalf("index %s column[%d]=%q want=%q", tt.indexName, i, columns[i].Name, tt.wantColumns[i])
				}
			}

			var plan []struct{ Detail string }
			if err := db.Raw(tt.query, tt.args...).Scan(&plan).Error; err != nil {
				t.Fatalf("explain query: %v", err)
			}
			var details strings.Builder
			for i := range plan {
				details.WriteString(plan[i].Detail)
				details.WriteByte('\n')
			}
			if !strings.Contains(details.String(), tt.indexName) {
				t.Fatalf("plan does not use %s:\n%s", tt.indexName, details.String())
			}
			if strings.Contains(details.String(), "USE TEMP B-TREE") {
				t.Fatalf("plan uses temporary sort:\n%s", details.String())
			}
		})
	}
}
