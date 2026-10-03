package store

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// TestSecurityEventRuleInfoColumnsRoundTrip 守护 security_events 的规则
// 解释列：模型、AutoMigrateLogs 与 GORM 写读必须一致。
//
// 这些列同时被三处硬编码清单引用，任一处漏改都会在运行期才暴露：
//   - internal/observability/sqlite_bulk_flusher.go 的 securityEventSpecValues
//   - internal/store/repository/security_event.go 的 securityEventListColumns
//   - internal/admin/system/realtime.go 的 realtimeSecurityEvent
func TestSecurityEventRuleInfoColumnsRoundTrip(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "logs.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := AutoMigrateLogs(db); err != nil {
		t.Fatalf("AutoMigrateLogs: %v", err)
	}
	original := SecurityEvent{
		RequestID:    "rule-info-round-trip",
		Host:         "example.test",
		Path:         "/x",
		Method:       "GET",
		RuleIDStr:    "owasp:sqli:001",
		RuleName:     "SQL UNION 联合查询注入",
		RuleDesc:     "使用 UNION SELECT 追加攻击者控制的返回结果集",
		MatchScore:   7,
		MatchSnippet: "id=1 union select 1,2,3",
		MatchPart:    "body",
		Severity:     "critical",
		Source:       "nvd",
		CVSSScore:    9.8,
		CWEType:      "CWE-89",
		References:   "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
	}
	if err := db.Create(&original).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	var loaded SecurityEvent
	if err := db.First(&loaded, original.ID).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if loaded.RuleName != original.RuleName ||
		loaded.RuleDesc != original.RuleDesc ||
		loaded.MatchScore != original.MatchScore ||
		loaded.MatchSnippet != original.MatchSnippet ||
		loaded.MatchPart != original.MatchPart ||
		loaded.Severity != original.Severity ||
		loaded.Source != original.Source ||
		loaded.CVSSScore != original.CVSSScore ||
		loaded.CWEType != original.CWEType ||
		loaded.References != original.References {
		t.Fatalf("rule-info round trip mismatch:\n got %+v\nwant %+v", loaded, original)
	}
}
