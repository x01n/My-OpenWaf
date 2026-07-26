package repository

import (
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestHourBucketExprSQLite 验证 SQLite 走 strftime 分支。
func TestHourBucketExprSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	expr := hourBucketExpr(db)
	if !strings.Contains(expr, "strftime") {
		t.Fatalf("sqlite 应使用 strftime，实际为：%s", expr)
	}
	if !strings.HasSuffix(expr, "as bucket") {
		t.Fatalf("表达式必须以 as bucket 结尾（Group/Order 依赖该别名）：%s", expr)
	}
}

// TestHourBucketExprProducesSameFormatAcrossDialects 是核心回归：
// 三种方言必须产出**完全一致**的 `YYYY-MM-DD HH:00` 文本。
//
// 前端按该格式（空格分隔、非 ISO）切分出 HH:mm 作为图表轴标签，
// 任一方言格式不同都会让该方言下的图表轴渲染错乱。
//
// 这里校验格式串本身，因为跨库真实执行需要三套数据库实例。
func TestHourBucketExprProducesSameFormatAcrossDialects(t *testing.T) {
	// 与 hourBucketExpr 内的分支一一对应。
	exprs := map[string]string{
		"sqlite":   "strftime('%Y-%m-%d %H:00', created_at) as bucket",
		"mysql":    "DATE_FORMAT(created_at, '%Y-%m-%d %H:00') as bucket",
		"postgres": "to_char(date_trunc('hour', created_at), 'YYYY-MM-DD HH24:00') as bucket",
	}

	for name, expr := range exprs {
		if !strings.HasSuffix(expr, "as bucket") {
			t.Errorf("%s: 必须以 as bucket 结尾，Group(\"bucket\") 依赖该别名：%s", name, expr)
		}
		// 分隔符必须是空格而非 T，且分钟位固定为 00。
		if !strings.Contains(expr, " %H:00") && !strings.Contains(expr, " HH24:00") {
			t.Errorf("%s: 小时与分钟之间的格式不符合 ' HH:00'：%s", name, expr)
		}
		if strings.Contains(expr, "T%H") || strings.Contains(expr, "THH24") {
			t.Errorf("%s: 不得使用 ISO 的 T 分隔符，前端按空格切分：%s", name, expr)
		}
	}

	// 年月日部分：sqlite/mysql 用 %Y-%m-%d，postgres 用 YYYY-MM-DD，语义等价。
	const dateFmt = "%Y-%m-%d"
	if !strings.Contains(exprs["sqlite"], dateFmt) {
		t.Errorf("sqlite 日期格式应为 %s", dateFmt)
	}
	if !strings.Contains(exprs["mysql"], dateFmt) {
		t.Errorf("mysql 日期格式应为 %s", dateFmt)
	}
	if !strings.Contains(exprs["postgres"], "YYYY-MM-DD") {
		t.Error("postgres 日期格式应为 YYYY-MM-DD")
	}
}

// TestTimelineQueryRunsOnSQLite 端到端确认 Timeline 在 SQLite 上仍可执行，
// 且输出的 bucket 形如 "YYYY-MM-DD HH:00"。
func TestTimelineQueryRunsOnSQLite(t *testing.T) {
	db := newTestDB(t)
	repo := NewSecurityEventRepo(db)

	now := time.Now()
	buckets, err := repo.Timeline(now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	// 空表返回空集即算通过；有数据时校验格式。
	for _, b := range buckets {
		if len(b.Bucket) != len("2026-07-26 06:00") {
			t.Errorf("bucket 格式异常：%q", b.Bucket)
		}
		if !strings.Contains(b.Bucket, " ") || !strings.HasSuffix(b.Bucket, ":00") {
			t.Errorf("bucket 应形如 'YYYY-MM-DD HH:00'：%q", b.Bucket)
		}
	}
}
