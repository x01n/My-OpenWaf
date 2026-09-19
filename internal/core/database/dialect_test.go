package database

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenMySQLRequiresParseTime 验证缺少 parseTime=True 时在启动阶段即报错。
//
// 若放过，DATETIME 列会被扫描成 []byte 而模型是 time.Time，
// 问题要等到首次查询 created_at 才暴露，排障成本高得多。
func TestOpenMySQLRequiresParseTime(t *testing.T) {
	_, err := Open(Options{
		Driver: "mysql",
		DSN:    "user:pass@tcp(127.0.0.1:3306)/waf?charset=utf8mb4",
	})
	if err == nil {
		t.Fatal("缺少 parseTime=True 应报错")
	}
	if !strings.Contains(err.Error(), "parseTime=True") {
		t.Fatalf("错误信息应指出 parseTime=True，实际为：%v", err)
	}
}

// TestOpenMySQLErrorMasksPassword 验证错误信息不泄漏 DSN 中的口令。
func TestOpenMySQLErrorMasksPassword(t *testing.T) {
	_, err := Open(Options{
		Driver: "mysql",
		DSN:    "admin:sup3rs3cret@tcp(127.0.0.1:3306)/waf?charset=utf8mb4",
	})
	if err == nil {
		t.Fatal("应报错")
	}
	if strings.Contains(err.Error(), "sup3rs3cret") {
		t.Fatalf("错误信息泄漏了口令：%v", err)
	}
}

func TestOpenMySQLEmptyDSN(t *testing.T) {
	if _, err := Open(Options{Driver: "mysql"}); err == nil {
		t.Fatal("空 DSN 应报错")
	}
}

func TestOpenPostgresEmptyDSN(t *testing.T) {
	if _, err := Open(Options{Driver: "postgres"}); err == nil {
		t.Fatal("空 DSN 应报错")
	}
}

func TestOpenUnsupportedDriver(t *testing.T) {
	_, err := Open(Options{Driver: "oracle", DSN: "x"})
	if err == nil {
		t.Fatal("不支持的驱动应报错")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("错误信息不明确：%v", err)
	}
}

// TestOpenSQLiteLogDBPragmas 验证 LogDB 标记切换日志库专属 PRAGMA 组合。
//
// 主库必须保持 foreign_keys=ON 与较激进的检查点；
// 日志库为高写入率关闭外键校验、扩大页缓存并后移检查点。
func TestOpenSQLiteLogDBPragmas(t *testing.T) {
	dir := t.TempDir()
	mainDB := filepath.Join(dir, "waf.db")
	logDB := filepath.Join(dir, "waf_logs.db")

	mh, err := Open(Options{Driver: "sqlite", DSN: mainDB})
	if err != nil {
		t.Fatalf("打开主库失败：%v", err)
	}
	lh, err := Open(Options{Driver: "sqlite", DSN: logDB, LogDB: true})
	if err != nil {
		t.Fatalf("打开日志库失败：%v", err)
	}

	var mainFK, logFK int
	if err := mh.Raw("PRAGMA foreign_keys").Scan(&mainFK).Error; err != nil {
		t.Fatalf("读主库 foreign_keys 失败：%v", err)
	}
	if err := lh.Raw("PRAGMA foreign_keys").Scan(&logFK).Error; err != nil {
		t.Fatalf("读日志库 foreign_keys 失败：%v", err)
	}
	if mainFK != 1 {
		t.Fatalf("主库 foreign_keys=%d，应为 1", mainFK)
	}
	if logFK != 0 {
		t.Fatalf("日志库 foreign_keys=%d，应为 0", logFK)
	}
}

// TestPostgresqlAliasAccepted 验证 postgresql 别名被 Open 接受（走到 DSN 校验而非
// "unsupported driver"）。与 core.Config.Validate 的白名单必须一致。
func TestPostgresqlAliasAccepted(t *testing.T) {
	_, err := Open(Options{Driver: "postgresql"})
	if err == nil {
		t.Fatal("空 DSN 应报错")
	}
	if strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("postgresql 别名应被接受，实际被拒：%v", err)
	}
	if !strings.Contains(err.Error(), "postgres requires") {
		t.Fatalf("应走到 postgres 的 DSN 校验，实际为：%v", err)
	}
}

func TestPreferSimpleProtocolFromDSN(t *testing.T) {
	cases := []struct {
		dsn  string
		want bool
	}{
		{"postgres://u:p@localhost:5432/waf?sslmode=disable", false},
		{"postgres://u:p@localhost:6432/waf?pgbouncer=true", true},
		{"postgres://u:p@localhost:6432/waf?PgBouncer=True", true},
		{"", false},
	}
	for _, tt := range cases {
		if got := preferSimpleProtocolFromDSN(tt.dsn); got != tt.want {
			t.Errorf("preferSimpleProtocolFromDSN(%q) = %v, want %v", tt.dsn, got, tt.want)
		}
	}
}

func TestMaskDSN(t *testing.T) {
	cases := []struct{ in, want string }{
		{"admin:secret@tcp(127.0.0.1:3306)/waf", "admin:******@tcp(127.0.0.1:3306)/waf"},
		{"nocredentials", "nocredentials"},
	}
	for _, tt := range cases {
		got := maskDSN(tt.in)
		if got != tt.want {
			t.Errorf("maskDSN(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if strings.Contains(got, "secret") {
			t.Errorf("maskDSN 未遮蔽口令：%q", got)
		}
	}
}

// TestMaskDatabaseOpenErrorHidesPostgresCredentials 验证 PostgreSQL 建连错误中的完整 DSN 被再次脱敏。
func TestMaskDatabaseOpenErrorHidesPostgresCredentials(t *testing.T) {
	dsn := `host=db.internal user=waf password="pg secret" dbname=waf`
	err := maskDatabaseOpenError(errors.New("dial failed: "+dsn), dsn)
	if err == nil {
		t.Fatal("应返回脱敏后的错误")
	}
	message := err.Error()
	if strings.Contains(message, "pg secret") || strings.Contains(message, dsn) {
		t.Fatalf("错误信息泄漏 PostgreSQL 凭据：%v", message)
	}
	if !strings.Contains(message, "password=******") {
		t.Fatalf("错误信息未保留脱敏标记：%v", message)
	}
}

// TestMaskDSNKeywordValuesHandlesQuotedPostgresCredentials 验证关键字 DSN 的引号值与畸形值边界。
func TestMaskDSNKeywordValuesHandlesQuotedPostgresCredentials(t *testing.T) {
	cases := []struct {
		name string
		dsn  string
		want string
	}{
		{
			name: "double quoted password",
			dsn:  `host=db.internal password="pg secret" dbname=waf`,
			want: `host=db.internal password=****** dbname=waf`,
		},
		{
			name: "malformed quote",
			dsn:  `host=db.internal password="pg secret dbname=waf`,
			want: "[redacted]",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskDSNKeywordValues(tt.dsn); got != tt.want {
				t.Fatalf("maskDSNKeywordValues(%q) = %q, want %q", tt.dsn, got, tt.want)
			}
		})
	}
}
