package database

import (
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
		{"admin:secret@tcp(127.0.0.1:3306)/waf", "admin:***@tcp(127.0.0.1:3306)/waf"},
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
