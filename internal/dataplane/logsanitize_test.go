package dataplane

import (
	"strings"
	"testing"
)

// TestSensitiveLogValueHintsCoverPattern 是防漏改回归：
// sanitizeLogText 用 sensitiveLogValueHints 做前置短路，一旦正则新增了关键字
// 而 hints 未同步，该关键字的取值将不再被遮蔽——属于静默的凭据泄漏。
//
// 这里对正则首个捕获组中的每个字面量构造样本，逐一验证仍会被脱敏。
func TestSensitiveLogValueHintsCoverPattern(t *testing.T) {
	// 与 sensitiveLogValuePattern 首个捕获组一致的关键字清单。
	// api[_-]?key 与 auth[_-]?token 展开为各自的三种写法。
	patternKeywords := []string{
		"password", "passwd", "pwd", "token", "secret", "session",
		"apikey", "api_key", "api-key",
		"authtoken", "auth_token", "auth-token",
		"csrf", "code",
	}
	for _, kw := range patternKeywords {
		input := kw + "=supersecretvalue"
		got := sanitizeLogText(input)
		if strings.Contains(got, "supersecretvalue") {
			t.Errorf("关键字 %q 的取值未被遮蔽：%q —— 请同步更新 sensitiveLogValueHints", kw, got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("关键字 %q 的结果缺少 [redacted]：%q", kw, got)
		}
	}
}

// TestSanitizeLogTextCaseInsensitive 验证前置短路不破坏正则的大小写无关性。
func TestSanitizeLogTextCaseInsensitive(t *testing.T) {
	for _, input := range []string{
		"PASSWORD=hunter2",
		"Token: AbCdEf123456",
		"Api-Key=xyz789",
		"SeSsIoN=deadbeef",
	} {
		got := sanitizeLogText(input)
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("大小写混合输入 %q 未被遮蔽：%q", input, got)
		}
	}
}

// TestSanitizeLogTextLeavesPlainTextUntouched 验证无敏感内容时原样返回。
func TestSanitizeLogTextLeavesPlainTextUntouched(t *testing.T) {
	for _, input := range []string{
		"",
		"Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0",
		"gzip, deflate, br",
		"text/html,application/xhtml+xml;q=0.9",
		"https://example.com/products/12345?page=2&sort=price",
	} {
		if got := sanitizeLogText(input); got != input {
			t.Errorf("普通文本被改动：输入 %q 得到 %q", input, got)
		}
	}
}

// TestSanitizeLogTextRedactsOnlyValue 验证只遮蔽取值，保留键名与分隔符，
// 便于排障时仍能看出出现过哪个字段。
func TestSanitizeLogTextRedactsOnlyValue(t *testing.T) {
	got := sanitizeLogText("user=admin&password=hunter2&page=1")
	if !strings.Contains(got, "user=admin") {
		t.Errorf("非敏感字段应保留：%q", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("敏感取值未被遮蔽：%q", got)
	}
	if !strings.Contains(got, "password") {
		t.Errorf("键名应保留：%q", got)
	}
}

// TestIsSensitiveLogKeyLoweredMatchesWrapper 验证两个版本判定一致，
// 且 Lowered 版对已小写输入免去重复转换。
func TestIsSensitiveLogKeyLoweredMatchesWrapper(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"Authorization", true},
		{"authorization", true},
		{"COOKIE", true},
		{"Set-Cookie", true},
		{"X-Api-Key", true},
		{"X-CSRF-Token", true},
		{"User-Agent", false},
		{"Accept-Encoding", false},
		{"Content-Type", false},
		{"", false},
	}
	for _, tt := range cases {
		if got := isSensitiveLogKey(tt.key); got != tt.want {
			t.Errorf("isSensitiveLogKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
		if got := isSensitiveLogKeyLowered(toLowerASCII(tt.key)); got != tt.want {
			t.Errorf("isSensitiveLogKeyLowered(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}
