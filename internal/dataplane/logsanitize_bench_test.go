package dataplane

import "testing"

// 绝大多数 header value 不含敏感关键字，这是最常见的输入形态。
var benchPlainValues = []string{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"gzip, deflate, br",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"zh-CN,zh;q=0.9,en;q=0.8",
	"keep-alive",
	"https://example.com/products/12345?page=2&sort=price",
}

var benchSensitiveValue = "user=admin&password=hunter2&token=abcdef123456"

func BenchmarkSanitizeLogTextPlain(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, v := range benchPlainValues {
			_ = sanitizeLogText(v)
		}
	}
}

func BenchmarkSanitizeLogTextSensitive(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeLogText(benchSensitiveValue)
	}
}

func BenchmarkIsSensitiveLogKey(b *testing.B) {
	keys := []string{"user-agent", "accept-encoding", "content-type", "authorization", "x-request-id"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, k := range keys {
			_ = isSensitiveLogKey(k)
		}
	}
}
