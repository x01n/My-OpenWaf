package dataplane

import (
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

// newInternalH3StripContext 构造一条带普通业务头的请求上下文。
func newInternalH3StripContext() *app.RequestContext {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/items?page=2")
	ctx.Request.Header.SetHost("shop.example.com")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	ctx.Request.Header.Set("Accept", "text/html")
	ctx.Request.Header.Set("Cookie", "sid=abc123; theme=dark")
	ctx.Request.Header.Set("X-Request-Id", "4b8f2c1e")
	return ctx
}

// TestClearInternalHTTP3MetadataHeadersStripsAllInternalHeaders 钉住「存在内部头时
// 全部剥离」的语义：伪造 rt 头即使没有合法 h3 标记也必须被删除。
func TestClearInternalHTTP3MetadataHeadersStripsAllInternalHeaders(t *testing.T) {
	ctx := newInternalH3StripContext()
	for _, name := range internalHTTP3HeaderNames {
		ctx.Request.Header.Set(name, "forged")
	}

	clearInternalHTTP3RequestMetadataHeaders(ctx)

	for _, name := range internalHTTP3HeaderNames {
		if got := string(ctx.Request.Header.Peek(name)); got != "" {
			t.Fatalf("internal header %s not stripped, got %q", name, got)
		}
	}
	// 普通业务头必须完整保留。
	if got := string(ctx.Request.Header.Peek("X-Request-Id")); got != "4b8f2c1e" {
		t.Fatalf("ordinary header lost, got %q", got)
	}
	if got := string(ctx.Request.Header.Peek("Accept")); got != "text/html" {
		t.Fatalf("ordinary header lost, got %q", got)
	}
}

// TestClearInternalHTTP3MetadataHeadersNoInternalHeaders 钉住「无内部头时不改动
// 任何请求头」的快速路径。
func TestClearInternalHTTP3MetadataHeadersNoInternalHeaders(t *testing.T) {
	ctx := newInternalH3StripContext()
	before := ctx.Request.Header.Len()

	clearInternalHTTP3RequestMetadataHeaders(ctx)

	if got := ctx.Request.Header.Len(); got != before {
		t.Fatalf("header count changed on fast path: %d -> %d", before, got)
	}
	if got := string(ctx.Request.Header.Peek("Accept")); got != "text/html" {
		t.Fatalf("ordinary header lost, got %q", got)
	}
}

// TestHasInternalHTTP3HeaderPrefix 钉住大小写折叠的前缀判定：Hertz 规范化后的
// 形式是 X-Openwaf-...，与常量的 X-OpenWAF 大小写不同。
func TestHasInternalHTTP3HeaderPrefix(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"规范化形式", "X-Openwaf-Internal-Proto", true},
		{"常量原样", "X-OpenWAF-Internal-TLS-JA3", true},
		{"全小写", "x-openwaf-internal-0rtt", true},
		{"普通业务头", "X-Request-Id", false},
		{"前缀相同但更短", "X-Openwaf-Intern", false},
		{"空串", "", false},
		{"相近前缀", "X-Openweb-Internal-Proto", false},
	}
	for _, tc := range cases {
		if got := hasInternalHTTP3HeaderPrefix([]byte(tc.in)); got != tc.want {
			t.Fatalf("%s: hasInternalHTTP3HeaderPrefix(%q) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}

// BenchmarkClearInternalHTTP3MetadataHeadersNoInternal 记录「无内部头」请求的
// 剥离开销，用于佐证快速路径的收益（旧实现固定 15 次 Del）。
func BenchmarkClearInternalHTTP3MetadataHeadersNoInternal(b *testing.B) {
	ctx := newInternalH3StripContext()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clearInternalHTTP3RequestMetadataHeaders(ctx)
	}
}
