package pipeline

import "testing"

// benchmarkPoolHeaderKeyFill 以 fixedKeys 头键数模拟一个全新 ctx 的
// HeaderKeys 填充:池外新建(等价于池刚启动/峰值期 New)时,初始 cap
// 决定是否发生扩容。稳态下 ctx 从池中取出,容量已定型,该指标为 0。
func benchmarkPoolHeaderKeyFill(b *testing.B, fixedKeys int) {
	keys := make([]string, fixedKeys)
	host := "example.com"
	for i := range keys {
		keys[i] = host
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := &RequestCtx{HeaderKeys: make([]string, 0, pooledHeaderKeysBaseCap)}
		for _, k := range keys {
			ctx.AppendHeaderKey(k)
		}
		if len(ctx.HeaderKeys) != fixedKeys {
			b.Fatalf("unexpected header key count: %d", len(ctx.HeaderKeys))
		}
	}
}

// BenchmarkPoolFreshHeaderKeys20 测量"池空期"20 头 ctx 的填充扩容次数。
// pooledHeaderKeysBaseCap>=20 时仅 New 一次分配,扩容为 0。
func BenchmarkPoolFreshHeaderKeys20(b *testing.B) { benchmarkPoolHeaderKeyFill(b, 20) }

// BenchmarkPoolFreshHeaderKeys12 覆盖常见请求(约 12 头)的填充路径。
func BenchmarkPoolFreshHeaderKeys12(b *testing.B) { benchmarkPoolHeaderKeyFill(b, 12) }
