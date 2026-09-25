package rules

import (
	"testing"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
)

/**
 * TestQueryParamJSONPathMatcherSharedCaches 与 matcher_test.go 的既有语义测试
 * 互补：这里从签名相快照层验证懒缓存在引擎分相规则全链中的可见性，
 * 即签名/自定义两相之上的请求共享语义没有被 MatchCtx 拷贝破坏。
 *
 * @param t 测试句柄
 * @return void
 */
func TestQueryParamJSONPathMatcherSharedCaches(t *testing.T) {
	ctx := pipeline.AcquireCtx()
	defer pipeline.ReleaseCtx(ctx)

	t.Run("query values across signature phase", func(t *testing.T) {
		ctx.RawQuery = "a=1&b=2"
		sig := NewSignaturePhasePrecompiled(Compile([]store.Rule{
			{Phase: "signature", Pattern: "query_param:a:1", Action: "intercept", Priority: 1, Enabled: true},
		}))
		if r, _ := sig.Execute(ctx); !r.Matched {
			t.Fatal("signature query_param rule should match")
		}
		if _, ok := ctx.CachedMatcherQueryValues(); !ok {
			t.Fatal("query values should be cached after signature phase")
		}
	})

	t.Run("json object across signature phase", func(t *testing.T) {
		ctx.Body = []byte(`{"user":{"role":"admin"}}`)
		sig := NewSignaturePhasePrecompiled(Compile([]store.Rule{
			{Phase: "signature", Pattern: `block_body_json_path:$.user.role:^admin$`, Action: "intercept", Priority: 1, Enabled: true},
		}))
		if r, _ := sig.Execute(ctx); !r.Matched {
			t.Fatal("signature body_json_path rule should match")
		}
		if obj, done := ctx.CachedJSONBodyObject(); !done || obj == nil {
			t.Fatal("JSON parse should be cached after signature phase")
		}
	})
}

var benchRulesSink bool

/**
 * BenchmarkQueryParamMatchersSharedCtx 测 query_param 匹配器两条路线：
 * MatchCtx 携带共享 RequestCtx（拦截链主路径，单请求单次解析）与纯值
 * MatchCtx（回归路径，每条规则各自 url.ParseQuery）。
 *
 * @param b 基准句柄
 * @return void
 */
func BenchmarkQueryParamMatchersSharedCtx(b *testing.B) {
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: "query_param:id:1000", Action: "intercept", Priority: 1, Enabled: true},
		{Phase: "custom", Pattern: "query_param:op:list", Action: "intercept", Priority: 2, Enabled: true},
		{Phase: "custom", Pattern: "query_param_regex:id:^[0-9]+$", Action: "intercept", Priority: 3, Enabled: true},
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := pipeline.AcquireCtx()
		ctx.RawQuery = "id=1000&op=list&x=1"
		mc := ctxFromPipeline(ctx, false)
		for j := range rules {
			benchRulesSink = rules[j].Match(mc)
		}
		pipeline.ReleaseCtx(ctx)
	}
}

func BenchmarkQueryParamMatchersValueCtx(b *testing.B) {
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: "query_param:id:1000", Action: "intercept", Priority: 1, Enabled: true},
		{Phase: "custom", Pattern: "query_param:op:list", Action: "intercept", Priority: 2, Enabled: true},
		{Phase: "custom", Pattern: "query_param_regex:id:^[0-9]+$", Action: "intercept", Priority: 3, Enabled: true},
	})
	mc := MatchCtx{Query: "id=1000&op=list&x=1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range rules {
			benchRulesSink = rules[j].Match(mc)
		}
	}
}

func BenchmarkQueryParamMatcherSingleSharedCtx(b *testing.B) {
	m := &queryParamMatcher{param: "id", value: "1000"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := pipeline.AcquireCtx()
		ctx.RawQuery = "id=1000&op=list&x=1"
		benchRulesSink = m.Match(ctxFromPipeline(ctx, false))
		pipeline.ReleaseCtx(ctx)
	}
}

func BenchmarkQueryParamMatcherSingleValueCtx(b *testing.B) {
	m := &queryParamMatcher{param: "id", value: "1000"}
	mc := MatchCtx{Query: "id=1000&op=list&x=1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRulesSink = m.Match(mc)
	}
}

func BenchmarkBodyJSONPathMatchersSharedCtx(b *testing.B) {
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: `block_body_json_path:$.user.role:^admin$`, Action: "intercept", Priority: 1, Enabled: true},
		{Phase: "custom", Pattern: `block_body_json_path:$.user.session`, Action: "intercept", Priority: 2, Enabled: true},
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := pipeline.AcquireCtx()
		ctx.Body = []byte(`{"user":{"role":"admin","session":"abc123"},"service":"billing"}`)
		mc := ctxFromPipeline(ctx, false)
		for j := range rules {
			benchRulesSink = rules[j].Match(mc)
		}
		pipeline.ReleaseCtx(ctx)
	}
}

func BenchmarkBodyJSONPathMatchersValueCtx(b *testing.B) {
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: `block_body_json_path:$.user.role:^admin$`, Action: "intercept", Priority: 1, Enabled: true},
		{Phase: "custom", Pattern: `block_body_json_path:$.user.session`, Action: "intercept", Priority: 2, Enabled: true},
	})
	mc := MatchCtx{Body: []byte(`{"user":{"role":"admin","session":"abc123"},"service":"billing"}`)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range rules {
			benchRulesSink = rules[j].Match(mc)
		}
	}
}

func BenchmarkBodyJSONPathMatcherSingleSharedCtx(b *testing.B) {
	m := &bodyJSONPathMatcher{jsonPath: "$.user.role", parts: []string{"user", "role"}, pattern: nil}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := pipeline.AcquireCtx()
		ctx.Body = []byte(`{"user":{"role":"admin","session":"abc123"},"service":"billing"}`)
		benchRulesSink = m.Match(ctxFromPipeline(ctx, false))
		pipeline.ReleaseCtx(ctx)
	}
}

func BenchmarkBodyJSONPathMatcherSingleValueCtx(b *testing.B) {
	m := &bodyJSONPathMatcher{jsonPath: "$.user.role", parts: []string{"user", "role"}, pattern: nil}
	mc := MatchCtx{Body: []byte(`{"user":{"role":"admin","session":"abc123"},"service":"billing"}`)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRulesSink = m.Match(mc)
	}
}

/**
 * BenchmarkCustomPhaseQueryParamRules 锚定主路径成本：拦截链一次
 * fillMatchCtxFromPipeline 后执行 3 条 query_param 规则。改写前每条规则
 * 各自 url.ParseQuery（对照 BenchmarkQueryParamMatchersValueCtx 的口径），
 * 改写后单次解析共享。
 *
 * @param b 基准句柄
 * @return void
 */
func BenchmarkCustomPhaseQueryParamRules(b *testing.B) {
	phase := NewCustomPhasePrecompiled(Compile([]store.Rule{
		{Phase: "custom", Pattern: "query_param:id:1000", Action: "intercept", Priority: 1, Enabled: true},
		{Phase: "custom", Pattern: "query_param:op:list", Action: "intercept", Priority: 2, Enabled: true},
		{Phase: "custom", Pattern: "query_param_regex:id:^[0-9]+$", Action: "intercept", Priority: 3, Enabled: true},
	}))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := pipeline.AcquireCtx()
		ctx.RawQuery = "id=1000&op=list&x=1"
		r, _ := phase.Execute(ctx)
		benchRulesSink = r.Matched
		pipeline.ReleaseCtx(ctx)
	}
}
