package engine

import (
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/waf/luaplugin"
)

// rulesNewLuaPhase 构造管道阶段；rules.NewLuaPhase 返回的是接口，测试需要
// 直接调用 Execute。
func rulesNewLuaPhase(lp *luaplugin.Engine, stage luaplugin.Stage) pipeline.Phase {
	return rules.NewLuaPhase(lp, stage)
}

// actionPass 与 interceptResult 是判定基线，避免每个用例重复构造。
func actionPass() action.Result { return action.Pass() }

func interceptResult() action.Result {
	return action.Result{Type: action.Intercept, Matched: true, Phase: "owasp", Category: "sqli"}
}

// TestLuaPreRequestMutationReachesPipelineContext 锁定 pre 阶段请求改写的
// 核心契约：脚本改写在管道内就地生效，后续阶段看到的是改写后的请求。
func TestLuaPreRequestMutationReachesPipelineContext(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePre, `
function handle(ctx)
  return {
    request = {
      method = "POST",
      path = "/internal/rewritten",
      query = "debug=1",
      headers = { ["X-Internal"] = "1" },
      delete_headers = { "X-Remove" }
    }
  }
end`)

	reqCtx := &pipeline.RequestCtx{
		Bind: ":80", Host: "example.com", Path: "/original", Method: "GET",
		Headers: map[string]string{"x-remove": "gone", "x-keep": "kept"},
	}
	phase := rulesNewLuaPhase(lp, luaplugin.StagePre)
	if _, stop := phase.Execute(reqCtx); stop {
		t.Fatal("request-only mutation must not stop the pipeline")
	}

	if reqCtx.Method != "POST" {
		t.Fatalf("method = %q, want POST", reqCtx.Method)
	}
	if reqCtx.Path != "/internal/rewritten" {
		t.Fatalf("path = %q, want /internal/rewritten", reqCtx.Path)
	}
	if reqCtx.RawQuery != "debug=1" {
		t.Fatalf("raw query = %q, want debug=1", reqCtx.RawQuery)
	}
	if reqCtx.Headers["x-internal"] != "1" {
		t.Fatalf("headers = %#v, want x-internal=1", reqCtx.Headers)
	}
	if _, exists := reqCtx.Headers["x-remove"]; exists {
		t.Fatalf("headers = %#v, want x-remove deleted", reqCtx.Headers)
	}
	if reqCtx.Headers["x-keep"] != "kept" {
		t.Fatalf("headers = %#v, want x-keep kept", reqCtx.Headers)
	}

	mutation, ok := reqCtx.DrainRequestMutation()
	if !ok {
		t.Fatal("DrainRequestMutation() = false, want the mutation for the data plane")
	}
	if mutation.Path == nil || *mutation.Path != "/internal/rewritten" {
		t.Fatalf("drained mutation = %#v", mutation)
	}
	if _, again := reqCtx.DrainRequestMutation(); again {
		t.Fatal("second DrainRequestMutation() must be empty")
	}
}

// TestLuaPreMutationDoesNotChangeVerdictSemantics 确认改写与判定相互独立：
// 只改写的脚本不产生判定，带判定的脚本照常短路。
func TestLuaPreMutationDoesNotChangeVerdictSemantics(t *testing.T) {
	rewriteOnly := luaEngineWith(t, luaplugin.StagePre, `
function handle(ctx) return {request = {path = "/only-rewrite"}} end`)
	reqCtx := &pipeline.RequestCtx{Path: "/original", Headers: map[string]string{}}
	result, stop := rulesNewLuaPhase(rewriteOnly, luaplugin.StagePre).Execute(reqCtx)
	if stop || result.Matched {
		t.Fatalf("rewrite-only script = %#v stop=%v, want no verdict", result, stop)
	}
	if reqCtx.Path != "/only-rewrite" {
		t.Fatalf("path = %q, want /only-rewrite", reqCtx.Path)
	}

	withVerdict := luaEngineWith(t, luaplugin.StagePre, `
function handle(ctx)
  return {action = "intercept", request = {path = "/blocked"}}
end`)
	reqCtx = &pipeline.RequestCtx{Path: "/original", Headers: map[string]string{}}
	result, stop = rulesNewLuaPhase(withVerdict, luaplugin.StagePre).Execute(reqCtx)
	if !stop || result.Type != "intercept" {
		t.Fatalf("verdict = %#v stop=%v, want intercept", result, stop)
	}
	if reqCtx.Path != "/blocked" {
		t.Fatalf("path = %q, want mutation applied alongside verdict", reqCtx.Path)
	}
}

// TestLuaPostResponseMutationReachesRequestContext 锁定 post 阶段响应改写：
// 意图落在请求上下文，供 proxy 的响应变换链消费。
func TestLuaPostResponseMutationReachesRequestContext(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  return {response = {status_code = 503, body = "maintenance", headers = {["X-Waf"] = "1"}}}
end`)

	reqCtx := &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}
	applyPostLuaDecision(lp, reqCtx, actionPass())
	mutations := reqCtx.DrainResponseMutations()
	if len(mutations) != 1 {
		t.Fatalf("response mutations = %#v, want 1", mutations)
	}
	mutation := mutations[0]
	if mutation.StatusCode != 503 || mutation.Body == nil || *mutation.Body != "maintenance" {
		t.Fatalf("mutation = %#v", mutation)
	}
	if mutation.SetHeaders["X-Waf"] != "1" {
		t.Fatalf("set headers = %#v", mutation.SetHeaders)
	}
	if again := reqCtx.DrainResponseMutations(); again != nil {
		t.Fatalf("second drain = %#v, want nil", again)
	}
}

// TestLuaPostMutationSurvivesBuiltinTerminalVerdict 确认 post 的响应改写与
// 「内置判定优先」规则相互独立：内置终止动作保留，但改写意图照样传递。
func TestLuaPostMutationSurvivesBuiltinTerminalVerdict(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx) return {response = {headers = {["X-Post"] = "1"}}} end`)

	reqCtx := &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}
	builtin := interceptResult()
	got := applyPostLuaDecision(lp, reqCtx, builtin)
	if got.Type != builtin.Type {
		t.Fatalf("verdict = %q, want builtin %q preserved", got.Type, builtin.Type)
	}
	if mutations := reqCtx.DrainResponseMutations(); len(mutations) != 1 {
		t.Fatalf("response mutations = %#v, want 1", mutations)
	}
}

// TestLuaPreResponseMutationIgnored 确认 pre 阶段的 response 子表无处可去时
// 不会污染管道上下文：响应还没产生，改写只会是静默失效的开关。
func TestLuaPreResponseMutationIgnored(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePre, `
function handle(ctx) return {response = {status_code = 503}} end`)
	reqCtx := &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}
	rulesNewLuaPhase(lp, luaplugin.StagePre).Execute(reqCtx)
	if mutations := reqCtx.DrainResponseMutations(); len(mutations) != 0 {
		t.Fatalf("pre-stage response mutations = %#v, want none", mutations)
	}
	if _, ok := reqCtx.DrainRequestMutation(); ok {
		t.Fatal("pre-stage response-only script must not register a request mutation")
	}
}

// TestLuaPostRequestMutationIgnored 确认 post 阶段的 request 子表同样不会被
// 记录：响应已经回完，改写请求没有去处。
func TestLuaPostRequestMutationIgnored(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx) return {request = {path = "/too-late"}} end`)
	reqCtx := &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}
	applyPostLuaDecision(lp, reqCtx, actionPass())
	if _, ok := reqCtx.DrainRequestMutation(); ok {
		t.Fatal("post-stage request mutation must not be recorded")
	}
	if reqCtx.Path != "/api" {
		t.Fatalf("path = %q, want unchanged", reqCtx.Path)
	}
}
