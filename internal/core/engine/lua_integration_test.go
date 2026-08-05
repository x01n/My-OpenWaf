package engine

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/luaplugin"
)

type luaEngineTestKV struct{}

func (luaEngineTestKV) Available() bool { return true }

func (luaEngineTestKV) Get(string) ([]byte, bool) { return nil, false }

func (luaEngineTestKV) Set(string, []byte, time.Duration) error { return nil }

func (luaEngineTestKV) Delete(string) {}

func (luaEngineTestKV) Incr(string, time.Duration) (int64, error) { return 1, nil }

func luaEngineWith(t *testing.T, stage luaplugin.Stage, src string) *luaplugin.Engine {
	t.Helper()
	script, err := luaplugin.Compile("t", stage, src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e := luaplugin.NewEngine(luaEngineTestKV{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Reload([]*luaplugin.Script{script})
	return e
}

// TestPostLuaCanOverrideBuiltinIntercept 是后置阶段存在的理由。
//
// 管道遇终止动作即 return，挂在链尾的普通阶段永远读不到「已被拦截」的判定。
// 后置策略因此在 Process 中于管道之后执行——本用例锁定该行为：
// 脚本既能看到内置判定，也能用 allow 推翻它（对误报放行）。
func TestPostLuaCanOverrideBuiltinIntercept(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  if ctx.action == "intercept" and ctx.path == "/known-false-positive" then
    return "allow"
  end
  return nil
end`)

	builtin := action.Result{
		Type: action.Intercept, Matched: true, Phase: "owasp", Category: "sqli",
	}

	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{Path: "/known-false-positive"}, builtin)
	if got.IsTerminal() {
		t.Fatalf("脚本 allow 应推翻内置拦截，仍得到终止判定 %+v", got)
	}
	if got.Phase != "lua_post" {
		t.Errorf("覆盖后的 Phase = %q, want lua_post", got.Phase)
	}

	kept := applyPostLuaDecision(lp, &pipeline.RequestCtx{Path: "/other"}, builtin)
	if !kept.IsTerminal() || kept.Type != action.Intercept {
		t.Fatalf("未命中放行条件时应保留内置拦截，得到 %+v", kept)
	}
}

// TestPostLuaCannotEscalateOverBuiltinTerminal 验证脚本无法绕过内置的终止优先级。
//
// 否则脚本能把 ACL 的 drop 改写成 redirect，使 drop > intercept > challenge
// 的既有语义失效。
func TestPostLuaCannotEscalateOverBuiltinTerminal(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx) return {action="redirect", redirect_to="/evil"} end`)

	builtin := action.Result{Type: action.Drop, Matched: true, Phase: "acl"}
	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{}, builtin)

	if got.Type != action.Drop {
		t.Fatalf("内置终止判定不应被非 allow 动作改写，得到 %+v", got)
	}
	if got.RedirectTo != "" {
		t.Error("脚本的 redirect_to 不应生效")
	}
}

// TestPostLuaAppliesWhenBuiltinPassed 验证内置放行时脚本判定正常生效。
func TestPostLuaAppliesWhenBuiltinPassed(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  if ctx.user_agent == "scanner/1.0" then
    return {action="intercept", message="blocked by custom policy", status_code=418}
  end
  return nil
end`)

	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{UserAgent: "scanner/1.0"}, action.Result{})
	if got.Type != action.Intercept || !got.Matched {
		t.Fatalf("内置放行时脚本拦截应生效，得到 %+v", got)
	}
	if got.StatusCode != 418 {
		t.Errorf("StatusCode = %d, want 418", got.StatusCode)
	}
	if got.MatchDesc != "blocked by custom policy" {
		t.Errorf("MatchDesc = %q", got.MatchDesc)
	}
}

// TestPostLuaIgnoresUnknownAction 验证脚本笔误不会升级为误封。
func TestPostLuaIgnoresUnknownAction(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `function handle(ctx) return "blokc" end`)

	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{}, action.Result{})
	if got.Matched {
		t.Fatalf("无法识别的动作应被忽略，得到 %+v", got)
	}
}

// TestPostLuaSeesBuiltinPhase 验证内置阶段名被传给脚本。
func TestPostLuaSeesBuiltinVerdict(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  local v = ctx.verdict
  if not v.matched or v.phase ~= "owasp" or v.action ~= "intercept" then return "intercept" end
  if v.category ~= "sqli" or v.rule_id ~= 17 or v.rule_id_str ~= "owasp:sqli:017" then return "intercept" end
  if v.status_code ~= 403 or v.redirect_to ~= "" then return "intercept" end
  if v.tags[1] ~= "sql" or v.tags[2] ~= "builtin" then return "intercept" end
  return {action="allow", message=v.phase}
end`)

	tags := []string{"sql", "builtin"}
	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{}, action.Result{
		Type: action.Intercept, Matched: true, Phase: "owasp", Category: "sqli",
		RuleID: 17, RuleIDStr: "owasp:sqli:017", StatusCode: 403, Tags: &tags,
	})
	if got.IsTerminal() {
		t.Fatalf("verdict metadata matching allow should override builtin terminal: %+v", got)
	}
	if got.MatchDesc != "owasp" {
		t.Errorf("脚本读到的 verdict.phase = %q, want owasp", got.MatchDesc)
	}
}

// TestPostLuaCanceledRequestKeepsBuiltinDecision 验证取消请求不接受 post 脚本的覆盖。
func TestPostLuaCanceledRequestKeepsBuiltinDecision(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	builtin := action.Result{Type: action.Intercept, Matched: true, Phase: "owasp"}
	allow := luaEngineWith(t, luaplugin.StagePost, `function handle(ctx) return "allow" end`)
	if got := applyPostLuaDecision(allow, &pipeline.RequestCtx{Context: ctx}, builtin); got != builtin {
		t.Fatalf("cancelled request must keep builtin decision, got %+v", got)
	}

	intercept := luaEngineWith(t, luaplugin.StagePost, `function handle(ctx) return "intercept" end`)
	if got := applyPostLuaDecision(intercept, &pipeline.RequestCtx{Context: ctx}, action.Result{}); got.Matched {
		t.Fatalf("cancelled request must not become Lua intercept, got %+v", got)
	}
}

func TestPostLuaCarriesControlledOutput(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  return {
    action="intercept",
    headers={["x-lua-post"]="matched"},
    response_body="post response",
    tags={"post", "lua"}
  }
end`)

	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{}, action.Result{})
	if got.Type != action.Intercept || !got.Matched {
		t.Fatalf("post 判定未进入 action.Result：%+v", got)
	}
	if got.SetHeaders == nil || (*got.SetHeaders)["x-lua-post"] != "matched" {
		t.Errorf("post SetHeaders 未进入 action.Result：%+v", got.SetHeaders)
	}
	if got.ResponseBody == nil || *got.ResponseBody != "post response" {
		t.Errorf("post ResponseBody 未进入 action.Result：%v", got.ResponseBody)
	}
	if got.Tags == nil || len(*got.Tags) != 2 || (*got.Tags)[0] != "post" || (*got.Tags)[1] != "lua" {
		t.Errorf("post Tags 未进入 action.Result：%+v", got.Tags)
	}
}

// TestSetLuaPluginsHotSwap 验证引擎可热替换与停用。
func TestSetLuaPluginsHotSwap(t *testing.T) {
	e := &Engine{}
	if e.LuaPlugins() != nil {
		t.Error("初始应为 nil")
	}

	lp := luaEngineWith(t, luaplugin.StagePre, `function handle(ctx) return nil end`)
	e.SetLuaPlugins(lp)
	if e.LuaPlugins() != lp {
		t.Error("SetLuaPlugins 未生效")
	}

	e.SetLuaPlugins(nil)
	if e.LuaPlugins() != nil {
		t.Error("传 nil 应停用插件")
	}
}

func TestNilEngineLuaAccessorsSafe(t *testing.T) {
	var e *Engine
	e.SetLuaPlugins(nil) // 不应 panic
	if e.LuaPlugins() != nil {
		t.Error("nil 引擎应返回 nil")
	}
}
