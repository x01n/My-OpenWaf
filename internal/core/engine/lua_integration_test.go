package engine

import (
	"io"
	"log/slog"
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/luaplugin"
)

func luaEngineWith(t *testing.T, stage luaplugin.Stage, src string) *luaplugin.Engine {
	t.Helper()
	script, err := luaplugin.Compile("t", stage, src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e := luaplugin.NewEngine(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
func TestPostLuaSeesBuiltinPhase(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx) return {action="observe", message=ctx.phase} end`)

	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{}, action.Result{Phase: "owasp"})
	if got.MatchDesc != "owasp" {
		t.Errorf("脚本读到的 phase = %q, want owasp", got.MatchDesc)
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
