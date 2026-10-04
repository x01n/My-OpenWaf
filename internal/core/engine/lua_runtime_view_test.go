package engine

import (
	"context"
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/luaplugin"
)

/**
 * TestPostLuaSeesRuntimePhase 验证后置脚本读到的是 post 阶段，而不是 pre。
 *
 * 后置脚本由 applyPostLuaDecision 在管道之外执行，走的是独立于 luaPhase 的
 * 路径：若这里忘了覆盖 Runtime，脚本会拿到前置阶段留下的 lua_pre 标注——
 * 它据此判断「内置判定已经跑过了」就必然是错的。
 */
func TestPostLuaSeesRuntimePhase(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  if ctx.runtime.stage ~= "post" then return "intercept" end
  if ctx.runtime.phase ~= "lua_post" then return "intercept" end
  if ctx.runtime.request_id ~= "req-post" then return "intercept" end
  return {action="allow", message=ctx.runtime.phase}
end`)

	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{RequestID: "req-post"}, action.Result{})
	if got.IsTerminal() {
		t.Fatalf("post 脚本应读到 post 阶段并以 allow 覆盖，得到 %+v", got)
	}
	if got.MatchDesc != "lua_post" {
		t.Errorf("脚本读到的阶段名 = %q, want lua_post", got.MatchDesc)
	}
}

// TestPostLuaRuntimeOverridesPreDefault 锁定覆盖顺序：BuildLuaRequestView
// 默认写 lua_pre，applyPostLuaDecision 必须在其后覆盖。
func TestPostLuaRuntimeOverridesPreDefault(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  if ctx.runtime.phase == "lua_pre" then return "intercept" end
  return nil
end`)

	got := applyPostLuaDecision(lp, &pipeline.RequestCtx{}, action.Result{})
	if got.Matched {
		t.Fatalf("后置阶段不应残留前置阶段名：%+v", got)
	}
}

/**
 * TestPrePhaseRuntimeReachesScript 验证前置脚本经完整管道装配后仍读得到 runtime。
 *
 * 前置路径的视图由 rules.BuildLuaRequestView 构造，本用例经 Process 走完整
 * 装配，确认字段没有在中途被丢弃。
 *
 * 脚本对错误取值返回 drop、对正确取值返回 intercept：两种结果都是终止动作，
 * 「读不到字段」与「字段正确」因此不会被同样的空结果掩盖。
 */
func TestPrePhaseRuntimeReachesScript(t *testing.T) {
	holder := newTestHolder(store.DefaultProtectionConfig(), nil)
	eng := New(holder, nil, nil, nil)
	eng.SetLuaPlugins(luaEngineWith(t, luaplugin.StagePre, `
function handle(ctx)
  if ctx.runtime.stage ~= "pre" then return "drop" end
  if ctx.runtime.phase ~= "lua_pre" then return "drop" end
  if ctx.runtime.request_id ~= "req-pre" then return "drop" end
  return {action="intercept", message="runtime ok"}
end`))

	got := eng.Process(&pipeline.RequestCtx{
		Bind:      ":80",
		Host:      "example.com",
		Path:      "/",
		RequestID: "req-pre",
		Headers:   map[string]string{},
		Context:   context.Background(),
	}).Action

	if got.Type != action.Intercept {
		t.Fatalf("前置脚本读到的 runtime 不符合预期：%+v", got)
	}
	if got.MatchDesc != "runtime ok" {
		t.Errorf("MatchDesc = %q", got.MatchDesc)
	}
}
