package engine

import (
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/luaplugin"
)

/**
 * 本文件锁定 applyPostLuaDecision 的覆盖语义（engine.go:234）。
 *
 * 覆盖规则是刻意不对称的：
 *   - 只有 allow 能推翻内置的终止判定（drop / intercept / rate_limit / challenge / ...）
 *   - 其余合法动作仅在内置未终止时生效，避免脚本绕过 drop > intercept > rate_limit
 *     的既有终止优先级
 *   - 无法识别的动作与「无动作」一律保留内置判定，脚本笔误不得升级为误封
 *   - 响应改写与判定是两条独立通道：动作被保留时改写照样传递，动作被推翻时
 *     改写同样不得丢失（engine.go:264 在动作分支之前处理）
 *
 * 每条断言都用「脚本身份（RuleID/RuleIDStr）+ Phase + IsTerminal/ShouldLog」
 * 共同判定：保留内置与推翻内置在结果上必然不同，无法被同一个空结果掩盖。
 */

// luaPostScriptIdentity 是 luaEngineWith 固定使用的脚本 ID 与名称。
// 覆盖生效时结果会带上它们，保留内置时不会，因此可用来区分两条分支。
const (
	luaPostScriptID   uint   = 42
	luaPostScriptName string = "t"
)

// assertLuaPostAllowWon 断言脚本的 allow 推翻成功：结果不再是终止动作，
// 且能在结果上读到 Lua post 判定的身份。
func assertLuaPostAllowWon(t *testing.T, got action.Result, wantMsg string) {
	t.Helper()
	if got.IsTerminal() {
		t.Fatalf("allow 应推翻内置终止判定，仍得到终止动作：%+v", got)
	}
	if got.Matched {
		t.Fatalf("allow 判定不应带 Matched：%+v", got)
	}
	if got.ShouldLog() {
		t.Fatalf("allow 判定不应要求写安全日志：%+v", got)
	}
	if got.Type != "" {
		t.Fatalf("allow 判定不应残留动作类型：%q", got.Type)
	}
	if got.Phase != "lua_post" {
		t.Fatalf("Phase = %q, want lua_post", got.Phase)
	}
	if got.MatchDesc != wantMsg {
		t.Fatalf("MatchDesc = %q, want %q", got.MatchDesc, wantMsg)
	}
	if got.RuleID != luaPostScriptID || got.RuleIDStr != luaPostScriptName {
		t.Fatalf("Lua 身份 = %d/%q, want %d/%q", got.RuleID, got.RuleIDStr, luaPostScriptID, luaPostScriptName)
	}
}

// assertLuaPostKeptBuiltin 断言内置判定被原样保留：结构相等，且保留的是终止动作
// 而非 Lua 判定（Phase 仍为内置阶段名，身份仍为内置规则）。
func assertLuaPostKeptBuiltin(t *testing.T, got, builtin action.Result) {
	t.Helper()
	if got != builtin {
		t.Fatalf("内置判定应原样保留：got %+v, want %+v", got, builtin)
	}
	if !got.IsTerminal() {
		t.Fatalf("内置终止判定不应被降级为非终止：%+v", got)
	}
	if got.Phase == "lua_post" {
		t.Fatalf("Phase 不应被改写成 lua_post：%+v", got)
	}
	if got.RuleID == luaPostScriptID {
		t.Fatalf("结果不应带 Lua 脚本身份：%+v", got)
	}
}

/**
 * TestPostLuaAllowOverridesBuiltinTerminal 覆盖矩阵 1-3：
 * allow 可推翻 intercept、drop、rate_limit 三种终止判定。
 *
 * drop 的终止优先级最高（90），若覆盖规则被改成「只有更严重的动作才能胜出」，
 * 这三条里 drop 必然先暴露。
 */
func TestPostLuaAllowOverridesBuiltinTerminal(t *testing.T) {
	builtins := []struct {
		name    string
		builtin action.Result
	}{
		{"intercept", action.Result{
			Type: action.Intercept, Matched: true, Phase: "owasp",
			Category: "sqli", RuleID: 17, RuleIDStr: "owasp:sqli:017",
		}},
		{"drop", action.Result{
			Type: action.Drop, Matched: true, Phase: "iprep", RuleID: 3,
		}},
		{"rate_limit", action.Result{
			Type: action.RateLimit, Matched: true, Phase: "ratelimit", RuleID: 5,
		}},
	}
	for _, tc := range builtins {
		t.Run(tc.name, func(t *testing.T) {
			// message 拼接内置动作名：顺带证明脚本读到的是内置判定本身，
			// 而不是某个在覆盖前就被清空的结果。
			lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  return {action="allow", message="fp:" .. ctx.verdict.action}
end`)
			reqCtx := &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}
			got := applyPostLuaDecision(lp, reqCtx, tc.builtin)

			assertLuaPostAllowWon(t, got, "fp:"+string(tc.builtin.Type))
			if mutations := reqCtx.DrainResponseMutations(); mutations != nil {
				t.Fatalf("本条脚本没有 response 子表，不应产生响应改写：%#v", mutations)
			}
		})
	}
}

/**
 * TestPostLuaNonAllowKeepsBuiltinTerminal 覆盖矩阵 4-5：
 * 非 allow 动作不得推翻内置终止判定。
 *
 * observe 是「更轻」的动作、drop 是「更重」的动作，两者都必须被内置判定挡住：
 * 覆盖规则只放开 allow 一个口子，不按严重度比较。
 */
func TestPostLuaNonAllowKeepsBuiltinTerminal(t *testing.T) {
	builtin := action.Result{
		Type: action.Intercept, Matched: true, Phase: "owasp",
		Category: "sqli", RuleID: 17, RuleIDStr: "owasp:sqli:017",
	}
	actions := []string{"observe", "drop"}
	for _, act := range actions {
		t.Run(act, func(t *testing.T) {
			lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx) return {action="`+act+`", message="script wants `+act+`"} end`)
			got := applyPostLuaDecision(lp, &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}, builtin)

			assertLuaPostKeptBuiltin(t, got, builtin)
			if got.Type != action.Intercept {
				t.Fatalf("Type = %q, want 内置的 intercept", got.Type)
			}
		})
	}
}

/**
 * TestPostLuaAppliesOverNonTerminalBuiltin 覆盖矩阵 6-7：
 * 内置未终止时，脚本的合法动作生效；allow 在没有可推翻判定时仍留下 Lua post 结果。
 *
 * 这两条共同说明「内置终止」是唯一的分岔条件，而非「内置是否 Matched」。
 */
func TestPostLuaAppliesOverNonTerminalBuiltin(t *testing.T) {
	passed := action.Result{} // Matched=false，模拟管道全程未命中

	t.Run("intercept", func(t *testing.T) {
		lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx) return {action="intercept", message="custom block", status_code=418} end`)
		got := applyPostLuaDecision(lp, &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}, passed)

		if !got.Matched || got.Type != action.Intercept || !got.IsTerminal() {
			t.Fatalf("内置未终止时脚本拦截应生效，得到 %+v", got)
		}
		if !got.ShouldLog() {
			t.Fatalf("生效的拦截应写安全日志：%+v", got)
		}
		if got.Phase != "lua_post" || got.MatchDesc != "custom block" {
			t.Fatalf("Lua 判定标注缺失：%+v", got)
		}
		if got.StatusCode != 418 {
			t.Fatalf("StatusCode = %d, want 418", got.StatusCode)
		}
		if got.RuleID != luaPostScriptID || got.RuleIDStr != luaPostScriptName {
			t.Fatalf("Lua 身份 = %d/%q", got.RuleID, got.RuleIDStr)
		}
	})

	t.Run("allow", func(t *testing.T) {
		lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx) return {action="allow", message="explicit pass"} end`)
		got := applyPostLuaDecision(lp, &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}, passed)

		if got.IsTerminal() || got.Matched {
			t.Fatalf("内置未终止时 allow 结果应保持放行，得到 %+v", got)
		}
		if got.Phase != "lua_post" || got.MatchDesc != "explicit pass" {
			t.Fatalf("allow 结果应带 Lua post 标注：%+v", got)
		}
		if got.RuleID != luaPostScriptID {
			t.Fatalf("allow 结果应带脚本身份：%+v", got)
		}
	})
}

/**
 * TestPostLuaInvalidActionKeepsBuiltinTerminal 覆盖矩阵 8-9：
 * 无法识别的动作（"captcha" 不是 action.Type 的合法取值）与「无动作」都必须保留内置判定。
 *
 * 这一条防的是笔误放大：脚本写成 captcha 而非 captcha_challenge 时，若被当成
 * 合法动作处理，就会凭空冒出一个内置并未要求的挑战。
 *
 * 子用例 not_matched_builtin_* 是必需的补充：内置终止时 IsValid 分支被前面的
 * IsTerminal 分支遮蔽，删掉 IsValid 校验也照样保留内置，矩阵 8-9 因此无法证明
 * 该校验存在。只有内置未终止时，未知动作是否被过滤才会显现为结果差异。
 */
func TestPostLuaInvalidActionKeepsBuiltinTerminal(t *testing.T) {
	builtin := action.Result{
		Type: action.Intercept, Matched: true, Phase: "owasp",
		Category: "sqli", RuleID: 17, RuleIDStr: "owasp:sqli:017",
	}
	cases := []struct {
		name    string
		script  string
		builtin action.Result
	}{
		{"unknown_action", `function handle(ctx) return "captcha" end`, builtin},
		{"no_action", `function handle(ctx) return nil end`, builtin},
		{"not_matched_builtin_unknown_action", `function handle(ctx) return "captcha" end`, action.Result{}},
		{"not_matched_builtin_no_action", `function handle(ctx) return nil end`, action.Result{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lp := luaEngineWith(t, luaplugin.StagePost, tc.script)
			got := applyPostLuaDecision(lp, &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}, tc.builtin)

			if got != tc.builtin {
				t.Fatalf("非法/缺省动作应原样返回内置判定：got %+v, want %+v", got, tc.builtin)
			}
			if got.Phase == "lua_post" || got.RuleID == luaPostScriptID {
				t.Fatalf("结果不应带 Lua 判定痕迹：%+v", got)
			}
			if tc.builtin.Matched && !got.IsTerminal() {
				t.Fatalf("内置终止判定不得被降级：%+v", got)
			}
			if !tc.builtin.Matched && got.Matched {
				t.Fatalf("非法动作不得凭空产生判定：%+v", got)
			}
		})
	}
}

/**
 * TestPostLuaAllowKeepsResponseMutation 覆盖矩阵 10：
 * 响应改写与判定互相独立。
 *
 * applyPostLuaDecision 先登记 response mutation（engine.go:264），再看动作
 * （engine.go:273 起）：即使脚本同时用 allow 推翻了内置终止判定，改写也必须
 * 留在 RequestCtx 上交给 proxy 的响应变换链，否则「放行 + 改响应」的脚本会
 * 静默丢一半效果。
 */
func TestPostLuaAllowKeepsResponseMutation(t *testing.T) {
	lp := luaEngineWith(t, luaplugin.StagePost, `
function handle(ctx)
  return {
    action="allow",
    message="pass with rewrite",
    response={status_code=503, body="maintenance", headers={["X-Waf"]="post"}}
  }
end`)

	builtin := action.Result{
		Type: action.Intercept, Matched: true, Phase: "owasp",
		Category: "sqli", RuleID: 17, RuleIDStr: "owasp:sqli:017",
	}
	reqCtx := &pipeline.RequestCtx{Path: "/api", Headers: map[string]string{}}
	got := applyPostLuaDecision(lp, reqCtx, builtin)

	assertLuaPostAllowWon(t, got, "pass with rewrite")

	mutations := reqCtx.DrainResponseMutations()
	if len(mutations) != 1 {
		t.Fatalf("response mutations = %#v, want 1", mutations)
	}
	mutation := mutations[0]
	if mutation.ScriptName != luaPostScriptName {
		t.Fatalf("ScriptName = %q, want %q", mutation.ScriptName, luaPostScriptName)
	}
	if mutation.StatusCode != 503 {
		t.Fatalf("StatusCode = %d, want 503", mutation.StatusCode)
	}
	if mutation.Body == nil || *mutation.Body != "maintenance" {
		t.Fatalf("Body = %v, want maintenance", mutation.Body)
	}
	if mutation.SetHeaders["X-Waf"] != "post" {
		t.Fatalf("SetHeaders = %#v", mutation.SetHeaders)
	}
	if again := reqCtx.DrainResponseMutations(); again != nil {
		t.Fatalf("第二次 drain = %#v, want nil", again)
	}
}
