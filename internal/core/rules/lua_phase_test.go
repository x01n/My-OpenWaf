package rules

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/luaplugin"
)

func luaPhaseWith(t *testing.T, src string) pipeline.Phase {
	t.Helper()
	script, err := luaplugin.Compile("t", luaplugin.StagePre, src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e := luaplugin.NewEngine(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Reload([]*luaplugin.Script{script})
	return NewLuaPhase(e, luaplugin.StagePre)
}

func TestLuaPhaseNameByStage(t *testing.T) {
	pre := NewLuaPhase(nil, luaplugin.StagePre)
	if pre.Name() != "lua_pre" {
		t.Errorf("pre 阶段名 = %q, want lua_pre", pre.Name())
	}
	post := NewLuaPhase(nil, luaplugin.StagePost)
	if post.Name() != "lua_post" {
		t.Errorf("post 阶段名 = %q, want lua_post", post.Name())
	}
}

// TestLuaPhaseNilEngineIsNoop 验证未配置插件时阶段零成本通过。
func TestLuaPhaseNilEngineIsNoop(t *testing.T) {
	res, terminal := NewLuaPhase(nil, luaplugin.StagePre).Execute(&pipeline.RequestCtx{})
	if res.Matched || terminal {
		t.Errorf("nil 引擎应不产生判定，得到 %+v terminal=%v", res, terminal)
	}
}

// TestLuaPhaseTerminalActions 验证终止动作被正确标记。
//
// terminal 为 false 会让 pipeline 继续执行后续阶段并最终放行——
// 拦截类动作漏标就是静默失效。
func TestLuaPhaseTerminalActions(t *testing.T) {
	cases := []struct {
		act          string
		wantTerminal bool
	}{
		{"intercept", true},
		{"drop", true},
		{"challenge", true},
		{"redirect", true},
		{"rate_limit", true},
		// observe 与 tag 是非终止动作，应记录后继续。
		{"observe", false},
		{"tag", false},
	}
	for _, tt := range cases {
		phase := luaPhaseWith(t, `function handle(ctx) return "`+tt.act+`" end`)
		res, terminal := phase.Execute(&pipeline.RequestCtx{})
		if !res.Matched {
			t.Errorf("action %q: 应产生命中", tt.act)
			continue
		}
		if terminal != tt.wantTerminal {
			t.Errorf("action %q: terminal = %v, want %v", tt.act, terminal, tt.wantTerminal)
		}
		if res.Phase != "lua_pre" || res.Category != "lua_plugin" {
			t.Errorf("action %q: Phase/Category = %q/%q", tt.act, res.Phase, res.Category)
		}
	}
}

// TestLuaPhaseIgnoresUnknownAction 验证脚本笔误不会升级为误封。
func TestLuaPhaseIgnoresUnknownAction(t *testing.T) {
	phase := luaPhaseWith(t, `function handle(ctx) return "blokc" end`) // 刻意拼错 intercept
	res, terminal := phase.Execute(&pipeline.RequestCtx{})
	if res.Matched || terminal {
		t.Errorf("无法识别的动作应被忽略，得到 %+v terminal=%v", res, terminal)
	}
}

// TestLuaPhaseLegacyActionNormalized 验证旧动作名被归一化。
// block → intercept、log_only → observe 是项目既有的兼容映射。
func TestLuaPhaseLegacyActionNormalized(t *testing.T) {
	phase := luaPhaseWith(t, `function handle(ctx) return "block" end`)
	res, terminal := phase.Execute(&pipeline.RequestCtx{})
	if res.Type != action.Intercept {
		t.Errorf("block 应归一化为 intercept，得到 %q", res.Type)
	}
	if !terminal {
		t.Error("intercept 应为终止动作")
	}
}

func TestLuaPhaseCarriesRedirectAndStatus(t *testing.T) {
	phase := luaPhaseWith(t, `
function handle(ctx)
  return {action="redirect", redirect_to="/login", status_code=302, message="need auth"}
end`)
	res, _ := phase.Execute(&pipeline.RequestCtx{})
	if res.RedirectTo != "/login" {
		t.Errorf("RedirectTo = %q", res.RedirectTo)
	}
	if res.StatusCode != 302 {
		t.Errorf("StatusCode = %d", res.StatusCode)
	}
	if res.MatchDesc != "need auth" {
		t.Errorf("MatchDesc = %q", res.MatchDesc)
	}
}

// TestBuildLuaRequestViewMapsFields 验证上下文字段被正确传给脚本。
func TestBuildLuaRequestViewMapsFields(t *testing.T) {
	ctx := &pipeline.RequestCtx{
		RequestID:   "r1",
		ClientIP:    net.ParseIP("203.0.113.9"),
		Method:      "POST",
		Path:        "/api/login",
		RawQuery:    "next=%2Fhome",
		Host:        "app.example.com",
		UserAgent:   "curl/8.0",
		SiteID:      12,
		ContentType: "application/json",
		Headers:     map[string]string{"x-forwarded-for": "1.2.3.4"},
		QueryParams: map[string]string{"next": "/home"},
		Body:        []byte(`{"u":"admin"}`),
		TLS: bot.TLSClientFingerprint{
			TLSVersion: "TLS13", JA3Hash: "abc", JA4: "t13d", SNI: "app.example.com",
		},
	}

	view := BuildLuaRequestView(ctx)
	if view.ClientIP != "203.0.113.9" {
		t.Errorf("ClientIP = %q", view.ClientIP)
	}
	if view.Method != "POST" || view.Path != "/api/login" || view.SiteID != 12 {
		t.Errorf("基本字段映射有误: %+v", view)
	}
	if view.Headers["x-forwarded-for"] != "1.2.3.4" {
		t.Errorf("Headers 未映射")
	}
	if view.QueryParams["next"] != "/home" {
		t.Errorf("QueryParams 未映射")
	}
	if view.Body != `{"u":"admin"}` {
		t.Errorf("Body = %q", view.Body)
	}
	if view.TLSVersion != "TLS13" || view.TLSJA3 != "abc" || view.TLSJA4 != "t13d" || view.TLSSNI != "app.example.com" {
		t.Errorf("TLS 字段映射有误: %+v", view)
	}
}

// TestBuildLuaRequestViewNilClientIP 验证 ClientIP 为 nil 时不 panic。
func TestBuildLuaRequestViewNilClientIP(t *testing.T) {
	view := BuildLuaRequestView(&pipeline.RequestCtx{})
	if view.ClientIP != "" {
		t.Errorf("nil ClientIP 应映射为空串，得到 %q", view.ClientIP)
	}
}

// TestLuaPhaseScriptErrorDoesNotBlock 验证脚本报错时请求不被拦截。
//
// 自定义策略故障不应导致站点不可用——这是数据面的可用性底线。
func TestLuaPhaseScriptErrorDoesNotBlock(t *testing.T) {
	phase := luaPhaseWith(t, `function handle(ctx) error("boom") end`)
	res, terminal := phase.Execute(&pipeline.RequestCtx{})
	if res.Matched || terminal {
		t.Errorf("脚本报错时不应拦截，得到 %+v terminal=%v", res, terminal)
	}
}
