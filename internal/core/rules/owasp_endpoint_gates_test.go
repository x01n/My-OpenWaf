package rules

import (
	"net/http"
	"testing"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/owasp"
)

// endpointFallbackRequest 构造一个必然命中端点兜底规则的请求。
// `/global-protect/login.esp` 是 Palo Alto GlobalProtect 登录端点（owasp:endpoint:001），
// 请求行合法、目标串不含攻击特征，主扫描必然放行，只能靠端点判据拦截。
func endpointFallbackRequest() *pipeline.RequestCtx {
	return &pipeline.RequestCtx{
		Method:  http.MethodPost,
		Path:    "/global-protect/login.esp",
		Headers: map[string]string{"host": "vpn.example.com"},
	}
}

// newOWASPPhaseForEndpointTest 构造 OWASP 阶段，可指定全局档位、类别覆盖与规则级覆盖。
func newOWASPPhaseForEndpointTest(t *testing.T, sensitivity, catSens, rulesConfig string) pipeline.Phase {
	t.Helper()
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPEnabled = true
	cfg.OWASPSensitivity = sensitivity
	cfg.OWASPAction = "intercept"
	cfg.CategorySensitivity = catSens
	cfg.OWASPRulesConfig = rulesConfig
	return NewOWASPPhase(&cfg)
}

// TestOWASPPhaseEndpointFallbackHonorsCategoryOff 锁定端点兜底受类别硬开关管辖。
//
// 端点规则不经主扫描阈值体系，若只看 ShouldSkipRule，管理员把某类别调到 off
// （或把全局档位调到 off）后端点族仍会照常拦截 —— 与其"停用该类别"的意图相反。
func TestOWASPPhaseEndpointFallbackHonorsCategoryOff(t *testing.T) {
	req := endpointFallbackRequest()

	// 基线：类别非 off 时端点兜底照常拦截（该端点属 cmd_injection 类别）。
	base := newOWASPPhaseForEndpointTest(t, "mid", `{"cmd_injection":"mid"}`, "")
	if res, terminal := base.Execute(req); !terminal {
		t.Fatalf("类别非 off 时端点兜底应拦截 /global-protect/login.esp，实得 %+v", res)
	}

	// 类别 off：端点族必须一并停用。
	catOff := newOWASPPhaseForEndpointTest(t, "mid", `{"cmd_injection":"off"}`, "")
	if res, terminal := catOff.Execute(endpointFallbackRequest()); terminal {
		t.Fatalf("类别 cmd_injection=off 时端点兜底不得拦截，实得 %+v", res)
	}

	// 全局档位 off：同样必须停用（CompileThresholds 已把全部类别置为 disabled）。
	globalOff := newOWASPPhaseForEndpointTest(t, "off", "", "")
	if res, terminal := globalOff.Execute(endpointFallbackRequest()); terminal {
		t.Fatalf("全局档位 off 时端点兜底不得拦截，实得 %+v", res)
	}
}

// TestOWASPPhaseEndpointFallbackHonorsRuleOff 锁定规则级 sensitivity=off 能停用单条端点规则。
func TestOWASPPhaseEndpointFallbackHonorsRuleOff(t *testing.T) {
	rulesOff := newOWASPPhaseForEndpointTest(t, "mid", "",
		`{"owasp:endpoint:001":{"sensitivity":"off"}}`)
	if res, terminal := rulesOff.Execute(endpointFallbackRequest()); terminal {
		t.Fatalf("规则级 sensitivity=off 时端点兜底不得拦截，实得 %+v", res)
	}
}

// TestOWASPPhaseEndpointFallbackIgnoresScoreThreshold 锁定端点兜底**不**比较 hit.Score。
//
// 端点规则的 Score 是规则固有风险分（全表只有 5/6 两档），不是本次请求的累计
// 攻击分；拿它与 sensitivity 阈值比较只会退化成"low 档整族关闭"，与 sensitivity
// "要求更多证据" 的语义无关。因此规则级 sensitivity=low（阈值 7 > 6）时端点
// 仍须拦截，真正表达"关闭"的是 off。
func TestOWASPPhaseEndpointFallbackIgnoresScoreThreshold(t *testing.T) {
	rulesLow := newOWASPPhaseForEndpointTest(t, "mid", "",
		`{"owasp:endpoint:001":{"sensitivity":"low"}}`)
	if res, terminal := rulesLow.Execute(endpointFallbackRequest()); !terminal {
		t.Fatalf("规则级 sensitivity=low 不得关闭端点兜底（Score 不参与阈值比较），实得 %+v", res)
	}

	hit, ok := owasp.CheckSensitiveEndpointPath("/global-protect/login.esp", http.MethodPost)
	if !ok {
		t.Fatal("用例失效：/global-protect/login.esp 未命中端点规则")
	}
	if hit.Score >= 7 {
		t.Fatalf("用例前提失效：端点分值 %d 已不小于 low 档阈值 7，无法验证「不比较 Score」", hit.Score)
	}
}

// TestOWASPPhaseEndpointFallbackKeepsEnabledAndWhitelist 锁定既有开关行为不变。
func TestOWASPPhaseEndpointFallbackKeepsEnabledAndWhitelist(t *testing.T) {
	disabled := newOWASPPhaseForEndpointTest(t, "mid", "",
		`{"owasp:endpoint:001":{"enabled":false}}`)
	if res, terminal := disabled.Execute(endpointFallbackRequest()); terminal {
		t.Fatalf("规则级 enabled=false 时端点兜底不得拦截，实得 %+v", res)
	}

	whitelisted := newOWASPPhaseForEndpointTest(t, "mid", "",
		`{"owasp:endpoint:001":{"whitelist":["/global-protect/*"]}}`)
	if res, terminal := whitelisted.Execute(endpointFallbackRequest()); terminal {
		t.Fatalf("路径白名单命中时端点兜底不得拦截，实得 %+v", res)
	}
}
