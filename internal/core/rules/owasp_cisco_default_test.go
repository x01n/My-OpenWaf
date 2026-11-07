package rules

import (
	"net/http"
	"testing"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
)

// ciscoCSCOEPortalRequest 构造 ASA WebVPN 门户登录请求（带 tgroup= 查询参数）。
// 这是白侧的量产形态：`GET /+CSCOE+/logon.html?tgroup=<隧道组>`，path 无穿越标记。
func ciscoCSCOEPortalRequest() *pipeline.RequestCtx {
	return &pipeline.RequestCtx{
		Method:   http.MethodGet,
		Path:     "/+CSCOE+/logon.html",
		RawQuery: "tgroup=TGr-SERVICE",
		Headers:  map[string]string{"host": "vpn.example.com"},
	}
}

// ciscoCSCOTExploitRequest 构造 CVE-2020-3452 的真实利用请求。
// 形态取自语料黑样本：`+CSCOT+/translation-table` 借 `%2bCSCOE%2b` 读门户 Lua 文件。
func ciscoCSCOTExploitRequest() *pipeline.RequestCtx {
	return &pipeline.RequestCtx{
		Method:   http.MethodGet,
		Path:     "/+CSCOT+/translation-table",
		RawQuery: "type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../",
		Headers:  map[string]string{"host": "vpn.example.com"},
	}
}

// newOWASPPhaseForCiscoTest 构造一个 OWASP 阶段，仅指定 cisco 档位相关的配置。
// rulesConfig 是按策略的规则级覆盖 JSON；空串表示「没有任何规则被覆盖」。
func newOWASPPhaseForCiscoTest(t *testing.T, rulesConfig string) pipeline.Phase {
	t.Helper()
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPEnabled = true
	cfg.OWASPSensitivity = "mid"
	cfg.OWASPAction = "intercept"
	cfg.OWASPRulesConfig = rulesConfig
	return NewOWASPPhase(&cfg)
}

// TestOWASPPhaseCiscoASADefaultsToScoped 锁定数据面默认档位：
// 未配置 cisco_asa_mode 时按 scoped 档判 +CSCOE+，带 tgroup= 的门户登录页放行，
// 同时 +CSCOT+ 利用路径一条不丢。
func TestOWASPPhaseCiscoASADefaultsToScoped(t *testing.T) {
	phase := newOWASPPhaseForCiscoTest(t, "")

	result, stop := phase.Execute(ciscoCSCOEPortalRequest())
	if stop && result.RuleIDStr == "owasp:path:006" {
		t.Fatalf("未配置档位时不应按 legacy 拦截 ASA 门户登录: rule=%q action=%q",
			result.RuleIDStr, result.Type)
	}

	result, stop = phase.Execute(ciscoCSCOTExploitRequest())
	if !stop || result.RuleIDStr != "owasp:path:006" {
		t.Fatalf("+CSCOT+ 利用路径在默认档下必须仍被 owasp:path:006 拦截: stop=%v rule=%q",
			stop, result.RuleIDStr)
	}
}

// TestOWASPPhaseCiscoASAExplicitModesOverrideDefault 锁定显式档位覆盖：
// 配 legacy 恢复历史拦截（CSCOE 与 CSCOT 一并拦），配 strict 只保留 CSCOT。
func TestOWASPPhaseCiscoASAExplicitModesOverrideDefault(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		base    bool // CSCOE+tgroup 是否命中 path:006
		exploit bool // CSCOT 利用路径是否命中 path:006
	}{
		{name: "legacy", config: `{"owasp:path:006":{"cisco_asa_mode":"legacy"}}`, base: true, exploit: true},
		{name: "strict", config: `{"owasp:path:006":{"cisco_asa_mode":"strict"}}`, base: false, exploit: true},
		{name: "scoped", config: `{"owasp:path:006":{"cisco_asa_mode":"scoped"}}`, base: false, exploit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			phase := newOWASPPhaseForCiscoTest(t, tt.config)

			result, stop := phase.Execute(ciscoCSCOEPortalRequest())
			baseHit := stop && result.RuleIDStr == "owasp:path:006"
			if baseHit != tt.base {
				t.Fatalf("CSCOE+tgroup 命中 path:006 = %v, 期望 %v (rule=%q action=%q)",
					baseHit, tt.base, result.RuleIDStr, result.Type)
			}

			result, stop = phase.Execute(ciscoCSCOTExploitRequest())
			exploitHit := stop && result.RuleIDStr == "owasp:path:006"
			if exploitHit != tt.exploit {
				t.Fatalf("CSCOT 命中 path:006 = %v, 期望 %v (rule=%q action=%q)",
					exploitHit, tt.exploit, result.RuleIDStr, result.Type)
			}
		})
	}
}
