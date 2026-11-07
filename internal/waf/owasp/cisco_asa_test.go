package owasp

import "testing"

// ciscoModePathCases 覆盖三个档位下的判定边界。
var ciscoModePathCases = []struct {
	name  string
	path  string
	query string
	// legacy / strict / scoped 三档期望是否命中
	legacy bool
	strict bool
	scoped bool
}{
	{"CSCOT-攻击形态", "/+CSCOT+/translation-table", "", true, true, true},
	{"CSCOT-编码变体", "/%2bCSCOT%2b/oem-customization", "", true, true, true},
	{"CSCOE-门户登录带tgroup", "/+CSCOE+/logon.html", "tgroup=TGr-SERVICE", true, false, false},
	{"CSCOE-门户登录无query", "/+CSCOE+/logon.html", "", true, false, true},
	{"CSCOE-blank页", "/+CSCOE+/blank.html", "", true, false, true},
	{"CSCOE-带其他query", "/+CSCOE+/session_password.html", "fcadbadd=1", true, false, true},
	{"CSCOE-空query", "/+CSCOE+/tunnel_linux.jnlp", "====", true, false, true},
	{"CSCOE-编码变体带tgroup", "/%2bCSCOE%2b/logon.html", "tgroup=x", true, false, false},
	{"无关路径", "/index.html", "", false, false, false},
}

func TestCiscoASAModeTiers(t *testing.T) {
	for _, tc := range ciscoModePathCases {
		for _, tier := range []struct {
			mode string
			want bool
		}{
			{CiscoASAModeLegacy, tc.legacy},
			{CiscoASAModeStrict, tc.strict},
			{CiscoASAModeScoped, tc.scoped},
		} {
			hit, ok := checkCiscoASAPathTraversal(tc.path, tc.query, tier.mode)
			if ok != tier.want {
				t.Errorf("%s [%s]: 命中=%v 期望 %v", tc.name, tier.mode, ok, tier.want)
				continue
			}
			if ok && hit.RuleID != "owasp:path:006" {
				t.Errorf("%s [%s]: RuleID=%q 期望 owasp:path:006", tc.name, tier.mode, hit.RuleID)
			}
		}
	}
}

// TestCiscoASAModeLegacyMatchesHistoricalCheck 锁定默认档与历史判据逐例等价。
func TestCiscoASAModeLegacyMatchesHistoricalCheck(t *testing.T) {
	paths := []string{
		"/+CSCOT+/translation-table",
		"/+CSCOE+/logon.html",
		"/%2bcscot%2b/config",
		"/%2bcscoe%2b/logon.html",
		"/mgmt/tm/util/bash",
		"/api/jsonws/invoke",
		"/webtools/control/xmlrpc",
		"/rest/tinymce/1/macro/preview",
		"/think?x=invokefunction",
		"/gadgets/makerequest",
		"/coreui_user",
		"/mailsms/x",
		"/.git/config",
		"/securityrealm/descriptorbyname",
		"/deleteusername",
		"/admin;jsessionid=x",
		"/api/index.php/v1/config/x",
		"/service/rest/x/repositories/y",
		"/service/extdirect",
		"/index.html",
	}
	for _, p := range paths {
		want, wantOK := checkDangerousPath(p)
		got, gotOK := checkDangerousPathWithMode(p, "", CiscoASAModeLegacy)
		if wantOK != gotOK || want.RuleID != got.RuleID {
			t.Errorf("path=%q: 历史判据=(%v,%s) 与 legacy 档=(%v,%s) 不一致",
				p, wantOK, want.RuleID, gotOK, got.RuleID)
		}
	}
}

// TestCiscoASAModeEmptyDefaultsToLegacy 锁定空串/未知值回落到 legacy。
func TestCiscoASAModeEmptyDefaultsToLegacy(t *testing.T) {
	for _, raw := range []string{"", "  ", "LEGACY", "Legacy", "unknown", "off"} {
		got := NormalizeCiscoASAMode(raw)
		want := CiscoASAModeLegacy
		if raw == "LEGACY" || raw == "Legacy" {
			want = CiscoASAModeLegacy
		}
		if got != want {
			t.Errorf("NormalizeCiscoASAMode(%q) = %q 期望 %q", raw, got, want)
		}
	}
	for _, raw := range []string{"strict", "STRICT", " scoped "} {
		if NormalizeCiscoASAMode(raw) == CiscoASAModeLegacy {
			t.Errorf("NormalizeCiscoASAMode(%q) 不应回落到 legacy", raw)
		}
	}
	if !IsValidCiscoASAMode("") || !IsValidCiscoASAMode("strict") || !IsValidCiscoASAMode("SCOPED") {
		t.Fatal("合法档位被拒")
	}
	for _, raw := range []string{"strictx", "legacy2", "verbose"} {
		if IsValidCiscoASAMode(raw) {
			t.Errorf("非法档位 %q 被接受", raw)
		}
	}
}

// TestHasCiscoTunnelGroupQuery 锁定 tgroup 参数名精确匹配：
// 子串包含不算命中，避免把无关键名误判为门户跳转。
func TestHasCiscoTunnelGroupQuery(t *testing.T) {
	yes := []string{"tgroup=X", "a=1&tgroup=X", "TGROUP=X", "a=1&TGroup=", "tgroup="}
	no := []string{"", "x=1", "foobartgroup=x", "tgroupx=y", "atgroup=1", "tgroup"}
	for _, q := range yes {
		if !hasCiscoTunnelGroupQuery(q) {
			t.Errorf("query=%q 应判定含 tgroup", q)
		}
	}
	for _, q := range no {
		if hasCiscoTunnelGroupQuery(q) {
			t.Errorf("query=%q 不应判定含 tgroup", q)
		}
	}
}

// TestCiscoASAModeScopedDoesNotLeakCSCOT 锁定 scoped 档不会因为带 tgroup
// 而放过真正的 CSCOT 攻击形态。
func TestCiscoASAModeScopedDoesNotLeakCSCOT(t *testing.T) {
	hit, ok := checkCiscoASAPathTraversal("/+CSCOT+/translation-table", "tgroup=x", CiscoASAModeScoped)
	if !ok {
		t.Fatal("scoped 档不得因 tgroup 放过 +CSCOT+ 攻击形态")
	}
	if hit.RuleID != "owasp:path:006" {
		t.Fatalf("RuleID=%q", hit.RuleID)
	}
}
