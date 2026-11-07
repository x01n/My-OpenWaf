package owasp

import "testing"

// scoped 档的放行前置校验：门户登录页跳转必须自带干净的 path。
//
// 背景：scoped 档原本只要求「path 命中 +CSCOE+」且「query 带 tgroup=」即放行，
// 而 tgroup= 完全由客户端控制。`/+CSCOE+/../../../../etc/passwd?tgroup=x`
// 因此能从本档整体穿过。下面这组用例把「path 自带穿越序列时不得放行」钉死，
// 同时锁住真实门户跳转（path 干净）仍被放行的行为。
var ciscoScopedPortalCases = []struct {
	name  string
	path  string
	query string
	// scoped 档是否放行（false 表示拦截）
	allow bool
}{
	{"真实门户跳转", "/+CSCOE+/logon.html", "tgroup=TGr-SERVICE", true},
	{"门户跳转带其他参数", "/+CSCOE+/logon.html", "next=/&tgroup=x", true},
	{"门户跳转编码变体", "/%2bCSCOE%2b/logon.html", "tgroup=x", true},

	{"穿越加 tgroup 掩护", "/+CSCOE+/../etc/passwd", "tgroup=x", false},
	{"多级穿越", "/+CSCOE+/../../../../etc/passwd", "tgroup=x", false},
	{"穿越到 CSCOT", "/+CSCOE+/../../../../+CSCOT+/translation-table", "tgroup=x", false},
	{"编码穿越", "/+CSCOE+/%2e%2e/%2e%2e/etc/passwd", "tgroup=x", false},
	{"双重编码穿越", "/+CSCOE+/%252e%252e/etc/passwd", "tgroup=x", false},
	{"反斜杠穿越", `/+CSCOE+/..\windows\win.ini`, "tgroup=x", false},
	{"分号穿越", "/+CSCOE+/..;/logon.html", "tgroup=x", false},
	{"编码斜杠穿越", "/+CSCOE+/..%2fetc%2fpasswd", "tgroup=x", false},

	{"无 tgroup 不放行", "/+CSCOE+/logon.html", "", false},
	{"CSCOT 不受 tgroup 影响", "/+CSCOT+/translation-table", "tgroup=x", false},
	{"无关路径", "/index.html", "", true},
}

func TestCiscoScopedPortalRequiresCleanPath(t *testing.T) {
	for _, tc := range ciscoScopedPortalCases {
		_, hit := checkCiscoASAPathTraversal(tc.path, tc.query, CiscoASAModeScoped)
		if hit == tc.allow {
			t.Errorf("%s: path=%q query=%q 放行=%v 期望 %v",
				tc.name, tc.path, tc.query, hit, tc.allow)
		}
	}
}

// TestCiscoScopedMarkerCheckDoesNotAffectLegacyOrStrict 锁定穿越标记校验
// 只作用于 scoped 档：legacy 与 strict 的判定与历史一致，不因本改动放宽。
func TestCiscoScopedMarkerCheckDoesNotAffectLegacyOrStrict(t *testing.T) {
	for _, tc := range ciscoScopedPortalCases {
		legacyHit, legacyOK := checkCiscoASAPathTraversal(tc.path, tc.query, CiscoASAModeLegacy)
		strictHit, strictOK := checkCiscoASAPathTraversal(tc.path, tc.query, CiscoASAModeStrict)
		wantLegacy := containsAnyFold(tc.path, ciscoCSCOTTokens) || containsAnyFold(tc.path, ciscoCSCOETokens)
		wantStrict := containsAnyFold(tc.path, ciscoCSCOTTokens)
		if legacyOK != wantLegacy {
			t.Errorf("%s: legacy 档 path=%q 命中=%v 期望 %v", tc.name, tc.path, legacyOK, wantLegacy)
		}
		if strictOK != wantStrict {
			t.Errorf("%s: strict 档 path=%q 命中=%v 期望 %v", tc.name, tc.path, strictOK, wantStrict)
		}
		_ = legacyHit
		_ = strictHit
	}
}

// TestCiscoPortalTraversalMarkerRecognition 锁定标记识别的边界：
// 标记是形态而非具体文件名，且大小写不敏感。
func TestCiscoPortalTraversalMarkerRecognition(t *testing.T) {
	yes := []string{
		"/+CSCOE+/../x",
		"/+CSCOE+/..%2Fx",
		"/+CSCOE+/%2e%2e/x",
		"/+CSCOE+/%252e%252e/x",
		`/+CSCOE+/..\x`,
		"/+CSCOE+/..;/x",
		"/+CSCOE+/..%5Cx",
		"/+CSCOE+/..%2fx",
	}
	no := []string{
		"/+CSCOE+/logon.html",
		"/+CSCOE+/blank.html",
		"/+CSCOE+/session_password.html",
		"/+CSCOE+/tunnel_linux.jnlp",
		"/+CSCOE+/sdesktop/webstart.xml",
		"/index.html",
	}
	for _, p := range yes {
		if !hasCiscoPortalTraversalMarker(p) {
			t.Errorf("path=%q 应判定含穿越标记", p)
		}
	}
	for _, p := range no {
		if hasCiscoPortalTraversalMarker(p) {
			t.Errorf("path=%q 不应判定含穿越标记", p)
		}
	}
}
