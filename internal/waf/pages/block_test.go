package pages

import (
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/waf/challenge"
	"github.com/cloudwego/hertz/pkg/app"
)

func TestDefaultFallbackHTMLIncludesRequestID(t *testing.T) {
	html := defaultFallbackHTML("req-123", action.Result{
		RuleID:    42,
		RuleIDStr: "owasp-942100",
		Type:      action.Intercept,
		Phase:     "owasp",
		Category:  "sqli",
		MatchDesc: "union select",
	}, false, action.Intercept)

	if !strings.Contains(html, "req-123") {
		t.Fatalf("fallback block page missed request ID: %s", html)
	}
	if !strings.Contains(html, "403") {
		t.Fatalf("fallback block page missed status code 403: %s", html)
	}
	for _, leak := range []string{"owasp-942100", "sqli", "union select"} {
		if strings.Contains(html, leak) {
			t.Fatalf("fallback block page leaked sensitive info %q: %s", leak, html)
		}
	}
}

func TestWriteBlockResponseAllowsNilSnapshot(t *testing.T) {
	var c app.RequestContext
	WriteBlockResponse(&c, "req-nil", nil, nil, action.Result{Type: action.Intercept, RuleIDStr: "r1"})
	if c.Response.StatusCode() != 403 {
		t.Fatalf("status = %d", c.Response.StatusCode())
	}
	if !strings.Contains(string(c.Response.Body()), "req-nil") {
		t.Fatalf("response missed request id: %s", c.Response.Body())
	}
}

func TestDefaultFallbackHTMLNormalizesRateLimitAction(t *testing.T) {
	html := defaultFallbackHTML("req-429", action.Result{RuleID: 7, Type: action.RateLimit}, false, action.RateLimit)
	if !strings.Contains(html, "req-429") {
		t.Fatalf("rate-limit fallback page missed request ID: %s", html)
	}
	if !strings.Contains(html, "429") {
		t.Fatalf("rate-limit fallback page missed status code 429: %s", html)
	}
}

func TestDefaultFallbackHTMLMaintenanceMode(t *testing.T) {
	html := defaultFallbackHTML("req-maint", action.Result{}, true, action.Intercept)
	if !strings.Contains(html, "req-maint") {
		t.Fatalf("maintenance page missed request ID: %s", html)
	}
	if !strings.Contains(html, "503") {
		t.Fatalf("maintenance page missed 503: %s", html)
	}
	if !strings.Contains(html, "Maintenance") {
		t.Fatalf("maintenance page missed 'Maintenance': %s", html)
	}
}

func TestValueOrFallbackReturnsValue(t *testing.T) {
	if got := valueOrFallback("hello", "fallback"); got != "hello" {
		t.Errorf("valueOrFallback(non-empty) = %q, want \"hello\"", got)
	}
}

func TestValueOrFallbackReturnsFallback(t *testing.T) {
	if got := valueOrFallback("", "fallback"); got != "fallback" {
		t.Errorf("valueOrFallback(empty) = %q, want \"fallback\"", got)
	}
}

func TestBuildErrorFallbackHTMLDefault(t *testing.T) {
	html := buildErrorFallbackHTML("req-err", 500)
	if !strings.Contains(html, "req-err") {
		t.Fatalf("error fallback HTML missed request ID: %s", html)
	}
	if !strings.Contains(html, "500") {
		t.Fatalf("error fallback HTML missed status code: %s", html)
	}
}

func TestBuildErrorFallbackHTML502(t *testing.T) {
	html := buildErrorFallbackHTML("req-502", 502)
	if !strings.Contains(html, "Bad Gateway") {
		t.Fatalf("502 page missed 'Bad Gateway': %s", html)
	}
	if !strings.Contains(html, "req-502") {
		t.Fatalf("502 page missed request ID: %s", html)
	}
}

func TestBuildErrorFallbackHTML503(t *testing.T) {
	html := buildErrorFallbackHTML("req-503", 503)
	if !strings.Contains(html, "Service Unavailable") {
		t.Fatalf("503 page missed 'Service Unavailable': %s", html)
	}
}

func TestBuildErrorFallbackHTML504(t *testing.T) {
	html := buildErrorFallbackHTML("req-504", 504)
	if !strings.Contains(html, "Gateway Timeout") {
		t.Fatalf("504 page missed 'Gateway Timeout': %s", html)
	}
}

func TestBuildChallengeHTMLContainsTokens(t *testing.T) {
	html := buildChallengeHTML("req-chal", "ts-value", "tok-value", "", "")
	if !strings.Contains(html, "req-chal") {
		t.Fatalf("challenge HTML missed reqID: %s", html)
	}
	if !strings.Contains(html, "ts-value") {
		t.Fatalf("challenge HTML missed ts: %s", html)
	}
	if !strings.Contains(html, "tok-value") {
		t.Fatalf("challenge HTML missed token: %s", html)
	}
}

func TestBuildChallengeHTMLWithEnvJS(t *testing.T) {
	html := buildChallengeHTML("req-env", "ts2", "tok2", "var env_injected=1;", "")
	if !strings.Contains(html, "env_injected") {
		t.Fatalf("challenge HTML missed injected envJS: %s", html)
	}
}

// TestBuildChallengeHTMLInjectsPoWScript 验证 WASM PoW 脚本被注入挑战页。
func TestBuildChallengeHTMLInjectsPoWScript(t *testing.T) {
	html := buildChallengeHTML("req-pow", "ts3", "tok3", "", "var __pow_marker=1;")
	if !strings.Contains(html, "__pow_marker") {
		t.Fatalf("challenge HTML missed injected PoW script: %s", html)
	}
	if !strings.Contains(html, "__owaf_pow_callback") {
		t.Fatalf("challenge HTML must wire the WASM PoW callback: %s", html)
	}
}

// TestBuildChallengeHTMLHasNoJSPoWFallback 是回归测试：
// 工作量证明必须只由 WASM 求解，页面内不得内联 JS 版 SHA-256 实现，
// 否则攻击者可绕过 WASM 直接用脚本求解。
func TestBuildChallengeHTMLHasNoJSPoWFallback(t *testing.T) {
	html := buildChallengeHTML("req-nofb", "ts4", "tok4", "", "")
	// 纯 JS SHA-256 实现的特征常量（K 表首项与初始哈希值）。
	for _, marker := range []string{"0x428a2f98", "0x6a09e667", "0x71374491"} {
		if strings.Contains(html, marker) {
			t.Fatalf("challenge HTML must not embed a JS SHA-256 fallback (found %s)", marker)
		}
	}
}

func TestWriteUpstreamErrorResponseSetsStatusCode(t *testing.T) {
	var c app.RequestContext
	WriteUpstreamErrorResponse(&c, "req-upstream", 502)
	if c.Response.StatusCode() != 502 {
		t.Fatalf("status = %d, want 502", c.Response.StatusCode())
	}
	body := string(c.Response.Body())
	if !strings.Contains(body, "req-upstream") {
		t.Fatalf("upstream error response missed request ID: %s", body)
	}
}

func TestWriteChallengeResponseSetsHeaders(t *testing.T) {
	var c app.RequestContext
	claims := challenge.ChallengeTokenClaims{ClientIP: "203.0.113.9", UserAgent: "ua", Host: "a.example", SiteID: 3}
	WriteChallengeResponse(&c, "req-chal-hdr", nil, false, 403, claims)
	if c.Response.StatusCode() != 403 {
		t.Fatalf("status = %d, want 403", c.Response.StatusCode())
	}
	if string(c.Response.Header.Get("X-Request-ID")) != "req-chal-hdr" {
		t.Errorf("X-Request-ID header not set")
	}
	body := string(c.Response.Body())
	if !strings.Contains(body, "req-chal-hdr") {
		t.Fatalf("challenge response missed request ID: %s", body)
	}
}

// TestWriteChallengeResponseIssuesClientBoundToken 验证挑战页里的 token
// 只对签发它的客户端有效，其他客户端复制三元组无法通过校验。
func TestWriteChallengeResponseIssuesClientBoundToken(t *testing.T) {
	var c app.RequestContext
	owner := challenge.ChallengeTokenClaims{ClientIP: "203.0.113.9", UserAgent: "ua", Host: "a.example", SiteID: 3}
	WriteChallengeResponse(&c, "req-chal-bound", nil, false, 403, owner)

	body := string(c.Response.Body())
	ts := extractHiddenField(t, body, "__waf_challenge_ts")
	token := extractHiddenField(t, body, "__waf_challenge_token")

	if !challenge.VerifyChallengeTokenWithClaims("req-chal-bound", ts, token, owner, 5*time.Minute) {
		t.Fatal("token from the rendered page must verify for its own client")
	}
	attacker := challenge.ChallengeTokenClaims{ClientIP: "198.51.100.7", UserAgent: "ua", Host: "a.example", SiteID: 3}
	if challenge.VerifyChallengeTokenWithClaims("req-chal-bound", ts, token, attacker, 5*time.Minute) {
		t.Fatal("token must not verify for a different client IP")
	}
}

// extractHiddenField 从挑战页 JS 中取出 af("<name>", <var>) 所绑定的变量字面量值。
func extractHiddenField(t *testing.T, body, name string) string {
	t.Helper()
	var varName string
	switch name {
	case "__waf_challenge_ts":
		varName = "ts"
	case "__waf_challenge_token":
		varName = "tk"
	default:
		t.Fatalf("unsupported field %q", name)
	}
	marker := varName + `="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("challenge page did not define %s for %s: %s", varName, name, body)
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("unterminated %s literal in challenge page", varName)
	}
	return rest[:end]
}

func TestWriteMaintenanceResponseNilSnapshot(t *testing.T) {
	var c app.RequestContext
	sn := &snapshot.Snapshot{}
	WriteMaintenanceResponse(&c, "req-maint-nil", nil, sn)
	if c.Response.StatusCode() != 503 {
		t.Fatalf("status = %d, want 503", c.Response.StatusCode())
	}
}

func TestWriteBlockResponseWithCustomBlockHTML(t *testing.T) {
	var c app.RequestContext
	rt := &snapshot.SiteRuntime{BlockHTML: "<html>custom block {{.RequestID}}</html>"}
	sn := &snapshot.Snapshot{}
	WriteBlockResponse(&c, "req-custom", rt, sn, action.Result{Type: action.Intercept})
	body := string(c.Response.Body())
	if !strings.Contains(body, "req-custom") {
		t.Fatalf("custom block page missed request ID: %s", body)
	}
}
