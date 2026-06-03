package pages

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/core/action"
	"github.com/cloudwego/hertz/pkg/app"
)

func TestDefaultFallbackHTMLIncludesSecurityContext(t *testing.T) {
	html := defaultFallbackHTML("req-123", action.Result{
		RuleID:    42,
		RuleIDStr: "owasp-942100",
		Type:      action.Intercept,
		Phase:     "owasp",
		Category:  "sqli",
		MatchDesc: "union select",
	}, false, action.Intercept)

	for _, want := range []string{"req-123", "intercept", "owasp-942100", "owasp", "sqli", "union select"} {
		if !strings.Contains(html, want) {
			t.Fatalf("fallback block page missed %q: %s", want, html)
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
	for _, want := range []string{"req-429", "rate_limit", "429 Rate Limit"} {
		if !strings.Contains(html, want) {
			t.Fatalf("rate-limit fallback page missed %q: %s", want, html)
		}
	}
}
