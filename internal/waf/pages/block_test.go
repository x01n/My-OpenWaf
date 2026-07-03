package pages

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/core/action"
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
