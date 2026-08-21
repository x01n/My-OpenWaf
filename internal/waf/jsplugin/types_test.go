package jsplugin

import (
	"strings"
	"testing"
)

func TestScriptMetadataCopiesSiteScope(t *testing.T) {
	siteID := uint(42)
	script := newScript("export default {}", ScriptOptions{Name: "metadata"})
	script.setMetadata(ScriptMetadata{
		Stage:       "request",
		Priority:    7,
		FailureMode: "fail_closed",
		SiteID:      &siteID,
	})
	siteID = 99
	if script.Stage() != "request" || script.Priority() != 7 || script.FailureMode() != "fail_closed" {
		t.Fatalf("metadata = %#v", script.Metadata())
	}
	if got := script.SiteID(); got == nil || *got != 42 {
		t.Fatalf("site id = %v, want 42", got)
	}
}

func TestNormalizeRequestSnapshotCopiesMaps(t *testing.T) {
	snapshot := RequestSnapshot{
		Headers:     map[string]string{"X-Test": "before"},
		QueryParams: map[string]string{"q": "value"},
	}
	normalized, err := normalizeRequestSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Headers["X-Test"] = "after"
	snapshot.QueryParams["q"] = "changed"
	if normalized.Headers["X-Test"] != "before" || normalized.QueryParams["q"] != "value" {
		t.Fatalf("snapshot maps were not copied: %#v", normalized)
	}
}

func TestNormalizeRequestSnapshotRejectsOversizedFields(t *testing.T) {
	if _, err := normalizeRequestSnapshot(RequestSnapshot{Body: strings.Repeat("x", MaxRequestSnapshotBodyBytes+1)}); err == nil {
		t.Fatal("oversized body was accepted")
	}
	if _, err := normalizeRequestSnapshot(RequestSnapshot{Headers: map[string]string{"X-Test": strings.Repeat("x", MaxRequestSnapshotStringBytes+1)}}); err == nil {
		t.Fatal("oversized header value was accepted")
	}
	if _, err := normalizeRequestSnapshot(RequestSnapshot{Headers: map[string]string{"X-Test": strings.Repeat("x", MaxRequestSnapshotStringBytes)}, QueryParams: map[string]string{"q": strings.Repeat("x", MaxRequestSnapshotStringBytes)}}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateMutationPlanRejectsUnsafeRequestChanges(t *testing.T) {
	stringValue := func(value string) *string { return &value }
	cases := []struct {
		name string
		plan MutationPlan
	}{
		{name: "invalid method", plan: MutationPlan{Method: stringValue("GET /admin")}},
		{name: "absolute path", plan: MutationPlan{Path: stringValue("https://example.test/admin")}},
		{name: "path query", plan: MutationPlan{Path: stringValue("/admin?debug=1")}},
		{name: "invalid escaped path", plan: MutationPlan{Path: stringValue("/%zz")}},
		{name: "fragment query", plan: MutationPlan{RawQuery: stringValue("token=abc#fragment")}},
		{name: "invalid escaped query", plan: MutationPlan{RawQuery: stringValue("token=%zz")}},
		{name: "host set", plan: MutationPlan{SetHeaders: map[string]string{"Host": "evil.example"}}},
		{name: "host deletion", plan: MutationPlan{DeleteHeaders: []string{"hOsT"}}},
		{name: "content length set", plan: MutationPlan{SetHeaders: map[string]string{"Content-Length": "1"}}},
		{name: "content length deletion", plan: MutationPlan{DeleteHeaders: []string{"CONTENT-LENGTH"}}},
		{name: "transfer encoding set", plan: MutationPlan{SetHeaders: map[string]string{"Transfer-Encoding": "chunked"}}},
		{name: "transfer encoding deletion", plan: MutationPlan{DeleteHeaders: []string{"tRaNsFeR-EnCoDiNg"}}},
		{name: "connection set", plan: MutationPlan{SetHeaders: map[string]string{"Connection": "close"}}},
		{name: "connection deletion", plan: MutationPlan{DeleteHeaders: []string{"cOnNeCtIoN"}}},
		{name: "upgrade set", plan: MutationPlan{SetHeaders: map[string]string{"Upgrade": "websocket"}}},
		{name: "upgrade deletion", plan: MutationPlan{DeleteHeaders: []string{"uPgRaDe"}}},
		{name: "proxy connection set", plan: MutationPlan{SetHeaders: map[string]string{"Proxy-Connection": "keep-alive"}}},
		{name: "proxy connection deletion", plan: MutationPlan{DeleteHeaders: []string{"pRoXy-CoNnEcTiOn"}}},
		{name: "trailer set", plan: MutationPlan{SetHeaders: map[string]string{"Trailer": "X-Trailer"}}},
		{name: "trailer deletion", plan: MutationPlan{DeleteHeaders: []string{"tRaIlEr"}}},
		{name: "keep alive set", plan: MutationPlan{SetHeaders: map[string]string{"Keep-Alive": "timeout=5"}}},
		{name: "keep alive deletion", plan: MutationPlan{DeleteHeaders: []string{"kEeP-AlIvE"}}},
		{name: "te set", plan: MutationPlan{SetHeaders: map[string]string{"TE": "trailers"}}},
		{name: "te deletion", plan: MutationPlan{DeleteHeaders: []string{"tE"}}},
		{name: "proxy authenticate set", plan: MutationPlan{SetHeaders: map[string]string{"Proxy-Authenticate": "Basic"}}},
		{name: "proxy authenticate deletion", plan: MutationPlan{DeleteHeaders: []string{"pRoXy-AuThEnTiCaTe"}}},
		{name: "proxy authorization set", plan: MutationPlan{SetHeaders: map[string]string{"Proxy-Authorization": "Basic token"}}},
		{name: "proxy authorization deletion", plan: MutationPlan{DeleteHeaders: []string{"pRoXy-AuThOrIzAtIoN"}}},
		{name: "header control byte", plan: MutationPlan{SetHeaders: map[string]string{"X-Test": "before\x00after"}}},
		{name: "duplicate normalized header", plan: MutationPlan{SetHeaders: map[string]string{"X-Test": "1", "x-test": "2"}}},
		{name: "header conflict", plan: MutationPlan{SetHeaders: map[string]string{"X-Test": "1"}, DeleteHeaders: []string{"x-test"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateMutationPlan(tc.plan); err == nil {
				t.Fatal("ValidateMutationPlan() error = nil")
			}
		})
	}
}

func TestValidateMutationPlanAcceptsSafeRequestChanges(t *testing.T) {
	method := "PATCH"
	path := "/accounts/profile"
	rawQuery := "mode=preview&tab=security"
	plan := MutationPlan{
		Method:        &method,
		Path:          &path,
		RawQuery:      &rawQuery,
		SetHeaders:    map[string]string{"X-Request-Mode": "preview"},
		DeleteHeaders: []string{"X-Legacy-Mode"},
	}
	if err := ValidateMutationPlan(plan); err != nil {
		t.Fatalf("ValidateMutationPlan() error = %v", err)
	}
}
