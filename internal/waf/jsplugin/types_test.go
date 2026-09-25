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

func TestValidateWithOptionsRejectsUnknownStage(t *testing.T) {
	if err := ValidateWithOptions(
		"pre",
		`export default { fetch() { return {}; } }`,
		ScriptOptions{},
	); err == nil {
		t.Fatal("ValidateWithOptions(pre) error = nil, want unknown-stage error")
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

func TestValidateResponseMutationPlanRejectsUnsafeChanges(t *testing.T) {
	intValue := func(value int) *int { return &value }
	stringValue := func(value string) *string { return &value }
	cases := []struct {
		name string
		plan ResponseMutationPlan
	}{
		{name: "status below range", plan: ResponseMutationPlan{Status: intValue(99)}},
		{name: "status above range", plan: ResponseMutationPlan{Status: intValue(1000)}},
		{name: "body too large", plan: ResponseMutationPlan{Body: stringValue(strings.Repeat("x", MaxMutationStringBytes+1))}},
		{name: "content length set", plan: ResponseMutationPlan{SetHeaders: map[string]string{"Content-Length": "1"}}},
		{name: "content length deletion", plan: ResponseMutationPlan{DeleteHeaders: []string{"CONTENT-LENGTH"}}},
		{name: "connection set", plan: ResponseMutationPlan{SetHeaders: map[string]string{"Connection": "close"}}},
		{name: "header control byte", plan: ResponseMutationPlan{SetHeaders: map[string]string{"X-Test": "before\x00after"}}},
		{name: "duplicate normalized header", plan: ResponseMutationPlan{SetHeaders: map[string]string{"X-Test": "1", "x-test": "2"}}},
		{name: "header conflict", plan: ResponseMutationPlan{SetHeaders: map[string]string{"X-Test": "1"}, DeleteHeaders: []string{"x-test"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateResponseMutationPlan(tc.plan); err == nil {
				t.Fatal("ValidateResponseMutationPlan() error = nil")
			}
		})
	}

	status := 418
	body := "replaced"
	ok := ResponseMutationPlan{
		Status:        &status,
		Body:          &body,
		SetHeaders:    map[string]string{"X-Response-Mode": "preview"},
		DeleteHeaders: []string{"X-Legacy-Mode"},
	}
	if err := ValidateResponseMutationPlan(ok); err != nil {
		t.Fatalf("ValidateResponseMutationPlan() error = %v", err)
	}
}

func TestNormalizeAndEncodeResponseSnapshot(t *testing.T) {
	snapshot := ResponseSnapshot{
		RequestID:      "req-1",
		SiteID:         7,
		Status:         200,
		Path:           "/",
		ContentType:    "text/html",
		Body:           "ok",
		Headers:        map[string]string{"content-type": "text/html"},
		Method:         "GET",
		RawQuery:       "a=1",
		ClientIP:       "192.0.2.1",
		RequestHeaders: map[string]string{"accept": "*/*"},
	}
	normalized, err := normalizeResponseSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Headers["content-type"] = "changed"
	snapshot.RequestHeaders["accept"] = "changed"
	if normalized.Headers["content-type"] != "text/html" || normalized.RequestHeaders["accept"] != "*/*" {
		t.Fatalf("snapshot maps were not copied: %#v", normalized)
	}
	if _, err := encodeResponseSnapshot(snapshot); err != nil {
		t.Fatalf("encodeResponseSnapshot() error = %v", err)
	}
}

func TestEncodeResponseSnapshotRejectsOversizedFields(t *testing.T) {
	if _, err := encodeResponseSnapshot(ResponseSnapshot{Body: strings.Repeat("x", MaxResponseSnapshotBodyBytes+1)}); err == nil {
		t.Fatal("oversized body was accepted")
	}
	if _, err := encodeResponseSnapshot(ResponseSnapshot{Headers: map[string]string{"X-Test": strings.Repeat("x", MaxResponseSnapshotStringBytes+1)}}); err == nil {
		t.Fatal("oversized header value was accepted")
	}
	if _, err := encodeResponseSnapshot(ResponseSnapshot{RequestHeaders: map[string]string{"X-Test": strings.Repeat("x", MaxResponseSnapshotStringBytes+1)}}); err == nil {
		t.Fatal("oversized request header value was accepted")
	}
}
