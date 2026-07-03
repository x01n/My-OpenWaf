package appresource

import "testing"

func TestBuildRecordedResourceAllowsEmptyMatchedRules(t *testing.T) {
	rec := BuildRecordedResource(7, nil, &Material{
		Method:      "GET",
		Host:        "example.com",
		Path:        "/assets/app.js",
		QueryString: "v=20260611",
		ClientIP:    "203.0.113.10",
		StatusCode:  200,
		ContentType: "application/javascript",
		UserAgent:   "Mozilla/5.0",
		TLSVersion:  "TLS13",
		TLSSNI:      "example.com",
		TLSALPN:     "h2",
		JA3Hash:     "ja3-hash",
		JA4:         "ja4-hash",
	})
	if rec == nil {
		t.Fatal("BuildRecordedResource should keep unmatched site resources")
	}
	if rec.PrimaryRuleID != 0 {
		t.Fatalf("PrimaryRuleID = %d, want 0", rec.PrimaryRuleID)
	}
	if rec.MatchedRuleIDs != "" {
		t.Fatalf("MatchedRuleIDs = %q, want empty", rec.MatchedRuleIDs)
	}
	if rec.Path != "/assets/app.js" || rec.Host != "example.com" {
		t.Fatalf("unexpected resource identity: %#v", rec)
	}
	if rec.QueryString != "v=20260611" {
		t.Fatalf("QueryString = %q, want %q", rec.QueryString, "v=20260611")
	}
	if rec.TLSVersion != "TLS13" || rec.TLSSNI != "example.com" || rec.TLSALPN != "h2" {
		t.Fatalf("TLS metadata = %#v", rec)
	}
	if rec.JA4 != "ja4-hash" {
		t.Fatalf("JA4 = %q, want %q", rec.JA4, "ja4-hash")
	}
}
