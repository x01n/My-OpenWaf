package detect

import (
	"encoding/json"
	"testing"
)

func TestListOWASPRulesIncludeGroupedDefaultsToCompatibleResponse(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	defaultCtx := invokeCVERuleListHandler(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules?policy_id=1&page_size=500")
	if defaultCtx.Response.StatusCode() != 200 {
		t.Fatalf("default status=%d body=%s", defaultCtx.Response.StatusCode(), defaultCtx.Response.Body())
	}
	var defaultResp map[string]json.RawMessage
	if err := json.Unmarshal(defaultCtx.Response.Body(), &defaultResp); err != nil {
		t.Fatalf("decode default response: %v", err)
	}
	if len(defaultResp["items"]) == 0 || len(defaultResp["grouped"]) == 0 {
		t.Fatalf("default response missing items/grouped: %v", defaultResp)
	}

	flatCtx := invokeCVERuleListHandler(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules?policy_id=1&page_size=500&include_grouped=false")
	if flatCtx.Response.StatusCode() != 200 {
		t.Fatalf("flat status=%d body=%s", flatCtx.Response.StatusCode(), flatCtx.Response.Body())
	}
	var flatResp map[string]json.RawMessage
	if err := json.Unmarshal(flatCtx.Response.Body(), &flatResp); err != nil {
		t.Fatalf("decode flat response: %v", err)
	}
	if _, ok := flatResp["grouped"]; ok {
		t.Fatalf("flat response unexpectedly contains grouped: %s", flatCtx.Response.Body())
	}
	for _, key := range []string{"items", "total", "policy_id"} {
		if len(flatResp[key]) == 0 {
			t.Fatalf("flat response missing %q: %s", key, flatCtx.Response.Body())
		}
	}
	if string(flatResp["items"]) != string(defaultResp["items"]) {
		t.Fatal("flat items differ from compatible response")
	}
	if len(flatCtx.Response.Body()) >= len(defaultCtx.Response.Body()) {
		t.Fatalf("flat bytes=%d want less than default bytes=%d", len(flatCtx.Response.Body()), len(defaultCtx.Response.Body()))
	}

	otherCtx := invokeCVERuleListHandler(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules?policy_id=1&page_size=500&include_grouped=0")
	var otherResp map[string]json.RawMessage
	if err := json.Unmarshal(otherCtx.Response.Body(), &otherResp); err != nil {
		t.Fatalf("decode non-false response: %v", err)
	}
	if len(otherResp["grouped"]) == 0 {
		t.Fatalf("non-false include_grouped must preserve grouped: %s", otherCtx.Response.Body())
	}
}
