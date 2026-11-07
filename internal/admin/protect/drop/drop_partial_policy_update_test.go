package drop

import (
	"encoding/json"
	"testing"
)

func TestUpdateDropPolicyPreservesAbsentFieldsInStoredPartialPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("drop_policy", `{"cve_auto_drop_critical":false}`); err != nil {
		t.Fatalf("seed partial drop policy: %v", err)
	}

	ctx := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error { return nil }), map[string]any{
		"cve_auto_drop_high": true,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	value, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &stored); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if len(stored) != 2 || string(stored["cve_auto_drop_critical"]) != "false" || string(stored["cve_auto_drop_high"]) != "true" {
		t.Fatalf("partial update should retain only stored and submitted fields, got %s", value)
	}
	for _, key := range []string{"enabled", "bot_score_threshold"} {
		if _, exists := stored[key]; exists {
			t.Errorf("partial update materialized absent %q field: %s", key, value)
		}
	}
}

func TestUpdateDropPolicyPreservesExplicitFieldsInPartialPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("drop_policy", `{"enabled":false,"bot_score_threshold":73}`); err != nil {
		t.Fatalf("seed partial drop policy: %v", err)
	}

	ctx := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error { return nil }), map[string]any{
		"cve_auto_drop_critical": true,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	value, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &stored); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if string(stored["enabled"]) != "false" || string(stored["bot_score_threshold"]) != "73" || string(stored["cve_auto_drop_critical"]) != "true" {
		t.Fatalf("partial update changed explicitly stored fields: %s", value)
	}
	if _, exists := stored["cve_auto_drop_high"]; exists {
		t.Fatalf("partial update materialized absent cve_auto_drop_high field: %s", value)
	}
}

func TestUpdateDropPolicyRejectsNonObjectStoredPolicy(t *testing.T) {
	for _, stored := range []string{"{invalid", "null", "[]", "true", "7", `{"enabled":"false"}`} {
		t.Run(stored, func(t *testing.T) {
			repo := newSystemSettingsRepoForTest(t)
			if err := repo.Set("drop_policy", stored); err != nil {
				t.Fatalf("seed invalid drop policy: %v", err)
			}

			reloadCalls := 0
			ctx := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error {
				reloadCalls++
				return nil
			}), map[string]any{"enabled": false})
			if ctx.Response.StatusCode() != 500 {
				t.Fatalf("expected status 500, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
			}
			value, err := repo.Get("drop_policy")
			if err != nil {
				t.Fatalf("get drop policy: %v", err)
			}
			if value != stored {
				t.Errorf("invalid stored policy was modified: got %q, want %q", value, stored)
			}
			if reloadCalls != 0 {
				t.Errorf("reload called %d times for invalid stored policy", reloadCalls)
			}
		})
	}
}
