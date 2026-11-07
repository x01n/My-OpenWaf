package shared

import (
	"encoding/json"
	"testing"
)

func TestSyncBotThresholdToDropPolicyRuntimeCreatesPartialPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := SyncBotThresholdToDropPolicyRuntime(repo, 55); err != nil {
		t.Fatalf("sync bot threshold: %v", err)
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if len(got) != 1 || string(got["bot_score_threshold"]) != "55" {
		t.Fatalf("expected only bot_score_threshold, got %s", val)
	}
}

func TestSyncCVEAutoDropToDropPolicyRuntimeCreatesPartialPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := SyncCVEAutoDropToDropPolicyRuntime(repo, false, true); err != nil {
		t.Fatalf("sync CVE auto-drop fields: %v", err)
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if len(got) != 2 || string(got["cve_auto_drop_critical"]) != "false" || string(got["cve_auto_drop_high"]) != "true" {
		t.Fatalf("expected only CVE auto-drop fields, got %s", val)
	}
}

func TestSyncRuntimeDropPolicyFieldsPreservesExistingFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	initial := `{"enabled":false,"bot_score_threshold":80,"cve_auto_drop_critical":true,"cve_auto_drop_high":false,"custom":"kept"}`
	if err := repo.Set("drop_policy", initial); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}
	if err := SyncBotThresholdToDropPolicyRuntime(repo, 55); err != nil {
		t.Fatalf("sync bot threshold: %v", err)
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if string(got["enabled"]) != "false" || string(got["bot_score_threshold"]) != "55" ||
		string(got["cve_auto_drop_critical"]) != "true" || string(got["cve_auto_drop_high"]) != "false" ||
		string(got["custom"]) != `"kept"` {
		t.Fatalf("existing drop policy fields changed: %s", val)
	}
}

func TestSyncRuntimeDropPolicyFieldsWritesPartialJSONForEmptyValue(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("drop_policy", " "); err != nil {
		t.Fatalf("seed empty drop policy: %v", err)
	}
	if err := SyncCVEAutoDropToDropPolicyRuntime(repo, false, false); err != nil {
		t.Fatalf("sync CVE auto-drop fields: %v", err)
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if len(got) != 2 || string(got["cve_auto_drop_critical"]) != "false" || string(got["cve_auto_drop_high"]) != "false" {
		t.Fatalf("expected only CVE auto-drop fields, got %s", val)
	}
}
