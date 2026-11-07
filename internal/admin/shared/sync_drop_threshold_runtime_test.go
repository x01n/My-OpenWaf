package shared

import (
	"encoding/json"
	"testing"
)

func TestSyncDropThresholdToBotSettingsRuntimeCreatesPartialSettings(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := SyncDropThresholdToBotSettingsRuntime(repo, 65); err != nil {
		t.Fatalf("sync drop threshold: %v", err)
	}

	value, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("get bot settings: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &settings); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if len(settings) != 1 || string(settings["score_threshold"]) != "65" {
		t.Fatalf("expected only score_threshold, got %s", value)
	}
}

func TestSyncDropThresholdToBotSettingsRuntimePreservesExistingFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	initial := `{"enabled":true,"score_threshold":60,"high_risk_countries":["CN"],"custom":"kept"}`
	if err := repo.Set("bot_settings", initial); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}
	if err := SyncDropThresholdToBotSettingsRuntime(repo, 88); err != nil {
		t.Fatalf("sync drop threshold: %v", err)
	}

	value, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("get bot settings: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &settings); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if string(settings["enabled"]) != "true" || string(settings["score_threshold"]) != "88" ||
		string(settings["high_risk_countries"]) != `["CN"]` || string(settings["custom"]) != `"kept"` {
		t.Fatalf("existing bot settings fields changed: %s", value)
	}
}
