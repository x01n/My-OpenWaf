package admin

import (
	"encoding/json"
	"testing"
)

func TestNormalizeChainStepPayloadUsesRuntimeFields(t *testing.T) {
	raw := json.RawMessage(`[{"type":"captcha","condition":"all"},{"type":"pow","match":"score>50"}]`)
	got, ok := normalizeChainStepPayload(raw)
	if !ok {
		t.Fatal("normalizeChainStepPayload() rejected valid steps")
	}
	var steps []chainStepPayload
	if err := json.Unmarshal([]byte(got), &steps); err != nil {
		t.Fatalf("normalizeChainStepPayload() returned invalid JSON: %v", err)
	}
	if len(steps) != 2 || steps[0].Type != "captcha" || steps[0].Condition != "all" || steps[1].Type != "pow" || steps[1].Condition != "score>50" {
		t.Fatalf("normalizeChainStepPayload() decoded to %#v", steps)
	}
}

func TestNormalizeChainStepPayloadRejectsUnsupportedStep(t *testing.T) {
	if _, ok := normalizeChainStepPayload(json.RawMessage(`[{"type":"shield","condition":"all"}]`)); ok {
		t.Fatal("normalizeChainStepPayload() accepted unsupported shield step")
	}
}
