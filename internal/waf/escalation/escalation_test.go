package escalation

import "testing"

func TestResetIPClearsLocalStatus(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	m.SetDefaultConfig(EscalationConfig{
		Enabled:    true,
		WindowSecs: 60,
		Steps: []EscalationStep{
			{Threshold: 1, Action: "challenge"},
		},
	})

	const ip = "203.0.113.10"
	m.RecordHit(ip, 0, nil)

	before := m.GetIPStatus(ip, 0)
	if before.HitCount != 1 || before.Level != 0 || before.Action != "challenge" {
		t.Fatalf("unexpected status before reset: %#v", before)
	}

	m.ResetIP(ip, 0)

	after := m.GetIPStatus(ip, 0)
	if after.HitCount != 0 || after.Level != -1 || after.Action != "" {
		t.Fatalf("unexpected status after reset: %#v", after)
	}
}
