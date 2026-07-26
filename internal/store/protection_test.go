package store

import (
	"encoding/json"
	"testing"
)

// --- normalizeProtectionSensitivityLevel ---

func TestNormalizeProtectionSensitivityLevel(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"off", "off"},
		{"OFF", "off"},
		{"none", "off"},
		{"NONE", "off"},
		{"low", "low"},
		{"LOW", "low"},
		{"medium", "mid"},
		{"mid", "mid"},
		{"MID", "mid"},
		{"MEDIUM", "mid"},
		{"high", "high"},
		{"HIGH", "high"},
		{"very_high", "very_high"},
		{"very-high", "very_high"},
		{"veryhigh", "very_high"},
		{"VERY_HIGH", "very_high"},
		{"strict", "strict"},
		{"STRICT", "strict"},
		{"  mid  ", "mid"},
		{"unknown", ""},
		{"", ""},
		{"invalid", ""},
	}
	for _, c := range cases {
		got := normalizeProtectionSensitivityLevel(c.input)
		if got != c.want {
			t.Errorf("normalizeProtectionSensitivityLevel(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// --- normalizeProtectionSensitivityMap ---

func TestNormalizeProtectionSensitivityMap(t *testing.T) {
	t.Run("nil map returns nil", func(t *testing.T) {
		if normalizeProtectionSensitivityMap(nil) != nil {
			t.Error("expected nil")
		}
	})
	t.Run("empty map returns nil", func(t *testing.T) {
		if normalizeProtectionSensitivityMap(map[string]string{}) != nil {
			t.Error("expected nil for empty map")
		}
	})
	t.Run("invalid values stripped, valid values kept", func(t *testing.T) {
		m := map[string]string{
			"sqli": "high",
			"xss":  "INVALID",
			"lfi":  "medium",
		}
		out := normalizeProtectionSensitivityMap(m)
		if len(out) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(out))
		}
		if out["sqli"] != "high" {
			t.Errorf("sqli = %q, want high", out["sqli"])
		}
		if out["lfi"] != "mid" {
			t.Errorf("lfi = %q, want mid", out["lfi"])
		}
		if _, ok := out["xss"]; ok {
			t.Error("invalid entry xss should be stripped")
		}
	})
	t.Run("all invalid returns nil", func(t *testing.T) {
		m := map[string]string{"a": "bad", "b": "also bad"}
		if normalizeProtectionSensitivityMap(m) != nil {
			t.Error("expected nil when all values invalid")
		}
	})
}

// --- GetCategorySensitivity ---

func TestGetCategorySensitivity(t *testing.T) {
	t.Run("empty string returns nil", func(t *testing.T) {
		p := &ProtectionConfig{}
		if p.GetCategorySensitivity() != nil {
			t.Error("expected nil for empty CategorySensitivity")
		}
	})
	t.Run("empty object returns nil", func(t *testing.T) {
		p := &ProtectionConfig{CategorySensitivity: "{}"}
		if p.GetCategorySensitivity() != nil {
			t.Error("expected nil for '{}'")
		}
	})
	t.Run("invalid json returns nil", func(t *testing.T) {
		p := &ProtectionConfig{CategorySensitivity: "not-json"}
		if p.GetCategorySensitivity() != nil {
			t.Error("expected nil for invalid json")
		}
	})
	t.Run("valid json parsed and normalized", func(t *testing.T) {
		p := &ProtectionConfig{CategorySensitivity: `{"sqli":"HIGH","xss":"mid"}`}
		m := p.GetCategorySensitivity()
		if m["sqli"] != "high" || m["xss"] != "mid" {
			t.Errorf("got %v", m)
		}
	})
}

// --- SetCategorySensitivity ---

func TestSetCategorySensitivity(t *testing.T) {
	t.Run("nil map sets empty object", func(t *testing.T) {
		p := &ProtectionConfig{}
		p.SetCategorySensitivity(nil)
		if p.CategorySensitivity != "{}" {
			t.Errorf("expected '{}', got %q", p.CategorySensitivity)
		}
	})
	t.Run("valid map serializes and round-trips", func(t *testing.T) {
		p := &ProtectionConfig{}
		p.SetCategorySensitivity(map[string]string{"sqli": "high", "xss": "low"})
		m := p.GetCategorySensitivity()
		if m["sqli"] != "high" || m["xss"] != "low" {
			t.Errorf("round-trip failed: %v", m)
		}
	})
	t.Run("all-invalid values sets empty object", func(t *testing.T) {
		p := &ProtectionConfig{}
		p.SetCategorySensitivity(map[string]string{"cat": "garbage"})
		if p.CategorySensitivity != "{}" {
			t.Errorf("expected '{}', got %q", p.CategorySensitivity)
		}
	})
}

// --- GetOWASPModules ---

func TestGetOWASPModules(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		p := &ProtectionConfig{}
		if p.GetOWASPModules() != nil {
			t.Error("expected nil")
		}
	})
	t.Run("valid json parsed", func(t *testing.T) {
		p := &ProtectionConfig{OWASPModules: `{"rce":"strict"}`}
		m := p.GetOWASPModules()
		if m["rce"] != "strict" {
			t.Errorf("got %v", m)
		}
	})
}

// --- EffectiveCategorySensitivity ---

func TestEffectiveCategorySensitivity(t *testing.T) {
	t.Run("both empty returns nil", func(t *testing.T) {
		p := &ProtectionConfig{}
		if p.EffectiveCategorySensitivity() != nil {
			t.Error("expected nil")
		}
	})
	t.Run("category only", func(t *testing.T) {
		p := &ProtectionConfig{CategorySensitivity: `{"sqli":"high"}`}
		m := p.EffectiveCategorySensitivity()
		if m["sqli"] != "high" || len(m) != 1 {
			t.Errorf("got %v", m)
		}
	})
	t.Run("modules only", func(t *testing.T) {
		p := &ProtectionConfig{OWASPModules: `{"xss":"low"}`}
		m := p.EffectiveCategorySensitivity()
		if m["xss"] != "low" || len(m) != 1 {
			t.Errorf("got %v", m)
		}
	})
	t.Run("category overrides modules for same key", func(t *testing.T) {
		// CategorySensitivity应覆盖OWASPModules中相同的key
		p := &ProtectionConfig{
			CategorySensitivity: `{"sqli":"strict"}`,
			OWASPModules:        `{"sqli":"low","xss":"mid"}`,
		}
		m := p.EffectiveCategorySensitivity()
		if m["sqli"] != "strict" {
			t.Errorf("category should override modules: sqli = %q", m["sqli"])
		}
		if m["xss"] != "mid" {
			t.Errorf("modules key not in category should remain: xss = %q", m["xss"])
		}
	})
}

// --- GetOWASPRulesConfig / SetOWASPRulesConfig ---

func TestOWASPRulesConfig(t *testing.T) {
	t.Run("empty string returns nil", func(t *testing.T) {
		p := &ProtectionConfig{}
		if p.GetOWASPRulesConfig() != nil {
			t.Error("expected nil")
		}
	})
	t.Run("empty object returns nil", func(t *testing.T) {
		p := &ProtectionConfig{OWASPRulesConfig: "{}"}
		if p.GetOWASPRulesConfig() != nil {
			t.Error("expected nil for '{}'")
		}
	})
	t.Run("invalid json returns nil", func(t *testing.T) {
		p := &ProtectionConfig{OWASPRulesConfig: "bad"}
		if p.GetOWASPRulesConfig() != nil {
			t.Error("expected nil for invalid json")
		}
	})
	t.Run("round-trip", func(t *testing.T) {
		p := &ProtectionConfig{}
		cfg := map[string]interface{}{"sqli_enabled": true, "threshold": float64(5)}
		p.SetOWASPRulesConfig(cfg)
		got := p.GetOWASPRulesConfig()
		if got["sqli_enabled"] != true || got["threshold"] != float64(5) {
			t.Errorf("round-trip failed: %v", got)
		}
	})
	t.Run("nil config sets empty object", func(t *testing.T) {
		p := &ProtectionConfig{}
		p.SetOWASPRulesConfig(nil)
		if p.OWASPRulesConfig != "{}" {
			t.Errorf("expected '{}', got %q", p.OWASPRulesConfig)
		}
	})
}

// --- GetEscalationSteps / SetEscalationSteps ---

func TestEscalationSteps(t *testing.T) {
	t.Run("empty string returns nil", func(t *testing.T) {
		p := &ProtectionConfig{}
		if p.GetEscalationSteps() != nil {
			t.Error("expected nil")
		}
	})
	t.Run("empty array returns nil", func(t *testing.T) {
		p := &ProtectionConfig{EscalationSteps: "[]"}
		if p.GetEscalationSteps() != nil {
			t.Error("expected nil for '[]'")
		}
	})
	t.Run("invalid json returns nil", func(t *testing.T) {
		p := &ProtectionConfig{EscalationSteps: "not json"}
		if p.GetEscalationSteps() != nil {
			t.Error("expected nil for invalid json")
		}
	})
	t.Run("round-trip", func(t *testing.T) {
		p := &ProtectionConfig{}
		steps := []EscalationStepDef{
			{Threshold: 5, Action: "intercept"},
			{Threshold: 10, Action: "drop"},
		}
		p.SetEscalationSteps(steps)
		got := p.GetEscalationSteps()
		if len(got) != 2 {
			t.Fatalf("expected 2 steps, got %d", len(got))
		}
		if got[0].Threshold != 5 || got[0].Action != "intercept" {
			t.Errorf("step 0 mismatch: %+v", got[0])
		}
		if got[1].Threshold != 10 || got[1].Action != "drop" {
			t.Errorf("step 1 mismatch: %+v", got[1])
		}
	})
	t.Run("nil steps sets empty array", func(t *testing.T) {
		p := &ProtectionConfig{}
		p.SetEscalationSteps(nil)
		if p.EscalationSteps != "[]" {
			t.Errorf("expected '[]', got %q", p.EscalationSteps)
		}
	})
	t.Run("empty steps sets empty array", func(t *testing.T) {
		p := &ProtectionConfig{}
		p.SetEscalationSteps([]EscalationStepDef{})
		if p.EscalationSteps != "[]" {
			t.Errorf("expected '[]', got %q", p.EscalationSteps)
		}
	})
}

// --- DefaultProtectionConfig ---

func TestDefaultProtectionConfig(t *testing.T) {
	cfg := DefaultProtectionConfig()

	if cfg.OWASPSensitivity != "mid" {
		t.Errorf("OWASPSensitivity = %q, want mid", cfg.OWASPSensitivity)
	}
	if cfg.OWASPAction != "intercept" {
		t.Errorf("OWASPAction = %q, want intercept", cfg.OWASPAction)
	}
	if cfg.RequestRateLimitWindow != 60 {
		t.Errorf("RequestRateLimitWindow = %d, want 60", cfg.RequestRateLimitWindow)
	}
	if cfg.RequestRateLimitMax != 300 {
		t.Errorf("RequestRateLimitMax = %d, want 300", cfg.RequestRateLimitMax)
	}
	if cfg.AutoBanThreshold != 10 {
		t.Errorf("AutoBanThreshold = %d, want 10", cfg.AutoBanThreshold)
	}
	if cfg.CaptchaType != "math" {
		t.Errorf("CaptchaType = %q, want math", cfg.CaptchaType)
	}
	if cfg.ShieldDifficulty != 4 {
		t.Errorf("ShieldDifficulty = %d, want 4", cfg.ShieldDifficulty)
	}
	if cfg.EscalationWindowSecs != 60 {
		t.Errorf("EscalationWindowSecs = %d, want 60", cfg.EscalationWindowSecs)
	}
	if cfg.MaintenanceGlobalStatus != 503 {
		t.Errorf("MaintenanceGlobalStatus = %d, want 503", cfg.MaintenanceGlobalStatus)
	}
	// 验证可以JSON序列化和反序列化（结构体完整性检查）
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal DefaultProtectionConfig failed: %v", err)
	}
	var cfg2 ProtectionConfig
	if err := json.Unmarshal(b, &cfg2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if cfg2.OWASPSensitivity != cfg.OWASPSensitivity {
		t.Error("round-trip mismatch on OWASPSensitivity")
	}
}

// --- DefaultBotProtectionConfig ---

func TestDefaultBotProtectionConfig(t *testing.T) {
	cfg := DefaultBotProtectionConfig()
	if cfg.Enabled != false {
		t.Error("default Enabled should be false")
	}
	if cfg.Level != "medium" {
		t.Errorf("Level = %q, want medium", cfg.Level)
	}
	if cfg.Action != "intercept" {
		t.Errorf("Action = %q, want intercept", cfg.Action)
	}
}

// --- DefaultAttackProtectionConfig ---

func TestDefaultAttackProtectionConfig(t *testing.T) {
	cfg := DefaultAttackProtectionConfig()
	if !cfg.OWASPEnabled {
		t.Error("OWASPEnabled should be true by default")
	}
	if cfg.OWASPSensitivity != "mid" {
		t.Errorf("OWASPSensitivity = %q, want mid", cfg.OWASPSensitivity)
	}
	if cfg.OWASPAction != "intercept" {
		t.Errorf("OWASPAction = %q, want intercept", cfg.OWASPAction)
	}
	if cfg.SignatureEnabled != false {
		t.Error("SignatureEnabled should be false by default")
	}
	if cfg.SignatureAction != "intercept" {
		t.Errorf("SignatureAction = %q, want intercept", cfg.SignatureAction)
	}
}
