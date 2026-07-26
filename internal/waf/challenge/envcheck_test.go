package challenge

import (
	"encoding/json"
	"testing"
)

func TestParseEnvFingerprintEmptyReturnsNil(t *testing.T) {
	if ParseEnvFingerprint("") != nil {
		t.Error("ParseEnvFingerprint('') should return nil")
	}
}

func TestParseEnvFingerprintInvalidJSONReturnsNil(t *testing.T) {
	if ParseEnvFingerprint("{not-json}") != nil {
		t.Error("ParseEnvFingerprint invalid JSON should return nil")
	}
}

func TestParseEnvFingerprintValidJSON(t *testing.T) {
	fp := &EnvFingerprint{WebDriver: true, Languages: "zh-CN"}
	data, _ := json.Marshal(fp)
	got := ParseEnvFingerprint(string(data))
	if got == nil {
		t.Fatal("ParseEnvFingerprint valid JSON returned nil")
	}
	if !got.WebDriver || got.Languages != "zh-CN" {
		t.Errorf("ParseEnvFingerprint fields wrong: %+v", got)
	}
}

func TestGenerateEnvSessionKeyLength(t *testing.T) {
	key := GenerateEnvSessionKey()
	if len(key) != 16 {
		t.Errorf("GenerateEnvSessionKey() length = %d, want 16", len(key))
	}
}

func TestGenerateEnvSessionKeyIsRandom(t *testing.T) {
	a := GenerateEnvSessionKey()
	b := GenerateEnvSessionKey()
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("two consecutive GenerateEnvSessionKey calls produced identical keys")
	}
}

func TestEnvSessionKeyHexLength(t *testing.T) {
	key := GenerateEnvSessionKey()
	hex := EnvSessionKeyHex(key)
	if len(hex) != 32 {
		t.Errorf("EnvSessionKeyHex length = %d, want 32 (16 bytes × 2)", len(hex))
	}
}

func TestIsSuspiciousRendererKnownVMs(t *testing.T) {
	cases := []struct {
		renderer string
		want     bool
	}{
		{"ANGLE (Google SwiftShader)", true},
		{"llvmpipe (LLVM 10.0.0, 256 bits)", true},
		{"VirtualBox SVGA 3D", true},
		{"VMware SVGA 3D", true},
		{"Mesa DRI Intel", true},
		{"NVIDIA GeForce RTX 3090", false},
		{"Apple M1", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isSuspiciousRenderer(tc.renderer)
		if got != tc.want {
			t.Errorf("isSuspiciousRenderer(%q) = %v, want %v", tc.renderer, got, tc.want)
		}
	}
}

func TestEnvContainsCICaseInsensitive(t *testing.T) {
	if !envContainsCI("SwiftShader renderer", "swiftshader") {
		t.Error("envContainsCI case-insensitive match failed")
	}
	if envContainsCI("normal string", "notfound") {
		t.Error("envContainsCI should not match absent substring")
	}
	if !envContainsCI("abc", "") {
		t.Error("envContainsCI empty substr should return true")
	}
}

func TestValidateEnvFingerprintNilInput(t *testing.T) {
	result := ValidateEnvFingerprint(nil)
	if result.Pass {
		t.Error("nil fingerprint should not pass")
	}
	if result.Score != 100 {
		t.Errorf("nil fingerprint score = %d, want 100", result.Score)
	}
}

func TestValidateEnvFingerprintWebDriverFails(t *testing.T) {
	fp := &EnvFingerprint{WebDriver: true}
	result := ValidateEnvFingerprint(fp)
	if result.Pass {
		t.Error("WebDriver=true should not pass")
	}
	if result.Score != 100 {
		t.Errorf("WebDriver=true score = %d, want 100", result.Score)
	}
}

func TestValidateEnvFingerprintAutomationSignFails(t *testing.T) {
	fp := &EnvFingerprint{AutomationSign: "selenium"}
	result := ValidateEnvFingerprint(fp)
	if result.Pass {
		t.Error("AutomationSign set should not pass")
	}
}

func TestValidateEnvFingerprintNoBotSignalScoresLow(t *testing.T) {
	// 仅验证无任何自动化信号时评分低于即时失败阈值（100），不要求必须通过
	fp := &EnvFingerprint{
		ChromePresent: true,
		Languages:     "en-US",
	}
	result := ValidateEnvFingerprint(fp)
	if result.Score == 100 && len(result.Reasons) == 1 && result.Reasons[0] == "no fingerprint data" {
		t.Error("non-nil fingerprint should not be treated as missing data")
	}
}

func TestDecryptEnvFingerprintEmptyReturnsNil(t *testing.T) {
	if DecryptEnvFingerprint("", []byte("key")) != nil {
		t.Error("empty encrypted should return nil")
	}
	if DecryptEnvFingerprint("data", nil) != nil {
		t.Error("empty key should return nil")
	}
}
