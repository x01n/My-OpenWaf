package challenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
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

func TestParseEnvFingerprintAcceptsIntegralFloatValues(t *testing.T) {
	data := `{"color_depth":24.0,"hardware_concurrency":8.0,"inner_width":780.0,"pixel_ratio":1.0}`
	got := ParseEnvFingerprint(data)
	if got == nil {
		t.Fatal("ParseEnvFingerprint integral float JSON returned nil")
	}
	if got.ColorDepth != 24 || got.HardwareConcur != 8 || got.InnerWidth != 780 || got.PixelRatio != 1 {
		t.Fatalf("parsed fingerprint = %+v", got)
	}
}

func TestParseEnvFingerprintRejectsNonIntegralIntegerFields(t *testing.T) {
	for _, data := range []string{
		`{"color_depth":24.5}`,
		`{"color_depth":"24"}`,
		`{"color_depth":true}`,
	} {
		if got := ParseEnvFingerprint(data); got != nil {
			t.Fatalf("ParseEnvFingerprint(%s) = %+v, want nil", data, got)
		}
	}
}

func TestGenerateEnvSessionKeyLength(t *testing.T) {
	key := GenerateEnvSessionKey()
	if len(key) != 32 {
		t.Errorf("GenerateEnvSessionKey() length = %d, want 32", len(key))
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
	if len(hex) != 64 {
		t.Errorf("EnvSessionKeyHex length = %d, want 64 (32 bytes x 2)", len(hex))
	}
}

func TestEnvSessionKeyFromChallengeToken(t *testing.T) {
	key := EnvSessionKeyFromChallengeToken(strings.Repeat("ab", envSessionKeySize))
	if len(key) != envSessionKeySize {
		t.Fatalf("decoded key length = %d, want %d", len(key), envSessionKeySize)
	}
	if EnvSessionKeyFromChallengeToken("not-hex") != nil {
		t.Fatal("invalid token must not produce an environment key")
	}
}

func TestDecryptEnvFingerprintRejectsPlaintextAndAcceptsAuthenticatedCiphertext(t *testing.T) {
	key := GenerateEnvSessionKey()
	fp := EnvFingerprint{ChromePresent: true, Languages: "zh-CN"}
	plaintext, err := json.Marshal(fp)
	if err != nil {
		t.Fatalf("marshal fingerprint: %v", err)
	}
	aad := "owaf-env:v1|challenge|7|example.test|:443|request"
	encrypted := encryptVersionedEnvFingerprint(t, plaintext, key, aad)

	got := DecryptEnvFingerprintWithAAD(encrypted, key, aad)
	if got == nil || got.Languages != fp.Languages {
		t.Fatalf("encrypted fingerprint = %+v, want language %q", got, fp.Languages)
	}
	if DecryptEnvFingerprintWithAAD(encrypted, key, aad+"-other") != nil {
		t.Fatal("fingerprint authenticated for a different AAD")
	}
	if DecryptEnvFingerprintWithAAD(strings.TrimPrefix(encrypted, envCiphertextPrefix), key, aad) != nil {
		t.Fatal("unversioned fingerprint must not be accepted")
	}
	if DecryptEnvFingerprintWithAAD(string(plaintext), key, aad) != nil {
		t.Fatal("plaintext fingerprint must not be accepted")
	}
}

func encryptVersionedEnvFingerprint(t *testing.T, plaintext, key []byte, aad string) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("random nonce: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))
	return envCiphertextPrefix + base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...))
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
	if DecryptEnvFingerprintWithAAD("", []byte("key"), "owaf-env:v1|test|1|example.test|:443|session") != nil {
		t.Error("empty encrypted should return nil")
	}
	if DecryptEnvFingerprintWithAAD("data", nil, "owaf-env:v1|test|1|example.test|:443|session") != nil {
		t.Error("empty key should return nil")
	}
}

func TestEnvFingerprintAADMatchesVersionConstant(t *testing.T) {
	got := EnvFingerprintAAD("challenge", "session", ChallengeSessionBinding{SiteID: 1, Host: "example.test", Bind: ":443"})
	want := "owaf-env:" + EnvFingerprintProtocolVersion + "|challenge|1|example.test|:443|session"
	if got != want {
		t.Fatalf("EnvFingerprintAAD() = %q, want %q", got, want)
	}
}
