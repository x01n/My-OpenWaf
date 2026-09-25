package challenge

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/gm"
)

var testSessionKey = []byte("0123456789abcdef0123456789abcdef")

// TestCaptchaEnvelopeMatchesEnvironmentEnvelopeFormat 断言题目/答案信封与
// 环境指纹信封共用同一线格式与算法族（GM v2 + 魔数 OWVE），保证 WASM 侧
// 为客户端浏览器准备的解密原语（gm_decrypt_challenge_data）能解开 Go 侧
// 发出的信封。
func TestCaptchaEnvelopeMatchesEnvironmentEnvelopeFormat(t *testing.T) {
	payload := `{"type":"math","prompt":"1+1=?","master_img":"data:image/png;base64,AA===","width":200,"height":80}`
	envelope, err := EncryptChallengeData(payload, testSessionKey)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := gm.Decode(envelope)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	// 魔数 4 字节 + 头 4 字节 + nonce 12 字节开头：
	if len(raw) < 8+gm.NonceSize {
		t.Fatalf("envelope raw length = %d, too short", len(raw))
	}
	if string(raw[:4]) != gm.Magic {
		t.Fatalf("envelope magic = %q, want %q", raw[:4], gm.Magic)
	}
	if raw[4] != gm.EnvelopeVersion || raw[5] != gm.DomainCaptchaItem {
		t.Fatalf("envelope header = %x, want version=%d domain=%d", raw[4:6], gm.EnvelopeVersion, gm.DomainCaptchaItem)
	}
	got, err := gm.Open(testSessionKey[:16], raw, []byte(captchaItemDataAAD), gm.DomainCaptchaItem, true)
	if err != nil {
		t.Fatalf("native open: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("native decrypt mismatch: %q", got)
	}

	// 负例：跨用途域必须被拒（防重放绑定由 domain 字节 + 会话唯一密钥承担）。
	if _, err := gm.Open(testSessionKey[:16], raw, []byte(captchaItemDataAAD), gm.DomainEnv, true); err == nil {
		t.Fatal("cross-domain envelope must be rejected")
	}
}

// TestCaptchaEnvelopeUsesSMSessionKeyLayout 断言会话密钥布局约束（32 字节主密钥，16 字节 SM4 密钥）。
func TestCaptchaEnvelopeUsesSMSessionKeyLayout(t *testing.T) {
	if envSessionKeySize != 32 {
		t.Fatalf("envSessionKeySize = %d, want 32", envSessionKeySize)
	}
}

func TestCaptchaChallengeCarriesAnswerOnlyInSession(t *testing.T) {
	manager := NewCaptchaManager(nil, 0)
	defer manager.Close()

	ch, err := manager.GenerateWithBinding(CaptchaTypeMath, false, ChallengeSessionBinding{})
	if err != nil {
		t.Fatal(err)
	}
	if ch == nil || ch.CaptchaData == "" {
		t.Fatal("math captcha must carry an encrypted data envelope")
	}
	// 结构体字段上不得出现任何答案线索。
	for _, probe := range []string{ch.SessionID, ch.CaptchaData, ch.Type, ch.Prompt} {
		if strings.Contains(probe, "answer") {
			t.Fatalf("unexpected answer marker in challenge field: %q", probe)
		}
	}
	// 答案只存在于会话侧。
	answer, _, _, found := CaptchaManagerPendingForTest(manager, ch.SessionID)
	if !found || answer == "" {
		t.Fatal("answer must exist only in session storage")
	}
}

func TestCaptchaMathEnvelopeDecryptsToMathPrompt(t *testing.T) {
	manager := NewCaptchaManager(nil, 0)
	defer manager.Close()
	ch, err := manager.GenerateWithBinding(CaptchaTypeMath, false, ChallengeSessionBinding{})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _, found := CaptchaManagerPendingForTest(manager, ch.SessionID)
	if !found || len(key) != envSessionKeySize {
		t.Fatalf("session key missing: found=%v", found)
	}
	payload := DecryptChallengeData(ch.CaptchaData, key)
	if payload == nil {
		t.Fatal("math envelope did not decrypt")
	}
	if payload.Type != string(CaptchaTypeMath) {
		t.Fatalf("payload type = %q, want math", payload.Type)
	}
	if payload.Prompt == "" {
		t.Fatal("math payload missing prompt")
	}
	if payload.InputMode != "输入计算结果" {
		t.Fatalf("math payload input_mode = %q", payload.InputMode)
	}
	if !strings.HasPrefix(payload.MasterImg, "data:image/png;base64,") {
		t.Fatal("math payload master_img is not a PNG data URI")
	}
}

func TestCaptchaEnvelopeJsonCarriesOnlyChallengeFields(t *testing.T) {
	items := &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    "S3CR3T",
		MasterImg: "data:image/png;base64,WA==",
		Width:     200,
		Height:    80,
	}
	ch, err := newCaptchaChallenge("session", testSessionKey, items)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := gm.Decode(ch.CaptchaData)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gm.Open(testSessionKey[:16], raw, []byte(captchaItemDataAAD), gm.DomainCaptchaItem, true)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	for field := range m {
		switch field {
		case "type", "prompt", "master_img", "thumb_img", "width", "height", "input_mode":
		default:
			t.Fatalf("unexpected envelope field %q (answer must never be issued)", field)
		}
	}
}

func TestCaptchaEnvelopeRoundTripsWithRandomPaddingImage(t *testing.T) {
	// 大 payload（slide 题型规模）往返稳定。
	blob := make([]byte, 4096)
	_, _ = rand.Read(blob)
	big := "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(blob)
	items := &CaptchaItems{
		Type:      CaptchaTypeSlide,
		Prompt:    "请将滑块拖动到正确位置",
		MasterImg: big,
		Width:     300,
		Height:    220,
	}
	ch, err := newCaptchaChallenge("s", testSessionKey, items)
	if err != nil {
		t.Fatal(err)
	}
	got := DecryptChallengeData(ch.CaptchaData, testSessionKey)
	if got == nil || got.MasterImg != big {
		t.Fatal("large slide envelope roundtrip failed")
	}
}

func TestCaptchaEnvelopeRejectsGarbageKeys(t *testing.T) {
	_, err := EncryptChallengeData(`{"type":"math"}`, []byte("short"))
	if err == nil {
		t.Fatal("short key must be rejected")
	}
	if got := DecryptChallengeData("!!not-base64!!", testSessionKey); got != nil {
		t.Fatal("bad base64 must be rejected")
	}
	if got := DecryptChallengeData("", testSessionKey); got != nil {
		t.Fatal("empty envelope must be rejected")
	}
}

func TestCaptchaEnvelopeKeysAreHexCompatibleWithWASM(t *testing.T) {
	// WASM 侧拿到的 EnvKeyHex 用 hex 编码；解密时 hex 解回来必须同键。
	hexKey := hex.EncodeToString(testSessionKey)
	envelope, err := EncryptChallengeData(`{"type":"math"}`, testSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(hexKey)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("hex key decode: %v", err)
	}
	if got := DecryptChallengeData(envelope, decoded); got == nil {
		t.Fatal("hex round-tripped key must decrypt the envelope")
	}
}
