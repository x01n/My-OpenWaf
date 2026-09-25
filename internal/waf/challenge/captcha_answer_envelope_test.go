package challenge

import (
	"encoding/hex"
	"testing"
	"time"

	"My-OpenWaf/internal/waf/challenge/gm"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("decode test key: %v", err)
	}
	return key
}

func mustEnvelope(t *testing.T, plain string, key []byte) string {
	t.Helper()
	// 答案信封域固定为 DomainCaptchaAnswer（与前端 gm_encrypt_challenge_answer 对齐）。
	raw, err := envEncrypt([]byte(plain), key, []byte(captchaItemDataAAD), gm.DomainCaptchaAnswer)
	if err != nil {
		t.Fatalf("encrypt answer: %v", err)
	}
	return gm.Encode(raw)
}

func sessionAnswer(t *testing.T, cm *CaptchaManager, sessionID string) string {
	t.Helper()
	answer, _, _, found := CaptchaManagerPendingForTest(cm, sessionID)
	if !found {
		t.Fatalf("pending session %q not found", sessionID)
	}
	return answer
}

func sessionKey(t *testing.T, cm *CaptchaManager, sessionID string) []byte {
	t.Helper()
	_, key, _, found := CaptchaManagerPendingForTest(cm, sessionID)
	if !found || len(key) != envSessionKeySize {
		t.Fatalf("pending session %q env key missing", sessionID)
	}
	return key
}

// TestCaptchaAnswerEnvelopeEndToEnd 覆盖「答案提交加密」的完整闭环：
// 前端用会话密钥把答案明文装进 v1.* 信封提交，后端 VerifyWithBinding
// 解密后与 session.Answer 做常量时间比较；旧客户端明文答案保持兼容；
// 错误密钥、跨用途密文都必须拒绝。
func TestCaptchaAnswerEnvelopeEndToEnd(t *testing.T) {
	manager := NewCaptchaManager(nil, time.Minute)
	defer manager.Close()

	binding := ChallengeSessionBinding{SiteID: 7, Host: "answer-env.example.test", Bind: ":80"}
	first, err := manager.GenerateWithBinding(CaptchaTypeMath, false, binding)
	if err != nil {
		t.Fatalf("generate math captcha: %v", err)
	}
	if first.CaptchaData == "" || first.EnvKeyHex == "" {
		t.Fatalf("challenge missing envelope or key: %+v", first)
	}
	key := sessionKey(t, manager, first.SessionID)

	// 信封必须是 GM v2 魔数信封，答案明文不得出现在信封里。
	encrypted := mustEnvelope(t, sessionAnswer(t, manager, first.SessionID), key)
	raw, err := gm.Decode(encrypted)
	if err != nil || len(raw) < 4 || string(raw[:4]) != gm.Magic {
		t.Fatalf("encrypted answer missing GM envelope magic: %q", encrypted)
	}
	// 第一个会话已由上面的读取耗尽，重新签发一个用于真实验证。
	second, err := manager.GenerateWithBinding(CaptchaTypeMath, false, binding)
	if err != nil {
		t.Fatalf("generate second captcha: %v", err)
	}
	if !manager.VerifyWithBinding(second.SessionID, mustEnvelope(t, sessionAnswer(t, manager, second.SessionID), sessionKey(t, manager, second.SessionID)), binding) {
		t.Fatal("encrypted correct answer must verify through VerifyWithBinding")
	}
	if manager.VerifyWithBinding(second.SessionID, "anything", binding) {
		t.Fatal("consumed session must not verify again")
	}

	// 强制化语义：明文答案必须拒绝（不允许旧客户端兼容回退）。
	third, err := manager.GenerateWithBinding(CaptchaTypeMath, false, binding)
	if err != nil {
		t.Fatalf("generate third captcha: %v", err)
	}
	if manager.VerifyWithBinding(third.SessionID, sessionAnswer(t, manager, third.SessionID), binding) {
		t.Fatal("plaintext answer must be rejected under forced-envelope semantics")
	}

	// 错误密钥信封：解密失败必须拒绝。
	fourth, err := manager.GenerateWithBinding(CaptchaTypeMath, false, binding)
	if err != nil {
		t.Fatalf("generate fourth captcha: %v", err)
	}
	wrongKey := GenerateEnvSessionKey()
	for i := range wrongKey {
		wrongKey[i] ^= 0xFF
	}
	if manager.VerifyWithBinding(fourth.SessionID, mustEnvelope(t, sessionAnswer(t, manager, fourth.SessionID), wrongKey), binding) {
		t.Fatal("answer encrypted under wrong key must be rejected")
	}

	// 交换答案：用会话密钥加密"错误答案"，密钥对但内容错，必须拒绝。
	fifth, err := manager.GenerateWithBinding(CaptchaTypeMath, false, binding)
	if err != nil {
		t.Fatalf("generate fifth captcha: %v", err)
	}
	if manager.VerifyWithBinding(fifth.SessionID, mustEnvelope(t, "000", sessionKey(t, manager, fifth.SessionID)), binding) {
		t.Fatal("wrong answer in correct envelope must be rejected")
	}
}

// TestCaptchaSlideAnswerEnvelopeGoesThroughToleranceCheck 覆盖高级题型
// （slide/click/rotate 共用 VerifyAdvancedSessionWithBinding 路径）答案
// 信封解密后仍走容差校验。
func TestCaptchaSlideAnswerEnvelopeGoesThroughToleranceCheck(t *testing.T) {
	manager := NewCaptchaManager(nil, time.Minute)
	defer manager.Close()
	manager.sessions["slide-env-session"] = &CaptchaSession{
		ID:        "slide-env-session",
		Type:      CaptchaTypeSlide,
		Answer:    `{"x":35,"y":7,"dx":15,"dy":0}`,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
		EnvKey:    testKey(t),
	}

	// 前端滑动 offset 20 → 绝对 X = 15+20 = 35，与 stored.X=35 对齐，
	// 默认容差 20 内通过；Y 用 stored.DY+Y=7 对齐 stored.Y=7。
	ok, _ := manager.VerifyAdvancedSessionWithBinding("slide-env-session", mustEnvelope(t, `{"x":20}`, testKey(t)), ChallengeSessionBinding{})
	if !ok {
		t.Fatal("encrypted slide answer must pass tolerance verification")
	}
}
