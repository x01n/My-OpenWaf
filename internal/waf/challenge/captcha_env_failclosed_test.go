package challenge

import (
	"encoding/json"
	"testing"
)

/**
 * TestVerifyCaptchaEnvEnvelope 覆盖验证码验证路径 fail-closed 环境校验归一函数：
 * nil 会话、半配态密钥、空/乱码密文、解密失败、硬性自动化信号均须拒绝；
 * EnvKey 空同样拒绝（强制化语义，不存在纯答案放行路径）。
 */
func TestVerifyCaptchaEnvEnvelope(t *testing.T) {
	binding := ChallengeSessionBinding{SiteID: 7, Host: "env.example.test", Bind: ":80"}
	sessionID := "session-env-1"
	key := GenerateEnvSessionKey()
	aad := EnvFingerprintAAD("captcha", sessionID, binding)

	encryptFingerprint := func(fp *EnvFingerprint) string {
		t.Helper()
		plaintext, err := json.Marshal(fp)
		if err != nil {
			t.Fatalf("marshal fingerprint: %v", err)
		}
		return encryptVersionedEnvFingerprint(t, plaintext, key, aad)
	}

	tests := []struct {
		name     string
		session  *CaptchaSession
		envFP    string
		wantPass bool
	}{
		{
			name: "nil 会话拒绝",
			envFP: encryptFingerprint(&EnvFingerprint{
				ChromePresent: true, Languages: "zh-CN", PluginsCount: 5, ScreenWidth: 1920,
				ScreenHeight: 1080, HardwareConcur: 8, ColorDepth: 24, PixelRatio: 1,
				SessionStorage: true, IndexedDB: true, CookieEnabled: true, FontCount: 12,
				WebAssembly: true, ServiceWorker: true, MediaDevices: true,
			}),
			wantPass: false,
		},
		{
			name:     "EnvKey 空（强制化语义）拒绝",
			session:  &CaptchaSession{ChallengeSessionBinding: binding, ID: sessionID, EnvKey: nil},
			wantPass: false,
		},
		{
			name:     "EnvKey 长度异常的半配态拒绝",
			session:  &CaptchaSession{ChallengeSessionBinding: binding, ID: sessionID, EnvKey: []byte("short")},
			wantPass: false,
		},
		{
			name:     "空 env 密文拒绝",
			session:  &CaptchaSession{ChallengeSessionBinding: binding, ID: sessionID, EnvKey: key},
			envFP:    "",
			wantPass: false,
		},
		{
			name:     "乱码 env 密文解密失败拒绝",
			session:  &CaptchaSession{ChallengeSessionBinding: binding, ID: sessionID, EnvKey: key},
			envFP:    "v1.not-base64",
			wantPass: false,
		},
		{
			name:     "环境评分 100（webdriver）拒绝",
			session:  &CaptchaSession{ChallengeSessionBinding: binding, ID: sessionID, EnvKey: key},
			envFP:    encryptFingerprint(&EnvFingerprint{WebDriver: true, ScreenWidth: 1920, ScreenHeight: 1080}),
			wantPass: false,
		},
		{
			name:    "合法指纹放行",
			session: &CaptchaSession{ChallengeSessionBinding: binding, ID: sessionID, EnvKey: key},
			envFP: encryptFingerprint(&EnvFingerprint{
				ChromePresent: true, Languages: "zh-CN", PluginsCount: 5, CanvasHash: "canvas",
				WebGLRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
				ScreenWidth:   1920, ScreenHeight: 1080, HardwareConcur: 8, ColorDepth: 24,
				PixelRatio: 1, SessionStorage: true, IndexedDB: true, CookieEnabled: true,
				FontCount: 12, WebAssembly: true, ServiceWorker: true, MediaDevices: true,
				PlatformStr: "Linux x86_64", AudioHash: "audio-hash",
				ScreenConsistency: true, TimezoneConsistency: true,
				LanguageConsistency: true, MathConsistency: true,
			}),
			wantPass: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifyCaptchaEnvEnvelope(tc.envFP, tc.session); got != tc.wantPass {
				t.Fatalf("VerifyCaptchaEnvEnvelope() = %v, want %v", got, tc.wantPass)
			}
		})
	}
}

/**
 * TestVerifyCaptchaEnvEnvelopeRejectsSuspendedThresholdFingerprints 回归
 * 验证码路径“可疑区间”阈值：Score 位于 51~99（Pass=false）的指纹必须拒绝，
 * 而不是只在 100 分硬信号时拦截。
 */
func TestVerifyCaptchaEnvEnvelopeRejectsSuspendedThresholdFingerprints(t *testing.T) {
	binding := ChallengeSessionBinding{SiteID: 7, Host: "env.example.test", Bind: ":80"}
	sessionID := "session-env-2"
	key := GenerateEnvSessionKey()
	aad := EnvFingerprintAAD("captcha", sessionID, binding)

	fp := &EnvFingerprint{
		ChromePresent: true, Languages: "zh-CN", PluginsCount: 5, CanvasHash: "canvas",
		WebGLRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
		ScreenWidth:   1920, ScreenHeight: 1080, HardwareConcur: 8, ColorDepth: 24,
		PixelRatio: 1, SessionStorage: true, IndexedDB: true, CookieEnabled: true,
		FontCount: 12, WebAssembly: true, ServiceWorker: true, MediaDevices: true,
		PlatformStr: "Linux x86_64", AudioHash: "audio-hash",
		ScreenConsistency: true, TimezoneConsistency: true,
		LanguageConsistency: true, MathConsistency: true,
		DevtoolsOpen: true, DevtoolsTiming: 200, CDPRuntime: true,
	}
	plaintext, err := json.Marshal(fp)
	if err != nil {
		t.Fatalf("marshal fingerprint: %v", err)
	}
	envFP := encryptVersionedEnvFingerprint(t, plaintext, key, aad)

	session := &CaptchaSession{ChallengeSessionBinding: binding, ID: sessionID, EnvKey: key}
	result := ValidateEnvFingerprint(DecryptEnvFingerprintWithAAD(envFP, session.EnvKey, aad))
	if result.Score <= 50 || result.Score >= 100 {
		t.Fatalf("suspended threshold fingerprint score = %d, want in (50,100)", result.Score)
	}
	if VerifyCaptchaEnvEnvelope(envFP, session) {
		t.Fatal("suspended threshold fingerprint (50<score<100) must fail the captcha env gate")
	}
}
func TestCaptchaGenerateAlwaysIssuesEnvKey(t *testing.T) {
	manager := NewCaptchaManager(nil, 0)
	defer manager.Close()
	binding := ChallengeSessionBinding{SiteID: 7, Host: "env.example.test", Bind: ":80"}

	for _, envCheck := range []bool{false, true} {
		pending, err := manager.GenerateWithBinding(CaptchaTypeMath, envCheck, binding)
		if err != nil {
			t.Fatalf("GenerateWithBinding(envCheck=%v): %v", envCheck, err)
		}
		if len(pending.EnvKeyHex) != 64 {
			t.Fatalf("envCheck=%v: challenge EnvKeyHex length = %d, want 64", envCheck, len(pending.EnvKeyHex))
		}
		_, envKey, _, found := CaptchaManagerPendingForTest(manager, pending.SessionID)
		if !found {
			t.Fatalf("envCheck=%v: pending session not found", envCheck)
		}
		if len(envKey) != 32 {
			t.Fatalf("envCheck=%v: session EnvKey length = %d, want 32", envCheck, len(envKey))
		}
	}
}
