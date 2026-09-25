package challenge

import (
	"encoding/json"
	"testing"
	"time"
)

/**
 * TestShieldVerifyIPHistoryAddsScoreInBehaviorField 验证方案 B 签发 IP 史评分接线：
 * ShieldSession 携带签发 IP；IP 史注入函数在行为开启时生效；
 * 违规/封禁不同层级时验证通过性保持（加成 ≤20 + 基线 0）且不崩溃。
 */
func TestShieldVerifyIPHistoryAddsScoreInBehaviorField(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewShieldManager(captcha, nil, 1)
	defer mgr.Close()

	cfg := DefaultShieldConfig()
	cfg.Difficulty = 1
	cfg.EnableEnvCheck = true
	cfg.EnableBehaviorCheck = true
	cfg.EnvStrictness = 2
	mgr.SetConfig(cfg)

	mgr.SetIPHistory(func(ip string) (int64, bool) { return 0, false })

	session, err := mgr.GenerateChallengeWithBinding("/iphist", "http/1.1", ChallengeSessionBinding{
		SiteID: 9, Host: "iphist.example.test", Bind: ":80", ClientIP: "203.0.113.44",
	})
	if err != nil {
		t.Fatalf("GenerateChallengeWithBinding(): %v", err)
	}
	if session.ClientIP != "203.0.113.44" {
		t.Fatalf("session ClientIP = %q, want carried issuer IP", session.ClientIP)
	}

	fingerprint := shieldNormalEnvFingerprint()
	fingerprint.Behavior = &BehaviorStats{
		Events: 120, Entropy: 3.4, ZeroRatio: 0.2, Jitter: 0.8, MaxSpeed: 14.0, ActionKey: 1,
	}
	envJSON := marshalShieldEnvFingerprint(t, fingerprint)
	envEnc := encryptShieldEnvFingerprint(
		t, envJSON, session.EnvKey, EnvFingerprintAAD("shield", session.ID, session.ChallengeSessionBinding))
	counter, hash := findShieldPoWSolution(t, session.Nonce, session.Difficulty)

	if ok, _ := mgr.VerifyChallengeWithBinding(session.ID, "", counter, hash, envEnc, "http/1.1", session.ChallengeSessionBinding); !ok {
		t.Fatal("historyless verifier with normal behavior fingerprint: want pass")
	}

	for _, tc := range []struct {
		name       string
		violations int64
		banned     bool
	}{
		{"prior violation", 1, false},
		{"repeat violations", 5, false},
		{"currently banned", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr.SetIPHistory(func(ip string) (int64, bool) { return tc.violations, tc.banned })

			sess, err := mgr.GenerateChallengeWithBinding("/iphist", "http/1.1", ChallengeSessionBinding{
				SiteID: 9, Host: "iphist.example.test", Bind: ":80", ClientIP: "203.0.113.44",
			})
			if err != nil {
				t.Fatalf("GenerateChallengeWithBinding(): %v", err)
			}
			enc := encryptShieldEnvFingerprint(
				t, envJSON, sess.EnvKey, EnvFingerprintAAD("shield", sess.ID, sess.ChallengeSessionBinding))
			c, h := findShieldPoWSolution(t, sess.Nonce, sess.Difficulty)
			ok, _ := mgr.VerifyChallengeWithBinding(
				sess.ID, "", c, h, enc, "http/1.1", sess.ChallengeSessionBinding,
			)
			if !ok {
				t.Fatalf("VerifyChallengeWithBinding with %s history = false, want pass (addition <= 20 keeps score at 50)", tc.name)
			}
		})
	}
}

/**
 * TestShieldVerifyIPHistoryOnlyInBehaviorGate 验证边界：IP 史维度只在行为开启时生效。
 * 行为关闭时恶意 IP 史不改变判定；注入函数为 nil 时同样不加分。
 */
func TestShieldVerifyIPHistoryOnlyInBehaviorGate(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewShieldManager(captcha, nil, 1)
	defer mgr.Close()

	cfg := DefaultShieldConfig()
	cfg.Difficulty = 1
	cfg.EnableEnvCheck = false
	cfg.EnableBehaviorCheck = false
	cfg.EnvStrictness = 0
	mgr.SetConfig(cfg)

	mgr.SetIPHistory(func(ip string) (int64, bool) { return 99, true })

	sess, err := mgr.GenerateChallengeWithBinding("/nohist", "http/1.1", ChallengeSessionBinding{
		SiteID: 10, Host: "nohist.example.test", Bind: ":80", ClientIP: "198.51.100.7",
	})
	if err != nil {
		t.Fatalf("GenerateChallengeWithBinding(): %v", err)
	}
	c, h := findShieldPoWSolution(t, sess.Nonce, sess.Difficulty)
	if ok, _ := mgr.VerifyChallengeWithBinding(sess.ID, "", c, h, "", "http/1.1", sess.ChallengeSessionBinding); !ok {
		t.Fatal("disabled behavior must keep IP history out of the verdict")
	}

	cfg2 := DefaultShieldConfig()
	cfg2.Difficulty = 1
	cfg2.EnableEnvCheck = true
	cfg2.EnableBehaviorCheck = true
	cfg2.EnvStrictness = 0
	mgr.SetConfig(cfg2)
	mgr.SetIPHistory(nil)

	sess2, err := mgr.GenerateChallengeWithBinding("/nilhist", "http/1.1", ChallengeSessionBinding{
		SiteID: 10, Host: "nohist.example.test", Bind: ":80", ClientIP: "198.51.100.7",
	})
	if err != nil {
		t.Fatalf("GenerateChallengeWithBinding(): %v", err)
	}
	fingerprint := shieldNormalEnvFingerprint()
	fingerprint.Behavior = &BehaviorStats{
		Events: 120, Entropy: 3.4, ZeroRatio: 0.2, Jitter: 0.8, MaxSpeed: 14.0, ActionKey: 1,
	}
	enc := encryptShieldEnvFingerprint(
		t, marshalShieldEnvFingerprint(t, fingerprint), sess2.EnvKey,
		EnvFingerprintAAD("shield", sess2.ID, sess2.ChallengeSessionBinding))
	c2, h2 := findShieldPoWSolution(t, sess2.Nonce, sess2.Difficulty)
	if ok, _ := mgr.VerifyChallengeWithBinding(sess2.ID, "", c2, h2, enc, "http/1.1", sess2.ChallengeSessionBinding); !ok {
		t.Fatal("nil IP history provider must not alter the verdict")
	}
}

/**
 * TestShieldSessionClientIPRoundTrip 验证签发 IP 随会话持久化往返一致，
 * 且不参与 binding.matches 三元组判定。
 */
func TestShieldSessionClientIPRoundTrip(t *testing.T) {
	session := &ShieldSession{
		ChallengeSessionBinding: ChallengeSessionBinding{SiteID: 7, Host: "rt.example.test", Bind: ":443", ClientIP: "192.0.2.9"},
		ID:                      "rt-session",
		ClientIP:                "192.0.2.9",
		CreatedAt:               time.Now(),
	}
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	var back ShieldSession
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.ClientIP != "192.0.2.9" {
		t.Fatalf("round-trip session ClientIP = %q, want issuer IP carried", back.ClientIP)
	}
	// binding 内嵌的 ClientIP 不参与序列化（json:"-"），往返后应为空，
	// 关键的独立 session.ClientIP 字段必须保留。
	if back.ChallengeSessionBinding.ClientIP != "" {
		t.Fatalf("round-trip binding ClientIP = %q, want empty (not serialized)", back.ChallengeSessionBinding.ClientIP)
	}
	if !back.ChallengeSessionBinding.matches(ChallengeSessionBinding{SiteID: 7, Host: "rt.example.test", Bind: ":443"}) {
		t.Fatal("client_ip must not participate in binding matches")
	}
}
