package challenge

import (
	"strconv"
	"testing"
)

func TestShieldVerifyGeoAttrConservativeTiers(t *testing.T) {
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

	normal := shieldNormalEnvFingerprint()
	normal.Behavior = &BehaviorStats{
		Events: 120, Entropy: 3.4, ZeroRatio: 0.2, Jitter: 0.8, MaxSpeed: 14.0, ActionKey: 1,
	}
	hanging := shieldNormalEnvFingerprint()
	hanging.Behavior = normal.Behavior
	hanging.ChromePresent = false
	hanging.PluginsCount = 0
	hanging.Languages = ""
	hanging.CanvasHash = ""

	binding := ChallengeSessionBinding{SiteID: 11, Host: "geoattr.example.test", Bind: ":80", ClientIP: "203.0.113.44"}

	type tier struct {
		name       string
		fp         *EnvFingerprint
		attrScore  int
		attrReason string
		wantPass   bool
		wantCost   bool // 属性面是否提供了非零代价
	}
	tiers := []tier{
		{"clean-attr0", normal, 0, "", true, false},
		{"clean-attr5", normal, 5, "hosting-like", true, true},
		{"clean-attr8", normal, 8, "vpn/proxy-like", true, true},
		{"clean-attr12", normal, 12, "datacenter-like", true, true},
		{"hanging-attr0", hanging, 0, "", true, false},
		{"hanging-attr5", hanging, 5, "hosting-like", true, true},
		{"hanging-attr8", hanging, 8, "vpn/proxy-like", false, true},
		{"hanging-attr12", hanging, 12, "datacenter-like", false, true},
	}

	for _, tc := range tiers {
		t.Run(tc.name, func(t *testing.T) {
			mgr.SetGeoAttr(func(ip string) (int, []string) {
				if ip != binding.ClientIP {
					t.Fatalf("geo attr queried with %q, want %q", ip, binding.ClientIP)
				}
				if tc.attrScore == 0 {
					return 0, nil
				}
				return tc.attrScore, []string{tc.attrReason + " (+" + strconv.Itoa(tc.attrScore) + ")"}
			})
			sess, err := mgr.GenerateChallengeWithBinding("/geoattr", "http/1.1", binding)
			if err != nil {
				t.Fatalf("GenerateChallengeWithBinding(): %v", err)
			}
			enc := encryptShieldEnvFingerprint(
				t, marshalShieldEnvFingerprint(t, tc.fp), sess.EnvKey,
				EnvFingerprintAAD("shield", sess.ID, sess.ChallengeSessionBinding))
			c, h := findShieldPoWSolution(t, sess.Nonce, sess.Difficulty)
			ok, _ := mgr.VerifyChallengeWithBinding(
				sess.ID, "", c, h, enc, "http/1.1", sess.ChallengeSessionBinding,
			)
			if ok != tc.wantPass {
				t.Fatalf("attr tier %q: VerifyChallengeWithBinding = %t, want %t (attrScore=%d)", tc.name, ok, tc.wantPass, tc.attrScore)
			}
			if !tc.wantCost {
				return
			}
			// 兑换后会话必须被消费（属性面只读，不改会话生命周期语义）。
			if _, exists := mgr.sessions[sess.ID]; exists {
				t.Fatalf("session %s not consumed after verify", sess.ID)
			}
		})
	}
}

/**
 * TestShieldVerifyGeoAttrNilAndNoIPCostZero 验证两个零代价路径：
 * geo attr 未接线（nil 注入）与 session 无签发 IP 时判定与基线完全等价。
 */
func TestShieldVerifyGeoAttrNilAndNoIPCostZero(t *testing.T) {
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
	mgr.SetGeoAttr(nil)

	fingerprint := shieldNormalEnvFingerprint()
	fingerprint.Behavior = &BehaviorStats{
		Events: 120, Entropy: 3.4, ZeroRatio: 0.2, Jitter: 0.8, MaxSpeed: 14.0, ActionKey: 1,
	}

	// 无签发 IP + nil 注入。
	sess, err := mgr.GenerateChallengeWithBinding("/geoattr-noip", "http/1.1", ChallengeSessionBinding{
		SiteID: 11, Host: "geoattr.example.test", Bind: ":80",
	})
	if err != nil {
		t.Fatalf("GenerateChallengeWithBinding(): %v", err)
	}
	enc := encryptShieldEnvFingerprint(
		t, marshalShieldEnvFingerprint(t, fingerprint), sess.EnvKey,
		EnvFingerprintAAD("shield", sess.ID, sess.ChallengeSessionBinding))
	c, h := findShieldPoWSolution(t, sess.Nonce, sess.Difficulty)
	if ok, _ := mgr.VerifyChallengeWithBinding(sess.ID, "", c, h, enc, "http/1.1", sess.ChallengeSessionBinding); !ok {
		t.Fatal("nil attr with no issuer IP must keep baseline pass")
	}

	// 有签发 IP + nil 注入（nil 注入函数不产生任何代价）。
	sess2, err := mgr.GenerateChallengeWithBinding("/geoattr-withip", "http/1.1", ChallengeSessionBinding{
		SiteID: 11, Host: "geoattr.example.test", Bind: ":80", ClientIP: "203.0.113.9",
	})
	if err != nil {
		t.Fatalf("GenerateChallengeWithBinding(): %v", err)
	}
	enc2 := encryptShieldEnvFingerprint(
		t, marshalShieldEnvFingerprint(t, fingerprint), sess2.EnvKey,
		EnvFingerprintAAD("shield", sess2.ID, sess2.ChallengeSessionBinding))
	c2, h2 := findShieldPoWSolution(t, sess2.Nonce, sess2.Difficulty)
	if ok, _ := mgr.VerifyChallengeWithBinding(sess2.ID, "", c2, h2, enc2, "http/1.1", sess2.ChallengeSessionBinding); !ok {
		t.Fatal("nil attr provider with issuer IP must keep baseline pass")
	}
}
