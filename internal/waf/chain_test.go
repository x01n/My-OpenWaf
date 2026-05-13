package waf

import (
	"strings"
	"testing"
	"time"
)

func TestChainReconfigureUpdatesSteps(t *testing.T) {
	mgr := NewChainChallengeManager(NewCaptchaManager(nil, 0), nil)
	mgr.Reconfigure([]ChainStepConfig{{Type: ChainStepCaptcha, Condition: "all"}}, 2)

	_, html := mgr.StartChain("/admin")
	if !strings.Contains(html, "CAPTCHA Verification") {
		t.Fatalf("StartChain() did not use configured captcha step: %s", html)
	}
	if strings.Contains(html, "Environment Check") || strings.Contains(html, "Proof of Work") {
		t.Fatalf("StartChain() included default steps after reconfigure: %s", html)
	}
}

func TestChainReconfigureFallbacksToDefaults(t *testing.T) {
	mgr := NewChainChallengeManager(NewCaptchaManager(nil, 0), nil)
	mgr.Reconfigure([]ChainStepConfig{{Type: ChainStepType("unsupported"), Condition: "all"}}, 0)

	_, html := mgr.StartChain("/")
	if !strings.Contains(html, "Environment Check") {
		t.Fatalf("StartChain() did not fall back to default environment step: %s", html)
	}
}

func TestPoWScriptUsesShieldAndChainCallback(t *testing.T) {
	script := GeneratePoWScript(1, "nonce")
	if !strings.Contains(script, "__owaf_pow_callback") {
		t.Fatalf("GeneratePoWScript() did not expose shield/chain callback: %s", script)
	}
	if !strings.Contains(script, "__onPoWComplete") {
		t.Fatalf("GeneratePoWScript() dropped legacy callback: %s", script)
	}
}

func TestEnvCheckJSExportsOwafEnv(t *testing.T) {
	script := EnvCheckJS()
	if !strings.Contains(script, "window.__owaf_env=fp") {
		t.Fatalf("EnvCheckJS() did not expose __owaf_env: %s", script)
	}
	if !strings.Contains(script, "window.__envFingerprint") {
		t.Fatalf("EnvCheckJS() dropped legacy fingerprint export: %s", script)
	}
}

func TestChallengePassCookieIsSignedAndBound(t *testing.T) {
	now := time.Unix(100, 0)
	value := SignChallengePassValue("example.com", nil, now, time.Hour)
	if value == "1" {
		t.Fatal("challenge pass cookie value must not be a static boolean")
	}
	if !VerifyChallengePassValue(value, "example.com", nil, now.Add(time.Second)) {
		t.Fatal("signed challenge pass cookie did not verify")
	}
	if VerifyChallengePassValue(value, "other.example", nil, now.Add(time.Second)) {
		t.Fatal("signed challenge pass cookie verified for another host")
	}
	if VerifyChallengePassValue(value, "example.com", nil, now.Add(2*time.Hour)) {
		t.Fatal("expired challenge pass cookie verified")
	}
}
