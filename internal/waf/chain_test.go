package waf

import (
	"strings"
	"testing"
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
