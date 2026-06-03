package challenge

import (
	"strings"
	"testing"
	"time"
)

func TestChainSessionManagementUsesRealState(t *testing.T) {
	mgr := NewChainChallengeManager(NewCaptchaManager(nil, 0), nil)
	sessionID, _ := mgr.StartChain("/admin")

	sessions := mgr.ListSessions()
	if len(sessions) != 1 || sessions[0].ID != sessionID || sessions[0].OriginalURL != "/admin" || sessions[0].StepCount == 0 {
		t.Fatalf("unexpected sessions: %+v", sessions)
	}
	if !mgr.DeleteSession(sessionID) {
		t.Fatalf("expected existing session to be deleted")
	}
	if mgr.DeleteSession(sessionID) {
		t.Fatalf("expected deleted session to be absent")
	}
	if got := mgr.ListSessions(); len(got) != 0 {
		t.Fatalf("expected no sessions after delete, got %+v", got)
	}
}

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

func TestChainCaptchaUsesAdvancedVerification(t *testing.T) {
	captchaManager := NewCaptchaManager(nil, 0)
	sessionID := "click-session"
	captchaManager.sessions[sessionID] = &CaptchaSession{
		ID:        sessionID,
		Type:      CaptchaTypeClick,
		Answer:    `{"target":{"x":10,"y":20}}`,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	mgr := NewChainChallengeManager(captchaManager, nil)
	chainSession := "chain-session"
	mgr.states[chainSession] = &ChainState{
		SessionID:   chainSession,
		CurrentStep: 0,
		Steps:       []ChainStepConfig{{Type: ChainStepCaptcha, Condition: "all", CaptchaType: CaptchaTypeClick}},
		Scores:      map[string]int{},
		OriginalURL: "/protected",
		CaptchaID:   sessionID,
		CreatedAt:   time.Now(),
	}

	ok, redirect, nextHTML := mgr.ProcessStep(chainSession, map[string]string{"captcha_answer": `[{"x":12,"y":19}]`})
	if !ok || redirect != "/protected" || nextHTML != "" {
		t.Fatalf("advanced chain captcha answer was not verified: ok=%v redirect=%q html=%q", ok, redirect, nextHTML)
	}
}

func TestShieldPageUsesRuntimeConfig(t *testing.T) {
	mgr := NewShieldManager(NewCaptchaManager(nil, 0), nil, 4)
	mgr.SetConfig(ShieldConfig{
		Difficulty:           2,
		TimeoutSecs:          7,
		AutoStartDelay:       1234,
		MaxRetries:           5,
		EnvStrictness:        1,
		RequireHTTP2:         true,
		RequireHTTP3:         false,
		AllowHTTP1:           false,
		EnableWASM:           false,
		EnableEnvCheck:       false,
		EnableDevToolsDetect: false,
	})

	session, err := mgr.GenerateChallenge("/shield")
	if err != nil {
		t.Fatal(err)
	}
	powScript := GeneratePoWScript(session.Difficulty, session.Nonce)
	cfg := mgr.Config()
	html := shieldPageHTMLWithConfig(session.ID, cfg, "", powScript)

	checks := []string{
		`autoDelay=1234`,
		`timeoutMs=7000`,
		`maxRetries=5`,
		`enableEnv=false`,
		`detectDev=false`,
		`requireH2=true`,
		`allowH1=false`,
		`window.__powWorker=w`,
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Fatalf("shield page did not include %q: %s", want, html)
		}
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
	if !strings.Contains(script, "__owaf_env_encrypted") {
		t.Fatalf("EnvCheckJS() dropped encrypted fingerprint export: %s", script)
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
