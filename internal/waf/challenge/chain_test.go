package challenge

import (
	"encoding/hex"
	"fmt"
	"strconv"
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

// TestChainCaptchaConditionCannotSkip 验证 CAPTCHA 步骤不会被环境分数条件跳过。
func TestChainCaptchaConditionCannotSkip(t *testing.T) {
	captchaManager := NewCaptchaManager(nil, 0)
	defer captchaManager.Close()
	mgr := NewChainChallengeManager(captchaManager, nil)
	defer mgr.Close()
	mgr.Reconfigure([]ChainStepConfig{
		{Type: ChainStepPoW, Condition: "all"},
		{Type: ChainStepCaptcha, Condition: "env_score>30", CaptchaType: CaptchaTypeMath},
	}, 1)

	sessionID, _ := mgr.StartChain("/protected")
	state := chainStateOf(t, mgr, sessionID)
	if got := state.Steps[1].Condition; got != "all" {
		t.Fatalf("CAPTCHA condition = %q, want all", got)
	}
	counter, hash := solveChainPoW(t, state.Nonce, state.powDifficulty(mgr.difficultyValue()))
	got := mgr.ProcessStepDetailed(sessionID, map[string]string{
		"pow_counter": counter,
		"pow_hash":    hash,
	})
	if got.Passed {
		t.Fatal("a configured CAPTCHA step must not be skipped by env_score condition")
	}
	if got.Failed {
		t.Fatal("valid PoW advancement must not be marked as failed")
	}
	if got.NextHTML == "" || !strings.Contains(got.NextHTML, "CAPTCHA Verification") {
		t.Fatalf("PoW advancement did not render the mandatory CAPTCHA step: %q", got.NextHTML)
	}
}

func TestShieldPageUsesRuntimeConfig(t *testing.T) {
	mgr := NewShieldManager(NewCaptchaManager(nil, 0), nil, 4)
	cfg := ShieldConfig{
		Difficulty:           2,
		TimeoutSecs:          7,
		AutoStartDelay:       1234,
		MaxRetries:           5,
		EnvStrictness:        1,
		RequireHTTP2:         true,
		RequireHTTP3:         false,
		AllowHTTP1:           false,
		EnableEnvCheck:       false,
		EnableDevToolsDetect: false,
	}
	mgr.SetConfig(cfg)

	session, err := mgr.GenerateChallenge("/shield", "h2")
	if err != nil {
		t.Fatal(err)
	}
	powScript := GeneratePoWWASMScript(session.Difficulty, session.Nonce)
	runtimeCfg := mgr.Config()
	html := shieldPageHTMLWithConfig(session.ID, runtimeCfg, "h2", "", powScript)

	checks := []string{
		`=1234`,
		`=7000`,
		`=5,`,
		`=false`,
		`=true`,
		`="h2"`,
		`pow_glue.js`,
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Fatalf("shield page did not include %q: %s", want, html)
		}
	}
}

func TestShieldPageNormalizesUnsafeProtocolBeforeRendering(t *testing.T) {
	cfg := DefaultShieldConfig()
	unsafeProtocol := `";alert(document.domain);//`
	html := shieldPageHTMLWithConfig("session", cfg, unsafeProtocol, "", "")

	if strings.Contains(html, unsafeProtocol) || strings.Contains(html, "alert(document.domain)") {
		t.Fatalf("shield page reflected unsafe protocol into inline script: %s", html)
	}
	if !strings.Contains(html, `="http/1.1"`) {
		t.Fatalf("shield page did not fall back to HTTP/1.1: %s", html)
	}
}

func TestNormalizeShieldProtocolRejectsUnknownValues(t *testing.T) {
	if got := normalizeShieldProtocol(`";alert(document.domain);//`); got != "" {
		t.Fatalf("normalizeShieldProtocol() = %q, want empty value for unknown protocol", got)
	}
	if got := shieldProtocolValue(`";alert(document.domain);//`); got != "http/1.1" {
		t.Fatalf("shieldProtocolValue() = %q, want %q", got, "http/1.1")
	}
}

func TestShieldVerifyEnforcesProtocolRequirements(t *testing.T) {
	mgr := NewShieldManager(NewCaptchaManager(nil, 0), nil, 1)

	makeConfig := func(requireH2, requireH3, allowH1 bool) ShieldConfig {
		cfg := DefaultShieldConfig()
		cfg.Difficulty = 1
		cfg.TimeoutSecs = 7
		cfg.AutoStartDelay = 50
		cfg.MaxRetries = 1
		cfg.RequireHTTP2 = requireH2
		cfg.RequireHTTP3 = requireH3
		cfg.AllowHTTP1 = allowH1
		cfg.EnableEnvCheck = false
		cfg.EnableDevToolsDetect = false
		return cfg
	}

	cases := []struct {
		name         string
		cfg          ShieldConfig
		requestProto string
		wantVerify   bool
	}{
		{
			name:         "require h3 accepts h3",
			cfg:          makeConfig(false, true, false),
			requestProto: "h3",
			wantVerify:   true,
		},
		{
			name:         "require h2 accepts h2",
			cfg:          makeConfig(true, false, false),
			requestProto: "h2",
			wantVerify:   true,
		},
		{
			name:         "disallow http1 rejects http1",
			cfg:          makeConfig(false, false, false),
			requestProto: "http/1.1",
			wantVerify:   false,
		},
		{
			name:         "require h3 rejects h2",
			cfg:          makeConfig(false, true, true),
			requestProto: "h2",
			wantVerify:   false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mgr.SetConfig(tt.cfg)
			session, err := mgr.GenerateChallenge("/shield", tt.requestProto)
			if err != nil {
				t.Fatalf("GenerateChallenge(): %v", err)
			}
			counter, hash := findShieldPoWSolution(t, session.Nonce, session.Difficulty)
			ok, redirect := mgr.VerifyChallenge(session.ID, "", counter, hash, "", tt.requestProto)
			if ok != tt.wantVerify {
				t.Fatalf("VerifyChallenge() ok = %v, want %v", ok, tt.wantVerify)
			}
			if redirect != "/shield" {
				t.Fatalf("VerifyChallenge() redirect = %q, want %q", redirect, "/shield")
			}
		})
	}
}

func findShieldPoWSolution(t *testing.T, nonce string, difficulty int) (int64, string) {
	t.Helper()
	prefix := strings.Repeat("0", difficulty)
	for counter := int64(0); counter < 1_000_000; counter++ {
		hash := sha256Hex(fmt.Sprintf("%s%d", nonce, counter))
		if strings.HasPrefix(hash, prefix) {
			return counter, hash
		}
	}
	t.Fatalf("no PoW solution found for nonce %q difficulty %d", nonce, difficulty)
	return 0, ""
}

func TestPoWScriptUsesShieldAndChainCallback(t *testing.T) {
	script := GeneratePoWWASMScript(1, "nonce")
	if !strings.Contains(script, "__owaf_pow_callback") {
		t.Fatalf("GeneratePoWWASMScript() did not expose shield/chain callback: %s", script)
	}
	if !strings.Contains(script, "__onPoWComplete") {
		t.Fatalf("GeneratePoWWASMScript() dropped legacy callback: %s", script)
	}
	markers := []string{
		"BigInt(self.__off)",
		"BigInt(self.__bs*self.__nc)",
		"wasm_bindgen({module_or_path:",
		"self.__p=",
		"solve_pow_batched(self.__n,self.__d,self.__p,self.__bs,off)",
		"__owaf_pow_error",
		"__owaf_pow_cancel",
	}
	for _, marker := range markers {
		if !strings.Contains(script, marker) {
			t.Fatalf("GeneratePoWWASMScript() missing marker %q: %s", marker, script)
		}
	}
	if strings.Contains(script, "var off=self.__off") || strings.Contains(script, "off+=self.__bs*self.__nc") {
		t.Fatalf("GeneratePoWWASMScript() still uses numeric start_counter: %s", script)
	}
}

func TestGeneratedPoWScriptEmbedsValidVMProgram(t *testing.T) {
	const (
		programMarker = "self.__p="
		programEnd    = ";self.__off="
	)
	wantOps := []byte{
		vmOpLoadNonce,
		vmOpLoadCounter,
		vmOpConcat,
		vmOpSHA256,
		vmOpCheckPrefix,
	}

	for i := 0; i < 100; i++ {
		script := GeneratePoWWASMScript(1, "nonce")
		start := strings.Index(script, programMarker)
		if start < 0 {
			t.Fatalf("generated script is missing %q: %s", programMarker, script)
		}
		start += len(programMarker)
		relEnd := strings.Index(script[start:], programEnd)
		if relEnd < 0 {
			t.Fatalf("generated script has no program terminator %q: %s", programEnd, script)
		}
		quoted := script[start : start+relEnd]
		program, err := strconv.Unquote(quoted)
		if err != nil {
			t.Fatalf("decode quoted VM program %q: %v", quoted, err)
		}
		bytecode, err := hex.DecodeString(program)
		if err != nil {
			t.Fatalf("decode VM program %q: %v", program, err)
		}
		if len(bytecode) < len(wantOps)+2 || len(bytecode) > len(wantOps)+5 {
			t.Fatalf("unexpected VM program length %d: %x", len(bytecode), bytecode)
		}

		nonNops := make([]byte, 0, len(wantOps))
		nopCount := 0
		for _, op := range bytecode {
			if op == vmOpNop {
				nopCount++
				continue
			}
			nonNops = append(nonNops, op)
		}
		if nopCount < 2 || nopCount > 5 {
			t.Fatalf("unexpected NOP count %d: %x", nopCount, bytecode)
		}
		if len(nonNops) != len(wantOps) {
			t.Fatalf("unexpected non-NOP opcodes %x, want %x", nonNops, wantOps)
		}
		for j := range wantOps {
			if nonNops[j] != wantOps[j] {
				t.Fatalf("non-NOP opcode order %x, want %x", nonNops, wantOps)
			}
		}
	}
}

func TestEnvCheckJSUsesWASMOnly(t *testing.T) {
	script := EnvCheckJSPlain()
	for _, forbidden := range []string{"navigator.webdriver", "JSON.stringify(fp)", "window.__owaf_env=fp"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("EnvCheckJSPlain() retained JavaScript security calculation %q: %s", forbidden, script)
		}
	}
	if !strings.Contains(script, "wasm_bindgen.collect_fingerprint") {
		t.Fatalf("EnvCheckJSPlain() did not call the WASM collector: %s", script)
	}

	encrypted := EnvCheckJSEncrypted(
		"aabbccdd112233445566778899001122aabbccdd112233445566778899001122",
		"owaf-env:v1|challenge|1|example.test|:443|request",
	)
	if encrypted == "" {
		t.Fatal("encrypted envcheck loader was not generated")
	}
	for _, forbidden := range []string{"navigator.webdriver", "JSON.stringify(fp)", "crypto.subtle"} {
		if strings.Contains(encrypted, forbidden) {
			t.Fatalf("encrypted envcheck retained JavaScript security calculation %q: %s", forbidden, encrypted)
		}
	}
	if !strings.Contains(encrypted, "wasm_bindgen.collect_and_encrypt_fingerprint") {
		t.Fatalf("encrypted envcheck must call the WASM collector: %s", encrypted)
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
