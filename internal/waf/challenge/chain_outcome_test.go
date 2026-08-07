package challenge

import (
	"strconv"
	"strings"
	"testing"
)

// solveChainPoW 按会话锁定的难度求出合法 PoW 解答。
func solveChainPoW(t *testing.T, nonce string, difficulty int) (counter string, hash string) {
	t.Helper()
	prefix := strings.Repeat("0", difficulty)
	for i := int64(0); i < 5_000_000; i++ {
		h := sha256Hex(nonce + strconv.FormatInt(i, 10))
		if strings.HasPrefix(h, prefix) {
			return strconv.FormatInt(i, 10), h
		}
	}
	t.Fatalf("未能求出难度 %d 的解", difficulty)
	return "", ""
}

// chainStateOf 读取内存态会话，供测试获取 nonce 与难度。
func chainStateOf(t *testing.T, mgr *ChainChallengeManager, sessionID string) *ChainState {
	t.Helper()
	st := mgr.loadChainState(sessionID)
	if st == nil {
		t.Fatalf("会话 %s 不存在", sessionID)
	}
	return st
}

func chainEnvironmentEnvelope(t *testing.T, manager *ChainChallengeManager, sessionID string, binding ChallengeSessionBinding) string {
	t.Helper()
	state := chainStateOf(t, manager, sessionID)
	if len(state.EnvKey) != envSessionKeySize {
		t.Fatalf("chain environment key length = %d, want %d", len(state.EnvKey), envSessionKeySize)
	}
	payload := marshalShieldEnvFingerprint(t, shieldNormalEnvFingerprint())
	return encryptVersionedEnvFingerprint(
		t,
		[]byte(payload),
		state.EnvKey,
		EnvFingerprintAAD("chain", sessionID, binding),
	)
}

// TestProcessStepDetailedMissingSessionIsFailure 验证会话缺失被判为失败。
func TestProcessStepDetailedMissingSessionIsFailure(t *testing.T) {
	mgr := NewChainChallengeManager(NewCaptchaManager(nil, 0), nil)
	defer mgr.Close()

	if got := mgr.ProcessStepDetailed("", nil); !got.Failed {
		t.Fatal("空 sessionID 应判为失败")
	}
	if got := mgr.ProcessStepDetailed("no-such-session", nil); !got.Failed {
		t.Fatal("不存在的会话应判为失败")
	}
}

// TestProcessStepDetailedAdvanceIsNotFailure 是核心回归：
// 链内「当前步通过、推进到下一步」与「步内校验失败」的三元返回值完全相同
// （false, "", html），若把前者也记为失败，正常推进多步挑战的访客会被误封。
func TestProcessStepDetailedAdvanceIsNotFailure(t *testing.T) {
	mgr := NewChainChallengeManager(NewCaptchaManager(nil, 0), nil)
	defer mgr.Close()
	mgr.Reconfigure([]ChainStepConfig{
		{Type: ChainStepEnv, Condition: "all"},
		{Type: ChainStepPoW, Condition: "all"},
	}, 3)

	sessionID, _ := mgr.StartChain("/admin")
	state := chainStateOf(t, mgr, sessionID)
	payload := marshalShieldEnvFingerprint(t, shieldNormalEnvFingerprint())
	envelope := encryptVersionedEnvFingerprint(
		t,
		[]byte(payload),
		state.EnvKey,
		EnvFingerprintAAD("chain", sessionID, state.ChallengeSessionBinding),
	)
	got := mgr.ProcessStepDetailed(sessionID, map[string]string{"env_fp": envelope})

	if got.Failed {
		t.Fatal("valid encrypted env step must not be marked failed")
	}
	if got.Passed {
		t.Fatal("a chain with a remaining PoW step must not pass")
	}
	if got.NextHTML == "" {
		t.Fatal("valid env step should render the next page")
	}
}

// TestProcessStepDetailedWrongPoWIsFailure 验证 PoW 解答错误被判为失败，
// 且该分支同样返回 NextHTML（重渲染当前步），因此只能靠 Failed 区分。
func TestProcessStepDetailedWrongPoWIsFailure(t *testing.T) {
	mgr := NewChainChallengeManager(NewCaptchaManager(nil, 0), nil)
	defer mgr.Close()
	mgr.Reconfigure([]ChainStepConfig{{Type: ChainStepPoW, Condition: "all"}}, 3)

	sessionID, _ := mgr.StartChain("/admin")
	got := mgr.ProcessStepDetailed(sessionID, map[string]string{
		"pow_counter": "1",
		"pow_hash":    strings.Repeat("f", 64),
	})

	if !got.Failed {
		t.Fatal("PoW 解答错误应判为失败")
	}
	if got.Passed {
		t.Fatal("PoW 错误不应通过")
	}
	if got.NextHTML == "" {
		t.Fatal("失败时应重渲染当前步——正是该分支与正常推进难以区分之处")
	}
}

// TestProcessStepDetailedCorrectPoWPasses 验证正确解答通过且不计失败。
func TestProcessStepDetailedCorrectPoWPasses(t *testing.T) {
	mgr := NewChainChallengeManager(NewCaptchaManager(nil, 0), nil)
	defer mgr.Close()
	mgr.Reconfigure([]ChainStepConfig{{Type: ChainStepPoW, Condition: "all"}}, 3)

	sessionID, _ := mgr.StartChain("/protected")
	st := chainStateOf(t, mgr, sessionID)
	counter, hash := solveChainPoW(t, st.Nonce, st.powDifficulty(mgr.difficultyValue()))

	got := mgr.ProcessStepDetailed(sessionID, map[string]string{
		"pow_counter": counter,
		"pow_hash":    hash,
	})

	if got.Failed {
		t.Fatal("正确的 PoW 解答不得判为失败")
	}
	if !got.Passed {
		t.Fatalf("唯一步骤已通过，应整链通过：%+v", got)
	}
	if got.RedirectURL != "/protected" {
		t.Fatalf("RedirectURL = %q, want /protected", got.RedirectURL)
	}
}

// TestProcessStepKeepsLegacyBehaviour 验证保留的三值签名行为与 Detailed 一致，
// 确保既有调用方（测试）不受影响。
func TestProcessStepKeepsLegacyBehaviour(t *testing.T) {
	mgr := NewChainChallengeManager(NewCaptchaManager(nil, 0), nil)
	defer mgr.Close()
	mgr.Reconfigure([]ChainStepConfig{{Type: ChainStepPoW, Condition: "all"}}, 3)

	sessionID, _ := mgr.StartChain("/x")
	st := chainStateOf(t, mgr, sessionID)
	counter, hash := solveChainPoW(t, st.Nonce, st.powDifficulty(mgr.difficultyValue()))

	passed, redirect, html := mgr.ProcessStep(sessionID, map[string]string{
		"pow_counter": counter,
		"pow_hash":    hash,
	})
	if !passed || redirect != "/x" || html != "" {
		t.Fatalf("ProcessStep = (%v, %q, len=%d)", passed, redirect, len(html))
	}
}
