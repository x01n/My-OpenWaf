package challenge

import (
	"strconv"
	"strings"
	"testing"
)

// solveChallengeProof 以与挑战页脚本相同的算法求解，供测试构造合法解答。
func solveChallengeProof(t *testing.T, token string) (counter string, hash string) {
	t.Helper()
	prefix := strings.Repeat("0", ChallengeProofDifficulty)
	for i := int64(0); i < 5_000_000; i++ {
		h := sha256Hex(token + strconv.FormatInt(i, 10))
		if strings.HasPrefix(h, prefix) {
			return strconv.FormatInt(i, 10), h
		}
	}
	t.Fatalf("未能在上限内求出难度 %d 的解", ChallengeProofDifficulty)
	return "", ""
}

func TestVerifyChallengeProofAcceptsValidSolution(t *testing.T) {
	const token = "signed-token-abc"
	counter, hash := solveChallengeProof(t, token)

	if !VerifyChallengeProof(token, counter, hash) {
		t.Fatalf("合法解答应通过：counter=%s hash=%s", counter, hash)
	}
}

// TestVerifyChallengeProofRejectsConstantAnswer 是核心回归：
// 历史实现提交的 proof 是与 token 无关的定值 996500000，
// 攻击者硬编码即可绕过。改为真实 PoW 后该常量必须被拒绝。
func TestVerifyChallengeProofRejectsConstantAnswer(t *testing.T) {
	if VerifyChallengeProof("signed-token-abc", "0", "996500000") {
		t.Fatal("与 token 无关的常量答案必须被拒绝")
	}
}

// TestVerifyChallengeProofIsTokenBound 验证工作量无法跨挑战复用：
// 为 token A 求出的解答，用在 token B 上必须失败。
func TestVerifyChallengeProofIsTokenBound(t *testing.T) {
	const tokenA = "token-alpha"
	const tokenB = "token-beta"
	counter, hash := solveChallengeProof(t, tokenA)

	if !VerifyChallengeProof(tokenA, counter, hash) {
		t.Fatal("前置条件失败：解答对原 token 应有效")
	}
	if VerifyChallengeProof(tokenB, counter, hash) {
		t.Fatal("解答不得跨 token 复用")
	}
}

func TestVerifyChallengeProofRejectsMalformedInput(t *testing.T) {
	const token = "signed-token-abc"
	counter, hash := solveChallengeProof(t, token)

	tests := []struct {
		name             string
		token, cnt, hash string
	}{
		{"空 token", "", counter, hash},
		{"空 counter", token, "", hash},
		{"空 hash", token, counter, ""},
		{"counter 非数字", token, "abc", hash},
		{"counter 为负", token, "-1", hash},
		{"hash 非十六进制", token, counter, strings.Repeat("z", 64)},
		{"hash 长度不足", token, counter, "0000"},
		{"counter 与 hash 不匹配", token, "999999999", hash},
	}
	for _, tt := range tests {
		if VerifyChallengeProof(tt.token, tt.cnt, tt.hash) {
			t.Errorf("%s：应当被拒绝", tt.name)
		}
	}
}

// TestVerifyChallengeProofRejectsInsufficientWork 验证前导零不足的摘要被拒绝，
// 即便该摘要本身与 token+counter 真实对应。
func TestVerifyChallengeProofRejectsInsufficientWork(t *testing.T) {
	const token = "signed-token-abc"
	prefix := strings.Repeat("0", ChallengeProofDifficulty)
	for i := int64(0); i < 1000; i++ {
		cnt := strconv.FormatInt(i, 10)
		h := sha256Hex(token + cnt)
		if strings.HasPrefix(h, prefix) {
			continue // 恰好达标的跳过
		}
		if VerifyChallengeProof(token, cnt, h) {
			t.Fatalf("前导零不足的摘要必须被拒绝：counter=%s hash=%s", cnt, h)
		}
		return
	}
	t.Skip("未找到不达标样本")
}

// TestChallengeProofDifficultyWithinPoWBounds 确保难度常量落在 VerifyPoW 的合法区间，
// 否则所有解答都会被无条件拒绝。
func TestChallengeProofDifficultyWithinPoWBounds(t *testing.T) {
	if ChallengeProofDifficulty < minPoWDifficulty || ChallengeProofDifficulty > maxPoWDifficulty {
		t.Fatalf("ChallengeProofDifficulty=%d 超出 VerifyPoW 允许的 [%d,%d]",
			ChallengeProofDifficulty, minPoWDifficulty, maxPoWDifficulty)
	}
}
