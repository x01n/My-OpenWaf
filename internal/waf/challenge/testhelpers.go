package challenge

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"My-OpenWaf/internal/waf/challenge/gm"
)

// CaptchaManagerPendingForTest 仅供外部包测试（dataplane 验证码 fail-closed 回归）
// 读取内存会话的期望答案、环境密钥与站点绑定；生产代码不得调用。
func CaptchaManagerPendingForTest(cm *CaptchaManager, sessionID string) (answer string, envKey []byte, binding ChallengeSessionBinding, found bool) {
	if cm == nil {
		return "", nil, ChallengeSessionBinding{}, false
	}
	cm.mu.RLock()
	s := cm.sessions[sessionID]
	cm.mu.RUnlock()
	if s == nil {
		return "", nil, ChallengeSessionBinding{}, false
	}
	return s.Answer, s.EnvKey, s.ChallengeSessionBinding, true
}

// C2SeedCookieFromEnvelopeForTest 解封一枚 C2 种子信封并返回其中的 cookie 值，
// 供外部包测试构造「浏览器会原样落位」的合法输入；生产代码不得调用（生产侧
// 的解封发生在客户端 WASM 内，服务端从不解封自己签发的种子）。
// 任一步失败返回空串。
func C2SeedCookieFromEnvelopeForTest(envelope, keyHex string) string {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != envSessionKeySize {
		return ""
	}
	raw, err := gm.Decode(envelope)
	if err != nil {
		return ""
	}
	plain, err := gm.Open(key[:16], raw, []byte(c2SeedEnvelopeAAD), gm.DomainPowShards, false)
	if err != nil {
		return ""
	}
	var shardEnv PowShardEnvelope
	if json.Unmarshal(plain, &shardEnv) != nil || len(shardEnv.Shards) != 1 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(shardEnv.Shards[0].Data)
	if err != nil {
		return ""
	}
	var seed C2SeedPayload
	if json.Unmarshal(payload, &seed) != nil {
		return ""
	}
	return seed.Cookie
}
