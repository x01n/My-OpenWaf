package challenge

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
