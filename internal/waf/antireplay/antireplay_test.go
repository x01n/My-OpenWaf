package antireplay

import (
	"fmt"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

func newTestManager() *AntiReplayManager {
	return NewAntiReplayManager("test-secret-key-for-unit-tests", nil, 5*time.Minute)
}

// TestGenerateNonceDecodesValidLength 验证生成的 nonce 可以被解码且长度正确。
func TestGenerateNonceDecodesValidLength(t *testing.T) {
	m := newTestManager()
	nonce := m.GenerateNonce("1.2.3.4")
	if nonce == "" {
		t.Fatal("generated nonce is empty")
	}
	import_base64 := false
	_ = import_base64
	// 直接通过 ValidateAndRotate 验证结构合法性
	valid, isReplay, newNonce := m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)
	if !valid {
		t.Fatal("freshly generated nonce should be valid")
	}
	if isReplay {
		t.Fatal("fresh nonce should not be marked as replay")
	}
	if newNonce == "" {
		t.Fatal("rotated nonce should not be empty")
	}
}

// TestValidateAndRotateRejectsWrongIP 验证 IP 不匹配时签名无效。
func TestValidateAndRotateRejectsWrongIP(t *testing.T) {
	m := newTestManager()
	nonce := m.GenerateNonce("1.2.3.4")
	valid, _, _ := m.ValidateAndRotate(nonce, "9.9.9.9", 5*time.Minute)
	if valid {
		t.Fatal("nonce from different IP should be rejected")
	}
}

// TestValidateAndRotateRejectsMalformedNonce 验证格式错误的 nonce 被拒绝。
func TestValidateAndRotateRejectsMalformedNonce(t *testing.T) {
	m := newTestManager()
	for _, bad := range []string{"", "notbase64!!!", "aGVsbG8="} {
		valid, _, _ := m.ValidateAndRotate(bad, "1.2.3.4", 5*time.Minute)
		if valid {
			t.Errorf("malformed nonce %q should be rejected", bad)
		}
	}
}

// TestValidateAndRotateRejectsReplay 验证同一 nonce 在幂等窗口过期后再次提交时被标记为重放。
// 幂等窗口（8秒）内重试是合法的（幂等语义），8秒后提交同一 nonce 才是真正的重放。
// 本测试直接调用 validateAndRotateLocal 模拟跳过 idem 窗口的重放场景。
func TestValidateAndRotateRejectsReplay(t *testing.T) {
	m := newTestManager()
	nonce := m.GenerateNonce("1.2.3.4")
	freshNonce := m.GenerateNonce("1.2.3.4")

	// 第一次使用：合法
	valid1, isReplay1, _ := m.validateAndRotateLocal(nonce, freshNonce, 5*time.Minute)
	if !valid1 || isReplay1 {
		t.Fatalf("first use should succeed: valid=%v isReplay=%v", valid1, isReplay1)
	}

	// 模拟幂等窗口过期：直接删除 idemRotated 中的条目
	m.localMu.Lock()
	delete(m.idemRotated, nonce)
	m.localMu.Unlock()

	// 幂等窗口过期后，nonce 仍在 spentUntil 中 → 应被拒绝为重放
	valid2, isReplay2, _ := m.validateAndRotateLocal(nonce, freshNonce, 5*time.Minute)
	if valid2 {
		t.Fatal("nonce after idem window should be rejected as replay")
	}
	if !isReplay2 {
		t.Fatal("nonce after idem window should be flagged as replay")
	}
}

// TestValidateAndRotateIdempotentRetry 验证幂等重试（同一 nonce 在 idem 窗口内）返回相同的新 nonce。
func TestValidateAndRotateIdempotentRetry(t *testing.T) {
	m := newTestManager()
	nonce := m.GenerateNonce("1.2.3.4")
	valid1, _, newNonce1 := m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)
	if !valid1 {
		t.Fatal("first use should succeed")
	}
	// 直接调用内部幂等旋转（模拟幂等重试：nonce 已在 idemRotated 中）
	valid2, isReplay2, newNonce2 := m.validateAndRotateLocal(nonce, "different-new-nonce", 5*time.Minute)
	if !valid2 {
		t.Fatal("idempotent retry should be valid")
	}
	if isReplay2 {
		t.Fatal("idempotent retry should not be flagged as replay")
	}
	// 幂等语义：返回第一次旋转时生成的新 nonce
	if newNonce2 != newNonce1 {
		t.Fatalf("idempotent retry should return same rotated nonce: got %q, want %q", newNonce2, newNonce1)
	}
}

// TestSetRedisNilAndNonNil 验证 SetRedis 可以设置和清除 redis 客户端。
func TestSetRedisNilAndNonNil(t *testing.T) {
	m := newTestManager()
	if m.redisClient() != nil {
		t.Fatal("initial redis client should be nil")
	}
	fakeClient := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer fakeClient.Close()
	m.SetRedis(fakeClient)
	if m.redisClient() == nil {
		t.Fatal("redis client should be non-nil after SetRedis")
	}
	m.SetRedis(nil)
	if m.redisClient() != nil {
		t.Fatal("redis client should be nil after SetRedis(nil)")
	}
}

// TestValidateAndRotateLocalEvictsExpiredSpentUntil 验证 spentUntil 超过 20000 时清理已过期条目。
func TestValidateAndRotateLocalEvictsExpiredSpentUntil(t *testing.T) {
	m := newTestManager()
	m.localMu.Lock()
	for i := 0; i < 20001; i++ {
		m.spentUntil[fmt.Sprintf("expired-nonce-%d", i)] = time.Now().Add(-1 * time.Second)
	}
	m.localMu.Unlock()

	nonce := m.GenerateNonce("1.2.3.4")
	m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)

	m.localMu.Lock()
	count := len(m.spentUntil)
	m.localMu.Unlock()
	if count >= 20000 {
		t.Errorf("expected eviction to reduce spentUntil below 20000, got %d", count)
	}
}

// TestValidateAndRotateLocalEvictsExpiredIdemRotated 验证 idemRotated 超过 5000 时清理已过期条目。
func TestValidateAndRotateLocalEvictsExpiredIdemRotated(t *testing.T) {
	m := newTestManager()
	m.localMu.Lock()
	for i := 0; i < 5001; i++ {
		m.idemRotated[fmt.Sprintf("idem-key-%d", i)] = idemEntry{newNonce: "x", expires: time.Now().Add(-1 * time.Second)}
	}
	m.localMu.Unlock()

	nonce := m.GenerateNonce("1.2.3.4")
	m.ValidateAndRotate(nonce, "1.2.3.4", 5*time.Minute)

	m.localMu.Lock()
	count := len(m.idemRotated)
	m.localMu.Unlock()
	if count >= 5000 {
		t.Errorf("expected eviction to reduce idemRotated below 5000, got %d", count)
	}
}

// TestNewAntiReplayManagerDefaultTTL 验证 ttl<=0 时默认为 5 分钟。
func TestNewAntiReplayManagerDefaultTTL(t *testing.T) {
	m := NewAntiReplayManager("", nil, 0)
	if m.ttl != 5*time.Minute {
		t.Fatalf("expected default ttl=5m, got %v", m.ttl)
	}
	if len(m.secret) == 0 {
		t.Fatal("expected auto-generated secret when empty")
	}
}
