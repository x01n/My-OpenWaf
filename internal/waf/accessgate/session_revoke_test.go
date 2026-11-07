package accessgate

import (
	"context"
	"testing"
	"time"
)

/**
 * TestMemorySessionStoreRevokeAll 验证内存存储的全量吊销。
 *
 * 覆盖三条产品语义：
 *   - RevokeAll 后所有既有 token 的 Validate 必须全部返回 nil；
 *   - 吊销空存储幂等，不报错；
 *   - 吊销后 Create 生成的新会话仍然可用（防「一次吊销后存储永久不可用」）。
 */
func TestMemorySessionStoreRevokeAll(t *testing.T) {
	store := NewMemorySessionStore()

	const sessionCount = 5
	tokens := make([]string, 0, sessionCount)
	for i := 0; i < sessionCount; i++ {
		token, err := store.Create(uint(i+1), "user", "shared_password", 3600)
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		tokens = append(tokens, token)
	}
	for i, token := range tokens {
		info, err := store.Validate(token)
		if err != nil {
			t.Fatalf("Validate before RevokeAll #%d: %v", i, err)
		}
		if info == nil {
			t.Fatalf("Validate before RevokeAll #%d: session missing", i)
		}
	}

	if err := store.RevokeAll(); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	for i, token := range tokens {
		info, err := store.Validate(token)
		if err != nil {
			t.Fatalf("Validate after RevokeAll #%d: %v", i, err)
		}
		if info != nil {
			t.Fatalf("Validate after RevokeAll #%d: session should be gone, got %+v", i, info)
		}
	}

	// 幂等：空存储上再次吊销不报错。
	if err := store.RevokeAll(); err != nil {
		t.Fatalf("RevokeAll on empty store: %v", err)
	}

	// 吊销后存储必须仍可写入并可校验，否则恢复配置会让全站无法登录。
	fresh, err := store.Create(9, "reborn", "shared_password", 3600)
	if err != nil {
		t.Fatalf("Create after RevokeAll: %v", err)
	}
	info, err := store.Validate(fresh)
	if err != nil {
		t.Fatalf("Validate after RevokeAll + Create: %v", err)
	}
	if info == nil {
		t.Fatal("Validate after RevokeAll + Create: new session missing")
	}
	if info.SiteID != 9 || info.Identity != "reborn" {
		t.Fatalf("new session unexpected: %+v", info)
	}
}

/**
 * TestRedisSessionStoreRevokeAllClearsRedisAndLocal 验证 Redis 侧全量吊销。
 *
 * 用本包既有的 miniRedis 桩驱动，不依赖真实 Redis 实例。断言三件事：
 *   - Redis 中前缀下的会话键全部消失；
 *   - 内存降级路径中降级写入的会话同样被清（与 Redis 双端一致的语义）；
 *   - 吊销后 Redis 路径仍可写，新会话跨实例可见。
 *
 * 注意本用例不断言「非会话键存活」：miniRedis 桩的 cmdScan 忽略 MATCH 参数
 * （store_redis_test.go:213），SCAN 会返回键空间里的全部键，因此 DEL 会一并
 * 删掉 oauth-state 键——这是桩的实现缺口，不是生产代码的问题。在真实 Redis 上
 * MATCH "owaf:access:session:*" 只返回会话键。
 */
func TestRedisSessionStoreRevokeAllClearsRedisAndLocal(t *testing.T) {
	m := startMiniRedis(t, "")
	client := newMiniRedisClient(t, m)
	defer client.Close()
	store := NewRedisSessionStore(client)

	tokens := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		token, err := store.Create(uint(i+1), "user", "shared_password", 3600)
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		tokens = append(tokens, token)
	}

	// 降级路径写入的会话只存在于 local（SET 被注入错误时才会发生），
	// 这里直接往 local 塞一条，验证 RevokeAll 不会漏掉内存侧。
	fallbackToken, err := store.local.Create(4, "fallback", "shared_password", 3600)
	if err != nil {
		t.Fatalf("seed local fallback session: %v", err)
	}

	// 同前缀但本地无对应条目的孤立键：作为会话键一并清掉。
	orphanKey := accessSessionKey("orphan-token-without-local-entry")
	if err := client.Do(context.Background(),
		client.B().Set().Key(orphanKey).Value("{}").Px(time.Hour).Build()).Error(); err != nil {
		t.Fatalf("seed orphan session key: %v", err)
	}

	if err := store.RevokeAll(); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	for i, token := range tokens {
		info, err := store.Validate(token)
		if err != nil {
			t.Fatalf("Validate after RevokeAll #%d: %v", i, err)
		}
		if info != nil {
			t.Fatalf("Validate after RevokeAll #%d: session should be gone, got %+v", i, info)
		}
	}

	if info, _ := store.local.Validate(fallbackToken); info != nil {
		t.Fatalf("local fallback session should be gone after RevokeAll, got %+v", info)
	}

	for _, key := range []string{accessSessionKey(tokens[0]), accessSessionKey(tokens[1]), orphanKey} {
		n, err := client.Do(context.Background(), client.B().Exists().Key(key).Build()).AsInt64()
		if err != nil {
			t.Fatalf("Exists(%s): %v", key, err)
		}
		if n != 0 {
			t.Fatalf("key %s should be deleted from Redis, exists=%d", key, n)
		}
	}

	// 吊销后 Redis 路径必须仍可写：新会话应能跨实例可见，
	// 证明 RevokeAll 没有让 Redis 后端进入不可用状态。
	otherStore := NewRedisSessionStore(client)
	fresh, err := store.Create(5, "reborn", "shared_password", 3600)
	if err != nil {
		t.Fatalf("Create after RevokeAll: %v", err)
	}
	info, err := otherStore.Validate(fresh)
	if err != nil {
		t.Fatalf("Validate fresh session across instances: %v", err)
	}
	if info == nil {
		t.Fatal("fresh session should be visible in Redis after RevokeAll")
	}
}

/**
 * TestRedisSessionStoreRevokeAllNilRedis 验证 redis=nil 时全量吊销等价于内存实现。
 */
func TestRedisSessionStoreRevokeAllNilRedis(t *testing.T) {
	store := NewRedisSessionStore(nil)

	token, err := store.Create(6, "mem-only", "shared_password", 3600)
	if err != nil {
		t.Fatalf("Create with nil redis: %v", err)
	}
	if err := store.RevokeAll(); err != nil {
		t.Fatalf("RevokeAll with nil redis: %v", err)
	}
	info, err := store.Validate(token)
	if err != nil {
		t.Fatalf("Validate with nil redis: %v", err)
	}
	if info != nil {
		t.Fatalf("session should be gone after RevokeAll with nil redis, got %+v", info)
	}
}
