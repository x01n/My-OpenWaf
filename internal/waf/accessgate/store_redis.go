package accessgate

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Redis key 前缀，与 challenge 线 "owaf:captcha:" 等保持体系一致。
const (
	accessSessionKeyPrefix    = "owaf:access:session:"
	accessOAuthStateKeyPrefix = "owaf:access:oauth-state:"
)

const accessRedisOperationTimeout = 100 * time.Millisecond

var accessCleanupScript = goredis.NewScript(`
local removed = 0
for i = 1, #KEYS do
  local v = redis.call('GET', KEYS[i])
  if v then
    local ok, session = pcall(cjson.decode, v)
    if ok and type(session) == 'table' and type(session.expires_at) == 'number' then
      if session.expires_at <= tonumber(ARGV[1]) then
        redis.call('DEL', KEYS[i])
        removed = removed + 1
      end
    end
  end
end
return removed
`)

var accessTakeScript = goredis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then
  return nil
end
redis.call('DEL', KEYS[1])
return v
`)

// redisSessionInfo 会话在 Redis 中的 JSON 序列化形态。
// site_id 用 float64 承载 json.Number，站点上限远小于 2^53，转换无损。
type redisSessionInfo struct {
	SiteID    float64 `json:"site_id"`
	Token     string  `json:"token"`
	Identity  string  `json:"identity"`
	Provider  string  `json:"provider"`
	ExpiresAt int64   `json:"expires_at"` // Unix 毫秒
}

// RedisSessionStore 基于 Redis 的会话存储。
//
// Redis 可用时读写全走 Redis（TTL、原子 take、多实例共享）；Redis 未配置
// 或单条命令瞬时失败时降级到内嵌内存库，保证单机登录不被 Redis 抖动打断。
// 与 MemorySessionStore 语义等价：Create 生成随机 token，Validate 检查
// 过期并惰性删除，Revoke 幂等，CleanExpired 幂等。
type RedisSessionStore struct {
	mu    sync.RWMutex
	redis *goredis.Client
	local *MemorySessionStore
}

// NewRedisSessionStore 创建会话存储。redis 为 nil 时仅内存，等价于 MemorySessionStore。
func NewRedisSessionStore(redis *goredis.Client) *RedisSessionStore {
	return &RedisSessionStore{
		redis: redis,
		local: NewMemorySessionStore(),
	}
}

// SetRedis 注入或清除 Redis 客户端，供运行时热加载切换后端。
func (s *RedisSessionStore) SetRedis(redis *goredis.Client) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.redis = redis
	s.mu.Unlock()
}

func (s *RedisSessionStore) redisClient() *goredis.Client {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.redis
}

/**
 * Create 生成会话并写入存储。
 * Redis 可用时写入 Redis 并返回其 token；写入失败时降级到内存实现，
 * 由内存实现重新生成 token（极端的「Redis 写超时但实际已落库」会留下一个
 * 无人持有的孤儿键，随 TTL 自动过期，无泄漏）。
 */
func (s *RedisSessionStore) Create(siteID uint, identity string, provider string, ttl int) (string, error) {
	if ttl <= 0 {
		// 与 MemorySessionStore 保持同一语义：过期时刻在过去，Validate 立即失效。
		return s.local.Create(siteID, identity, provider, ttl)
	}
	token, err := GenerateToken()
	if err != nil {
		return "", err
	}
	info := &SessionInfo{
		SiteID:    siteID,
		Token:     token,
		Identity:  identity,
		Provider:  provider,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	if redis := s.redisClient(); redis != nil {
		if err := s.createInRedis(redis, info); err != nil {
			return s.local.Create(siteID, identity, provider, ttl)
		}
		return token, nil
	}
	return s.local.Create(siteID, identity, provider, ttl)
}

// createInRedis 写出会话 JSON 并设置 TTL。
func (s *RedisSessionStore) createInRedis(redis *goredis.Client, info *SessionInfo) error {
	payload, err := json.Marshal(&redisSessionInfo{
		SiteID:    float64(info.SiteID),
		Token:     info.Token,
		Identity:  info.Identity,
		Provider:  info.Provider,
		ExpiresAt: info.ExpiresAt.UnixMilli(),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), accessRedisOperationTimeout)
	defer cancel()
	return redis.Set(ctx, accessSessionKey(info.Token), payload, time.Until(info.ExpiresAt)).Err()
}

// Validate 校验会话 token。
// 未命中、损坏值、过期均返回 (nil, nil)；单条命令失败时降级到内存实现，
// Redis 时代的会话在降级窗口内会要求重新登录（安全方向，绝不误放行）。
func (s *RedisSessionStore) Validate(token string) (*SessionInfo, error) {
	if token == "" {
		return nil, nil
	}
	if redis := s.redisClient(); redis != nil {
		info, err := s.validateInRedis(redis, token)
		switch {
		case err != nil:
			// 命令失败不可判定：回退本地，绝不误放行。
			return s.local.Validate(token)
		case info != nil:
			return info, nil
		}
		// Redis 未命中时二次查询本地内存库：降级写入的会话只存在于
		// 本节点，Redis miss 不代表会话无效。
		return s.local.Validate(token)
	}
	return s.local.Validate(token)
}

// validateInRedis 读会话 JSON，过期则惰性删除并返回 nil。
func (s *RedisSessionStore) validateInRedis(redis *goredis.Client, token string) (*SessionInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), accessRedisOperationTimeout)
	defer cancel()
	raw, err := redis.Get(ctx, accessSessionKey(token)).Bytes()
	if err != nil {
		if err == goredis.Nil {
			return nil, nil
		}
		return nil, err
	}
	info, werr := decodeRedisSession(raw)
	if werr != nil {
		// 残留损坏值：按未命中处理并清除。
		_ = redis.Del(ctx, accessSessionKey(token)).Err()
		return nil, nil
	}
	if time.Now().After(info.ExpiresAt) {
		_ = redis.Del(ctx, accessSessionKey(token)).Err()
		return nil, nil
	}
	return info, nil
}

// decodeRedisSession 解析 Redis 会话 JSON。
func decodeRedisSession(raw []byte) (*SessionInfo, error) {
	var rs redisSessionInfo
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, err
	}
	if rs.SiteID < 0 || rs.SiteID > float64(1<<32) {
		return nil, fmt.Errorf("invalid session site_id %v", rs.SiteID)
	}
	return &SessionInfo{
		SiteID:    uint(rs.SiteID),
		Token:     rs.Token,
		Identity:  rs.Identity,
		Provider:  rs.Provider,
		ExpiresAt: time.UnixMilli(rs.ExpiresAt),
	}, nil
}

// Revoke 删除会话，幂等。内存与 Redis 双端都删一次，保证降级路径下不残留。
func (s *RedisSessionStore) Revoke(token string) error {
	var lastErr error
	if err := s.local.Revoke(token); err != nil {
		lastErr = err
	}
	if redis := s.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), accessRedisOperationTimeout)
		defer cancel()
		if err := redis.Del(ctx, accessSessionKey(token)).Err(); err != nil && err != goredis.Nil {
			lastErr = err
		}
	}
	return lastErr
}

// CleanExpired 清理过期会话：本地内存始终清理；Redis 可用时经 SCAN+Lua 原子清理。
func (s *RedisSessionStore) CleanExpired() error {
	if err := s.local.CleanExpired(); err != nil {
		return err
	}
	if redis := s.redisClient(); redis != nil {
		return s.cleanExpiredInRedis(redis)
	}
	return nil
}

// cleanExpiredInRedis 经 SCAN+Lua 原子删除过期会话。
func (s *RedisSessionStore) cleanExpiredInRedis(redis *goredis.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cursor := uint64(0)
	nowMillis := time.Now().UnixMilli()
	for {
		keys, next, err := redis.Scan(ctx, cursor, accessSessionKeyPrefix+"*", 128).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := accessCleanupScript.Run(ctx, redis, keys, nowMillis).Err(); err != nil {
				return err
			}
		}
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}

// redisOAuthState OAuth state 在 Redis 中的 JSON 序列化形态。
type redisOAuthState struct {
	State        string  `json:"state"`
	CodeVerifier string  `json:"code_verifier"`
	SiteID       float64 `json:"site_id"`
	ProviderID   float64 `json:"provider_id"`
	ReturnURL    string  `json:"return_url"`
	ExpiresAt    int64   `json:"expires_at"` // Unix 毫秒
}

// RedisOAuthStateStore 基于 Redis 的 OAuth state 存储，一次性状态带 TTL。
//
// 失败降级语义与 RedisSessionStore 一致；与 MemoryOAuthStateStore 等价：
// Save 覆盖同名 state（uid 层保证全局唯一），Get 惰性过期，Consume 一次性，
// Delete/CleanExpired 幂等。
type RedisOAuthStateStore struct {
	mu    sync.RWMutex
	redis *goredis.Client
	local *MemoryOAuthStateStore
}

// NewRedisOAuthStateStore 创建 OAuth state 存储。redis 为 nil 时仅内存。
func NewRedisOAuthStateStore(redis *goredis.Client) *RedisOAuthStateStore {
	return &RedisOAuthStateStore{
		redis: redis,
		local: NewMemoryOAuthStateStore(),
	}
}

// SetRedis 注入或清除 Redis 客户端，供运行时热加载切换后端。
func (s *RedisOAuthStateStore) SetRedis(redis *goredis.Client) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.redis = redis
	s.mu.Unlock()
}

func (s *RedisOAuthStateStore) redisClient() *goredis.Client {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.redis
}

/**
 * accessSessionKey 拼装会话 Redis 键。
 *
 * @param token 会话 token。
 * @return Redis 键。
 */
func accessSessionKey(token string) string {
	return accessSessionKeyPrefix + token
}

/**
 * accessOAuthStateKey 拼装 OAuth state Redis 键。
 *
 * @param stateParam state 参数。
 * @return Redis 键。
 */
func accessOAuthStateKey(stateParam string) string {
	return accessOAuthStateKeyPrefix + stateParam
}

// Save 保存 OAuth state。Redis 写入失败时降级到内存实现。
func (s *RedisOAuthStateStore) Save(state *OAuthState) error {
	if state == nil || state.State == "" {
		return fmt.Errorf("invalid oauth state")
	}
	if redis := s.redisClient(); redis != nil {
		if err := s.saveInRedis(redis, state); err != nil {
			return s.local.Save(state)
		}
		return nil
	}
	return s.local.Save(state)
}

// saveInRedis 写出 state JSON 并设置 TTL。
func (s *RedisOAuthStateStore) saveInRedis(redis *goredis.Client, state *OAuthState) error {
	payload, err := json.Marshal(&redisOAuthState{
		State:        state.State,
		CodeVerifier: state.CodeVerifier,
		SiteID:       float64(state.SiteID),
		ProviderID:   float64(state.ProviderID),
		ReturnURL:    state.ReturnURL,
		ExpiresAt:    state.ExpiresAt.UnixMilli(),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), accessRedisOperationTimeout)
	defer cancel()
	return redis.Set(ctx, accessOAuthStateKey(state.State), payload, time.Until(state.ExpiresAt)).Err()
}

// Get 读取 OAuth state。Redis 未命中时回退本地，降级写入的
// state 只存在于本节点。
func (s *RedisOAuthStateStore) Get(stateParam string) (*OAuthState, error) {
	if redis := s.redisClient(); redis != nil {
		st, err := s.getFromRedis(redis, stateParam)
		if err == nil && st == nil {
			return s.local.Get(stateParam)
		}
		return st, err
	}
	return s.local.Get(stateParam)
}

func (s *RedisOAuthStateStore) getFromRedis(redis *goredis.Client, stateParam string) (*OAuthState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), accessRedisOperationTimeout)
	defer cancel()
	raw, err := redis.Get(ctx, accessOAuthStateKey(stateParam)).Bytes()
	if err != nil {
		if err == goredis.Nil {
			return nil, nil
		}
		return nil, err
	}
	st, werr := decodeRedisOAuthState(raw)
	if werr != nil {
		_ = redis.Del(ctx, accessOAuthStateKey(stateParam)).Err()
		return nil, nil
	}
	if time.Now().After(st.ExpiresAt) {
		_ = redis.Del(ctx, accessOAuthStateKey(stateParam)).Err()
		return nil, nil
	}
	return st, nil
}

// Consume 原子地取出并删除 state，一次性语义。Redis 未命中时回退本地
// （降级保存的 state 只存在于本节点）；命令失败时直接返回错误（状态可能
// 已被半消费，二次本地删取会造成双窗口）。
func (s *RedisOAuthStateStore) Consume(stateParam string) (*OAuthState, error) {
	if redis := s.redisClient(); redis != nil {
		st, err := s.consumeFromRedis(redis, stateParam)
		if err == nil && st == nil {
			return s.local.Consume(stateParam)
		}
		return st, err
	}
	return s.local.Consume(stateParam)
}

func (s *RedisOAuthStateStore) consumeFromRedis(redis *goredis.Client, stateParam string) (*OAuthState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), accessRedisOperationTimeout)
	defer cancel()
	key := accessOAuthStateKey(stateParam)
	raw, err := accessTakeScript.Run(ctx, redis, []string{key}).Text()
	if err != nil {
		if err == goredis.Nil {
			// Lua nil 表示键不存在：go-redis 将其映射为 goredis.Nil。
			return nil, nil
		}
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	st, werr := decodeRedisOAuthState([]byte(raw))
	if werr != nil {
		return nil, werr
	}
	if time.Now().After(st.ExpiresAt) {
		return nil, nil
	}
	return st, nil
}

// decodeRedisOAuthState 解析 Redis state JSON。
func decodeRedisOAuthState(raw []byte) (*OAuthState, error) {
	var rs redisOAuthState
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, err
	}
	if rs.SiteID < 0 || rs.SiteID > float64(1<<32) {
		return nil, fmt.Errorf("invalid oauth state site_id %v", rs.SiteID)
	}
	if rs.ProviderID < 0 || rs.ProviderID > float64(1<<32) {
		return nil, fmt.Errorf("invalid oauth state provider_id %v", rs.ProviderID)
	}
	return &OAuthState{
		State:        rs.State,
		CodeVerifier: rs.CodeVerifier,
		SiteID:       uint(rs.SiteID),
		ProviderID:   uint(rs.ProviderID),
		ReturnURL:    rs.ReturnURL,
		ExpiresAt:    time.UnixMilli(rs.ExpiresAt),
	}, nil
}

// Delete 删除 OAuth state，幂等。内存与 Redis 双端都删一次。
func (s *RedisOAuthStateStore) Delete(stateParam string) error {
	var lastErr error
	if err := s.local.Delete(stateParam); err != nil {
		lastErr = err
	}
	if redis := s.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), accessRedisOperationTimeout)
		defer cancel()
		if err := redis.Del(ctx, accessOAuthStateKey(stateParam)).Err(); err != nil && err != goredis.Nil {
			lastErr = err
		}
	}
	return lastErr
}

// CleanExpired 清理过期 state：本地内存始终清理；Redis 可用时经 SCAN+Lua 原子清理。
func (s *RedisOAuthStateStore) CleanExpired() error {
	if err := s.local.CleanExpired(); err != nil {
		return err
	}
	if redis := s.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cursor := uint64(0)
		nowMillis := time.Now().UnixMilli()
		for {
			keys, next, err := redis.Scan(ctx, cursor, accessOAuthStateKeyPrefix+"*", 128).Result()
			if err != nil {
				return err
			}
			if len(keys) > 0 {
				if err := accessCleanupScript.Run(ctx, redis, keys, nowMillis).Err(); err != nil {
					return err
				}
			}
			cursor = next
			if cursor == 0 {
				return nil
			}
		}
	}
	return nil
}

var _ SessionStore = (*RedisSessionStore)(nil)
var _ OAuthStateStore = (*RedisOAuthStateStore)(nil)
