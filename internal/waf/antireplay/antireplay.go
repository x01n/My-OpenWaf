package antireplay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"sync"
	"time"

	"My-OpenWaf/internal/snapshot"
	rueidis "github.com/redis/rueidis"
)

type AntiReplayManager struct {
	secret      []byte
	redisMu     sync.RWMutex
	rdb         rueidis.Client
	ttl         time.Duration
	localMu     sync.Mutex
	spentUntil  map[string]time.Time
	idemRotated map[string]idemEntry
}

type idemEntry struct {
	newNonce string
	expires  time.Time
}

const antiReplayIdemSeconds = 8

const redisNonceLua = `
local spent = redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1])
if spent then
  redis.call('SET', KEYS[2], ARGV[3], 'EX', ARGV[2])
  return {1, ARGV[3]}
end
local idem = redis.call('GET', KEYS[2])
if idem then
  return {2, idem}
end
return {0}
`

var redisNonceScript = rueidis.NewLuaScript(redisNonceLua)

func NewAntiReplayManager(secret string, rdb rueidis.Client, ttl time.Duration) *AntiReplayManager {
	if secret == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secret = base64.RawURLEncoding.EncodeToString(b)
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &AntiReplayManager{secret: []byte(secret), rdb: rdb, ttl: ttl, spentUntil: make(map[string]time.Time, 4096), idemRotated: make(map[string]idemEntry, 1024)}
}

func (m *AntiReplayManager) redisClient() rueidis.Client {
	if m == nil {
		return nil
	}
	m.redisMu.RLock()
	client := m.rdb
	m.redisMu.RUnlock()
	return client
}

func (m *AntiReplayManager) SetRedis(rdb rueidis.Client) {
	if m == nil {
		return
	}
	m.redisMu.Lock()
	m.rdb = rdb
	m.redisMu.Unlock()
}

func (m *AntiReplayManager) GenerateNonce(clientIP string) string {
	now := time.Now().Unix()
	randomBytes := make([]byte, 16)
	_, _ = rand.Read(randomBytes)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(now))
	payload := make([]byte, 0, len(clientIP)+8+16)
	payload = append(payload, []byte(clientIP)...)
	payload = append(payload, tsBuf[:]...)
	payload = append(payload, randomBytes...)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payload)
	sig := mac.Sum(nil)
	nonce := make([]byte, 0, 8+16+32)
	nonce = append(nonce, tsBuf[:]...)
	nonce = append(nonce, randomBytes...)
	nonce = append(nonce, sig...)
	return base64.RawURLEncoding.EncodeToString(nonce)
}

func (m *AntiReplayManager) ValidateAndRotate(nonce string, clientIP string, sessionTTL time.Duration) (bool, bool, string) {
	if sessionTTL <= 0 {
		sessionTTL = m.ttl
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 8+16+32 {
		return false, false, ""
	}
	tsBuf := raw[:8]
	randomBytes := raw[8:24]
	sigGot := raw[24:]
	payload := make([]byte, 0, len(clientIP)+8+16)
	payload = append(payload, []byte(clientIP)...)
	payload = append(payload, tsBuf...)
	payload = append(payload, randomBytes...)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payload)
	sigExpected := mac.Sum(nil)
	if !hmac.Equal(sigGot, sigExpected) {
		return false, false, ""
	}
	ts := int64(binary.BigEndian.Uint64(tsBuf))
	age := time.Since(time.Unix(ts, 0))
	if age > sessionTTL || age < -30*time.Second {
		return false, false, ""
	}
	remaining := sessionTTL - age
	if remaining < time.Second {
		remaining = time.Second
	}
	spentTTL := int(remaining / time.Second)
	if spentTTL < 5 {
		spentTTL = 5
	}
	if spentTTL > snapshot.OneDaySeconds {
		spentTTL = snapshot.OneDaySeconds
	}
	newNonce := m.GenerateNonce(clientIP)
	if redis := m.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		spentKey := "waf:nonce:spent:" + nonce
		idemKey := "waf:nonce:idem:" + nonce
		resp := redisNonceScript.Exec(ctx, redis, []string{spentKey, idemKey}, []string{strconv.Itoa(spentTTL), strconv.Itoa(antiReplayIdemSeconds), newNonce})
		if err := resp.Error(); err != nil {
			return false, true, ""
		}
		arr, err := resp.ToArray()
		if err != nil {
			return false, true, ""
		}
		switch {
		case len(arr) == 1:
			v, err := arr[0].AsInt64()
			if err != nil || !arr[0].IsInt64() || v != 0 {
				return false, true, ""
			}
			return false, true, ""
		case len(arr) == 2:
			v, err := arr[0].AsInt64()
			// 迁移后类型判定与 go-redis 时代的 .(int64) 断言保持一致：
			// 仅接受 RESP 整数（IsInt64），bulk string "1" 视为畸形应答，
			// 统一走 fail-closed，避免类型混淆误放行。
			if err != nil || !arr[0].IsInt64() || (v != 1 && v != 2) {
				return false, true, ""
			}
			s, err := arr[1].ToString()
			if err != nil || !arr[1].IsString() {
				return false, true, ""
			}
			if s == "" {
				return false, true, ""
			}
			return true, false, s
		default:
			return false, true, ""
		}
	}
	return m.validateAndRotateLocal(nonce, newNonce, remaining)
}

func (m *AntiReplayManager) validateAndRotateLocal(presentedNonce, freshNonce string, spentTTL time.Duration) (bool, bool, string) {
	now := time.Now()
	idemTTL := time.Duration(antiReplayIdemSeconds) * time.Second
	m.localMu.Lock()
	defer m.localMu.Unlock()
	if len(m.spentUntil) > 20000 {
		for k, exp := range m.spentUntil {
			if now.After(exp) {
				delete(m.spentUntil, k)
			}
		}
	}
	if len(m.idemRotated) > 5000 {
		for k, e := range m.idemRotated {
			if now.After(e.expires) {
				delete(m.idemRotated, k)
			}
		}
	}
	if e, ok := m.idemRotated[presentedNonce]; ok && now.Before(e.expires) {
		return true, false, e.newNonce
	}
	if exp, ok := m.spentUntil[presentedNonce]; ok {
		if now.After(exp) {
			delete(m.spentUntil, presentedNonce)
		} else {
			return false, true, ""
		}
	}
	m.spentUntil[presentedNonce] = now.Add(spentTTL)
	m.idemRotated[presentedNonce] = idemEntry{newNonce: freshNonce, expires: now.Add(idemTTL)}
	return true, false, freshNonce
}
