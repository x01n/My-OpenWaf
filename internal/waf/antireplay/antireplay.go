package antireplay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

type AntiReplayManager struct {
	secret      []byte
	redisMu     sync.RWMutex
	rdb         *goredis.Client
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

func NewAntiReplayManager(secret string, rdb *goredis.Client, ttl time.Duration) *AntiReplayManager {
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

func (m *AntiReplayManager) redisClient() *goredis.Client {
	if m == nil {
		return nil
	}
	m.redisMu.RLock()
	client := m.rdb
	m.redisMu.RUnlock()
	return client
}

func (m *AntiReplayManager) SetRedis(rdb *goredis.Client) {
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
	if spentTTL > 86400 {
		spentTTL = 86400
	}
	newNonce := m.GenerateNonce(clientIP)
	if redis := m.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		spentKey := fmt.Sprintf("waf:nonce:spent:%s", nonce)
		idemKey := fmt.Sprintf("waf:nonce:idem:%s", nonce)
		res, err := redis.Eval(ctx, redisNonceLua, []string{spentKey, idemKey}, spentTTL, antiReplayIdemSeconds, newNonce).Result()
		if err == nil {
			switch arr := res.(type) {
			case []any:
				if len(arr) == 0 {
					return false, true, ""
				}
				switch v := arr[0].(type) {
				case int64:
					if v == 1 && len(arr) >= 2 {
						if s, ok := arr[1].(string); ok {
							return true, false, s
						}
						return true, false, newNonce
					}
					if v == 2 && len(arr) >= 2 {
						if s, ok := arr[1].(string); ok && s != "" {
							return true, false, s
						}
					}
					if v == 0 {
						return false, true, ""
					}
				}
			}
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
