package waf

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

// AntiReplayManager implements nonce-based request replay prevention.
// Nonces are HMAC-SHA256(secret, clientIP + timestamp + random) in base64url.
// Used nonces are tracked in Redis (primary) or a local LRU (fallback).
type AntiReplayManager struct {
	secret []byte
	rdb    *goredis.Client // nil when Redis unavailable
	ttl    time.Duration

	// Local LRU fallback when Redis is unavailable.
	mu       sync.Mutex
	lru      map[string]time.Time // nonce → expiry
	lruOrder []string             // insertion order for eviction
	lruCap   int
}

// NewAntiReplayManager creates a new anti-replay manager.
// rdb may be nil (local LRU only). ttl is the nonce validity window.
func NewAntiReplayManager(secret string, rdb *goredis.Client, ttl time.Duration) *AntiReplayManager {
	if secret == "" {
		// Generate a random secret if none provided.
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secret = base64.RawURLEncoding.EncodeToString(b)
	}
	return &AntiReplayManager{
		secret: []byte(secret),
		rdb:    rdb,
		ttl:    ttl,
		lru:    make(map[string]time.Time, 4096),
		lruCap: 100000, // 100k entries max
	}
}

// GenerateNonce creates a new nonce for the given client IP.
func (m *AntiReplayManager) GenerateNonce(clientIP string) string {
	// payload = clientIP + timestamp(8 bytes) + random(16 bytes)
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

	// nonce = base64url(timestamp[8] + random[16] + hmac[32])
	nonce := make([]byte, 0, 8+16+32)
	nonce = append(nonce, tsBuf[:]...)
	nonce = append(nonce, randomBytes...)
	nonce = append(nonce, sig...)

	return base64.RawURLEncoding.EncodeToString(nonce)
}

// ValidateAndRotate checks a nonce and issues a new one if valid.
// Returns:
//   - valid=true,  isReplay=false, newNonce: nonce is good, rotated
//   - valid=false, isReplay=true,  "":       nonce was already used (replay attack)
//   - valid=false, isReplay=false, "":       nonce is expired or tampered
func (m *AntiReplayManager) ValidateAndRotate(nonce string, clientIP string) (valid bool, isReplay bool, newNonce string) {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 8+16+32 {
		return false, false, ""
	}

	tsBuf := raw[:8]
	randomBytes := raw[8:24]
	sigGot := raw[24:]

	// Reconstruct payload and verify HMAC.
	payload := make([]byte, 0, len(clientIP)+8+16)
	payload = append(payload, []byte(clientIP)...)
	payload = append(payload, tsBuf...)
	payload = append(payload, randomBytes...)

	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payload)
	sigExpected := mac.Sum(nil)

	if !hmac.Equal(sigGot, sigExpected) {
		// Tampered or forged.
		return false, false, ""
	}

	// Check timestamp within TTL.
	ts := int64(binary.BigEndian.Uint64(tsBuf))
	age := time.Since(time.Unix(ts, 0))
	if age > m.ttl || age < -30*time.Second {
		// Expired or clock-skewed.
		return false, false, ""
	}

	// Replay detection: check if nonce was already used.
	replay := m.markUsed(nonce)
	if replay {
		return false, true, ""
	}

	// Valid — rotate to new nonce.
	return true, false, m.GenerateNonce(clientIP)
}

// markUsed attempts to mark a nonce as used. Returns true if it was already used (replay).
func (m *AntiReplayManager) markUsed(nonce string) bool {
	// Try Redis first.
	if m.rdb != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		key := fmt.Sprintf("waf:nonce:%s", nonce)
		// SETNX: returns true if key was set (not a replay).
		set, err := m.rdb.SetNX(ctx, key, "1", m.ttl).Result()
		if err == nil {
			if !set {
				// Key already existed → replay.
				return true
			}
			return false
		}
		// Redis error — fall through to LRU.
	}

	// LRU fallback.
	return m.markUsedLRU(nonce)
}

func (m *AntiReplayManager) markUsedLRU(nonce string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Evict expired entries lazily (batch of up to 64 from front).
	now := time.Now()
	evicted := 0
	for evicted < 64 && len(m.lruOrder) > 0 {
		oldest := m.lruOrder[0]
		if exp, ok := m.lru[oldest]; ok && now.After(exp) {
			delete(m.lru, oldest)
			m.lruOrder = m.lruOrder[1:]
			evicted++
		} else {
			break
		}
	}

	// Check if already used.
	if _, exists := m.lru[nonce]; exists {
		return true // replay
	}

	// Evict oldest if at capacity.
	for len(m.lru) >= m.lruCap && len(m.lruOrder) > 0 {
		oldest := m.lruOrder[0]
		delete(m.lru, oldest)
		m.lruOrder = m.lruOrder[1:]
	}

	// Mark as used.
	m.lru[nonce] = now.Add(m.ttl)
	m.lruOrder = append(m.lruOrder, nonce)
	return false
}

// NonceKey is the cookie name used for anti-replay nonces.
const NonceKey = "__waf_nonce"
