package waf

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"My-OpenWaf/internal/core/action"

	goredis "github.com/redis/go-redis/v9"
)

// EscalationStep defines one tier of the escalation ladder.
type EscalationStep struct {
	Threshold int    `json:"threshold"` // cumulative hit count within the window
	Action    string `json:"action"`    // challenge / intercept / block (drop)
}

// EscalationConfig holds the full escalation policy.
type EscalationConfig struct {
	Enabled    bool             `json:"enabled"`
	WindowSecs int              `json:"window_secs"` // sliding window duration
	Steps      []EscalationStep `json:"steps"`       // sorted by Threshold ascending
}

// DefaultEscalationConfig returns a sensible default escalation ladder.
func DefaultEscalationConfig() EscalationConfig {
	return EscalationConfig{
		Enabled:    false,
		WindowSecs: 60,
		Steps: []EscalationStep{
			{Threshold: 3, Action: "challenge"}, // 3 hits → JS challenge
			{Threshold: 5, Action: "intercept"}, // 5 hits → 403
			{Threshold: 10, Action: "block"},    // 10 hits → TCP RST
		},
	}
}

// localEntry stores hit counter + expiry for the local fallback cache.
type localEntry struct {
	count   int64
	expires int64 // unix seconds
}

// EscalationManager tracks per-IP hit counts and determines the current
// escalation level. Uses Redis when available, falls back to sync.Map.
type EscalationManager struct {
	redis      *goredis.Client // may be nil
	localCache sync.Map        // key → *localEntry
	defaultCfg atomic.Value    // stores EscalationConfig

	cleanupDone chan struct{}
}

// NewEscalationManager creates a new manager. redisClient may be nil.
func NewEscalationManager(redisClient *goredis.Client) *EscalationManager {
	m := &EscalationManager{
		redis:       redisClient,
		cleanupDone: make(chan struct{}),
	}
	m.defaultCfg.Store(DefaultEscalationConfig())

	// Background cleanup for local cache entries.
	go m.cleanupLoop()
	return m
}

// SetDefaultConfig updates the global default escalation configuration.
func (m *EscalationManager) SetDefaultConfig(cfg EscalationConfig) {
	m.defaultCfg.Store(cfg)
}

// DefaultConfig returns the current default configuration.
func (m *EscalationManager) DefaultConfig() EscalationConfig {
	return m.defaultCfg.Load().(EscalationConfig)
}

// Close stops the background cleanup goroutine.
func (m *EscalationManager) Close() {
	close(m.cleanupDone)
}

// redisKey builds the Redis key for a given IP + site.
func redisEscalationKey(ip string, siteID uint) string {
	return fmt.Sprintf("owaf:escalation:%s:%d", ip, siteID)
}

// localKey builds the local cache key for a given IP + site.
func localEscalationKey(ip string, siteID uint) string {
	return fmt.Sprintf("%s:%d", ip, siteID)
}

// effectiveCfg returns the provided config if non-nil and enabled,
// otherwise the manager's default.
func (m *EscalationManager) effectiveCfg(cfg *EscalationConfig) EscalationConfig {
	if cfg != nil && cfg.Enabled {
		return *cfg
	}
	return m.DefaultConfig()
}

// RecordHit increments the hit counter for the given IP + site.
func (m *EscalationManager) RecordHit(ip string, siteID uint, cfg *EscalationConfig) {
	ec := m.effectiveCfg(cfg)
	if !ec.Enabled || ec.WindowSecs <= 0 {
		return
	}

	// Try Redis first.
	if m.redis != nil {
		if m.recordHitRedis(ip, siteID, ec.WindowSecs) {
			return
		}
	}

	// Fallback to local cache.
	m.recordHitLocal(ip, siteID, ec.WindowSecs)
}

func (m *EscalationManager) recordHitRedis(ip string, siteID uint, windowSecs int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	key := redisEscalationKey(ip, siteID)
	pipe := m.redis.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, time.Duration(windowSecs)*time.Second)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false // Redis unavailable, caller should use local fallback
	}
	_ = incrCmd.Val()
	return true
}

func (m *EscalationManager) recordHitLocal(ip string, siteID uint, windowSecs int) {
	key := localEscalationKey(ip, siteID)
	now := time.Now().Unix()
	expiry := now + int64(windowSecs)

	if val, ok := m.localCache.Load(key); ok {
		entry := val.(*localEntry)
		if entry.expires > now {
			atomic.AddInt64(&entry.count, 1)
			return
		}
		// Expired — reset.
		m.localCache.Store(key, &localEntry{count: 1, expires: expiry})
		return
	}
	m.localCache.Store(key, &localEntry{count: 1, expires: expiry})
}

// getCount returns the current hit count for an IP + site.
func (m *EscalationManager) getCount(ip string, siteID uint) int {
	// Try Redis first.
	if m.redis != nil {
		if count, ok := m.getCountRedis(ip, siteID); ok {
			return count
		}
	}
	// Fallback to local cache.
	return m.getCountLocal(ip, siteID)
}

func (m *EscalationManager) getCountRedis(ip string, siteID uint) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	key := redisEscalationKey(ip, siteID)
	val, err := m.redis.Get(ctx, key).Int()
	if err != nil {
		return 0, false // Redis unavailable or key not found
	}
	return val, true
}

func (m *EscalationManager) getCountLocal(ip string, siteID uint) int {
	key := localEscalationKey(ip, siteID)
	val, ok := m.localCache.Load(key)
	if !ok {
		return 0
	}
	entry := val.(*localEntry)
	if entry.expires <= time.Now().Unix() {
		m.localCache.Delete(key)
		return 0
	}
	return int(atomic.LoadInt64(&entry.count))
}

// Evaluate returns the escalated action string for the current hit count.
// Returns "" if escalation is disabled or count is below all thresholds.
func (m *EscalationManager) Evaluate(ip string, siteID uint, cfg *EscalationConfig) string {
	ec := m.effectiveCfg(cfg)
	if !ec.Enabled || len(ec.Steps) == 0 {
		return ""
	}

	count := m.getCount(ip, siteID)
	return resolveAction(count, ec.Steps)
}

// GetCurrentLevel returns the current escalation level index (0-based) and
// the corresponding action. Returns (-1, "") if no threshold is met.
func (m *EscalationManager) GetCurrentLevel(ip string, siteID uint) (int, string) {
	cfg := m.DefaultConfig()
	if !cfg.Enabled || len(cfg.Steps) == 0 {
		return -1, ""
	}
	count := m.getCount(ip, siteID)
	level := -1
	act := ""
	for i, step := range cfg.Steps {
		if count >= step.Threshold {
			level = i
			act = step.Action
		}
	}
	return level, act
}

// IPEscalationStatus describes the current escalation state of a single IP.
type IPEscalationStatus struct {
	IP       string `json:"ip"`
	HitCount int    `json:"hit_count"`
	Level    int    `json:"current_step"`
	Action   string `json:"action"`
}

// GetIPStatus returns the current escalation state for a given IP.
func (m *EscalationManager) GetIPStatus(ip string, siteID uint) IPEscalationStatus {
	count := m.getCount(ip, siteID)
	level, act := m.GetCurrentLevel(ip, siteID)
	return IPEscalationStatus{
		IP:       ip,
		HitCount: count,
		Level:    level,
		Action:   act,
	}
}

// ResetIP clears escalation state for a given IP.
func (m *EscalationManager) ResetIP(ip string, siteID uint) {
	key := fmt.Sprintf("esc:%s:%d", ip, siteID)
	m.localCache.Delete(key)
	if m.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		m.redis.Del(ctx, "owaf:escalation:"+key)
	}
}

// resolveAction finds the highest step whose threshold is met.
func resolveAction(count int, steps []EscalationStep) string {
	act := ""
	for _, step := range steps {
		if count >= step.Threshold {
			act = step.Action
		}
	}
	return act
}

// ActionSeverity returns a numeric severity for action comparison.
// Higher = more severe.
func ActionSeverity(value string) int {
	if value == "block" {
		return action.TerminalPriority(action.Drop)
	}
	return action.TerminalPriority(action.Type(value))
}

// cleanupLoop periodically removes expired entries from the local cache.
func (m *EscalationManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.cleanupDone:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			m.localCache.Range(func(key, value any) bool {
				entry := value.(*localEntry)
				if entry.expires <= now {
					m.localCache.Delete(key)
				}
				return true
			})
		}
	}
}
