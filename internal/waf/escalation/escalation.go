package escalation

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"My-OpenWaf/internal/core/action"

	goredis "github.com/redis/go-redis/v9"
)

type EscalationStep struct {
	Threshold int    `json:"threshold"`
	Action    string `json:"action"`
}

type EscalationConfig struct {
	Enabled    bool             `json:"enabled"`
	WindowSecs int              `json:"window_secs"`
	Steps      []EscalationStep `json:"steps"`
}

func DefaultEscalationConfig() EscalationConfig {
	return EscalationConfig{Enabled: false, WindowSecs: 60, Steps: []EscalationStep{{Threshold: 3, Action: "challenge"}, {Threshold: 5, Action: "intercept"}, {Threshold: 10, Action: "block"}}}
}

type localEntry struct {
	count   int64
	expires int64
}

type EscalationManager struct {
	redis       *goredis.Client
	localCache  sync.Map
	defaultCfg  atomic.Value
	cleanupDone chan struct{}
}

func NewEscalationManager(redisClient *goredis.Client) *EscalationManager {
	m := &EscalationManager{redis: redisClient, cleanupDone: make(chan struct{})}
	m.defaultCfg.Store(DefaultEscalationConfig())
	go m.cleanupLoop()
	return m
}

func (m *EscalationManager) SetDefaultConfig(cfg EscalationConfig) { m.defaultCfg.Store(cfg) }
func (m *EscalationManager) DefaultConfig() EscalationConfig {
	return m.defaultCfg.Load().(EscalationConfig)
}
func (m *EscalationManager) Close() { close(m.cleanupDone) }
func redisEscalationKey(ip string, siteID uint) string {
	return fmt.Sprintf("owaf:escalation:%s:%d", ip, siteID)
}
func localEscalationKey(ip string, siteID uint) string { return fmt.Sprintf("%s:%d", ip, siteID) }
func (m *EscalationManager) effectiveCfg(cfg *EscalationConfig) EscalationConfig {
	if cfg != nil && cfg.Enabled {
		return *cfg
	}
	return m.DefaultConfig()
}
func (m *EscalationManager) RecordHit(ip string, siteID uint, cfg *EscalationConfig) {
	ec := m.effectiveCfg(cfg)
	if !ec.Enabled || ec.WindowSecs <= 0 {
		return
	}
	if m.redis != nil {
		if m.recordHitRedis(ip, siteID, ec.WindowSecs) {
			return
		}
	}
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
		return false
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
		m.localCache.Store(key, &localEntry{count: 1, expires: expiry})
		return
	}
	m.localCache.Store(key, &localEntry{count: 1, expires: expiry})
}
func (m *EscalationManager) getCount(ip string, siteID uint) int {
	if m.redis != nil {
		if count, ok := m.getCountRedis(ip, siteID); ok {
			return count
		}
	}
	return m.getCountLocal(ip, siteID)
}
func (m *EscalationManager) getCountRedis(ip string, siteID uint) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	key := redisEscalationKey(ip, siteID)
	val, err := m.redis.Get(ctx, key).Int()
	if err != nil {
		return 0, false
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
func (m *EscalationManager) Evaluate(ip string, siteID uint, cfg *EscalationConfig) string {
	ec := m.effectiveCfg(cfg)
	if !ec.Enabled || len(ec.Steps) == 0 {
		return ""
	}
	count := m.getCount(ip, siteID)
	return resolveAction(count, ec.Steps)
}
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

type IPEscalationStatus struct {
	IP       string `json:"ip"`
	HitCount int    `json:"hit_count"`
	Level    int    `json:"current_step"`
	Action   string `json:"action"`
}

func (m *EscalationManager) GetIPStatus(ip string, siteID uint) IPEscalationStatus {
	count := m.getCount(ip, siteID)
	level, act := m.GetCurrentLevel(ip, siteID)
	return IPEscalationStatus{IP: ip, HitCount: count, Level: level, Action: act}
}
func (m *EscalationManager) ResetIP(ip string, siteID uint) {
	key := fmt.Sprintf("esc:%s:%d", ip, siteID)
	m.localCache.Delete(key)
	if m.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		m.redis.Del(ctx, "owaf:escalation:"+key)
	}
}
func resolveAction(count int, steps []EscalationStep) string {
	act := ""
	for _, step := range steps {
		if count >= step.Threshold {
			act = step.Action
		}
	}
	return act
}
func ActionSeverity(value string) int {
	if value == "block" {
		return action.TerminalPriority(action.Drop)
	}
	return action.TerminalPriority(action.Type(value))
}
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
