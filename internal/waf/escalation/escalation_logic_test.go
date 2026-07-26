package escalation

import (
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// ---- resolveAction（纯函数） ----

func TestResolveActionEmptySteps(t *testing.T) {
	if got := resolveAction(5, nil); got != "" {
		t.Fatalf("empty steps: want \"\", got %q", got)
	}
}

func TestResolveActionBelowAllThresholds(t *testing.T) {
	steps := []EscalationStep{{Threshold: 3, Action: "challenge"}, {Threshold: 5, Action: "intercept"}}
	if got := resolveAction(2, steps); got != "" {
		t.Fatalf("count < all thresholds: want \"\", got %q", got)
	}
}

func TestResolveActionExactThreshold(t *testing.T) {
	steps := []EscalationStep{{Threshold: 3, Action: "challenge"}}
	if got := resolveAction(3, steps); got != "challenge" {
		t.Fatalf("exact threshold: want \"challenge\", got %q", got)
	}
}

func TestResolveActionMultiStepReturnsHighest(t *testing.T) {
	steps := []EscalationStep{
		{Threshold: 3, Action: "challenge"},
		{Threshold: 5, Action: "intercept"},
		{Threshold: 10, Action: "block"},
	}
	if got := resolveAction(7, steps); got != "intercept" {
		t.Fatalf("count=7: want \"intercept\", got %q", got)
	}
	if got := resolveAction(12, steps); got != "block" {
		t.Fatalf("count=12: want \"block\", got %q", got)
	}
}

// ---- effectiveCfg ----

func TestEffectiveCfgNilUsesDefault(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	def := EscalationConfig{Enabled: true, WindowSecs: 120, Steps: []EscalationStep{{Threshold: 1, Action: "challenge"}}}
	m.SetDefaultConfig(def)

	got := m.effectiveCfg(nil)
	if got.WindowSecs != 120 {
		t.Fatalf("nil cfg: want default WindowSecs=120, got %d", got.WindowSecs)
	}
}

func TestEffectiveCfgDisabledUsesDefault(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	def := EscalationConfig{Enabled: true, WindowSecs: 99, Steps: nil}
	m.SetDefaultConfig(def)

	override := &EscalationConfig{Enabled: false, WindowSecs: 10}
	got := m.effectiveCfg(override)
	if got.WindowSecs != 99 {
		t.Fatalf("disabled cfg: want default WindowSecs=99, got %d", got.WindowSecs)
	}
}

func TestEffectiveCfgEnabledOverrideWins(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	override := &EscalationConfig{Enabled: true, WindowSecs: 77, Steps: []EscalationStep{{Threshold: 1, Action: "intercept"}}}
	got := m.effectiveCfg(override)
	if got.WindowSecs != 77 {
		t.Fatalf("enabled override: want WindowSecs=77, got %d", got.WindowSecs)
	}
}

// ---- RecordHit + getCountLocal ----

func TestRecordHitDisabledDoesNotCount(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	m.SetDefaultConfig(EscalationConfig{Enabled: false, WindowSecs: 60, Steps: nil})

	m.RecordHit("1.2.3.4", 1, nil)
	if c := m.getCountLocal("1.2.3.4", 1); c != 0 {
		t.Fatalf("disabled: want count=0, got %d", c)
	}
}

func TestRecordHitAccumulatesCount(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	cfg := EscalationConfig{Enabled: true, WindowSecs: 60, Steps: []EscalationStep{{Threshold: 1, Action: "challenge"}}}
	m.SetDefaultConfig(cfg)

	const ip = "10.0.0.1"
	for i := 0; i < 5; i++ {
		m.RecordHit(ip, 1, nil)
	}
	if c := m.getCountLocal(ip, 1); c != 5 {
		t.Fatalf("want count=5, got %d", c)
	}
}

func TestGetCountLocalExpiredEntryReturnsZero(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	const ip = "10.0.0.2"
	key := localEscalationKey(ip, 0)
	// 直接写入一个已过期的条目
	m.localCache.Store(key, &localEntry{count: 3, expires: time.Now().Unix() - 1})

	if c := m.getCountLocal(ip, 0); c != 0 {
		t.Fatalf("expired entry: want 0, got %d", c)
	}
	// 过期后应已从缓存中删除
	if _, ok := m.localCache.Load(key); ok {
		t.Fatal("expired entry should have been deleted from cache")
	}
}

// ---- Evaluate ----

func TestEvaluateDisabledReturnsEmpty(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	m.SetDefaultConfig(EscalationConfig{Enabled: false, WindowSecs: 60, Steps: []EscalationStep{{Threshold: 1, Action: "challenge"}}})
	if got := m.Evaluate("1.1.1.1", 0, nil); got != "" {
		t.Fatalf("disabled: want \"\", got %q", got)
	}
}

func TestEvaluateNoStepsReturnsEmpty(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	m.SetDefaultConfig(EscalationConfig{Enabled: true, WindowSecs: 60, Steps: nil})
	m.RecordHit("2.2.2.2", 0, nil)
	if got := m.Evaluate("2.2.2.2", 0, nil); got != "" {
		t.Fatalf("no steps: want \"\", got %q", got)
	}
}

func TestEvaluateReturnsCorrectAction(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	cfg := EscalationConfig{
		Enabled:    true,
		WindowSecs: 60,
		Steps: []EscalationStep{
			{Threshold: 2, Action: "challenge"},
			{Threshold: 5, Action: "intercept"},
		},
	}
	m.SetDefaultConfig(cfg)

	const ip = "3.3.3.3"
	// 1次命中：低于所有阈值
	m.RecordHit(ip, 0, nil)
	if got := m.Evaluate(ip, 0, nil); got != "" {
		t.Fatalf("count=1: want \"\", got %q", got)
	}

	// 再命中1次到达 threshold=2
	m.RecordHit(ip, 0, nil)
	if got := m.Evaluate(ip, 0, nil); got != "challenge" {
		t.Fatalf("count=2: want \"challenge\", got %q", got)
	}

	// 再命中3次到达 threshold=5
	for i := 0; i < 3; i++ {
		m.RecordHit(ip, 0, nil)
	}
	if got := m.Evaluate(ip, 0, nil); got != "intercept" {
		t.Fatalf("count=5: want \"intercept\", got %q", got)
	}
}

// ---- GetCurrentLevel ----

func TestGetCurrentLevelDisabledReturnsNegative(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	m.SetDefaultConfig(EscalationConfig{Enabled: false, WindowSecs: 60, Steps: []EscalationStep{{Threshold: 1, Action: "challenge"}}})
	level, act := m.GetCurrentLevel("5.5.5.5", 0)
	if level != -1 || act != "" {
		t.Fatalf("disabled: want level=-1 act=\"\", got level=%d act=%q", level, act)
	}
}

func TestGetCurrentLevelMultiStep(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	m.SetDefaultConfig(EscalationConfig{
		Enabled:    true,
		WindowSecs: 60,
		Steps: []EscalationStep{
			{Threshold: 2, Action: "challenge"},
			{Threshold: 4, Action: "intercept"},
		},
	})

	const ip = "4.4.4.4"
	for i := 0; i < 4; i++ {
		m.RecordHit(ip, 0, nil)
	}
	level, act := m.GetCurrentLevel(ip, 0)
	if level != 1 || act != "intercept" {
		t.Fatalf("count=4: want level=1 act=\"intercept\", got level=%d act=%q", level, act)
	}
}

// ---- ActionSeverity ----

func TestActionSeverityBlock(t *testing.T) {
	// "block" 映射到 Drop 优先级（90）
	if s := ActionSeverity("block"); s != 90 {
		t.Fatalf("block: want 90, got %d", s)
	}
}

func TestActionSeverityIntercept(t *testing.T) {
	// intercept 优先级为 80
	if s := ActionSeverity("intercept"); s != 80 {
		t.Fatalf("intercept: want 80, got %d", s)
	}
}

func TestActionSeverityChallenge(t *testing.T) {
	// challenge 系列优先级为 60
	if s := ActionSeverity("challenge"); s != 60 {
		t.Fatalf("challenge: want 60, got %d", s)
	}
}

// ---- SetRedis nil 安全 ----

func TestSetRedisOnNilManagerNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SetRedis on nil manager panicked: %v", r)
		}
	}()
	var m *EscalationManager
	m.SetRedis(nil)
}

// ---- Key 生成函数 ----

func TestRedisEscalationKeyFormat(t *testing.T) {
	got := redisEscalationKey("1.2.3.4", 42)
	want := "owaf:escalation:1.2.3.4:42"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestLocalEscalationKeyFormat(t *testing.T) {
	got := localEscalationKey("1.2.3.4", 42)
	want := "1.2.3.4:42"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

// ---- DefaultEscalationConfig ----

func TestDefaultEscalationConfigValues(t *testing.T) {
	cfg := DefaultEscalationConfig()
	if cfg.Enabled {
		t.Fatal("default config should be disabled")
	}
	if cfg.WindowSecs != 60 {
		t.Fatalf("default WindowSecs: want 60, got %d", cfg.WindowSecs)
	}
	if len(cfg.Steps) != 3 {
		t.Fatalf("default steps: want 3, got %d", len(cfg.Steps))
	}
}

// ---- GetIPStatus ----

func TestGetIPStatusReflectsRecordedHits(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	m.SetDefaultConfig(EscalationConfig{
		Enabled:    true,
		WindowSecs: 60,
		Steps:      []EscalationStep{{Threshold: 3, Action: "challenge"}},
	})

	const ip = "6.6.6.6"
	m.RecordHit(ip, 0, nil)
	m.RecordHit(ip, 0, nil)
	m.RecordHit(ip, 0, nil)

	status := m.GetIPStatus(ip, 0)
	if status.HitCount != 3 {
		t.Fatalf("want HitCount=3, got %d", status.HitCount)
	}
	if status.Action != "challenge" {
		t.Fatalf("want Action=\"challenge\", got %q", status.Action)
	}
	if status.IP != ip {
		t.Fatalf("want IP=%q, got %q", ip, status.IP)
	}
}

// ---- 不同 siteID 隔离 ----

func TestRecordHitIsolatedBySiteID(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	m.SetDefaultConfig(EscalationConfig{Enabled: true, WindowSecs: 60, Steps: []EscalationStep{{Threshold: 1, Action: "challenge"}}})

	const ip = "7.7.7.7"
	m.RecordHit(ip, 1, nil)
	m.RecordHit(ip, 1, nil)

	if c := m.getCountLocal(ip, 1); c != 2 {
		t.Fatalf("site=1 want count=2, got %d", c)
	}
	if c := m.getCountLocal(ip, 2); c != 0 {
		t.Fatalf("site=2 want count=0, got %d", c)
	}
}

func TestDefaultConfigReflectsSetDefaultConfig(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	custom := EscalationConfig{Enabled: true, WindowSecs: 99, Steps: []EscalationStep{{Threshold: 5, Action: "intercept"}}}
	m.SetDefaultConfig(custom)
	got := m.DefaultConfig()
	if got.WindowSecs != 99 {
		t.Fatalf("DefaultConfig() WindowSecs = %d, want 99", got.WindowSecs)
	}
	if !got.Enabled {
		t.Error("DefaultConfig() Enabled should be true")
	}
}

func TestSetRedisUpdatesRedisClient(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	if m.redisClient() != nil {
		t.Fatal("initial redisClient should be nil")
	}

	fakeClient := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer fakeClient.Close()

	m.SetRedis(fakeClient)
	if m.redisClient() == nil {
		t.Error("redisClient() should not be nil after SetRedis(non-nil)")
	}
	m.SetRedis(nil)
	if m.redisClient() != nil {
		t.Error("redisClient() should be nil after SetRedis(nil)")
	}
}

func TestRecordHitWindowExpiredResets(t *testing.T) {
	m := NewEscalationManager(nil)
	defer m.Close()

	const ip = "8.8.8.8"
	key := localEscalationKey(ip, 0)
	// 写入一个刚好过期的条目
	m.localCache.Store(key, &localEntry{count: 99, expires: time.Now().Unix() - 1})

	m.SetDefaultConfig(EscalationConfig{Enabled: true, WindowSecs: 60, Steps: []EscalationStep{{Threshold: 1, Action: "challenge"}}})
	m.RecordHit(ip, 0, nil) // 应覆盖过期条目

	if c := m.getCountLocal(ip, 0); c != 1 {
		t.Fatalf("after RecordHit over expired entry: want count=1, got %d", c)
	}
}
