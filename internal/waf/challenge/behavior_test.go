package challenge

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

/**
 * TestBehaviorSamplerJSEmitsSafeShape 验证从 Go 生成的盾行为采样脚本是安全的：
 * 它必须包含收集器入口，且不能引用存储、Cookie 或网络 API。
 */
func TestBehaviorSamplerJSEmitsSafeShape(t *testing.T) {
	js := shieldBehaviorSamplerJS()
	if js == "" {
		t.Fatal("shieldBehaviorSamplerJS() is empty")
	}
	for _, want := range []string{
		"__owaf_behavior_sample",
		"pointermove",
		"keydown",
		"keypress",
		"clientX",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("behavior sampler js missing %q: %s", want, js)
		}
	}
	for _, forbidden := range []string{
		"localStorage",
		"document.cookie",
		"XMLHttpRequest",
		"fetch(",
		"navigator.",
	} {
		if strings.Contains(js, forbidden) {
			t.Fatalf("behavior sampler js must not reference %q: %s", forbidden, js)
		}
	}
}

/**
 * TestValidateBehaviorStatsNormal 验证正常人类的采样统计不加分：
 * 有位移、无零间隔、熵充足、速度在人类范围内。
 */
func TestValidateBehaviorStatsNormal(t *testing.T) {
	normal := &BehaviorStats{
		Events:    120,
		Entropy:   3.4,
		ZeroRatio: 0.2,
		Jitter:    0.8,
		MaxSpeed:  14.0,
		ActionKey: 1,
	}
	var reasons []string
	if added := validateBehaviorStats(normal, &reasons); added != 0 {
		t.Fatalf("normal behavior added = %d, want 0; reasons = %v", added, reasons)
	}
}

/**
 * TestValidateBehaviorStatsRobot 验证机器人 rect 采样必须显著加分：
 * 零位移、零间隔与过少事件分别触发对应的原因字段。
 */
func TestValidateBehaviorStatsRobot(t *testing.T) {
	robot := &BehaviorStats{
		Events:    8,
		Entropy:   0.0,
		ZeroRatio: 1.0,
		Jitter:    0.0,
		MaxSpeed:  0.0,
		ActionKey: 0,
	}
	var reasons []string
	added := validateBehaviorStats(robot, &reasons)
	if added < 35 {
		t.Fatalf("robot behavior added = %d, want >= 35; reasons = %v", added, reasons)
	}
	foundZeroJitter := false
	for _, reason := range reasons {
		if strings.Contains(reason, "zero-jitter") {
			foundZeroJitter = true
		}
	}
	if !foundZeroJitter {
		t.Fatalf("robot behavior reasons = %v, want zero-jitter", reasons)
	}

	silent := &BehaviorStats{
		Events:    2,
		Entropy:   0,
		ZeroRatio: 0,
		Jitter:    1,
		MaxSpeed:  0,
		ActionKey: 0,
	}
	reasons = nil
	if added := validateBehaviorStats(silent, &reasons); added < 15 {
		t.Fatalf("silent behavior added = %d, want >= 15; reasons = %v", added, reasons)
	}
}

/**
 * TestValidateBehaviorStatsOverflow 验证非有限值与巨量事件按合成洪水处置：
 * 防御前端无法伪造的 NaN/Infinity 与整数溢出的攻击样本。
 */
func TestValidateBehaviorStatsOverflow(t *testing.T) {
	cases := []*BehaviorStats{
		{Events: 4096, MaxSpeed: 0, Entropy: 1, ZeroRatio: 0.1, Jitter: 1},
		{Events: 1, MaxSpeed: math.NaN(), Entropy: 1, ZeroRatio: 0.1, Jitter: 1},
		{Events: 1, MaxSpeed: math.Inf(1), Entropy: 1, ZeroRatio: 0.1, Jitter: 1},
		{Events: 1, MaxSpeed: -1, Entropy: 1, ZeroRatio: 0.1, Jitter: 1},
		{Events: 1, MaxSpeed: 1, Entropy: -1, ZeroRatio: 0.1, Jitter: 1},
		{Events: 30, MaxSpeed: 1, Entropy: 1, ZeroRatio: 0.1, Jitter: -1},
	}
	for i, b := range cases {
		var reasons []string
		if added := validateBehaviorStats(b, &reasons); added < 40 {
			t.Fatalf("overflow case %d behavior added = %d, want >= 40; reasons = %v", i, added, reasons)
		}
	}
}

/**
 * TestValidateBehaviorStatsOverflow 验证非有限值与巨量事件按合成洪水处置：
 * 防御前端无法伪造的 NaN/Infinity 与整数溢出的攻击样本。
 */
func TestParseEnvFingerprintRejectsInvalidBehavior(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"string events", `{"behavior":{"events":"one","entropy":1,"zero_ratio":0,"jitter":1,"max_speed":1,"action_key":0}}`},
		{"negative events", `{"behavior":{"events":-1,"entropy":1,"zero_ratio":0,"jitter":1,"max_speed":1,"action_key":0}}`},
		{"fractional events", `{"behavior":{"events":3.5,"entropy":1,"zero_ratio":0,"jitter":1,"max_speed":1,"action_key":0}}`},
		{"string entropy", `{"behavior":{"events":1,"entropy":"x","zero_ratio":0,"jitter":1,"max_speed":1,"action_key":0}}`},
		{"negative jitter", `{"behavior":{"events":1,"entropy":1,"zero_ratio":0,"jitter":-0.5,"max_speed":1,"action_key":0}}`},
		{"negative max_speed", `{"behavior":{"events":1,"entropy":1,"zero_ratio":0,"jitter":1,"max_speed":-2,"action_key":0}}`},
		{"negative action_key", `{"behavior":{"events":1,"entropy":1,"zero_ratio":0,"jitter":1,"max_speed":1,"action_key":-3}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseEnvFingerprint(tc.data); got != nil {
				t.Fatalf("ParseEnvFingerprint(%s) = %+v, want nil", tc.data, got)
			}
		})
	}
}

/**
 * TestParsedBehaviorSurvivesAndScoresRoundTrip 验证正常行为统计经过
 * JSON 往返后仍可解析，异常统计在标准严格度下评分超过 50。
 */
func TestParsedBehaviorSurvivesAndScoresRoundTrip(t *testing.T) {
	base := shieldNormalEnvFingerprint()
	base.Behavior = &BehaviorStats{
		Events:    120,
		Entropy:   3.4,
		ZeroRatio: 0.2,
		Jitter:    0.8,
		MaxSpeed:  14.0,
		ActionKey: 1,
	}
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	got := ParseEnvFingerprint(string(data))
	if got == nil || got.Behavior == nil {
		t.Fatalf("ParseEnvFingerprint lost behavior: %s", data)
	}
	if got.Behavior.Events != 120 || got.Behavior.MaxSpeed != 14.0 {
		t.Fatalf("behavior round-trip mismatch: %+v", got.Behavior)
	}

	robot := shieldNormalEnvFingerprint()
	robot.Behavior = &BehaviorStats{
		Events:    30,
		Entropy:   0,
		ZeroRatio: 1,
		Jitter:    0,
		MaxSpeed:  0,
		ActionKey: 0,
	}
	robotData, err := json.Marshal(robot)
	if err != nil {
		t.Fatal(err)
	}
	robotFP := ParseEnvFingerprint(string(robotData))
	if robotFP == nil {
		t.Fatal("robot fingerprint must parse")
	}
	result := ValidateEnvFingerprint(robotFP)
	if result.Score <= 50 {
		t.Fatalf("robot behavior score = %d, want > 50; reasons = %v", result.Score, result.Reasons)
	}
	found := false
	for _, reason := range result.Reasons {
		if strings.Contains(reason, "zero-jitter") {
			found = true
		}
	}
	if !found {
		t.Fatalf("robot behavior reasons = %v, want zero-jitter", result.Reasons)
	}
}
