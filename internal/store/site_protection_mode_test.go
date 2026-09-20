package store

import "testing"

// boolPtrTest 是测试内建布尔指针的辅助函数，避免每个用例重复定义。
func boolPtrTest(v bool) *bool { return &v }

/**
 * TestApplyProtectionModeOverrides 覆盖站点保护模式的枚举行为，固定以下语义：
 *   - protect → bot/owasp/cve/rate_limit 四组全开，动作分别为
 *     intercept / intercept / rate_limit（CVE 与 OWASP 相同）；
 *   - observe → bot 关闭挡流量、owasp/cve/rate_limit 全开但动作全部 observe；
 *   - 非法枚举 → 不产生任何写入；
 *   - sensitivity 为空时回填 mid，非空时保留原值。
 */
func TestApplyProtectionModeOverrides(t *testing.T) {
	cases := []struct {
		name         string
		level        string
		sensitivity  string
		wantBot      *bool
		wantOWASP    *bool
		wantSens     string
		wantOWASPAct string
		wantCVE      *bool
		wantCVEAct   string
		wantRL       *bool
		wantRLAct    string
	}{
		{
			name:         "protect fills defaults",
			level:        SiteProtectionModeProtect,
			wantBot:      boolPtrTest(true),
			wantOWASP:    boolPtrTest(true),
			wantSens:     "mid",
			wantOWASPAct: string(ActionIntercept),
			wantCVE:      boolPtrTest(true),
			wantCVEAct:   string(ActionIntercept),
			wantRL:       boolPtrTest(true),
			wantRLAct:    string(ActionRateLimit),
		},
		{
			name:         "observe disables bot and downgrades actions",
			level:        SiteProtectionModeObserve,
			wantBot:      boolPtrTest(false),
			wantOWASP:    boolPtrTest(true),
			wantSens:     "mid",
			wantOWASPAct: string(ActionObserve),
			wantCVE:      boolPtrTest(true),
			wantCVEAct:   string(ActionObserve),
			wantRL:       boolPtrTest(true),
			wantRLAct:    string(ActionObserve),
		},
		{
			name:         "protect keeps prefilled sensitivity",
			level:        SiteProtectionModeProtect,
			sensitivity:  "strict",
			wantBot:      boolPtrTest(true),
			wantOWASP:    boolPtrTest(true),
			wantSens:     "strict",
			wantOWASPAct: string(ActionIntercept),
			wantCVE:      boolPtrTest(true),
			wantCVEAct:   string(ActionIntercept),
			wantRL:       boolPtrTest(true),
			wantRLAct:    string(ActionRateLimit),
		},
		{
			name:  "invalid enum writes nothing",
			level: "ultra",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s := &Site{
				AttackProtectionLevel: tt.level,
				OWASPSensitivity:      tt.sensitivity,
			}
			s.ApplyProtectionModeOverrides()

			if !boolPtrEqual(t, "bot", s.BotProtectionEnabled, tt.wantBot) {
				t.Fatalf("bot enabled = %#v, want %#v", s.BotProtectionEnabled, tt.wantBot)
			}
			if !boolPtrEqual(t, "owasp", s.OWASPEnabled, tt.wantOWASP) {
				t.Fatalf("owasp enabled = %#v, want %#v", s.OWASPEnabled, tt.wantOWASP)
			}
			if !boolPtrEqual(t, "cve", s.CVEEnabled, tt.wantCVE) {
				t.Fatalf("cve enabled = %#v, want %#v", s.CVEEnabled, tt.wantCVE)
			}
			if !boolPtrEqual(t, "rate limit", s.RateLimitEnabled, tt.wantRL) {
				t.Fatalf("rate limit enabled = %#v, want %#v", s.RateLimitEnabled, tt.wantRL)
			}
			if s.OWASPSensitivity != tt.wantSens {
				t.Fatalf("owasp sensitivity = %q, want %q", s.OWASPSensitivity, tt.wantSens)
			}
			if s.OWASPAction != tt.wantOWASPAct {
				t.Fatalf("owasp action = %q, want %q", s.OWASPAction, tt.wantOWASPAct)
			}
			if s.CVEAction != tt.wantCVEAct {
				t.Fatalf("cve action = %q, want %q", s.CVEAction, tt.wantCVEAct)
			}
			if s.RateLimitAction != tt.wantRLAct {
				t.Fatalf("rate limit action = %q, want %q", s.RateLimitAction, tt.wantRLAct)
			}
		})
	}
}

// boolPtrEqual 断言两个布尔指针语义相等（nil == nil 为真）。
func boolPtrEqual(t *testing.T, field string, got, want *bool) bool {
	t.Helper()
	if got == nil || want == nil {
		return got == want
	}
	return *got == *want
}
