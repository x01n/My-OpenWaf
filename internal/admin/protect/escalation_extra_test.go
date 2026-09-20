package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	wafescalation "My-OpenWaf/internal/waf/escalation"
)

/**
 * invokeEscalationConfigHandlerWithID 复用升级配置 handler，但允许指定任意 :id 路由参数。
 */
func invokeEscalationConfigHandlerWithID(t *testing.T, handler app.HandlerFunc, method, id string, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI("/api/v1/protection/" + id + "/escalation")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: id}}
	handler(context.Background(), ctx)
	return ctx
}

// TestGetEscalationConfigReturnsStoredValues 验证读取接口返回已存储的开关、窗口与步骤。
func TestGetEscalationConfigReturnsStoredValues(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 300
	cfg.SetEscalationSteps([]store.EscalationStepDef{
		{Threshold: 2, Action: "observe"},
		{Threshold: 5, Action: "captcha_challenge"},
	})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeEscalationConfigHandlerWithID(t, GetEscalationConfig(repo), "GET", "global", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got struct {
		EscalationEnabled    bool                      `json:"escalation_enabled"`
		EscalationWindowSecs int                       `json:"escalation_window_secs"`
		EscalationSteps      []store.EscalationStepDef `json:"escalation_steps"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.EscalationEnabled || got.EscalationWindowSecs != 300 {
		t.Fatalf("escalation flags not reflected: %#v", got)
	}
	if len(got.EscalationSteps) != 2 || got.EscalationSteps[1].Action != "captcha_challenge" {
		t.Fatalf("escalation steps not reflected: %#v", got.EscalationSteps)
	}
}

// TestGetEscalationConfigReturnsEmptyStepsArray 验证未配置步骤时返回空数组而非 null。
func TestGetEscalationConfigReturnsEmptyStepsArray(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.EscalationSteps = ""
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeEscalationConfigHandlerWithID(t, GetEscalationConfig(repo), "GET", "global", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got struct {
		EscalationSteps json.RawMessage `json:"escalation_steps"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if string(got.EscalationSteps) != "[]" {
		t.Fatalf("escalation_steps = %s, want []", got.EscalationSteps)
	}
}

// TestEscalationConfigAcceptsNumericSiteID 验证站点级路径参数（数字 id）被接受。
func TestEscalationConfigAcceptsNumericSiteID(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeEscalationConfigHandlerWithID(t, GetEscalationConfig(repo), "GET", "12", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("GET with numeric id: unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	ctx = invokeEscalationConfigHandlerWithID(t, UpdateEscalationConfig(repo, func() error { return nil }), "POST", "12", []byte(`{"escalation_enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("POST with numeric id: unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestEscalationConfigRejectsInvalidID 验证非 global 且非数字的 id 返回 400。
func TestEscalationConfigRejectsInvalidID(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, id := range []string{"notanumber", "", "-1"} {
		ctx := invokeEscalationConfigHandlerWithID(t, GetEscalationConfig(repo), "GET", id, nil)
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("GET id=%q: expected 400, got %d", id, ctx.Response.StatusCode())
		}
		ctx = invokeEscalationConfigHandlerWithID(t, UpdateEscalationConfig(repo, func() error { return nil }), "POST", id, []byte(`{"escalation_enabled":true}`))
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("POST id=%q: expected 400, got %d", id, ctx.Response.StatusCode())
		}
	}
}

// TestUpdateEscalationConfigRejectsInvalidBody 验证请求体非法时返回 400。
func TestUpdateEscalationConfigRejectsInvalidBody(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), []byte(`{"escalation_enabled":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for malformed body, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateEscalationConfigRejectsInvalidSteps 验证步骤阈值、动作与单调性校验。
func TestUpdateEscalationConfigRejectsInvalidSteps(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"zero_threshold", `{"escalation_steps":[{"threshold":0,"action":"observe"}]}`},
		{"negative_threshold", `{"escalation_steps":[{"threshold":-3,"action":"observe"}]}`},
		{"empty_action", `{"escalation_steps":[{"threshold":3,"action":""}]}`},
		{"equal_thresholds", `{"escalation_steps":[{"threshold":3,"action":"observe"},{"threshold":3,"action":"intercept"}]}`},
		{"decreasing_thresholds", `{"escalation_steps":[{"threshold":5,"action":"observe"},{"threshold":2,"action":"intercept"}]}`},
	}
	for _, tc := range cases {
		repo := newSystemSettingsRepoForTest(t)
		cfg := store.DefaultProtectionConfig()
		cfg.SetEscalationSteps([]store.EscalationStepDef{{Threshold: 9, Action: "drop"}})
		if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
			t.Fatalf("%s: seed protection: %v", tc.name, err)
		}

		ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), []byte(tc.body))
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("%s: expected 400, got %d: %s", tc.name, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			continue
		}
		loaded := shared.LoadProtectionConfig(repo)
		steps := loaded.GetEscalationSteps()
		if len(steps) != 1 || steps[0].Threshold != 9 {
			t.Errorf("%s: rejected update must not modify stored steps: %#v", tc.name, steps)
		}
	}
}

// TestUpdateEscalationConfigPreservesDistinctChallengeActions 验证三种挑战动作在升级阶梯中各自保留，
// 不会被折叠成通用的 challenge。
func TestUpdateEscalationConfigPreservesDistinctChallengeActions(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	body := []byte(`{"escalation_steps":[
		{"threshold":1,"action":"captcha_challenge"},
		{"threshold":2,"action":"shield_challenge"},
		{"threshold":3,"action":"chain_challenge"},
		{"threshold":4,"action":"drop"}
	]}`)
	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	steps := loaded.GetEscalationSteps()
	want := []string{"captcha_challenge", "shield_challenge", "chain_challenge", "drop"}
	if len(steps) != len(want) {
		t.Fatalf("stored steps length = %d, want %d: %#v", len(steps), len(want), steps)
	}
	for i, action := range want {
		if steps[i].Action != action {
			t.Errorf("step %d action = %q, want %q", i, steps[i].Action, action)
		}
	}
}

// TestUpdateEscalationConfigReloadFailureReturns500 验证 reload 失败时返回 500，但配置已落库。
func TestUpdateEscalationConfigReloadFailureReturns500(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return errors.New("reload boom") }), []byte(`{"escalation_enabled":true}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 on reload failure, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !shared.LoadProtectionConfig(repo).EscalationEnabled {
		t.Fatal("config should already be saved before reload is attempted")
	}
}

// TestUpdateEscalationConfigPreservesUnrelatedProtectionFields 验证升级配置保存不清空验证码/链式/灵敏度字段。
func TestUpdateEscalationConfigPreservesUnrelatedProtectionFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = true
	cfg.CaptchaType = "rotate"
	cfg.ShieldEnabled = true
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"env","condition":"all"}]`
	cfg.SetCategorySensitivity(map[string]string{"rce": "strict"})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), []byte(`{"escalation_enabled":true,"escalation_window_secs":60}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.CaptchaEnabled || loaded.CaptchaType != "rotate" || !loaded.ShieldEnabled {
		t.Fatalf("escalation update clobbered captcha/shield config: %#v", loaded)
	}
	if !loaded.ChainEnabled || loaded.ChainSteps != cfg.ChainSteps {
		t.Fatalf("escalation update clobbered chain config: %#v", loaded)
	}
	if sens := loaded.GetCategorySensitivity(); sens["rce"] != "strict" {
		t.Fatalf("escalation update clobbered category sensitivity: %#v", sens)
	}
}

// TestEscalationIPStatusRejectsEmptyIP 验证缺失 ip 路由参数时返回 400。
func TestEscalationIPStatusRejectsEmptyIP(t *testing.T) {
	mgr := wafescalation.NewEscalationManager(nil)
	defer mgr.Close()

	ctx := invokeProtectHandler(t, GetEscalationIPStatus(mgr), "GET", "/api/v1/escalation/status/", nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("GetEscalationIPStatus: expected 400 for empty ip, got %d", ctx.Response.StatusCode())
	}

	ctx = invokeProtectHandler(t, ResetEscalationIPStatus(mgr), "POST", "/api/v1/escalation/status//reset", nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("ResetEscalationIPStatus: expected 400 for empty ip, got %d", ctx.Response.StatusCode())
	}
}

// TestEscalationIPStatusRejectsInvalidSiteID 验证 site_id 非数字时返回 400。
func TestEscalationIPStatusRejectsInvalidSiteID(t *testing.T) {
	mgr := wafescalation.NewEscalationManager(nil)
	defer mgr.Close()
	const ip = "203.0.113.77"

	ctx := invokeEscalationStatusHandler(t, GetEscalationIPStatus(mgr), "GET", "/api/v1/escalation/status/"+ip+"?site_id=abc", ip)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("GetEscalationIPStatus: expected 400 for invalid site_id, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	ctx = invokeEscalationStatusHandler(t, ResetEscalationIPStatus(mgr), "POST", "/api/v1/escalation/status/"+ip+"/reset?site_id=abc", ip)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("ResetEscalationIPStatus: expected 400 for invalid site_id, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestEscalationIPStatusWithNilManager 验证管理器未初始化时返回占位状态而不是 500。
func TestEscalationIPStatusWithNilManager(t *testing.T) {
	const ip = "203.0.113.88"

	ctx := invokeEscalationStatusHandler(t, GetEscalationIPStatus(nil), "GET", "/api/v1/escalation/status/"+ip, ip)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["ip"] != ip || got["current_step"] != float64(0) || got["hit_count"] != float64(0) {
		t.Fatalf("unexpected placeholder status: %#v", got)
	}
	if msg, ok := got["message"].(string); !ok || msg == "" {
		t.Fatalf("placeholder status should carry a message: %#v", got)
	}

	ctx = invokeEscalationStatusHandler(t, ResetEscalationIPStatus(nil), "POST", "/api/v1/escalation/status/"+ip+"/reset", ip)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("reset with nil manager: unexpected status %d", ctx.Response.StatusCode())
	}
}

// TestEscalationIPStatusWithoutSiteIDUsesGlobalScope 验证省略 site_id 时按全局作用域查询。
func TestEscalationIPStatusWithoutSiteIDUsesGlobalScope(t *testing.T) {
	mgr := wafescalation.NewEscalationManager(nil)
	defer mgr.Close()
	mgr.SetDefaultConfig(wafescalation.EscalationConfig{
		Enabled:    true,
		WindowSecs: 60,
		Steps:      []wafescalation.EscalationStep{{Threshold: 1, Action: "shield_challenge"}},
	})
	const ip = "203.0.113.99"
	mgr.RecordHit(ip, 0, nil)

	ctx := invokeEscalationStatusHandler(t, GetEscalationIPStatus(mgr), "GET", "/api/v1/escalation/status/"+ip, ip)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["hit_count"] != float64(1) {
		t.Fatalf("hit_count = %#v, want 1", got["hit_count"])
	}
	// 升级阶梯必须保留具体的挑战子类型。
	if got["action"] != "shield_challenge" {
		t.Fatalf("action = %#v, want shield_challenge", got["action"])
	}
}
