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
	"My-OpenWaf/internal/waf/challenge"
)

/**
 * invokeChainSessionHandler 构造带 :id 路由参数的请求上下文并调用 handler。
 */
func invokeChainSessionHandler(t *testing.T, handler app.HandlerFunc, id string) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/chain/sessions/" + id + "/delete")

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: id}}
	handler(context.Background(), ctx)
	return ctx
}

/**
 * newChainManagerForTest 建立仅含 env 步骤的内存链式挑战管理器，避免依赖验证码生成。
 */
func newChainManagerForTest(t *testing.T) *challenge.ChainChallengeManager {
	t.Helper()
	mgr := challenge.NewChainChallengeManager(nil, nil)
	mgr.Reconfigure([]challenge.ChainStepConfig{{Type: challenge.ChainStepEnv, Condition: "all"}}, 4)
	return mgr
}

// TestGetChainConfigReturnsStoredSteps 验证读取接口返回归一化后的链式步骤。
func TestGetChainConfigReturnsStoredSteps(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"env","condition":"all"},{"type":"captcha","condition":"env_score>30","captcha_type":"slide"}]`
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, GetChainConfig(repo), "GET", "/api/v1/chain/config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		ChainEnabled bool               `json:"chain_enabled"`
		ChainSteps   []chainStepPayload `json:"chain_steps"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.ChainEnabled {
		t.Fatal("chain_enabled should be true")
	}
	if len(resp.ChainSteps) != 2 {
		t.Fatalf("chain_steps length = %d, want 2: %#v", len(resp.ChainSteps), resp.ChainSteps)
	}
	if resp.ChainSteps[0].Type != challenge.ChainStepEnv || resp.ChainSteps[0].CaptchaType != "" {
		t.Fatalf("env step must not carry a captcha type: %#v", resp.ChainSteps[0])
	}
	if resp.ChainSteps[1].Type != challenge.ChainStepCaptcha || resp.ChainSteps[1].CaptchaType != challenge.CaptchaTypeSlide {
		t.Fatalf("captcha step lost its captcha type: %#v", resp.ChainSteps[1])
	}
}

// TestGetChainConfigReturnsEmptyArrayForUnsetOrCorruptSteps 验证未配置或损坏的步骤退化为空数组而非 null。
func TestGetChainConfigReturnsEmptyArrayForUnsetOrCorruptSteps(t *testing.T) {
	for _, stored := range []string{"", `not-json`, `[{"type":"shield"}]`} {
		repo := newSystemSettingsRepoForTest(t)
		cfg := store.DefaultProtectionConfig()
		cfg.ChainSteps = stored
		if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
			t.Fatalf("seed protection: %v", err)
		}

		ctx := invokeProtectHandler(t, GetChainConfig(repo), "GET", "/api/v1/chain/config", nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("stored=%q: unexpected status %d", stored, ctx.Response.StatusCode())
		}
		var resp struct {
			ChainSteps json.RawMessage `json:"chain_steps"`
		}
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("stored=%q: decode response: %v", stored, err)
		}
		if string(resp.ChainSteps) != "[]" {
			t.Fatalf("stored=%q: chain_steps = %s, want []", stored, resp.ChainSteps)
		}
	}
}

// TestNormalizedChainStepsJSONFallsBackToEmptyArray 验证归一化辅助函数的兜底分支。
func TestNormalizedChainStepsJSONFallsBackToEmptyArray(t *testing.T) {
	for _, raw := range []string{"", "null", "not-json", `[{"type":"unknown"}]`, `{"type":"env"}`} {
		if got := string(normalizedChainStepsJSON(raw)); got != "[]" {
			t.Errorf("normalizedChainStepsJSON(%q) = %s, want []", raw, got)
		}
	}
}

// TestNormalizeChainStepConditionRejectsUnknownValues 验证仅允许既定条件表达式，其余归零。
func TestNormalizeChainStepConditionRejectsUnknownValues(t *testing.T) {
	allowed := []string{"", "all", "env_score>30", "env_score<30", "score>50", "score>80"}
	for _, cond := range allowed {
		if got := normalizeChainStepCondition(cond); got != cond {
			t.Errorf("normalizeChainStepCondition(%q) = %q, want %q", cond, got, cond)
		}
	}
	for _, cond := range []string{"score>10", "ALL", "env_score>=30", "1=1", "drop"} {
		if got := normalizeChainStepCondition(cond); got != "" {
			t.Errorf("normalizeChainStepCondition(%q) = %q, want empty", cond, got)
		}
	}
}

// TestNormalizeChainStepPayloadFallsBackToMatchField 验证 match 字段在 condition 缺失时被采用。
func TestNormalizeChainStepPayloadFallsBackToMatchField(t *testing.T) {
	got, ok := normalizeChainStepPayload(json.RawMessage(`[{"type":"env","match":"env_score>30"}]`))
	if !ok {
		t.Fatal("normalizeChainStepPayload() rejected a valid match-based step")
	}
	var steps []chainStepPayload
	if err := json.Unmarshal([]byte(got), &steps); err != nil {
		t.Fatalf("decode normalized steps: %v", err)
	}
	if len(steps) != 1 || steps[0].Condition != "env_score>30" {
		t.Fatalf("match field was not promoted to condition: %#v", steps)
	}
}

// TestNormalizeChainStepPayloadHandlesEmptyInput 验证空输入与 null 返回空字符串且视为成功。
func TestNormalizeChainStepPayloadHandlesEmptyInput(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null")} {
		got, ok := normalizeChainStepPayload(raw)
		if !ok || got != "" {
			t.Fatalf("normalizeChainStepPayload(%s) = (%q,%v), want (\"\",true)", raw, got, ok)
		}
	}
}

// TestUpdateChainConfigRejectsInvalidBody 验证请求体非法时返回 400。
func TestUpdateChainConfigRejectsInvalidBody(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateChainConfig(repo, func() error { return nil }), "POST", "/api/v1/chain/config", []byte(`{"chain_enabled":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for malformed body, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateChainConfigRejectsUnsupportedStepType 验证未知步骤类型返回 400 且不写入配置。
func TestUpdateChainConfigRejectsUnsupportedStepType(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ChainSteps = `[{"type":"env","condition":"all"}]`
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateChainConfig(repo, func() error { return nil }), "POST", "/api/v1/chain/config", []byte(`{"chain_steps":[{"type":"shield_challenge"}]}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for unsupported step type, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if loaded := shared.LoadProtectionConfig(repo); loaded.ChainSteps != cfg.ChainSteps {
		t.Fatalf("rejected update must not modify stored chain steps, got %s", loaded.ChainSteps)
	}
}

// TestUpdateChainConfigStripsCaptchaTypeFromNonCaptchaSteps 验证挑战语义不被混淆：
// 只有 captcha 步骤保留 captcha_type，env/pow 步骤的该字段被清空。
func TestUpdateChainConfigStripsCaptchaTypeFromNonCaptchaSteps(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	body := []byte(`{"chain_steps":[{"type":"env","captcha_type":"rotate"},{"type":"pow","captcha_type":"click"},{"type":"captcha","captcha_type":"rotate"}]}`)
	ctx := invokeProtectHandler(t, UpdateChainConfig(repo, func() error { return nil }), "POST", "/api/v1/chain/config", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var steps []chainStepPayload
	if err := json.Unmarshal([]byte(shared.LoadProtectionConfig(repo).ChainSteps), &steps); err != nil {
		t.Fatalf("decode stored chain steps: %v", err)
	}
	if len(steps) != 3 {
		t.Fatalf("stored steps length = %d, want 3: %#v", len(steps), steps)
	}
	if steps[0].Type != challenge.ChainStepEnv || steps[0].CaptchaType != "" {
		t.Fatalf("env step should drop captcha_type: %#v", steps[0])
	}
	if steps[1].Type != challenge.ChainStepPoW || steps[1].CaptchaType != "" {
		t.Fatalf("pow step should drop captcha_type: %#v", steps[1])
	}
	if steps[2].Type != challenge.ChainStepCaptcha || steps[2].CaptchaType != challenge.CaptchaTypeRotate {
		t.Fatalf("captcha step should keep captcha_type: %#v", steps[2])
	}
}

// TestUpdateChainConfigNullStepsPreservesStored 验证 chain_steps 显式为 null 时不覆盖已存储步骤。
func TestUpdateChainConfigNullStepsPreservesStored(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ChainEnabled = false
	cfg.ChainSteps = `[{"type":"pow","condition":"all"}]`
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateChainConfig(repo, func() error { return nil }), "POST", "/api/v1/chain/config", []byte(`{"chain_enabled":true,"chain_steps":null}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.ChainEnabled {
		t.Fatal("chain_enabled=true was not persisted")
	}
	if loaded.ChainSteps != cfg.ChainSteps {
		t.Fatalf("null chain_steps should preserve stored steps, got %s", loaded.ChainSteps)
	}
}

// TestUpdateChainConfigReloadFailureReturns500 验证 reload 失败时返回 500，但配置已落库。
func TestUpdateChainConfigReloadFailureReturns500(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateChainConfig(repo, func() error { return errors.New("reload boom") }), "POST", "/api/v1/chain/config", []byte(`{"chain_enabled":true}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 on reload failure, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !shared.LoadProtectionConfig(repo).ChainEnabled {
		t.Fatal("config should already be saved before reload is attempted")
	}
}

// TestUpdateChainConfigPreservesUnrelatedProtectionFields 验证链式配置保存不会清空其他防护字段。
func TestUpdateChainConfigPreservesUnrelatedProtectionFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = true
	cfg.ShieldEnabled = true
	cfg.ShieldDifficulty = 6
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 111
	cfg.SetCategorySensitivity(map[string]string{"sqli": "strict"})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateChainConfig(repo, func() error { return nil }), "POST", "/api/v1/chain/config", []byte(`{"chain_enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.CaptchaEnabled || !loaded.ShieldEnabled || loaded.ShieldDifficulty != 6 {
		t.Fatalf("chain update clobbered captcha/shield fields: %#v", loaded)
	}
	if !loaded.EscalationEnabled || loaded.EscalationWindowSecs != 111 {
		t.Fatalf("chain update clobbered escalation fields: %#v", loaded)
	}
	if sens := loaded.GetCategorySensitivity(); sens["sqli"] != "strict" {
		t.Fatalf("chain update clobbered category sensitivity: %#v", sens)
	}
}

// TestListChainSessionsWithNilManager 验证管理器缺失时返回空列表而不是 500。
func TestListChainSessionsWithNilManager(t *testing.T) {
	ctx := invokeProtectHandler(t, ListChainSessions(nil), "GET", "/api/v1/chain/sessions", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []challenge.ChainSessionInfo `json:"items"`
		Total int                          `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 0 || len(resp.Items) != 0 {
		t.Fatalf("nil manager should yield an empty session list: %#v", resp)
	}
}

// TestListChainSessionsReturnsActiveSessions 验证活跃会话被列出且携带原始 URL。
func TestListChainSessionsReturnsActiveSessions(t *testing.T) {
	mgr := newChainManagerForTest(t)
	sid, _ := mgr.StartChain("https://example.com/protected")

	ctx := invokeProtectHandler(t, ListChainSessions(mgr), "GET", "/api/v1/chain/sessions", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []challenge.ChainSessionInfo `json:"items"`
		Total int                          `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected exactly one session, got %#v", resp)
	}
	if resp.Items[0].ID != sid {
		t.Fatalf("session id = %q, want %q", resp.Items[0].ID, sid)
	}
	if resp.Items[0].OriginalURL != "https://example.com/protected" {
		t.Fatalf("original URL not preserved: %#v", resp.Items[0])
	}
}

// TestDeleteChainSessionRejectsEmptyID 验证空 id 返回 400。
func TestDeleteChainSessionRejectsEmptyID(t *testing.T) {
	mgr := newChainManagerForTest(t)
	ctx := invokeChainSessionHandler(t, DeleteChainSession(mgr), "")
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for empty id, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestDeleteChainSessionUnknownIDReturns404 验证未知会话与管理器缺失都返回 404。
func TestDeleteChainSessionUnknownIDReturns404(t *testing.T) {
	mgr := newChainManagerForTest(t)
	ctx := invokeChainSessionHandler(t, DeleteChainSession(mgr), "no-such-session")
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 for unknown session, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	ctx = invokeChainSessionHandler(t, DeleteChainSession(nil), "any-session")
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 when manager is nil, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestDeleteChainSessionRemovesSession 验证删除后会话不再出现在列表中。
func TestDeleteChainSessionRemovesSession(t *testing.T) {
	mgr := newChainManagerForTest(t)
	sid, _ := mgr.StartChain("https://example.com/protected")

	ctx := invokeChainSessionHandler(t, DeleteChainSession(mgr), sid)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if sessions := mgr.ListSessions(); len(sessions) != 0 {
		t.Fatalf("session was not removed: %#v", sessions)
	}

	// 重复删除同一会话应返回 404。
	ctx = invokeChainSessionHandler(t, DeleteChainSession(mgr), sid)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("expected 404 on repeated delete, got %d", ctx.Response.StatusCode())
	}
}
