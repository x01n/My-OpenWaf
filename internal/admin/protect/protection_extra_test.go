package protect

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
)

// TestPutProtectionSettingsRejectsInvalidBody 验证请求体非法时返回 400。
func TestPutProtectionSettingsRejectsInvalidBody(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, body := range [][]byte{
		[]byte(`{"cve_enabled":`),
		[]byte(`[1,2,3]`),
		[]byte(`"plain string"`),
	} {
		ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("body=%s: expected 400, got %d: %s", body, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

// TestPutProtectionSettingsWritesAllActionFields 验证五个动作字段都被 setProtectionActionField 正确写回。
func TestPutProtectionSettingsWritesAllActionFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := shared.SaveProtectionConfig(repo, store.DefaultProtectionConfig()); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{
		"request_ratelimit_action":"drop",
		"error_ratelimit_action":"observe",
		"builtin_owasp_on_hit":"captcha_challenge",
		"cve_action":"shield_challenge",
		"auto_ban_action":"chain_challenge"
	}`)
	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.RequestRateLimitAction != "drop" {
		t.Errorf("RequestRateLimitAction = %q, want drop", loaded.RequestRateLimitAction)
	}
	if loaded.ErrorRateLimitAction != "observe" {
		t.Errorf("ErrorRateLimitAction = %q, want observe", loaded.ErrorRateLimitAction)
	}
	// 挑战动作必须保留各自子类型，不能被折叠为通用的 challenge。
	if loaded.OWASPAction != "captcha_challenge" {
		t.Errorf("OWASPAction = %q, want captcha_challenge", loaded.OWASPAction)
	}
	if loaded.CVEAction != "shield_challenge" {
		t.Errorf("CVEAction = %q, want shield_challenge", loaded.CVEAction)
	}
	if loaded.AutoBanAction != "chain_challenge" {
		t.Errorf("AutoBanAction = %q, want chain_challenge", loaded.AutoBanAction)
	}
}

// TestPutProtectionSettingsNormalizesLegacyActions 验证 block/log_only 归一化为 intercept/observe。
func TestPutProtectionSettingsNormalizesLegacyActions(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := shared.SaveProtectionConfig(repo, store.DefaultProtectionConfig()); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{"builtin_owasp_on_hit":"block","cve_action":"log_only"}`)
	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.OWASPAction != "intercept" {
		t.Errorf("legacy block should normalize to intercept, got %q", loaded.OWASPAction)
	}
	if loaded.CVEAction != "observe" {
		t.Errorf("legacy log_only should normalize to observe, got %q", loaded.CVEAction)
	}
}

// TestPutProtectionSettingsRejectsInvalidActionPerField 验证每个动作字段都会独立拒绝非法动作。
func TestPutProtectionSettingsRejectsInvalidActionPerField(t *testing.T) {
	fields := []string{
		"request_ratelimit_action",
		"error_ratelimit_action",
		"builtin_owasp_on_hit",
		"cve_action",
		"auto_ban_action",
	}
	// redirect 缺少跳转目标、allow/tag 不是有效的命中动作。
	for _, field := range fields {
		for _, invalid := range []string{"redirect", "allow", "tag", "not_an_action"} {
			repo := newSystemSettingsRepoForTest(t)
			if err := shared.SaveProtectionConfig(repo, store.DefaultProtectionConfig()); err != nil {
				t.Fatalf("seed protection: %v", err)
			}
			body := []byte(`{"` + field + `":"` + invalid + `"}`)
			ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", body)
			if ctx.Response.StatusCode() != 400 {
				t.Errorf("%s=%q: expected 400, got %d: %s", field, invalid, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
		}
	}
}

// TestPutProtectionSettingsValidatesStoredActionWhenEnableFlagIsSent 验证仅提交启用开关时，
// 仍会校验库里已存的动作值。
func TestPutProtectionSettingsValidatesStoredActionWhenEnableFlagIsSent(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = false
	cfg.CVEAction = "allow"
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"cve_enabled":true}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 when enabling a phase whose stored action is invalid, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestPutProtectionSettingsSkipsValidationForEmptyStoredAction 验证动作为空时跳过校验。
func TestPutProtectionSettingsSkipsValidationForEmptyStoredAction(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = false
	cfg.CVEAction = ""
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"cve_enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !shared.LoadProtectionConfig(repo).CVEEnabled {
		t.Fatal("cve_enabled=true was not persisted")
	}
}

// TestPutProtectionSettingsSkipsValidationWhenPhaseStaysDisabled 验证未启用且未提交动作字段时不做校验。
func TestPutProtectionSettingsSkipsValidationWhenPhaseStaysDisabled(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = false
	cfg.CVEAction = "allow"
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"login_max_attempts":9}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if shared.LoadProtectionConfig(repo).LoginMaxAttempts != 9 {
		t.Fatal("login_max_attempts was not persisted")
	}
}

// TestValidateCCRuleActions 验证 CC 规则动作校验的各分支。
func TestValidateCCRuleActions(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"empty", "", true},
		{"whitespace", "   ", true},
		{"empty_array", "[]", true},
		{"blank_action", `[{"action":""}]`, true},
		{"captcha_alias", `[{"action":"captcha"}]`, true},
		{"captcha_alias_mixed_case", `[{"action":" CAPTCHA "}]`, true},
		{"intercept", `[{"action":"intercept"}]`, true},
		{"drop", `[{"action":"drop"}]`, true},
		{"captcha_challenge", `[{"action":"captcha_challenge"}]`, true},
		{"shield_challenge", `[{"action":"shield_challenge"}]`, true},
		{"chain_challenge", `[{"action":"chain_challenge"}]`, true},
		{"legacy_block", `[{"action":"block"}]`, true},
		{"redirect", `[{"action":"redirect"}]`, false},
		{"allow", `[{"action":"allow"}]`, false},
		{"unknown", `[{"action":"explode"}]`, false},
		{"malformed_json", `not-json`, false},
		{"object_not_array", `{"action":"drop"}`, false},
		{"second_rule_invalid", `[{"action":"drop"},{"action":"redirect"}]`, false},
	}
	for _, tc := range cases {
		if got := validateCCRuleActions(tc.raw); got != tc.want {
			t.Errorf("%s: validateCCRuleActions(%q) = %v, want %v", tc.name, tc.raw, got, tc.want)
		}
	}
}

// TestPutProtectionSettingsRejectsMalformedCCRules 验证 cc_rules 不是合法 JSON 数组时返回 400。
func TestPutProtectionSettingsRejectsMalformedCCRules(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CCRules = "[]"
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"cc_rules":"definitely-not-json"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for malformed cc_rules, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if loaded := shared.LoadProtectionConfig(repo); loaded.CCRules != "[]" {
		t.Fatalf("rejected cc_rules must not be stored, got %q", loaded.CCRules)
	}
}

// TestPutProtectionSettingsValidatesStoredCCRulesWhenCustomEnabled 验证仅打开 cc_use_custom 时校验库里已存的规则。
func TestPutProtectionSettingsValidatesStoredCCRulesWhenCustomEnabled(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CCUseCustom = false
	cfg.CCRules = `[{"enabled":true,"action":"redirect"}]`
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"cc_use_custom":true}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 when enabling custom CC with an invalid stored action, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestPutProtectionSettingsPreservesAllJSONBlobsOnUnrelatedPatch 验证部分保存不清空七个 JSON blob 字段。
func TestPutProtectionSettingsPreservesAllJSONBlobsOnUnrelatedPatch(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CCRules = `[{"enabled":true,"action":"drop"}]`
	cfg.OWASPModules = `{"sqli":"high"}`
	cfg.ChainSteps = `[{"type":"pow","condition":"all"}]`
	cfg.EscalationSteps = `[{"threshold":3,"action":"shield_challenge"}]`
	cfg.CategorySensitivity = `{"xss":"strict"}`
	cfg.OWASPRulesConfig = `{"942100":{"enabled":false}}`
	cfg.CVERulesConfig = `{"CVE-2021-44228":{"enabled":true}}`
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"login_max_attempts":11}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	blobs := map[string][2]string{
		"cc_rules":             {loaded.CCRules, cfg.CCRules},
		"owasp_modules":        {loaded.OWASPModules, cfg.OWASPModules},
		"chain_steps":          {loaded.ChainSteps, cfg.ChainSteps},
		"escalation_steps":     {loaded.EscalationSteps, cfg.EscalationSteps},
		"category_sensitivity": {loaded.CategorySensitivity, cfg.CategorySensitivity},
		"owasp_rules_config":   {loaded.OWASPRulesConfig, cfg.OWASPRulesConfig},
		"cve_rules_config":     {loaded.CVERulesConfig, cfg.CVERulesConfig},
	}
	for key, pair := range blobs {
		if pair[0] != pair[1] {
			t.Errorf("%s was not preserved: got %q want %q", key, pair[0], pair[1])
		}
	}
}

// TestPutProtectionSettingsAcceptsJSONBlobsAsObjectsAndStrings 验证 blob 字段既可传对象/数组也可传 JSON 字符串。
func TestPutProtectionSettingsAcceptsJSONBlobsAsObjectsAndStrings(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := shared.SaveProtectionConfig(repo, store.DefaultProtectionConfig()); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{
		"cc_rules":[{"action":"drop"}],
		"owasp_modules":{"sqli":"high"},
		"chain_steps":[{"type":"env","condition":"all"}],
		"escalation_steps":[{"threshold":3,"action":"shield_challenge"}],
		"owasp_rules_config":{"942100":{"enabled":false}},
		"cve_rules_config":{"CVE-2021-44228":{"enabled":true}},
		"category_sensitivity":"{\"sqli\":\"strict\"}"
	}`)
	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	verbatim := map[string][2]string{
		"cc_rules":           {loaded.CCRules, `[{"action":"drop"}]`},
		"owasp_modules":      {loaded.OWASPModules, `{"sqli":"high"}`},
		"chain_steps":        {loaded.ChainSteps, `[{"type":"env","condition":"all"}]`},
		"escalation_steps":   {loaded.EscalationSteps, `[{"threshold":3,"action":"shield_challenge"}]`},
		"owasp_rules_config": {loaded.OWASPRulesConfig, `{"942100":{"enabled":false}}`},
		"cve_rules_config":   {loaded.CVERulesConfig, `{"CVE-2021-44228":{"enabled":true}}`},
	}
	for key, pair := range verbatim {
		if pair[0] != pair[1] {
			t.Errorf("%s not stored verbatim: got %q want %q", key, pair[0], pair[1])
		}
	}
	if sens := loaded.GetCategorySensitivity(); sens["sqli"] != "strict" {
		t.Errorf("category_sensitivity string form not decoded: %#v", sens)
	}
	// 升级阶梯里的挑战子类型必须原样保留。
	steps := loaded.GetEscalationSteps()
	if len(steps) != 1 || steps[0].Action != "shield_challenge" {
		t.Errorf("escalation step action was not preserved: %#v", steps)
	}
}

// TestPutProtectionSettingsSyncsBotDetectionEnabled 验证 bot_detection_enabled 同步写入 bot_settings。
func TestPutProtectionSettingsSyncsBotDetectionEnabled(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("bot_settings", `{"enabled":false,"score_threshold":73}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"bot_detection_enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("load bot settings: %v", err)
	}
	var bot shared.BotSettingsResponse
	if err := json.Unmarshal([]byte(val), &bot); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if !bot.Enabled {
		t.Fatal("bot_detection_enabled was not synced into bot_settings")
	}
	if bot.ScoreThreshold != 73 {
		t.Fatalf("sync should preserve the existing bot score threshold, got %d", bot.ScoreThreshold)
	}
}

// TestPutProtectionSettingsSyncsCVEAutoDropToDropPolicy 验证 CVE 自动丢弃开关同步写入 drop_policy。
func TestPutProtectionSettingsSyncsCVEAutoDropToDropPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("drop_policy", `{"enabled":true,"bot_score_threshold":66,"cve_auto_drop_critical":true,"cve_auto_drop_high":true}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"cve_auto_drop_critical":false,"cve_auto_drop_high":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("load drop policy: %v", err)
	}
	var policy DropPolicyResponse
	if err := json.Unmarshal([]byte(val), &policy); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if policy.CVEAutoDropCritical || policy.CVEAutoDropHigh {
		t.Fatalf("CVE auto-drop flags were not synced: %#v", policy)
	}
	if policy.BotScoreThreshold != 66 || !policy.Enabled {
		t.Fatalf("sync should preserve unrelated drop policy fields: %#v", policy)
	}
}

// TestPutProtectionSettingsReloadFailureReturns500 验证 reload 失败时返回 500，但配置已落库。
func TestPutProtectionSettingsReloadFailureReturns500(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return errors.New("reload boom") }), "POST", "/api/v1/protection-settings", []byte(`{"login_max_attempts":13}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 on reload failure, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if shared.LoadProtectionConfig(repo).LoginMaxAttempts != 13 {
		t.Fatal("config should already be saved before reload is attempted")
	}
}

// TestBuildProtectionResponseIgnoresCorruptedBlobs 验证损坏的 JSON blob 退化为空集合而不是泄漏原始字符串。
func TestBuildProtectionResponseIgnoresCorruptedBlobs(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CCRules = "not-json"
	cfg.OWASPModules = "not-json"
	cfg.ChainSteps = "not-json"
	cfg.EscalationSteps = "not-json"
	cfg.OWASPRulesConfig = "not-json"
	cfg.CVERulesConfig = "not-json"

	got := buildProtectionResponse(cfg)
	for _, key := range []string{"cc_rules", "chain_steps", "escalation_steps"} {
		items, ok := got[key].([]any)
		if !ok || len(items) != 0 {
			t.Errorf("%s should fall back to an empty array, got %#v", key, got[key])
		}
	}
	if modules, ok := got["owasp_modules"].(map[string]string); !ok || len(modules) != 0 {
		t.Errorf("owasp_modules should fall back to an empty object, got %#v", got["owasp_modules"])
	}
	for _, key := range []string{"owasp_rules_config", "cve_rules_config"} {
		obj, ok := got[key].(map[string]any)
		if !ok || len(obj) != 0 {
			t.Errorf("%s should fall back to an empty object, got %#v", key, got[key])
		}
	}
}

// TestBuildProtectionResponseExpandsPopulatedBlobs 验证有效的 JSON blob 被展开为结构化字段。
func TestBuildProtectionResponseExpandsPopulatedBlobs(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CCRules = `[{"action":"drop"}]`
	cfg.OWASPModules = `{"sqli":"high"}`
	cfg.ChainSteps = `[{"type":"env"},{"type":"pow"}]`
	cfg.EscalationSteps = `[{"threshold":3,"action":"chain_challenge"}]`
	cfg.OWASPRulesConfig = `{"942100":{"enabled":false}}`
	cfg.CVERulesConfig = `{"CVE-2021-44228":{"enabled":true}}`

	got := buildProtectionResponse(cfg)
	if items, ok := got["cc_rules"].([]any); !ok || len(items) != 1 {
		t.Errorf("cc_rules not expanded: %#v", got["cc_rules"])
	}
	if items, ok := got["chain_steps"].([]any); !ok || len(items) != 2 {
		t.Errorf("chain_steps not expanded: %#v", got["chain_steps"])
	}
	if items, ok := got["escalation_steps"].([]any); !ok || len(items) != 1 {
		t.Errorf("escalation_steps not expanded: %#v", got["escalation_steps"])
	}
	if modules, ok := got["owasp_modules"].(map[string]string); !ok || modules["sqli"] != "high" {
		t.Errorf("owasp_modules not expanded: %#v", got["owasp_modules"])
	}
	if obj, ok := got["owasp_rules_config"].(map[string]any); !ok || len(obj) != 1 {
		t.Errorf("owasp_rules_config not expanded: %#v", got["owasp_rules_config"])
	}
	if obj, ok := got["cve_rules_config"].(map[string]any); !ok || len(obj) != 1 {
		t.Errorf("cve_rules_config not expanded: %#v", got["cve_rules_config"])
	}
}

// TestSetProtectionActionFieldIgnoresUnknownField 验证未知字段名不会误改任何动作字段。
func TestSetProtectionActionFieldIgnoresUnknownField(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	before := cfg
	setProtectionActionField(&cfg, "unknown_action_field", "drop")
	if cfg.RequestRateLimitAction != before.RequestRateLimitAction ||
		cfg.ErrorRateLimitAction != before.ErrorRateLimitAction ||
		cfg.OWASPAction != before.OWASPAction ||
		cfg.CVEAction != before.CVEAction ||
		cfg.AutoBanAction != before.AutoBanAction {
		t.Fatalf("unknown field must not modify any action: %#v", cfg)
	}
}
