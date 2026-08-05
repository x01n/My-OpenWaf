package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/waf/pageconfig"
)

/**
 * invokePageTemplateHandler 构造带 :type 路由参数的请求上下文并调用 handler。
 *
 * @param handler  待调用的 Hertz handler
 * @param method   HTTP 方法，仅使用 GET/POST
 * @param pageType 路由参数 type 的取值
 * @param payload  请求体，nil 表示不带请求体
 */
func invokePageTemplateHandler(t *testing.T, handler app.HandlerFunc, method, pageType string, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI("/api/v1/page-templates/" + pageType)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "type", Value: pageType}}
	handler(context.Background(), ctx)
	return ctx
}

// TestGetPageTemplatesReturnsAllThreeConfigs 验证聚合接口同时返回 captcha/challenge/block 三份配置且缺省值来自 pageconfig 默认值。
func TestGetPageTemplatesReturnsAllThreeConfigs(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeProtectHandler(t, GetPageTemplates(repo), "GET", "/api/v1/page-templates", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got struct {
		Captcha   pageconfig.CaptchaPageConfig   `json:"captcha"`
		Challenge pageconfig.ChallengePageConfig `json:"challenge"`
		Block     pageconfig.BlockPageConfig     `json:"block"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Captcha.SubmitText != pageconfig.DefaultCaptchaPageConfig().SubmitText {
		t.Fatalf("captcha default not returned: %#v", got.Captcha)
	}
	if got.Challenge.CheckingText != pageconfig.DefaultChallengePageConfig().CheckingText {
		t.Fatalf("challenge default not returned: %#v", got.Challenge)
	}
	if got.Block.BlockTitle != pageconfig.DefaultBlockPageConfig().BlockTitle {
		t.Fatalf("block default not returned: %#v", got.Block)
	}
}

// TestGetPageTemplatesMergesStoredOverrides 验证已存储的部分字段覆盖默认值，未存储字段保持默认。
func TestGetPageTemplatesMergesStoredOverrides(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyBlockPage, `{"brand_name":"CustomBrand","block_title":"自定义拦截"}`); err != nil {
		t.Fatalf("seed block page: %v", err)
	}

	ctx := invokeProtectHandler(t, GetPageTemplates(repo), "GET", "/api/v1/page-templates", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got struct {
		Block pageconfig.BlockPageConfig `json:"block"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Block.BrandName != "CustomBrand" || got.Block.BlockTitle != "自定义拦截" {
		t.Fatalf("stored overrides not applied: %#v", got.Block)
	}
	if got.Block.RateLimitTitle != pageconfig.DefaultBlockPageConfig().RateLimitTitle {
		t.Fatalf("unset field should keep default, got %q", got.Block.RateLimitTitle)
	}
}

// TestGetPageTemplateByType 验证按类型查询返回对应配置，非法类型返回 400。
func TestGetPageTemplateByType(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	for _, pageType := range []string{"captcha", "challenge", "block"} {
		ctx := invokePageTemplateHandler(t, GetPageTemplate(repo), "GET", pageType, nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: unexpected status %d: %s", pageType, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var got map[string]any
		if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
			t.Fatalf("%s: decode response: %v", pageType, err)
		}
		if got["brand_name"] != pageconfig.DefaultPageConfig().BrandName {
			t.Fatalf("%s: brand_name missing from response: %#v", pageType, got)
		}
	}

	for _, pageType := range []string{"", "unknown", "Captcha"} {
		ctx := invokePageTemplateHandler(t, GetPageTemplate(repo), "GET", pageType, nil)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("page type %q: expected 400, got %d", pageType, ctx.Response.StatusCode())
		}
	}
}

// TestUpdatePageTemplatePersistsAndTriggersReload 验证保存成功写入存储并调用 reload 回调。
func TestUpdatePageTemplatePersistsAndTriggersReload(t *testing.T) {
	cases := []struct {
		pageType   string
		settingKey string
		body       string
	}{
		{"captcha", settingKeyCaptchaPage, `{"brand_name":"CaptchaBrand","submit_text":"GO"}`},
		{"challenge", settingKeyChallengePage, `{"brand_name":"ChallengeBrand","checking_text":"Verifying"}`},
		{"block", settingKeyBlockPage, `{"brand_name":"BlockBrand","block_title":"Denied"}`},
	}
	for _, tc := range cases {
		repo := newSystemSettingsRepoForTest(t)
		reloaded := false
		ctx := invokePageTemplateHandler(t, UpdatePageTemplate(repo, func() error {
			reloaded = true
			return nil
		}), "POST", tc.pageType, []byte(tc.body))
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: unexpected status %d: %s", tc.pageType, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		if !reloaded {
			t.Fatalf("%s: reload callback was not invoked", tc.pageType)
		}
		stored, err := repo.Get(tc.settingKey)
		if err != nil {
			t.Fatalf("%s: load stored template: %v", tc.pageType, err)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(stored), &got); err != nil {
			t.Fatalf("%s: stored template is not valid JSON: %v", tc.pageType, err)
		}
		if got["brand_name"] == nil || got["brand_name"] == "" {
			t.Fatalf("%s: brand_name was not persisted: %s", tc.pageType, stored)
		}
	}
}

// TestUpdatePageTemplateRejectsInvalidType 验证非法页面类型返回 400 且不写入任何配置键。
func TestUpdatePageTemplateRejectsInvalidType(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokePageTemplateHandler(t, UpdatePageTemplate(repo, func() error { return nil }), "POST", "shield", []byte(`{"brand_name":"X"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid page type, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	for _, key := range []string{settingKeyCaptchaPage, settingKeyChallengePage, settingKeyBlockPage} {
		if val, err := repo.Get(key); err == nil && val != "" {
			t.Fatalf("invalid page type should not persist %s, got %s", key, val)
		}
	}
}

// TestUpdatePageTemplateRejectsInvalidBody 验证三种页面类型的非法 JSON 请求体都返回 400。
func TestUpdatePageTemplateRejectsInvalidBody(t *testing.T) {
	for _, pageType := range []string{"captcha", "challenge", "block"} {
		repo := newSystemSettingsRepoForTest(t)
		reloaded := false
		ctx := invokePageTemplateHandler(t, UpdatePageTemplate(repo, func() error {
			reloaded = true
			return nil
		}), "POST", pageType, []byte(`{"brand_name":`))
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("%s: expected 400 for malformed body, got %d", pageType, ctx.Response.StatusCode())
		}
		if reloaded {
			t.Fatalf("%s: reload should not run when body is rejected", pageType)
		}
	}
}

// TestUpdatePageTemplateRejectsTypeMismatchedField 验证字段类型不匹配时返回 400。
func TestUpdatePageTemplateRejectsTypeMismatchedField(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokePageTemplateHandler(t, UpdatePageTemplate(repo, func() error { return nil }), "POST", "block", []byte(`{"brand_name":123}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for type-mismatched field, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdatePageTemplatePersistsSanitizedCustomCSS 验证保存前的 CSS 净化结果被真正写入存储。
//
// 已知缺陷复现：page_templates.go 中 UpdatePageTemplate 对解析后的 cfg 调用了
// sanitizePageCSS，但随后落库的是原始请求体 body，净化结果被丢弃。
func TestUpdatePageTemplatePersistsSanitizedCustomCSS(t *testing.T) {
	for _, pageType := range []struct {
		name       string
		settingKey string
	}{
		{"captcha", settingKeyCaptchaPage},
		{"challenge", settingKeyChallengePage},
		{"block", settingKeyBlockPage},
	} {
		repo := newSystemSettingsRepoForTest(t)
		body := []byte(`{"custom_css":"body{width:expression(alert(1));background:javascript:x}"}`)
		ctx := invokePageTemplateHandler(t, UpdatePageTemplate(repo, func() error { return nil }), "POST", pageType.name, body)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: unexpected status %d: %s", pageType.name, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}

		stored, err := repo.Get(pageType.settingKey)
		if err != nil {
			t.Fatalf("%s: load stored template: %v", pageType.name, err)
		}
		var got struct {
			CustomCSS string `json:"custom_css"`
		}
		if err := json.Unmarshal([]byte(stored), &got); err != nil {
			t.Fatalf("%s: stored template is not valid JSON: %v", pageType.name, err)
		}
		if indexCaseInsensitive(got.CustomCSS, "expression(") != -1 || indexCaseInsensitive(got.CustomCSS, "javascript:") != -1 {
			t.Errorf("%s: KNOWN DEFECT page_templates.go:88 — UpdatePageTemplate saves the raw request body instead of the sanitized cfg, so sanitizePageCSS() has no effect; stored custom_css = %q", pageType.name, got.CustomCSS)
		}
	}
}

// TestResetPageTemplateRestoresDefaults 验证重置删除存储键后读取回到默认值，并调用 reload。
func TestResetPageTemplateRestoresDefaults(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyChallengePage, `{"brand_name":"Temp","checking_text":"Temp"}`); err != nil {
		t.Fatalf("seed challenge page: %v", err)
	}

	reloaded := false
	ctx := invokePageTemplateHandler(t, ResetPageTemplate(repo, func() error {
		reloaded = true
		return nil
	}), "POST", "challenge", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !reloaded {
		t.Fatal("reload callback was not invoked")
	}
	if val, err := repo.Get(settingKeyChallengePage); err == nil && val != "" {
		t.Fatalf("reset should delete the stored template, got %s", val)
	}

	cfg := loadChallengePageConfig(repo)
	if cfg.BrandName != pageconfig.DefaultPageConfig().BrandName || cfg.CheckingText != pageconfig.DefaultChallengePageConfig().CheckingText {
		t.Fatalf("reset did not restore defaults: %#v", cfg)
	}
}

// TestResetPageTemplateRejectsInvalidType 验证非法类型返回 400 且不触发 reload。
func TestResetPageTemplateRejectsInvalidType(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	reloaded := false
	ctx := invokePageTemplateHandler(t, ResetPageTemplate(repo, func() error {
		reloaded = true
		return nil
	}), "POST", "welcome", nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid page type, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloaded {
		t.Fatal("reload should not run for an invalid page type")
	}
}

// TestResetPageTemplateCoversAllTypes 验证三种页面类型都能重置，且键不存在时仍返回 200。
func TestResetPageTemplateCoversAllTypes(t *testing.T) {
	cases := []struct {
		pageType   string
		settingKey string
	}{
		{"captcha", settingKeyCaptchaPage},
		{"challenge", settingKeyChallengePage},
		{"block", settingKeyBlockPage},
	}
	for _, tc := range cases {
		repo := newSystemSettingsRepoForTest(t)
		if err := repo.Set(tc.settingKey, `{"brand_name":"Temp"}`); err != nil {
			t.Fatalf("%s: seed template: %v", tc.pageType, err)
		}

		ctx := invokePageTemplateHandler(t, ResetPageTemplate(repo, func() error { return nil }), "POST", tc.pageType, nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: unexpected status %d: %s", tc.pageType, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		if val, err := repo.Get(tc.settingKey); err == nil && val != "" {
			t.Fatalf("%s: reset should delete the stored template, got %s", tc.pageType, val)
		}

		// 重复重置（键已不存在）仍应成功。
		ctx = invokePageTemplateHandler(t, ResetPageTemplate(repo, func() error { return nil }), "POST", tc.pageType, nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: repeated reset returned %d", tc.pageType, ctx.Response.StatusCode())
		}
	}
}

// TestUpdateAndResetPageTemplateWithNilReload 验证 reload 为 nil 时不会 panic。
func TestUpdateAndResetPageTemplateWithNilReload(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokePageTemplateHandler(t, UpdatePageTemplate(repo, nil), "POST", "block", []byte(`{"brand_name":"NoReload"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update with nil reload: unexpected status %d", ctx.Response.StatusCode())
	}
	ctx = invokePageTemplateHandler(t, ResetPageTemplate(repo, nil), "POST", "block", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("reset with nil reload: unexpected status %d", ctx.Response.StatusCode())
	}
}

// TestPreviewPageTemplate 验证预览接口对三种类型返回可直接放入 iframe srcDoc 的 HTML，非法类型返回 400。
func TestPreviewPageTemplate(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	for _, pageType := range []string{"captcha", "challenge", "block"} {
		ctx := invokePageTemplateHandler(t, PreviewPageTemplate(repo), "GET", pageType, nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: unexpected status %d: %s", pageType, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		if got := string(ctx.Response.Header.ContentType()); got != "text/html; charset=utf-8" {
			t.Fatalf("%s: content type = %q", pageType, got)
		}
		body := string(ctx.Response.Body())
		if !strings.Contains(body, "<!DOCTYPE html>") || !strings.Contains(body, "preview-request") {
			t.Fatalf("%s: preview response is not rendered HTML: %s", pageType, body)
		}
	}

	ctx := invokePageTemplateHandler(t, PreviewPageTemplate(repo), "GET", "shield", nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid preview type, got %d", ctx.Response.StatusCode())
	}
}

// TestPreviewPageTemplateDraftUsesBodyAndDoesNotPersist 验证草稿预览只使用请求体且不落库。
func TestPreviewPageTemplateDraftUsesBodyAndDoesNotPersist(t *testing.T) {
	for _, pageType := range []string{"captcha", "challenge", "block"} {
		repo := newSystemSettingsRepoForTest(t)
		body := []byte(`{"brand_name":"DraftBrand","title":"Draft Title","custom_css":"body{width:expression(alert(1))}"}`)
		ctx := invokePageTemplateHandler(t, PreviewPageTemplateDraft(repo), "POST", pageType, body)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("%s: unexpected status %d: %s", pageType, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		preview := string(ctx.Response.Body())
		if !strings.Contains(preview, "DraftBrand") || !strings.Contains(preview, "Draft Title") {
			t.Fatalf("%s: draft preview did not use submitted body: %s", pageType, preview)
		}
		if strings.Contains(preview, "expression(") {
			t.Fatalf("%s: draft preview did not sanitize custom CSS: %s", pageType, preview)
		}
		for _, key := range []string{settingKeyCaptchaPage, settingKeyChallengePage, settingKeyBlockPage} {
			if val, err := repo.Get(key); err == nil && val != "" {
				t.Fatalf("%s: draft preview must not persist %s, got %s", pageType, key, val)
			}
		}
	}
}

// TestPreviewPageTemplateDraftRejectsInvalidInput 验证草稿预览对非法类型和非法 JSON 返回 400。
func TestPreviewPageTemplateDraftRejectsInvalidInput(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokePageTemplateHandler(t, PreviewPageTemplateDraft(repo), "POST", "shield", []byte(`{"brand_name":"X"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid page type, got %d", ctx.Response.StatusCode())
	}
	for _, pageType := range []string{"captcha", "challenge", "block"} {
		ctx := invokePageTemplateHandler(t, PreviewPageTemplateDraft(repo), "POST", pageType, []byte(`{"brand_name":`))
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("%s: expected 400 for malformed body, got %d", pageType, ctx.Response.StatusCode())
		}
	}
}

// TestLoadPageConfigsIgnoreCorruptedStoredJSON 验证存储值损坏时回落到默认配置而不是 panic。
func TestLoadPageConfigsIgnoreCorruptedStoredJSON(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, key := range []string{settingKeyCaptchaPage, settingKeyChallengePage, settingKeyBlockPage} {
		if err := repo.Set(key, `not-json`); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	if got := loadCaptchaPageConfig(repo); got.SubmitText != pageconfig.DefaultCaptchaPageConfig().SubmitText {
		t.Fatalf("corrupted captcha config should fall back to default: %#v", got)
	}
	if got := loadChallengePageConfig(repo); got.CheckingText != pageconfig.DefaultChallengePageConfig().CheckingText {
		t.Fatalf("corrupted challenge config should fall back to default: %#v", got)
	}
	if got := loadBlockPageConfig(repo); got.BlockTitle != pageconfig.DefaultBlockPageConfig().BlockTitle {
		t.Fatalf("corrupted block config should fall back to default: %#v", got)
	}
}

// TestSanitizePageCSS 验证危险 CSS 整段被拒绝，安全 CSS 原样保留。
func TestSanitizePageCSS(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"safe", "body{color:red}", "body{color:red}"},
		{"expression", "a{width:expression(1)}", ""},
		{"expression_mixed_case", "a{width:EXPRESSION(1)}", ""},
		{"javascript_scheme", "a{background:javascript:alert(1)}", ""},
		{"import", "@import url(x);body{}", ""},
		{"behavior", "a{behavior:url(x)}", ""},
		{"style_breakout", "</style><script>alert(1)</script>", ""},
		{"escaped_marker", `body{color:\72 ed}`, ""},
	}
	for _, tc := range cases {
		if got := sanitizePageCSS(tc.input); got != tc.want {
			t.Errorf("%s: sanitizePageCSS(%q) = %q, want %q", tc.name, tc.input, got, tc.want)
		}
	}
}

func TestSanitizePageCSSRejectsURLFunction(t *testing.T) {
	const css = "body{background:url(/static/bg.png)}"
	if got := sanitizePageCSS(css); got != "" {
		t.Fatalf("sanitizePageCSS must reject url(), got %q", got)
	}
}

// TestIndexCaseInsensitive 验证大小写不敏感子串查找的边界行为。
func TestIndexCaseInsensitive(t *testing.T) {
	cases := []struct {
		s      string
		substr string
		want   int
	}{
		{"Hello", "ll", 2},
		{"Hello", "LL", 2},
		{"HELLO", "llo", 2},
		{"abc", "d", -1},
		{"ab", "abc", -1},
		{"abc", "", 0},
		{"", "abc", -1},
		{"aaa", "aa", 0},
		{"xexpression(", "EXPRESSION(", 1},
	}
	for _, tc := range cases {
		if got := indexCaseInsensitive(tc.s, tc.substr); got != tc.want {
			t.Errorf("indexCaseInsensitive(%q, %q) = %d, want %d", tc.s, tc.substr, got, tc.want)
		}
	}
}
