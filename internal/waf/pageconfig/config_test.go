package pageconfig

import (
	"strings"
	"testing"
)

// TestSanitizeCSSRemovesDangerousPatterns 验证危险 CSS 模式被清除。
func TestSanitizeCSSRemovesDangerousPatterns(t *testing.T) {
	cases := []struct {
		name  string
		input string
		bad   string
	}{
		{"expression", "body { background: expression(alert(1)) }", "expression("},
		{"javascript_url", "a { background: javascript:alert(1) }", "javascript:"},
		{"url_import", "body { background: url(http://evil.com/img.png) }", "url("},
		{"at_import", "@import url('evil.css')", "@import"},
		{"behavior", "li { behavior: url(evil.htc) }", "behavior:"},
		{"binding", "li { binding: url(evil.xml) }", "binding:"},
		{"mixed_case_expr", "body { background: EXPRESSION(alert(1)) }", "expression("},
		{"mixed_case_import", "@IMPORT url('evil.css')", "@import"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := SanitizeCSS(tc.input)
			if strings.Contains(strings.ToLower(out), tc.bad) {
				t.Errorf("SanitizeCSS(%q) still contains %q: got %q", tc.input, tc.bad, out)
			}
		})
	}
}

// TestSanitizeCSSPreservesSafeCSS 验证合法 CSS 不被误删。
func TestSanitizeCSSPreservesSafeCSS(t *testing.T) {
	safe := `body { color: #333; font-size: 14px; margin: 0 auto; }`
	out := SanitizeCSS(safe)
	if out != safe {
		t.Fatalf("safe CSS should not be modified, got %q", out)
	}
}

func TestSafePageStyleValuesAndLogoURL(t *testing.T) {
	defaults := DefaultPageConfig()
	if got := SafePrimaryColor("#12aBCd", defaults.PrimaryColor); got != "#12aBCd" {
		t.Fatalf("safe primary color rejected: %q", got)
	}
	if got := SafePrimaryColor("red;}</style><script>", defaults.PrimaryColor); got != defaults.PrimaryColor {
		t.Fatalf("unsafe primary color did not fall back: %q", got)
	}
	if got := SafeBackground("linear-gradient(90deg,#fff 0%,#000 100%)", defaults.BgGradient); got == defaults.BgGradient {
		t.Fatalf("safe background rejected: %q", got)
	}
	if got := SafeBackground("url(javascript:alert(1))", defaults.BgGradient); got != defaults.BgGradient {
		t.Fatalf("unsafe background did not fall back: %q", got)
	}
	for _, safe := range []string{"/brand/logo.png", "https://cdn.example/logo.png", "http://cdn.example/logo.png"} {
		if got := string(SafeLogoURL(safe)); got != safe {
			t.Fatalf("SafeLogoURL(%q) = %q", safe, got)
		}
	}
	for _, unsafe := range []string{"javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "//evil.example/logo.png", "relative/logo.png"} {
		if got := SafeLogoURL(unsafe); got != "" {
			t.Fatalf("SafeLogoURL(%q) = %q, want empty", unsafe, got)
		}
	}
}

// TestDefaultPageConfigFields 验证默认配置包含必要的非空字段。
func TestDefaultPageConfigFields(t *testing.T) {
	cfg := DefaultPageConfig()
	if cfg.BrandName == "" || cfg.PrimaryColor == "" || cfg.Title == "" {
		t.Fatalf("default page config has empty required fields: %+v", cfg)
	}
}

func TestDefaultCaptchaPageConfigEmbeddsPageConfig(t *testing.T) {
	cfg := DefaultCaptchaPageConfig()
	if cfg.BrandName == "" {
		t.Error("CaptchaPageConfig should embed non-empty PageConfig")
	}
	if cfg.Subtitle == "" || cfg.SubtitleZh == "" || cfg.SubmitText == "" {
		t.Errorf("CaptchaPageConfig missing default text fields: %+v", cfg)
	}
}

func TestDefaultChallengePageConfigFields(t *testing.T) {
	cfg := DefaultChallengePageConfig()
	if cfg.BrandName == "" {
		t.Error("ChallengePageConfig should embed non-empty PageConfig")
	}
	if cfg.CheckingText == "" || cfg.CheckingTextZh == "" {
		t.Errorf("ChallengePageConfig missing checking text: %+v", cfg)
	}
	if cfg.WaitText == "" || cfg.WaitTextZh == "" {
		t.Errorf("ChallengePageConfig missing wait text: %+v", cfg)
	}
}

func TestDefaultBlockPageConfigFields(t *testing.T) {
	cfg := DefaultBlockPageConfig()
	if cfg.BrandName == "" {
		t.Error("BlockPageConfig should embed non-empty PageConfig")
	}
	if cfg.BlockTitle == "" || cfg.BlockMessage == "" {
		t.Errorf("BlockPageConfig missing block fields: %+v", cfg)
	}
	if cfg.RateLimitTitle == "" || cfg.RateLimitMsg == "" {
		t.Errorf("BlockPageConfig missing rate-limit fields: %+v", cfg)
	}
}

func TestParsePageConfigsMergeStoredOverrides(t *testing.T) {
	captcha := ParseCaptchaPageConfig(`{"brand_name":"Custom","submit_text":"Continue"}`)
	if captcha.BrandName != "Custom" || captcha.SubmitText != "Continue" {
		t.Fatalf("captcha overrides were not applied: %#v", captcha)
	}
	if captcha.Subtitle != DefaultCaptchaPageConfig().Subtitle {
		t.Fatalf("captcha defaults were not preserved: %#v", captcha)
	}

	challenge := ParseChallengePageConfig(`{"checking_text":"Inspecting"}`)
	if challenge.CheckingText != "Inspecting" || challenge.WaitText != DefaultChallengePageConfig().WaitText {
		t.Fatalf("challenge config merge failed: %#v", challenge)
	}

	block := ParseBlockPageConfig(`{"block_title":"Denied"}`)
	if block.BlockTitle != "Denied" || block.RateLimitTitle != DefaultBlockPageConfig().RateLimitTitle {
		t.Fatalf("block config merge failed: %#v", block)
	}
}

func TestParsePageConfigsFallBackFromInvalidJSON(t *testing.T) {
	if got := ParseCaptchaPageConfig(`not-json`); got != DefaultCaptchaPageConfig() {
		t.Fatalf("invalid captcha JSON did not use defaults: %#v", got)
	}
	if got := ParseChallengePageConfig(`not-json`); got != DefaultChallengePageConfig() {
		t.Fatalf("invalid challenge JSON did not use defaults: %#v", got)
	}
	if got := ParseBlockPageConfig(`not-json`); got != DefaultBlockPageConfig() {
		t.Fatalf("invalid block JSON did not use defaults: %#v", got)
	}
}

func TestPageTemplateManagerGetSetCaptcha(t *testing.T) {
	m := NewPageTemplateManager()
	orig := m.GetCaptchaConfig()
	if orig.BrandName == "" {
		t.Fatal("manager should return non-empty default captcha config")
	}
	custom := orig
	custom.BrandName = "CustomBrand"
	m.SetCaptchaConfig(custom)
	got := m.GetCaptchaConfig()
	if got.BrandName != "CustomBrand" {
		t.Errorf("SetCaptchaConfig: got %q, want CustomBrand", got.BrandName)
	}
}

func TestPageTemplateManagerGetSetChallenge(t *testing.T) {
	m := NewPageTemplateManager()
	custom := m.GetChallengeConfig()
	custom.CheckingText = "Testing..."
	m.SetChallengeConfig(custom)
	if got := m.GetChallengeConfig().CheckingText; got != "Testing..." {
		t.Errorf("SetChallengeConfig: got %q", got)
	}
}

func TestPageTemplateManagerGetSetBlock(t *testing.T) {
	m := NewPageTemplateManager()
	custom := m.GetBlockConfig()
	custom.BlockTitle = "Blocked!"
	m.SetBlockConfig(custom)
	if got := m.GetBlockConfig().BlockTitle; got != "Blocked!" {
		t.Errorf("SetBlockConfig: got %q", got)
	}
}

func TestSafeHTMLAttrEscapesSpecialChars(t *testing.T) {
	cases := []struct{ input, wantContains string }{
		{`<script>`, `&lt;`},
		{`"quote"`, `&#34;`},
		{`normal`, `normal`},
	}
	for _, tc := range cases {
		out := SafeHTMLAttr(tc.input)
		if !strings.Contains(out, tc.wantContains) {
			t.Errorf("SafeHTMLAttr(%q) = %q, want to contain %q", tc.input, out, tc.wantContains)
		}
	}
}
