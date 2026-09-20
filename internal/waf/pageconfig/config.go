package pageconfig

import (
	"encoding/json"
	"html/template"
	"net/url"
	"strings"
	"sync"
)

// PageConfig holds customizable branding/theme settings for WAF pages.
const (
	SettingKeyCaptchaPage   = "page_template_captcha"
	SettingKeyChallengePage = "page_template_challenge"
	SettingKeyBlockPage     = "page_template_block"
)

type PageConfig struct {
	BrandName    string `json:"brand_name"`
	PrimaryColor string `json:"primary_color"`
	BgGradient   string `json:"bg_gradient"`
	LogoURL      string `json:"logo_url"`
	Title        string `json:"title"`
	FooterText   string `json:"footer_text"`
	CustomCSS    string `json:"custom_css"`
}

// CaptchaPageConfig extends PageConfig for captcha challenge pages.
type CaptchaPageConfig struct {
	PageConfig
	Subtitle   string `json:"subtitle"`
	SubtitleZh string `json:"subtitle_zh"`
	SubmitText string `json:"submit_text"`
}

// ChallengePageConfig extends PageConfig for JS challenge pages.
type ChallengePageConfig struct {
	PageConfig
	CheckingText   string `json:"checking_text"`
	CheckingTextZh string `json:"checking_text_zh"`
	WaitText       string `json:"wait_text"`
	WaitTextZh     string `json:"wait_text_zh"`
}

// BlockPageConfig extends PageConfig for block/intercept pages.
type BlockPageConfig struct {
	PageConfig
	BlockTitle     string `json:"block_title"`
	BlockMessage   string `json:"block_message"`
	RateLimitTitle string `json:"rate_limit_title"`
	RateLimitMsg   string `json:"rate_limit_message"`
}

// DefaultPageConfig returns the default page branding configuration.
func DefaultPageConfig() PageConfig {
	return PageConfig{
		BrandName:    "My-OpenWAF",
		PrimaryColor: "#14b8a6",
		BgGradient:   "linear-gradient(160deg,#f0fdfa 0%,#f8fafc 40%,#f1f5f9 100%)",
		Title:        "Security Verification",
		FooterText:   "Protected by My-OpenWAF",
	}
}

// DefaultCaptchaPageConfig returns the default captcha page configuration.
func DefaultCaptchaPageConfig() CaptchaPageConfig {
	return CaptchaPageConfig{
		PageConfig: DefaultPageConfig(),
		Subtitle:   "Please solve the challenge to continue",
		SubtitleZh: "请完成安全验证以继续访问",
		SubmitText: "Submit / 提交",
	}
}

// DefaultChallengePageConfig returns the default JS challenge page configuration.
func DefaultChallengePageConfig() ChallengePageConfig {
	return ChallengePageConfig{
		PageConfig:     DefaultPageConfig(),
		CheckingText:   "Checking your browser",
		CheckingTextZh: "正在验证您的浏览器",
		WaitText:       "This process is automatic, please wait...",
		WaitTextZh:     "此过程是自动的，请稍候...",
	}
}

// DefaultBlockPageConfig returns the default block page configuration.
func DefaultBlockPageConfig() BlockPageConfig {
	return BlockPageConfig{
		PageConfig:     DefaultPageConfig(),
		BlockTitle:     "访问被拒绝",
		BlockMessage:   "您的请求已被 Web 应用防火墙拦截。Your request was blocked by the web application firewall.",
		RateLimitTitle: "请求过于频繁",
		RateLimitMsg:   "当前访问频率过高，请稍后重试。Too many requests, please retry later.",
	}
}

// PageTemplateManager manages page template configurations.
func ParseCaptchaPageConfig(raw string) CaptchaPageConfig {
	cfg := DefaultCaptchaPageConfig()
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

func ParseChallengePageConfig(raw string) ChallengePageConfig {
	cfg := DefaultChallengePageConfig()
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

func ParseBlockPageConfig(raw string) BlockPageConfig {
	cfg := DefaultBlockPageConfig()
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

type PageTemplateManager struct {
	captchaCfg   CaptchaPageConfig
	challengeCfg ChallengePageConfig
	blockCfg     BlockPageConfig
	mu           sync.RWMutex
}

// NewPageTemplateManager creates a manager with default configurations.
func NewPageTemplateManager() *PageTemplateManager {
	return &PageTemplateManager{
		captchaCfg:   DefaultCaptchaPageConfig(),
		challengeCfg: DefaultChallengePageConfig(),
		blockCfg:     DefaultBlockPageConfig(),
	}
}

func (m *PageTemplateManager) GetCaptchaConfig() CaptchaPageConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.captchaCfg
}

func (m *PageTemplateManager) SetCaptchaConfig(cfg CaptchaPageConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.captchaCfg = cfg
}

func (m *PageTemplateManager) GetChallengeConfig() ChallengePageConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.challengeCfg
}

func (m *PageTemplateManager) SetChallengeConfig(cfg ChallengePageConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challengeCfg = cfg
}

func (m *PageTemplateManager) GetBlockConfig() BlockPageConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blockCfg
}

func (m *PageTemplateManager) SetBlockConfig(cfg BlockPageConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blockCfg = cfg
}

// SanitizeCSS rejects an entire custom stylesheet when it contains active or external CSS constructs.
// Safe CSS is returned unchanged so the renderer never executes a string created by deleting attacker input.
func SanitizeCSS(css string) string {
	value := strings.TrimSpace(css)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"</style", "<", ">", "expression(", "javascript:", "vbscript:",
		"url(", "@import", "behavior:", "binding:", "-moz-binding", "/*", "\\",
	} {
		if strings.Contains(lower, marker) {
			return ""
		}
	}
	return css
}

// SafePrimaryColor returns a restricted CSS color value or the supplied fallback.
func SafePrimaryColor(raw, fallback string) string {
	value := sanitizeCSSValue(raw)
	if value == "" || !isCSSColor(value) {
		return fallback
	}
	return value
}

// SafeBackground returns a restricted CSS background value or the supplied fallback.
func SafeBackground(raw, fallback string) string {
	value := sanitizeCSSValue(raw)
	lower := strings.ToLower(value)
	if value == "" || (!strings.HasPrefix(lower, "linear-gradient(") && !strings.HasPrefix(lower, "radial-gradient(")) || !strings.HasSuffix(value, ")") {
		return fallback
	}
	return value
}

// SafeLogoURL permits same-origin paths and explicitly http(s) image URLs only.
func SafeLogoURL(raw string) template.URL {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		return template.URL(value)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	return template.URL(value)
}

func sanitizeCSSValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"url(", "expression(", "javascript:", "@import", "behavior:", "binding:", "var(", "<", ">", "{", "}", ";", "\"", "'"} {
		if strings.Contains(lower, marker) {
			return ""
		}
	}
	for _, r := range value {
		if !(r == '#' || r == '(' || r == ')' || r == ',' || r == '.' || r == '%' || r == '-' || r == '/' || r == ':' || r == ' ' || r == '\t' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return ""
		}
	}
	return value
}

func isCSSColor(value string) bool {
	if strings.HasPrefix(value, "#") {
		length := len(value)
		if length != 4 && length != 5 && length != 7 && length != 9 {
			return false
		}
		for _, r := range value[1:] {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
		return true
	}
	lower := strings.ToLower(value)
	return (strings.HasPrefix(lower, "rgb(") || strings.HasPrefix(lower, "rgba(") || strings.HasPrefix(lower, "hsl(") || strings.HasPrefix(lower, "hsla(")) && strings.HasSuffix(value, ")")
}

// SafeHTMLAttr escapes a string for safe use in HTML attribute context.
func SafeHTMLAttr(s string) string {
	return template.HTMLEscapeString(s)
}
