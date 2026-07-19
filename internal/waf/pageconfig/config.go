package pageconfig

import (
	"html/template"
	"strings"
	"sync"
)

// PageConfig holds customizable branding/theme settings for WAF pages.
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

// SanitizeCSS performs basic CSS sanitization to prevent XSS via style injection.
func SanitizeCSS(css string) string {
	dangerous := []string{"expression(", "javascript:", "url(", "@import", "behavior:", "binding:"}
	result := css
	lower := strings.ToLower(result)
	for _, pattern := range dangerous {
		if strings.Contains(lower, pattern) {
			result = strings.ReplaceAll(result, pattern, "")
			lower = strings.ToLower(result)
		}
	}
	return result
}

// SafeHTMLAttr escapes a string for safe use in HTML attribute context.
func SafeHTMLAttr(s string) string {
	return template.HTMLEscapeString(s)
}
