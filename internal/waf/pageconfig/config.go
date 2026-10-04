package pageconfig

import (
	"encoding/json"
	"html/template"
	"net/url"
	"strings"
)

// 页面模板的设置键：分别指向 captcha / challenge / block 三类页面的存储值。
const (
	SettingKeyCaptchaPage   = "page_template_captcha"
	SettingKeyChallengePage = "page_template_challenge"
	SettingKeyBlockPage     = "page_template_block"
)

/**
 * PageConfig 保存 WAF 页面可自定义的品牌与主题设置。
 *
 * 它是三类页面配置（CaptchaPageConfig / ChallengePageConfig / BlockPageConfig）的内嵌公共部分，
 * 字段值经 Safe* 系列函数净化后才进入模板渲染。
 */
type PageConfig struct {
	BrandName    string `json:"brand_name"`
	PrimaryColor string `json:"primary_color"`
	BgGradient   string `json:"bg_gradient"`
	LogoURL      string `json:"logo_url"`
	Title        string `json:"title"`
	FooterText   string `json:"footer_text"`
	CustomCSS    string `json:"custom_css"`
}

/**
 * CaptchaPageConfig 在 PageConfig 基础上扩展 captcha 验证页专属文案。
 */
type CaptchaPageConfig struct {
	PageConfig
	Subtitle   string `json:"subtitle"`
	SubtitleZh string `json:"subtitle_zh"`
	SubmitText string `json:"submit_text"`
}

/**
 * ChallengePageConfig 在 PageConfig 基础上扩展 JS 挑战页专属文案。
 */
type ChallengePageConfig struct {
	PageConfig
	CheckingText   string `json:"checking_text"`
	CheckingTextZh string `json:"checking_text_zh"`
	WaitText       string `json:"wait_text"`
	WaitTextZh     string `json:"wait_text_zh"`
}

/**
 * BlockPageConfig 在 PageConfig 基础上扩展拦截页与限流页专属文案。
 */
type BlockPageConfig struct {
	PageConfig
	BlockTitle     string `json:"block_title"`
	BlockMessage   string `json:"block_message"`
	RateLimitTitle string `json:"rate_limit_title"`
	RateLimitMsg   string `json:"rate_limit_message"`
}

/**
 * DefaultPageConfig 返回默认的页面品牌配置。
 *
 * @return 带内置品牌名、主色、背景渐变、标题与页脚文案的 PageConfig。
 */
func DefaultPageConfig() PageConfig {
	return PageConfig{
		BrandName:    "My-OpenWAF",
		PrimaryColor: "#14b8a6",
		BgGradient:   "linear-gradient(160deg,#f0fdfa 0%,#f8fafc 40%,#f1f5f9 100%)",
		Title:        "Security Verification",
		FooterText:   "Protected by My-OpenWAF",
	}
}

/**
 * DefaultCaptchaPageConfig 返回默认的 captcha 页面配置。
 *
 * @return 内嵌默认品牌配置、并带默认提示文案的 CaptchaPageConfig。
 */
func DefaultCaptchaPageConfig() CaptchaPageConfig {
	return CaptchaPageConfig{
		PageConfig: DefaultPageConfig(),
		Subtitle:   "Please solve the challenge to continue",
		SubtitleZh: "请完成安全验证以继续访问",
		SubmitText: "Submit / 提交",
	}
}

/**
 * DefaultChallengePageConfig 返回默认的 JS 挑战页面配置。
 *
 * @return 内嵌默认品牌配置、并带默认提示文案的 ChallengePageConfig。
 */
func DefaultChallengePageConfig() ChallengePageConfig {
	return ChallengePageConfig{
		PageConfig:     DefaultPageConfig(),
		CheckingText:   "Checking your browser",
		CheckingTextZh: "正在验证您的浏览器",
		WaitText:       "This process is automatic, please wait...",
		WaitTextZh:     "此过程是自动的，请稍候...",
	}
}

/**
 * DefaultBlockPageConfig 返回默认的拦截页配置。
 *
 * @return 内嵌默认品牌配置、并带拦截与限流文案的 BlockPageConfig。
 */
func DefaultBlockPageConfig() BlockPageConfig {
	return BlockPageConfig{
		PageConfig:     DefaultPageConfig(),
		BlockTitle:     "访问被拒绝",
		BlockMessage:   "您的请求已被 Web 应用防火墙拦截。Your request was blocked by the web application firewall.",
		RateLimitTitle: "请求过于频繁",
		RateLimitMsg:   "当前访问频率过高，请稍后重试。Too many requests, please retry later.",
	}
}

// ParseCaptchaPageConfig 解析存储的 captcha 页面配置，空值或非法 JSON 时回落默认值。
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

/**
 * SafePrimaryColor 返回受限的 CSS 颜色值，非法时回落到调用方给出的 fallback。
 *
 * 先经 sanitizeCSSValue 剔除可注入的构造，再校验是否命中 #hex / rgb() / rgba() / hsl() / hsla()
 * 这几种颜色写法；颜色值会直接进入模板样式，任何一项不满足都必须回落而不是原样透出。
 *
 * @param raw 用户配置的原始颜色值。
 * @param fallback 校验失败时使用的值。
 * @return 合法颜色值或 fallback。
 */
func SafePrimaryColor(raw, fallback string) string {
	value := sanitizeCSSValue(raw)
	if value == "" || !isCSSColor(value) {
		return fallback
	}
	return value
}

/**
 * SafeBackground 返回受限的 CSS 背景值，非法时回落到调用方给出的 fallback。
 *
 * 只接受以 linear-gradient( / radial-gradient( 开头且以 ) 结尾的渐变表达式；
 * 背景值同样是直接进入模板的样式片段，因此比颜色多一层前缀白名单。
 *
 * @param raw 用户配置的原始背景值。
 * @param fallback 校验失败时使用的值。
 * @return 合法背景值或 fallback。
 */
func SafeBackground(raw, fallback string) string {
	value := sanitizeCSSValue(raw)
	lower := strings.ToLower(value)
	if value == "" || (!strings.HasPrefix(lower, "linear-gradient(") && !strings.HasPrefix(lower, "radial-gradient(")) || !strings.HasSuffix(value, ")") {
		return fallback
	}
	return value
}

/**
 * SafeLogoURL 只放行同源路径与显式 http(s) 图片地址。
 *
 * 返回 template.URL 类型，使该值在 html/template 中不再被二次转义；
 * 正因如此，这里的白名单必须自己扛住注入：协议相对地址（//evil.example）
 * 与非 http(s) 协议一律拒绝。
 *
 * @param raw 用户配置的原始 Logo 地址。
 * @return 合法的 template.URL；不合法时返回空值。
 */
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

/**
 * SafeHTMLAttr 转义字符串，使其可安全用于 HTML 属性上下文。
 *
 * @param s 待转义的原始字符串。
 * @return 转义后的字符串。
 */
func SafeHTMLAttr(s string) string {
	return template.HTMLEscapeString(s)
}
