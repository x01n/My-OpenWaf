package challenge

import (
	"bytes"
	"embed"
	"encoding/base64"
	"html/template"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/waf/pageconfig"
)

//go:embed templates/*.html
var challengePageFS embed.FS

var captchaPageTmpl = template.Must(template.ParseFS(challengePageFS, "templates/captcha.html"))

type captchaPageData struct {
	SessionID    string
	Type         string
	MasterImg    template.URL
	ThumbImg     template.URL
	Prompt       string
	InputMode    string
	RequestID    string
	SlideWidth   int
	IsClick      bool
	IsSlide      bool
	IsRotate     bool
	EnvJS        template.JS
	BrandName    string
	PageTitle    string
	Subtitle     string
	SubtitleZh   string
	SubmitText   string
	FooterText   string
	PrimaryColor template.CSS
	Background   template.CSS
	LogoURL      template.URL
	CustomCSS    template.CSS
}

func captchaImageURL(raw string) template.URL {
	prefix := ""
	switch {
	case strings.HasPrefix(raw, "data:image/png;base64,"):
		prefix = "data:image/png;base64,"
	case strings.HasPrefix(raw, "data:image/jpeg;base64,"):
		prefix = "data:image/jpeg;base64,"
	default:
		return ""
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, prefix)); err != nil {
		return ""
	}
	return template.URL(raw)
}

func renderCaptchaPage(challenge *CaptchaChallenge, reqID string, envJS string, cfg pageconfig.CaptchaPageConfig) []byte {
	if challenge == nil {
		return nil
	}
	defaults := pageconfig.DefaultCaptchaPageConfig()
	if cfg.BrandName == "" {
		cfg = defaults
	}
	captchaType := CaptchaType(challenge.Type)
	data := captchaPageData{
		SessionID:    challenge.SessionID,
		Type:         challenge.Type,
		MasterImg:    captchaImageURL(challenge.MasterImg),
		ThumbImg:     captchaImageURL(challenge.ThumbImg),
		Prompt:       challenge.Prompt,
		InputMode:    inputModeForCaptcha(challenge.Type),
		RequestID:    reqID,
		SlideWidth:   firstPositiveInt(challenge.Width, 360),
		IsClick:      captchaType == CaptchaTypeClick,
		IsSlide:      captchaType == CaptchaTypeSlide,
		IsRotate:     captchaType == CaptchaTypeRotate,
		EnvJS:        template.JS(envJS),
		BrandName:    valueOrDefault(cfg.BrandName, defaults.BrandName),
		PageTitle:    valueOrDefault(cfg.Title, defaults.Title),
		Subtitle:     valueOrDefault(cfg.Subtitle, defaults.Subtitle),
		SubtitleZh:   valueOrDefault(cfg.SubtitleZh, defaults.SubtitleZh),
		SubmitText:   valueOrDefault(cfg.SubmitText, defaults.SubmitText),
		FooterText:   valueOrDefault(cfg.FooterText, defaults.FooterText),
		PrimaryColor: template.CSS(pageconfig.SafePrimaryColor(cfg.PrimaryColor, defaults.PrimaryColor)),
		Background:   template.CSS(pageconfig.SafeBackground(cfg.BgGradient, defaults.BgGradient)),
		LogoURL:      pageconfig.SafeLogoURL(cfg.LogoURL),
		CustomCSS:    template.CSS(pageconfig.SanitizeCSS(cfg.CustomCSS)),
	}
	var buf bytes.Buffer
	if err := captchaPageTmpl.ExecuteTemplate(&buf, "captcha.html", data); err != nil {
		return []byte("<!DOCTYPE html><html><body><p>Unable to render security verification.</p></body></html>")
	}
	return buf.Bytes()
}

func RenderCaptchaPreview(cfg pageconfig.CaptchaPageConfig) []byte {
	const previewImage = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGMQ2bHsPwAEyAJyKnolIgAAAABJRU5ErkJggg=="
	return renderCaptchaPage(&CaptchaChallenge{
		SessionID: "preview",
		Type:      string(CaptchaTypeMath),
		MasterImg: previewImage,
		Prompt:    "CAPTCHA answer",
		Width:     200,
		Height:    80,
	}, "preview-request", "", cfg)
}

func valueOrDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func prepareChallengeResponseHeaders(c *app.RequestContext, reqID string) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
}

// WriteCaptchaChallengeResponse renders a standalone CAPTCHA challenge page.
// envCheck 为 true 时为该验证码会话绑定环境指纹密钥，并在页面注入加密的
// 浏览器/环境采集 JS，提交时携带 __waf_env_fp 供服务端校验是否为真实浏览器。
func WriteCaptchaChallengeResponse(c *app.RequestContext, reqID string, cm *CaptchaManager, captchaType CaptchaType, envCheck bool, binding ChallengeSessionBinding, statusCode int, cfg pageconfig.CaptchaPageConfig) {
	prepareChallengeResponseHeaders(c, reqID)
	captchaChallenge, err := cm.GenerateWithBinding(captchaType, envCheck, binding)
	if err != nil {
		c.String(500, "captcha generation failed")
		return
	}
	envJS := ""
	if envCheck && captchaChallenge.EnvKeyHex != "" {
		aad := EnvFingerprintAAD("captcha", captchaChallenge.SessionID, binding)
		envJS = EnvCheckJSEncrypted(captchaChallenge.EnvKeyHex, aad)
		if envJS == "" {
			c.String(500, "environment challenge initialization failed")
			return
		}
	}
	c.Data(statusCode, "text/html; charset=utf-8", renderCaptchaPage(captchaChallenge, reqID, envJS, cfg))
}

// WriteChainChallengeResponse starts a chain challenge and renders the first step.
func inputModeForCaptcha(captchaType string) string {
	switch CaptchaType(captchaType) {
	case CaptchaTypeClick:
		return "请按顺序点击目标"
	case CaptchaTypeSlide:
		return "拖动滑块到缺口位置"
	case CaptchaTypeRotate:
		return "旋转图片至正确角度"
	default:
		return "输入计算结果"
	}
}

func firstPositiveInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func WriteChainChallengeResponse(c *app.RequestContext, reqID string, cm *ChainChallengeManager, binding ChallengeSessionBinding, statusCode int) {
	prepareChallengeResponseHeaders(c, reqID)
	originalURL := string(c.Request.URI().RequestURI())
	_, html := cm.StartChainWithBinding(originalURL, binding)
	c.Data(statusCode, "text/html; charset=utf-8", []byte(html))
}
