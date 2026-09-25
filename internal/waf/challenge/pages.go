package challenge

import (
	"bytes"
	"embed"
	"html/template"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/waf/pageconfig"
)

//go:embed templates/*.html
var challengePageFS embed.FS

var captchaPageTmpl = template.Must(template.ParseFS(challengePageFS, "templates/captcha.html"))

type captchaPageData struct {
	SessionID    string
	CaptchaData  string
	KeyHex       string
	KeyPresent   bool
	RequestID    string
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

func renderCaptchaPage(challenge *CaptchaChallenge, reqID string, envJS string, cfg pageconfig.CaptchaPageConfig) []byte {
	if challenge == nil {
		return nil
	}
	defaults := pageconfig.DefaultCaptchaPageConfig()
	if cfg.BrandName == "" {
		cfg = defaults
	}
	data := captchaPageData{
		SessionID:    challenge.SessionID,
		CaptchaData:  challenge.CaptchaData,
		KeyHex:       challenge.EnvKeyHex,
		KeyPresent:   challenge.EnvKeyHex != "",
		RequestID:    reqID,
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
	return renderCaptchaSkeletonPreview(cfg)
}

func renderCaptchaSkeletonPreview(cfg pageconfig.CaptchaPageConfig) []byte {
	defaults := pageconfig.DefaultCaptchaPageConfig()
	if cfg.BrandName == "" {
		cfg = defaults
	}
	cfg.Title = valueOrDefault(cfg.Title, defaults.Title)
	cfg.SubmitText = valueOrDefault(cfg.SubmitText, defaults.SubmitText)
	cfg.FooterText = valueOrDefault(cfg.FooterText, defaults.FooterText)
	var buf bytes.Buffer
	if err := captchaPreviewTmpl.ExecuteTemplate(&buf, "captcha_preview.html", cfg); err != nil {
		return []byte("<!DOCTYPE html><html><body><p>Unable to render CAPTCHA preview.</p></body></html>")
	}
	return buf.Bytes()
}

var captchaPreviewTmpl = template.Must(template.ParseFS(challengePageFS, "templates/captcha_preview.html"))

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

func WriteCaptchaChallengeResponse(c *app.RequestContext, reqID string, cm *CaptchaManager, captchaType CaptchaType, envCheck bool, binding ChallengeSessionBinding, statusCode int, cfg pageconfig.CaptchaPageConfig) {
	prepareChallengeResponseHeaders(c, reqID)
	captchaChallenge, err := cm.GenerateWithBinding(captchaType, envCheck, binding)
	if err != nil {
		c.String(500, "captcha generation failed")
		return
	}
	envJS := ""
	if captchaChallenge.EnvKeyHex != "" {
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
