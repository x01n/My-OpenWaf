package pages

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"strings"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/waf/pageconfig"
)

//go:embed templates/*.html
var pageTemplateFS embed.FS

// fallbackPageData contains the public fields shown by block and maintenance fallbacks.
type fallbackPageData struct {
	Maintenance bool
	Title       string
	Message     string
	RequestID   string
	Label       string
}

// upstreamErrorPageData contains the public fields shown by the upstream fallback.
type upstreamErrorPageData struct {
	StatusCode int
	Title      string
	TitleZh    string
	Message    string
	MessageZh  string
	RequestID  string
	Icon       template.HTML
}

// errorPageTemplateData contains the fields rendered by the built-in error page.
type errorPageTemplateData struct {
	StatusCode int
	Title      string
	TitleZh    string
	BodyLines  []string
	CustomCSS  template.CSS
	Icon       template.HTML
}

// challengePageData contains trusted generated scripts and escaped challenge values.
type challengePageData struct {
	RequestID      string
	EnvJS          template.JS
	PowScript      template.JS
	TimestampJS    template.JS
	TokenJS        template.JS
	RequestIDJS    template.JS
	PageTitle      string
	BrandName      string
	CheckingText   string
	CheckingTextZh string
	WaitText       string
	WaitTextZh     string
	FooterText     string
	PrimaryColor   template.CSS
	Background     template.CSS
	LogoURL        template.URL
	CustomCSS      template.CSS
}

func javascriptString(value string) template.JS {
	encoded, err := json.Marshal(value)
	if err != nil {
		return template.JS(`""`)
	}
	return template.JS(encoded)
}

func executePageTemplate(name string, data any) ([]byte, error) {
	tpl, err := template.New(name).ParseFS(pageTemplateFS, "templates/"+name)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RenderChallengePreview renders a safe static preview of the JS challenge page.
func RenderChallengePreview(cfg pageconfig.ChallengePageConfig) []byte {
	return []byte(buildChallengeHTML("preview-request", "preview-ts", "preview-token", "", "", cfg))
}

// RenderBlockPreview renders a safe preview using the same configured block renderer.
func RenderBlockPreview(cfg pageconfig.BlockPageConfig) []byte {
	data := configuredPageConfig(cfg, false)
	data.RequestID = "preview-request"
	data.StatusLabel = "403 Forbidden"
	return renderConfiguredBlockPage(data)
}

func renderConfiguredBlockPage(data configuredBlockPageData) []byte {
	page, err := executePageTemplate("configured-block.html", data)
	if err != nil {
		return []byte(defaultFallbackHTML(data.RequestID, action.Result{}, false, action.Intercept))
	}
	return page
}

type configuredBlockPageData struct {
	PageTitle    string
	BrandName    string
	PrimaryColor template.CSS
	Background   template.CSS
	LogoURL      template.URL
	Heading      string
	Message      string
	RequestID    string
	FooterText   string
	StatusLabel  string
	CustomCSS    template.CSS
}

func configuredPageConfig(cfg pageconfig.BlockPageConfig, rateLimited bool) configuredBlockPageData {
	defaults := pageconfig.DefaultBlockPageConfig()
	heading, message := cfg.BlockTitle, cfg.BlockMessage
	if rateLimited {
		heading, message = cfg.RateLimitTitle, cfg.RateLimitMsg
	}
	return configuredBlockPageData{
		PageTitle:    valueOrFallback(cfg.Title, defaults.Title),
		BrandName:    valueOrFallback(cfg.BrandName, defaults.BrandName),
		PrimaryColor: template.CSS(pageconfig.SafePrimaryColor(cfg.PrimaryColor, defaults.PrimaryColor)),
		Background:   template.CSS(pageconfig.SafeBackground(cfg.BgGradient, defaults.BgGradient)),
		LogoURL:      pageconfig.SafeLogoURL(cfg.LogoURL),
		Heading:      valueOrFallback(heading, defaults.BlockTitle),
		Message:      valueOrFallback(message, defaults.BlockMessage),
		FooterText:   valueOrFallback(cfg.FooterText, defaults.FooterText),
		CustomCSS:    template.CSS(pageconfig.SanitizeCSS(cfg.CustomCSS)),
	}
}

func renderFallbackPage(data fallbackPageData) string {
	page, err := executePageTemplate("fallback.html", data)
	if err != nil {
		return "<!DOCTYPE html><html><head><title>Service Unavailable</title></head><body><h1>Service Unavailable</h1></body></html>"
	}
	return string(page)
}

func renderUpstreamErrorPage(data upstreamErrorPageData) string {
	page, err := executePageTemplate("upstream-error.html", data)
	if err != nil {
		return "<!DOCTYPE html><html><head><title>Upstream Error</title></head><body><h1>Upstream Error</h1></body></html>"
	}
	return string(page)
}

func renderBuiltInErrorPage(data errorPageTemplateData) []byte {
	page, err := executePageTemplate("error.html", data)
	if err != nil {
		return []byte("<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Error</h1></body></html>")
	}
	return page
}

func renderWelcomePage() []byte {
	page, err := executePageTemplate("welcome.html", nil)
	if err != nil {
		return []byte("<!DOCTYPE html><html><head><title>My-OpenWAF</title></head><body><h1>My-OpenWAF</h1></body></html>")
	}
	return page
}

func replaceEmbeddedPageValues(page []byte, replacements map[string]string) []byte {
	for marker, value := range replacements {
		page = bytes.ReplaceAll(page, []byte(marker), embeddedPageValue(value))
	}
	page = bytes.ReplaceAll(page, []byte(`"/_next/`), []byte(`"/__owaf/_next/`))
	page = bytes.ReplaceAll(page, []byte(`'/_next/`), []byte(`'/__owaf/_next/`))
	return page
}

func embeddedPageValue(value string) []byte {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) < 2 {
		return nil
	}
	return encoded[1 : len(encoded)-1]
}

func sanitizeTemplateCSS(css string) string {
	if css == "" {
		return ""
	}
	dangerous := []string{"</style", "<", ">", "expression(", "javascript:", "@import", "behavior:", "binding:"}
	clean := css
	for _, pattern := range dangerous {
		for {
			idx := strings.Index(strings.ToLower(clean), pattern)
			if idx == -1 {
				break
			}
			clean = clean[:idx] + clean[idx+len(pattern):]
		}
	}
	return clean
}
