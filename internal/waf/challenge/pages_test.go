package challenge

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"regexp"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/pageconfig"
)

func TestCaptchaImageURLAllowsGeneratedDataImagesOnly(t *testing.T) {
	validPNG := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("png"))
	validJPEG := "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString([]byte("jpeg"))
	if got := captchaImageURL(validPNG); string(got) != validPNG {
		t.Fatalf("captchaImageURL() rejected PNG data image: %q", got)
	}
	if got := captchaImageURL(validJPEG); string(got) != validJPEG {
		t.Fatalf("captchaImageURL() rejected JPEG data image: %q", got)
	}
	for _, raw := range []string{
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD4=",
		"data:image/png;base64,not-base64",
	} {
		if got := captchaImageURL(raw); got != "" {
			t.Fatalf("captchaImageURL(%q) = %q, want empty", raw, got)
		}
	}
}

func TestRenderCaptchaPageUsesConfigAndRejectsUnsafeValues(t *testing.T) {
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image"))
	cfg := pageconfig.DefaultCaptchaPageConfig()
	cfg.BrandName = `<script>brand()</script>`
	cfg.Title = "Custom CAPTCHA"
	cfg.Subtitle = "Custom subtitle"
	cfg.SubmitText = "Continue"
	cfg.LogoURL = "javascript:alert(1)"
	cfg.CustomCSS = `</style><script>alert(1)</script>.safe{color:red}`
	page := string(renderCaptchaPage(&CaptchaChallenge{
		SessionID: "session",
		Type:      string(CaptchaTypeMath),
		MasterImg: image,
		Prompt:    "answer",
	}, "request", "", cfg))

	for _, want := range []string{"Custom CAPTCHA", "Custom subtitle", "Continue", "&lt;script&gt;brand()&lt;/script&gt;"} {
		if !strings.Contains(page, want) {
			t.Fatalf("captcha page missed configured value %q: %s", want, page)
		}
	}
	for _, forbidden := range []string{`<script>brand()`, `src="javascript:`, `</style><script>alert(1)</script>`} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("captcha page included unsafe configured value %q: %s", forbidden, page)
		}
	}
}

func TestRenderCaptchaPageEscapesDynamicFields(t *testing.T) {
	payload := `"><script>alert("captcha")</script>`
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image"))
	page := string(renderCaptchaPage(&CaptchaChallenge{
		SessionID: payload,
		Type:      string(CaptchaTypeMath),
		MasterImg: image,
		Prompt:    payload,
	}, payload, "", pageconfig.DefaultCaptchaPageConfig()))
	if strings.Contains(page, `<script>alert("captcha")</script>`) {
		t.Fatalf("captcha page reflected executable input: %s", page)
	}
	if !strings.Contains(page, `&lt;script&gt;`) {
		t.Fatalf("captcha page did not escape dynamic content: %s", page)
	}
}

func TestRenderCaptchaPreviewIncludesValidPNG(t *testing.T) {
	cfg := pageconfig.DefaultCaptchaPageConfig()
	page := string(RenderCaptchaPreview(cfg))
	re := regexp.MustCompile(`data:image/png;base64,([A-Za-z0-9+/=]+)`)
	matches := re.FindStringSubmatch(page)
	if len(matches) < 2 {
		t.Fatalf("preview page did not include a PNG data URI: %s", page)
	}
	data, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		t.Fatalf("preview PNG base64 decode: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("preview PNG is not decodable: %v", err)
	}
}
